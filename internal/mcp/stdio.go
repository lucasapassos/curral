package mcp

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// ClientConfig configures the stdio MCP bridge that proxies tool calls to a
// remote curral HTTP server.
type ClientConfig struct {
	URL      string
	Token    string
	User     string
	Password string
	CAFile   string
	Insecure bool
	Timeout  time.Duration
	Version  string
}

const (
	maxStdioLineBytes = 4 << 20  // 4 MiB
	maxStdioRespBytes = 32 << 20 // 32 MiB
)

// RunStdio serves the MCP JSON-RPC 2.0 protocol over newline-delimited stdio
// streams (r for requests, w for responses) backed by a remote curral server.
// Credentials stay inside this process and are never written to w.
func RunStdio(ctx context.Context, r io.Reader, w io.Writer, cfg ClientConfig) error {
	baseURL := strings.TrimRight(strings.TrimSpace(cfg.URL), "/")
	if baseURL == "" {
		return errors.New("mcp stdio: server URL is required")
	}
	client, err := newHTTPClient(cfg.CAFile, cfg.Insecure, cfg.Timeout)
	if err != nil {
		return err
	}

	b := &stdioBridge{
		baseURL: baseURL,
		cfg:     cfg,
		client:  client,
	}

	br := bufio.NewReaderSize(r, 64<<10)
	bw := bufio.NewWriter(w)

	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		line, err := readLineLimited(br, maxStdioLineBytes)
		if err != nil && !errors.Is(err, io.EOF) {
			if errors.Is(err, errLineTooLong) {
				if werr := writeStdioRPC(bw, rpcResponse{
					JSONRPC: "2.0",
					ID:      json.RawMessage("null"),
					Error:   &rpcError{Code: errCodeInvalidRequest, Message: "request line too large"},
				}); werr != nil {
					return werr
				}
				continue
			}
			return err
		}

		trimmed := bytes.TrimSpace(line)
		if len(trimmed) > 0 {
			var req rpcRequest
			if jerr := json.Unmarshal(trimmed, &req); jerr != nil {
				if werr := writeStdioRPC(bw, rpcResponse{
					JSONRPC: "2.0",
					ID:      json.RawMessage("null"),
					Error:   &rpcError{Code: errCodeParse, Message: "parse error: " + jerr.Error()},
				}); werr != nil {
					return werr
				}
			} else if req.JSONRPC != "2.0" || req.Method == "" {
				if werr := writeStdioRPC(bw, rpcResponse{
					JSONRPC: "2.0",
					ID:      normalizeID(req.ID),
					Error:   &rpcError{Code: errCodeInvalidRequest, Message: "invalid JSON-RPC 2.0 request"},
				}); werr != nil {
					return werr
				}
			} else if !isNotification(req) {
				resp := dispatchRPC(req, cfg.Version, func() bool {
					return b.docsEnabled(ctx)
				}, func(spec *toolHTTPRequest) toolResult {
					return b.callRemote(ctx, spec)
				})
				if werr := writeStdioRPC(bw, resp); werr != nil {
					return werr
				}
			}
		}

		if errors.Is(err, io.EOF) {
			return nil
		}
	}
}

var errLineTooLong = errors.New("line exceeds maximum length")

func readLineLimited(br *bufio.Reader, limit int) ([]byte, error) {
	var buf []byte
	for {
		part, isPrefix, err := br.ReadLine()
		if len(buf)+len(part) > limit {
			// Drain the rest of the oversized line so subsequent lines stay aligned.
			for isPrefix && err == nil {
				_, isPrefix, err = br.ReadLine()
			}
			return nil, errLineTooLong
		}
		buf = append(buf, part...)
		if err != nil {
			return buf, err
		}
		if !isPrefix {
			return buf, nil
		}
	}
}

func writeStdioRPC(bw *bufio.Writer, resp rpcResponse) error {
	b, err := json.Marshal(resp)
	if err != nil {
		return err
	}
	if _, err := bw.Write(b); err != nil {
		return err
	}
	if err := bw.WriteByte('\n'); err != nil {
		return err
	}
	return bw.Flush()
}

type stdioBridge struct {
	baseURL     string
	cfg         ClientConfig
	client      *http.Client
	docsChecked bool
	docsOn      bool
}

func (b *stdioBridge) docsEnabled(ctx context.Context) bool {
	if b.docsChecked {
		return b.docsOn
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, b.baseURL+"/v1/capabilities", nil)
	if err != nil {
		return false
	}
	b.applyAuth(req)
	resp, err := b.client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
		return false
	}
	var capa struct {
		Docs struct {
			Enabled bool `json:"enabled"`
		} `json:"docs"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&capa); err != nil {
		return false
	}
	b.docsChecked = true
	b.docsOn = capa.Docs.Enabled
	return b.docsOn
}

func (b *stdioBridge) callRemote(ctx context.Context, spec *toolHTTPRequest) toolResult {
	var bodyReader io.Reader
	if len(spec.Body) > 0 {
		bodyReader = bytes.NewReader(spec.Body)
	}
	req, err := http.NewRequestWithContext(ctx, spec.Method, b.baseURL+spec.Path, bodyReader)
	if err != nil {
		return errorToolResult("failed to build request: " + err.Error())
	}
	if len(spec.Body) > 0 {
		req.Header.Set("Content-Type", "application/json")
	}
	b.applyAuth(req)

	resp, err := b.client.Do(req)
	if err != nil {
		return errorToolResult("request failed: " + err.Error())
	}
	defer resp.Body.Close()
	body, readErr := io.ReadAll(io.LimitReader(resp.Body, maxStdioRespBytes+1))
	if int64(len(body)) > maxStdioRespBytes {
		return errorToolResult("response exceeds 32 MiB MCP bridge limit; add LIMIT or aggregate in SQL")
	}
	if readErr != nil {
		return formatToolResponse(resp.StatusCode, resp.Header, resp.Trailer, nil, body, true)
	}
	return formatToolResponse(resp.StatusCode, resp.Header, resp.Trailer, nil, body, false)
}

func (b *stdioBridge) applyAuth(req *http.Request) {
	if tok := strings.TrimSpace(b.cfg.Token); tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
		return
	}
	if b.cfg.User != "" {
		req.SetBasicAuth(b.cfg.User, b.cfg.Password)
	}
}

func newHTTPClient(caFile string, insecure bool, timeout time.Duration) (*http.Client, error) {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: insecure} //nolint:gosec // opt-in for testing
	if caFile != "" {
		pem, err := os.ReadFile(caFile)
		if err != nil {
			return nil, err
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("%s: no certificates found", caFile)
		}
		tr.TLSClientConfig.RootCAs = pool
	}
	return &http.Client{Transport: tr, Timeout: timeout}, nil
}
