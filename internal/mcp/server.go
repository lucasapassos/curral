// Package mcp implements a native Model Context Protocol (MCP) server over
// Streamable HTTP and a stdio client bridge that talks to a remote curral
// server over HTTP.
package mcp

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
)

// ProtocolVersion is the MCP specification version implemented by this package.
const ProtocolVersion = "2025-03-26"

const defaultMaxBody int64 = 1 << 20 // 1 MiB

const (
	errCodeParse          = -32700
	errCodeInvalidRequest = -32600
	errCodeMethodNotFound = -32601
	errCodeInvalidParams  = -32602
	errCodeInternal       = -32603
)

const (
	headerExecutionContext = "X-Curral-Execution-Context"
	headerCallerContext    = "X-Curral-Caller-Context"
	headerEffectiveSubject = "X-Curral-Effective-Subject"
	headerCurralError      = "X-Curral-Error"
	headerRequestID        = "X-Request-Id"
)

var validDocID = regexp.MustCompile(`^[a-z0-9]{8,64}$`)

// Options configures the Streamable HTTP MCP handler.
type Options struct {
	Version     string
	DocsEnabled bool
	MaxBody     int64 // default 1 MiB
}

// rpcRequest is a JSON-RPC 2.0 request or notification.
type rpcRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

// rpcResponse is a JSON-RPC 2.0 response.
type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type initializeResult struct {
	ProtocolVersion string             `json:"protocolVersion"`
	Capabilities    serverCapabilities `json:"capabilities"`
	ServerInfo      serverInfo         `json:"serverInfo"`
}

type serverCapabilities struct {
	Tools map[string]any `json:"tools"`
}

type serverInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type toolDefinition struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	InputSchema map[string]any `json:"inputSchema"`
}

type toolCallParams struct {
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments,omitempty"`
}

type toolContent struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

type toolResult struct {
	Content []toolContent `json:"content"`
	IsError bool          `json:"isError,omitempty"`
}

// toolHTTPRequest describes the curral REST API call corresponding to an MCP tool call.
type toolHTTPRequest struct {
	Method string
	Path   string
	Body   []byte
}

// NewHandler returns an http.Handler implementing the MCP Streamable HTTP
// transport (JSON-RPC 2.0 over POST) backed by an in-process curral API handler.
func NewHandler(api http.Handler, opts Options) http.Handler {
	maxBody := opts.MaxBody
	if maxBody <= 0 {
		maxBody = defaultMaxBody
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodPost)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusMethodNotAllowed)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "method not allowed; use POST"})
			return
		}

		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBody))
		if err != nil {
			var tooLarge *http.MaxBytesError
			if errors.As(err, &tooLarge) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusRequestEntityTooLarge)
				_ = json.NewEncoder(w).Encode(map[string]string{"error": "request body too large"})
				return
			}
			writeRPC(w, rpcResponse{
				JSONRPC: "2.0",
				ID:      json.RawMessage("null"),
				Error:   &rpcError{Code: errCodeParse, Message: "failed to read request body: " + err.Error()},
			})
			return
		}

		var req rpcRequest
		if err := json.Unmarshal(body, &req); err != nil {
			writeRPC(w, rpcResponse{
				JSONRPC: "2.0",
				ID:      json.RawMessage("null"),
				Error:   &rpcError{Code: errCodeParse, Message: "parse error: " + err.Error()},
			})
			return
		}

		if req.JSONRPC != "2.0" || req.Method == "" {
			writeRPC(w, rpcResponse{
				JSONRPC: "2.0",
				ID:      normalizeID(req.ID),
				Error:   &rpcError{Code: errCodeInvalidRequest, Message: "invalid JSON-RPC 2.0 request"},
			})
			return
		}

		if isNotification(req) {
			w.WriteHeader(http.StatusAccepted)
			return
		}

		resp := dispatchRPC(req, opts.Version, func() bool { return opts.DocsEnabled }, func(spec *toolHTTPRequest) toolResult {
			return invokeInProcess(api, w, r, spec)
		})
		writeRPC(w, resp)
	})
}

func isNotification(req rpcRequest) bool {
	if req.Method == "notifications/initialized" {
		return true
	}
	return strings.HasPrefix(req.Method, "notifications/") && len(bytes.TrimSpace(req.ID)) == 0
}

func normalizeID(id json.RawMessage) json.RawMessage {
	if len(bytes.TrimSpace(id)) == 0 {
		return json.RawMessage("null")
	}
	return id
}

func writeRPC(w http.ResponseWriter, resp rpcResponse) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)
}

// dispatchRPC executes a single JSON-RPC 2.0 method and returns its response.
// Both the Streamable HTTP handler and the stdio bridge share this logic.
func dispatchRPC(
	req rpcRequest,
	version string,
	docsEnabled func() bool,
	callTool func(*toolHTTPRequest) toolResult,
) rpcResponse {
	id := normalizeID(req.ID)
	switch req.Method {
	case "initialize":
		_ = docsEnabled()
		return rpcResponse{
			JSONRPC: "2.0",
			ID:      id,
			Result: initializeResult{
				ProtocolVersion: ProtocolVersion,
				Capabilities:    serverCapabilities{Tools: map[string]any{}},
				ServerInfo:      serverInfo{Name: "curral", Version: version},
			},
		}
	case "ping":
		return rpcResponse{
			JSONRPC: "2.0",
			ID:      id,
			Result:  map[string]any{},
		}
	case "tools/list":
		return rpcResponse{
			JSONRPC: "2.0",
			ID:      id,
			Result:  map[string]any{"tools": toolDefinitions(docsEnabled())},
		}
	case "tools/call":
		var params toolCallParams
		if len(bytes.TrimSpace(req.Params)) == 0 {
			return rpcResponse{
				JSONRPC: "2.0",
				ID:      id,
				Error:   &rpcError{Code: errCodeInvalidParams, Message: "missing params"},
			}
		}
		if err := json.Unmarshal(req.Params, &params); err != nil || strings.TrimSpace(params.Name) == "" {
			return rpcResponse{
				JSONRPC: "2.0",
				ID:      id,
				Error:   &rpcError{Code: errCodeInvalidParams, Message: "invalid tools/call params"},
			}
		}
		spec, rpcErr, earlyRes := buildToolRequest(params.Name, params.Arguments, docsEnabled())
		if rpcErr != nil {
			return rpcResponse{JSONRPC: "2.0", ID: id, Error: rpcErr}
		}
		if earlyRes != nil {
			return rpcResponse{JSONRPC: "2.0", ID: id, Result: *earlyRes}
		}
		return rpcResponse{
			JSONRPC: "2.0",
			ID:      id,
			Result:  callTool(spec),
		}
	default:
		return rpcResponse{
			JSONRPC: "2.0",
			ID:      id,
			Error:   &rpcError{Code: errCodeMethodNotFound, Message: "method not found: " + req.Method},
		}
	}
}

func invokeInProcess(api http.Handler, outerW http.ResponseWriter, outerR *http.Request, spec *toolHTTPRequest) toolResult {
	var bodyReader io.Reader
	if len(spec.Body) > 0 {
		bodyReader = bytes.NewReader(spec.Body)
	}
	subReq, err := http.NewRequestWithContext(outerR.Context(), spec.Method, spec.Path, bodyReader)
	if err != nil {
		return errorToolResult("failed to build internal request: " + err.Error())
	}
	if len(spec.Body) > 0 {
		subReq.Header.Set("Content-Type", "application/json")
	}
	if auth := outerR.Header.Get("Authorization"); auth != "" {
		subReq.Header.Set("Authorization", auth)
	}
	forwardHeaders := []string{"X-Forwarded-For"}
	if spec.Path != "/v1/capabilities" {
		forwardHeaders = append(forwardHeaders, headerExecutionContext, headerCallerContext)
	}
	for _, h := range forwardHeaders {
		for _, v := range outerR.Header.Values(h) {
			subReq.Header.Add(h, v)
		}
	}
	subReq.RemoteAddr = outerR.RemoteAddr

	rec := httptest.NewRecorder()
	aborted := false
	func() {
		defer func() {
			if rv := recover(); rv != nil {
				if rv == http.ErrAbortHandler {
					aborted = true
					return
				}
				panic(rv)
			}
		}()
		api.ServeHTTP(rec, subReq)
	}()

	if subj := rec.Header().Get(headerEffectiveSubject); subj != "" {
		outerW.Header().Set(headerEffectiveSubject, subj)
	}
	res := rec.Result()
	defer res.Body.Close()
	respBody, _ := io.ReadAll(res.Body)
	return formatToolResponse(res.StatusCode, res.Header, res.Trailer, rec.Header(), respBody, aborted)
}

func toolDefinitions(docsEnabled bool) []toolDefinition {
	tools := []toolDefinition{
		{
			Name:        "curral_capabilities",
			Description: "Inspect server capabilities, caller subject, delegation status, supported formats, and semantic docs availability.",
			InputSchema: map[string]any{
				"type":                 "object",
				"properties":           map[string]any{},
				"additionalProperties": false,
			},
		},
		{
			Name:        "curral_schema",
			Description: "List databases, tables, views, and columns that the caller is authorized to read.",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"database": map[string]any{"type": "string", "description": "Filter by database name."},
					"schema":   map[string]any{"type": "string", "description": "Filter by schema name."},
					"table":    map[string]any{"type": "string", "description": "Filter by table or view name."},
				},
				"additionalProperties": false,
			},
		},
		{
			Name:        "curral_dry_run",
			Description: "Inspect a SQL statement and evaluate policy, limits, row filters, and column masks without executing it.",
			InputSchema: queryToolSchema(),
		},
		{
			Name:        "curral_query",
			Description: "Execute an authorized SQL statement and return JSON results.",
			InputSchema: queryToolSchema(),
		},
	}
	if docsEnabled {
		tools = append(tools,
			toolDefinition{
				Name:        "curral_search_docs",
				Description: "Search semantic documentation for tables, schemas, metrics, and example SQL.",
				InputSchema: map[string]any{
					"type":     "object",
					"required": []string{"q"},
					"properties": map[string]any{
						"q":       map[string]any{"type": "string", "description": "Search query text."},
						"table":   map[string]any{"type": "string", "description": "Filter by a single table name (mutually exclusive with tables)."},
						"tables":  map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "Filter by any of these table names."},
						"schema":  map[string]any{"type": "string", "description": "Filter by a single schema name (mutually exclusive with schemas)."},
						"schemas": map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "Filter by any of these schema names."},
						"limit":   map[string]any{"type": "integer", "minimum": 1, "maximum": 50, "description": "Maximum number of results (1-50)."},
						"fields":  map[string]any{"type": "string", "enum": []string{"full", "header"}, "description": "Return full documents or headers only."},
						"access":  map[string]any{"type": "boolean", "description": "Annotate each document with accessible and inaccessible tables."},
					},
					"additionalProperties": false,
				},
			},
			toolDefinition{
				Name:        "curral_get_doc",
				Description: "Retrieve a single semantic document by its ID.",
				InputSchema: map[string]any{
					"type":     "object",
					"required": []string{"id"},
					"properties": map[string]any{
						"id":     map[string]any{"type": "string", "pattern": "^[a-z0-9]{8,64}$", "description": "Document identifier."},
						"access": map[string]any{"type": "boolean", "description": "Annotate the document with accessible and inaccessible tables."},
					},
					"additionalProperties": false,
				},
			},
		)
	}
	return tools
}

func queryToolSchema() map[string]any {
	return map[string]any{
		"type":     "object",
		"required": []string{"sql"},
		"properties": map[string]any{
			"sql": map[string]any{"type": "string", "description": "SQL statement to inspect or execute."},
			"params": map[string]any{
				"type":        "array",
				"description": "Positional scalar parameters ($1, $2, ...).",
				"items":       map[string]any{"type": []string{"string", "number", "boolean", "null"}},
			},
			"database": map[string]any{"type": "string", "description": "Default database for unqualified names."},
			"max_rows": map[string]any{"type": "integer", "minimum": 0, "description": "Maximum rows to return (0 = server/policy limit)."},
		},
		"additionalProperties": false,
	}
}

func decodeArgs(raw json.RawMessage, dst any) error {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return nil
	}
	dec := json.NewDecoder(bytes.NewReader(trimmed))
	dec.UseNumber()
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return err
	}
	return nil
}

func buildToolRequest(name string, rawArgs json.RawMessage, docsEnabled bool) (*toolHTTPRequest, *rpcError, *toolResult) {
	switch name {
	case "curral_capabilities":
		var args struct{}
		if err := decodeArgs(rawArgs, &args); err != nil {
			res := errorToolResult("invalid arguments: " + err.Error())
			return nil, nil, &res
		}
		return &toolHTTPRequest{Method: http.MethodGet, Path: "/v1/capabilities"}, nil, nil

	case "curral_schema":
		var args struct {
			Database string `json:"database"`
			Schema   string `json:"schema"`
			Table    string `json:"table"`
		}
		if err := decodeArgs(rawArgs, &args); err != nil {
			res := errorToolResult("invalid arguments: " + err.Error())
			return nil, nil, &res
		}
		q := url.Values{}
		if args.Database != "" {
			q.Set("database", args.Database)
		}
		if args.Schema != "" {
			q.Set("schema", args.Schema)
		}
		if args.Table != "" {
			q.Set("table", args.Table)
		}
		path := "/v1/schema"
		if enc := q.Encode(); enc != "" {
			path += "?" + enc
		}
		return &toolHTTPRequest{Method: http.MethodGet, Path: path}, nil, nil

	case "curral_dry_run", "curral_query":
		var args struct {
			SQL      string `json:"sql"`
			Params   []any  `json:"params"`
			Database string `json:"database"`
			MaxRows  int64  `json:"max_rows"`
		}
		if err := decodeArgs(rawArgs, &args); err != nil {
			res := errorToolResult("invalid arguments: " + err.Error())
			return nil, nil, &res
		}
		if strings.TrimSpace(args.SQL) == "" {
			res := errorToolResult("sql is required")
			return nil, nil, &res
		}
		if args.MaxRows < 0 {
			res := errorToolResult("max_rows must be >= 0")
			return nil, nil, &res
		}
		payload := map[string]any{
			"sql": args.SQL,
		}
		if len(args.Params) > 0 {
			payload["params"] = args.Params
		}
		if args.Database != "" {
			payload["database"] = args.Database
		}
		if args.MaxRows > 0 {
			payload["max_rows"] = args.MaxRows
		}
		if name == "curral_dry_run" {
			payload["dry_run"] = true
		} else {
			payload["format"] = "json"
		}
		b, err := json.Marshal(payload)
		if err != nil {
			res := errorToolResult("failed to encode query request: " + err.Error())
			return nil, nil, &res
		}
		return &toolHTTPRequest{Method: http.MethodPost, Path: "/v1/query", Body: b}, nil, nil

	case "curral_search_docs":
		if !docsEnabled {
			return nil, &rpcError{Code: errCodeInvalidParams, Message: "unknown tool: " + name}, nil
		}
		var args struct {
			Q       string   `json:"q"`
			Table   string   `json:"table,omitempty"`
			Tables  []string `json:"tables,omitempty"`
			Schema  string   `json:"schema,omitempty"`
			Schemas []string `json:"schemas,omitempty"`
			Limit   int      `json:"limit,omitempty"`
			Fields  string   `json:"fields,omitempty"`
			Access  bool     `json:"access,omitempty"`
		}
		if err := decodeArgs(rawArgs, &args); err != nil {
			res := errorToolResult("invalid arguments: " + err.Error())
			return nil, nil, &res
		}
		if strings.TrimSpace(args.Q) == "" {
			res := errorToolResult("q is required")
			return nil, nil, &res
		}
		b, err := json.Marshal(args)
		if err != nil {
			res := errorToolResult("failed to encode search request: " + err.Error())
			return nil, nil, &res
		}
		return &toolHTTPRequest{Method: http.MethodPost, Path: "/v1/docs/search", Body: b}, nil, nil

	case "curral_get_doc":
		if !docsEnabled {
			return nil, &rpcError{Code: errCodeInvalidParams, Message: "unknown tool: " + name}, nil
		}
		var args struct {
			ID     string `json:"id"`
			Access bool   `json:"access"`
		}
		if err := decodeArgs(rawArgs, &args); err != nil {
			res := errorToolResult("invalid arguments: " + err.Error())
			return nil, nil, &res
		}
		if !validDocID.MatchString(args.ID) {
			res := errorToolResult("invalid document id: must match ^[a-z0-9]{8,64}$")
			return nil, nil, &res
		}
		path := "/v1/docs/" + args.ID
		if args.Access {
			path += "?access=true"
		}
		return &toolHTTPRequest{Method: http.MethodGet, Path: path}, nil, nil

	default:
		return nil, &rpcError{Code: errCodeInvalidParams, Message: "unknown tool: " + name}, nil
	}
}

func errorToolResult(msg string) toolResult {
	return toolResult{
		Content: []toolContent{{Type: "text", Text: msg}},
		IsError: true,
	}
}

func formatToolResponse(status int, headers, trailers, recHeaders http.Header, body []byte, aborted bool) toolResult {
	if status != http.StatusOK {
		msg := extractJSONError(body)
		if msg == "" {
			msg = strings.TrimSpace(string(body))
		}
		if msg == "" {
			msg = http.StatusText(status)
		}
		reqID := headers.Get(headerRequestID)
		if reqID == "" && recHeaders != nil {
			reqID = recHeaders.Get(headerRequestID)
		}
		if reqID != "" {
			return errorToolResult(fmt.Sprintf("HTTP %d (request %s): %s", status, reqID, msg))
		}
		return errorToolResult(fmt.Sprintf("HTTP %d: %s", status, msg))
	}

	curralErr := firstNonEmpty(
		headerGet(trailers, headerCurralError),
		headerGet(headers, headerCurralError),
		headerGet(recHeaders, headerCurralError),
	)
	if curralErr == "" && aborted {
		curralErr = "query aborted mid-stream"
	}
	if curralErr == "" {
		curralErr = extractJSONError(body)
	}

	text := strings.TrimSpace(string(body))
	if curralErr != "" {
		warning := fmt.Sprintf("WARNING: result incomplete (%s)", curralErr)
		if text != "" {
			text = warning + "\n" + text
		} else {
			text = warning
		}
		return toolResult{
			Content: []toolContent{{Type: "text", Text: text}},
			IsError: aborted || curralErr != "row limit reached",
		}
	}
	return toolResult{
		Content: []toolContent{{Type: "text", Text: text}},
	}
}

func extractJSONError(body []byte) string {
	var e struct {
		Error string `json:"error"`
	}
	if json.Unmarshal(body, &e) == nil && e.Error != "" {
		return e.Error
	}
	return ""
}

func headerGet(h http.Header, key string) string {
	if h == nil {
		return ""
	}
	return h.Get(key)
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
