package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/term"

	"github.com/lucasapassos/curral/internal/mcp"
)

type paramFlag []any

func (p *paramFlag) String() string { return fmt.Sprint(*p) }

// Set parses a JSON scalar (42, 1.5, true, null, "text"); anything that is
// not valid JSON is taken as a plain string.
func (p *paramFlag) Set(v string) error {
	var x any
	if err := json.Unmarshal([]byte(v), &x); err != nil {
		x = v
	}
	switch x.(type) {
	case []any, map[string]any:
		return fmt.Errorf("only scalar parameters are supported: %s", v)
	}
	*p = append(*p, x)
	return nil
}

const queryUsage = `Usage: curral query [flags] [SQL]

Runs one statement on a curral server and writes the result to stdout (or
-o). The SQL comes from the argument or, if absent, from stdin.

Credentials, in order of preference:
  CURRAL_TOKEN      API key (curral_...) or OIDC token, sent as Bearer
  CURRAL_USER and CURRAL_PASSWORD (or --user and a prompt) for Basic auth

Examples:
  curral query --url https://curral.example.com "SELECT * FROM orders LIMIT 10"
  curral query -f arrow -o orders.arrow "SELECT * FROM orders"
  curral query -p 42 "SELECT * FROM orders WHERE id = $1"
  echo "DELETE FROM orders" | curral query --dry-run

Flags:
`

func runQuery(args []string) error {
	fs := flag.NewFlagSet("curral query", flag.ContinueOnError)
	fs.Usage = func() { fmt.Fprint(fs.Output(), queryUsage); fs.PrintDefaults() }
	cfg := loadCredentialsFile()
	srvURL := fs.String("url", envOr("CURRAL_URL", orDefault(cfg["CURRAL_URL"], "http://127.0.0.1:8080")), "server URL (env CURRAL_URL)")
	user := fs.String("user", envOr("CURRAL_USER", cfg["CURRAL_USER"]), "user for Basic auth (env CURRAL_USER)")
	format := fs.String("f", "csv", "output format: csv, json, ndjson or arrow")
	database := fs.String("d", "", "database for unqualified names")
	out := fs.String("o", "", "write the result to this file instead of stdout")
	dryRun := fs.Bool("dry-run", false, "show the inspection and policy decision without executing")
	caFile := fs.String("ca", envOr("CURRAL_CA", cfg["CURRAL_CA"]), "PEM file with the CA that signed the server certificate")
	insecure := fs.Bool("insecure", false, "skip TLS certificate verification (testing only)")
	timeout := fs.Duration("timeout", 0, "client-side timeout (0 = none)")
	maxRows := fs.Int64("max-rows", 0, "return at most this many rows (lowers the server's limit; 0 = server limit)")
	var params paramFlag
	fs.Var(&params, "p", "positional parameter $1, $2, ... as a JSON scalar (repeatable)")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}

	sql := strings.Join(fs.Args(), " ")
	if sql == "" {
		b, err := io.ReadAll(os.Stdin)
		if err != nil {
			return err
		}
		sql = string(b)
	}
	if strings.TrimSpace(sql) == "" {
		fs.Usage()
		return errors.New("no SQL given")
	}

	body, _ := json.Marshal(map[string]any{
		"sql": sql, "params": []any(params), "format": *format,
		"database": *database, "dry_run": *dryRun, "max_rows": *maxRows,
	})
	req, err := http.NewRequest(http.MethodPost, strings.TrimRight(*srvURL, "/")+"/v1/query", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if err := applyAuth(req, *user, cfg); err != nil {
		return err
	}
	client, err := newHTTPClient(*caFile, *insecure, *timeout)
	if err != nil {
		return err
	}

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
		var e struct {
			Error string `json:"error"`
		}
		msg := strings.TrimSpace(string(b))
		if json.Unmarshal(b, &e) == nil && e.Error != "" {
			msg = e.Error
		}
		return fmt.Errorf("%s (request %s): %s", resp.Status, resp.Header.Get("X-Request-Id"), msg)
	}

	var w io.Writer = os.Stdout
	if *out != "" {
		f, err := os.Create(*out)
		if err != nil {
			return err
		}
		defer f.Close()
		w = f
	}
	start := time.Now()
	n, err := io.Copy(w, resp.Body)
	if err != nil {
		return fmt.Errorf("reading result: %w", err)
	}
	// Errors after the 200 status arrive as trailers.
	if msg := resp.Trailer.Get("X-Curral-Error"); msg != "" {
		// Cut at the limit asked with -max-rows: a sample, not a failure.
		if msg == "row limit reached" && *maxRows > 0 && resp.Header.Get("X-Curral-Max-Rows") == strconv.FormatInt(*maxRows, 10) {
			fmt.Fprintf(os.Stderr, "first %s rows (-max-rows); the result has more\n", resp.Trailer.Get("X-Curral-Row-Count"))
			return nil
		}
		return fmt.Errorf("result incomplete (%s rows): %s", resp.Trailer.Get("X-Curral-Row-Count"), msg)
	}
	if *out != "" {
		fmt.Fprintf(os.Stderr, "%s rows, %d bytes in %v -> %s\n",
			resp.Trailer.Get("X-Curral-Row-Count"), n, time.Since(start).Round(time.Millisecond), *out)
	}
	return nil
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func orDefault(v, def string) string {
	if v != "" {
		return v
	}
	return def
}

func loadCredentialsFile() map[string]string {
	out := map[string]string{}
	path := os.Getenv("CURRAL_CONFIG")
	if path == "" {
		if xdg := os.Getenv("XDG_CONFIG_HOME"); xdg != "" {
			path = filepath.Join(xdg, "curral", "credentials")
		} else if home, err := os.UserHomeDir(); err == nil {
			path = filepath.Join(home, ".config", "curral", "credentials")
		}
	}
	if path == "" {
		return out
	}
	f, err := os.Open(path)
	if err != nil {
		return out
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		k, v, ok := strings.Cut(sc.Text(), "=")
		if ok {
			out[strings.TrimSpace(k)] = v
		}
	}
	return out
}

func applyAuth(req *http.Request, user string, cfg map[string]string) error {
	// Tokens often come from files with a trailing newline.
	token := strings.TrimSpace(os.Getenv("CURRAL_TOKEN"))
	if token == "" && user == "" {
		token = strings.TrimSpace(cfg["CURRAL_TOKEN"])
	}
	switch {
	case token != "":
		req.Header.Set("Authorization", "Bearer "+token)
	case user != "":
		pass, ok := os.LookupEnv("CURRAL_PASSWORD")
		if !ok {
			if p, has := cfg["CURRAL_PASSWORD"]; has && user == cfg["CURRAL_USER"] {
				pass = p
			} else {
				var err error
				if pass, err = promptPassword(user); err != nil {
					return err
				}
			}
		}
		req.SetBasicAuth(user, pass)
	default:
		return errors.New("no credentials: set CURRAL_TOKEN, or CURRAL_USER/--user")
	}
	return nil
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

func runSimpleGET(name, endpoint string, args []string, allowedFilters []string) error {
	cfg := loadCredentialsFile()
	fs := flag.NewFlagSet("curral "+name, flag.ContinueOnError)
	srvURL := fs.String("url", envOr("CURRAL_URL", orDefault(cfg["CURRAL_URL"], "http://127.0.0.1:8080")), "server URL (env CURRAL_URL)")
	user := fs.String("user", envOr("CURRAL_USER", cfg["CURRAL_USER"]), "user for Basic auth (env CURRAL_USER)")
	caFile := fs.String("ca", envOr("CURRAL_CA", cfg["CURRAL_CA"]), "PEM file with the CA that signed the server certificate")
	insecure := fs.Bool("insecure", false, "skip TLS certificate verification (testing only)")
	timeout := fs.Duration("timeout", 0, "client-side timeout (0 = none)")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	q := url.Values{}
	for _, kv := range fs.Args() {
		k, v, ok := strings.Cut(kv, "=")
		if !ok || !containsStr(allowedFilters, k) {
			return fmt.Errorf("invalid argument %q", kv)
		}
		q.Add(k, v)
	}
	target := strings.TrimRight(*srvURL, "/") + endpoint
	if enc := q.Encode(); enc != "" {
		target += "?" + enc
	}
	req, err := http.NewRequest(http.MethodGet, target, nil)
	if err != nil {
		return err
	}
	if err := applyAuth(req, *user, cfg); err != nil {
		return err
	}
	client, err := newHTTPClient(*caFile, *insecure, *timeout)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
		var e struct {
			Error string `json:"error"`
		}
		msg := strings.TrimSpace(string(b))
		if json.Unmarshal(b, &e) == nil && e.Error != "" {
			msg = e.Error
		}
		return fmt.Errorf("%s (request %s): %s", resp.Status, resp.Header.Get("X-Request-Id"), msg)
	}
	_, err = io.Copy(os.Stdout, resp.Body)
	return err
}

func containsStr(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

func runSchema(args []string) error {
	return runSimpleGET("schema", "/v1/schema", args, []string{"database", "schema", "table"})
}

func runCapabilities(args []string) error {
	return runSimpleGET("capabilities", "/v1/capabilities", args, nil)
}

func runMCP(args []string) error {
	cfg := loadCredentialsFile()
	fs := flag.NewFlagSet("curral mcp", flag.ContinueOnError)
	srvURL := fs.String("url", envOr("CURRAL_URL", orDefault(cfg["CURRAL_URL"], "http://127.0.0.1:8080")), "server URL (env CURRAL_URL)")
	user := fs.String("user", envOr("CURRAL_USER", cfg["CURRAL_USER"]), "user for Basic auth (env CURRAL_USER)")
	caFile := fs.String("ca", envOr("CURRAL_CA", cfg["CURRAL_CA"]), "PEM file with the CA that signed the server certificate")
	insecure := fs.Bool("insecure", false, "skip TLS certificate verification (testing only)")
	timeout := fs.Duration("timeout", 0, "client-side timeout (0 = none)")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	token := strings.TrimSpace(os.Getenv("CURRAL_TOKEN"))
	if token == "" && *user == "" {
		token = strings.TrimSpace(cfg["CURRAL_TOKEN"])
	}
	pass := os.Getenv("CURRAL_PASSWORD")
	if token == "" && *user != "" && pass == "" && *user == cfg["CURRAL_USER"] {
		pass = cfg["CURRAL_PASSWORD"]
	}
	if token == "" && *user == "" {
		return errors.New("no credentials: set CURRAL_TOKEN, CURRAL_USER, or configure ~/.config/curral/credentials")
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return mcp.RunStdio(ctx, os.Stdin, os.Stdout, mcp.ClientConfig{
		URL:      *srvURL,
		Token:    token,
		User:     *user,
		Password: pass,
		CAFile:   *caFile,
		Insecure: *insecure,
		Timeout:  *timeout,
		Version:  version,
	})
}

func promptPassword(user string) (string, error) {
	if tty, err := os.Open("/dev/tty"); err == nil {
		defer tty.Close()
		fmt.Fprintf(os.Stderr, "Password for %s: ", user)
		b, err := readPassword(int(tty.Fd()))
		fmt.Fprintln(os.Stderr)
		return string(b), err
	}
	if term.IsTerminal(int(os.Stdin.Fd())) {
		fmt.Fprintf(os.Stderr, "Password for %s: ", user)
		b, err := readPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		return string(b), err
	}
	return "", errors.New("no password: set CURRAL_PASSWORD or run in a terminal")
}
