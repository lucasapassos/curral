package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
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
	url := fs.String("url", envOr("CURRAL_URL", "http://127.0.0.1:8080"), "server URL (env CURRAL_URL)")
	user := fs.String("user", os.Getenv("CURRAL_USER"), "user for Basic auth (env CURRAL_USER)")
	format := fs.String("f", "csv", "output format: csv, json, ndjson or arrow")
	database := fs.String("d", "", "database for unqualified names")
	out := fs.String("o", "", "write the result to this file instead of stdout")
	dryRun := fs.Bool("dry-run", false, "show the inspection and policy decision without executing")
	caFile := fs.String("ca", "", "PEM file with the CA that signed the server certificate")
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
	req, err := http.NewRequest(http.MethodPost, strings.TrimRight(*url, "/")+"/v1/query", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	// Tokens often come from files with a trailing newline.
	token := strings.TrimSpace(os.Getenv("CURRAL_TOKEN"))
	switch {
	case token != "":
		req.Header.Set("Authorization", "Bearer "+token)
	case *user != "":
		pass, ok := os.LookupEnv("CURRAL_PASSWORD")
		if !ok {
			if pass, err = promptPassword(*user); err != nil {
				return err
			}
		}
		req.SetBasicAuth(*user, pass)
	default:
		return errors.New("no credentials: set CURRAL_TOKEN, or CURRAL_USER/--user")
	}

	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: *insecure} //nolint:gosec // opt-in for testing
	if *caFile != "" {
		pem, err := os.ReadFile(*caFile)
		if err != nil {
			return err
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return fmt.Errorf("%s: no certificates found", *caFile)
		}
		tr.TLSClientConfig.RootCAs = pool
	}
	client := &http.Client{Transport: tr, Timeout: *timeout}

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

func promptPassword(user string) (string, error) {
	tty, err := os.Open("/dev/tty")
	if err != nil {
		return "", errors.New("no password: set CURRAL_PASSWORD or run in a terminal")
	}
	defer tty.Close()
	fmt.Fprintf(os.Stderr, "Password for %s: ", user)
	b, err := readPassword(int(tty.Fd()))
	fmt.Fprintln(os.Stderr)
	return string(b), err
}
