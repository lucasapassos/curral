package mcp_test

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	_ "github.com/duckdb/duckdb-go/v2"

	"github.com/lucasapassos/curral/internal/auth"
	"github.com/lucasapassos/curral/internal/config"
	"github.com/lucasapassos/curral/internal/docs"
	"github.com/lucasapassos/curral/internal/engine"
	"github.com/lucasapassos/curral/internal/mcp"
	"github.com/lucasapassos/curral/internal/metrics"
	"github.com/lucasapassos/curral/internal/policy"
	"github.com/lucasapassos/curral/internal/server"
)

type testEnv struct {
	srv     *server.Server
	handler http.Handler
	docID   string
}

func newTestEnv(t *testing.T, withDocs bool) *testEnv {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("CURRAL_DATA", dir)
	for file, stmts := range map[string][]string{
		"sales.duckdb": {
			"CREATE TABLE orders(id INT, amount DECIMAL(10,2))",
			"INSERT INTO orders VALUES (1, 10.50), (2, 20.00), (3, 30.00)",
			"CREATE TABLE salaries(name VARCHAR, value INT)",
			"INSERT INTO salaries VALUES ('alice', 100)",
		},
		"logs.duckdb": {
			"CREATE TABLE events(id INT)",
		},
	} {
		db, err := sql.Open("duckdb", filepath.Join(dir, file))
		if err != nil {
			t.Fatal(err)
		}
		for _, stmt := range stmts {
			if _, err := db.Exec(stmt); err != nil {
				t.Fatal(err)
			}
		}
		db.Close()
	}

	cat, err := config.LoadCatalog("../../examples/catalog.yaml")
	if err != nil {
		t.Fatal(err)
	}
	users, err := config.LoadUsers("../../examples/users.yaml")
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	pol, err := policy.Load(ctx, "data.curral.allow", []string{"../../examples/policy.rego", "../../examples/roles.json"})
	if err != nil {
		t.Fatal(err)
	}
	log := slog.New(slog.DiscardHandler)
	eng, err := engine.Open(ctx, cat, engine.Options{MaxConcurrency: 4, QueueTimeout: time.Second}, log)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { eng.Close() })

	s := &server.Server{
		Engine:  eng,
		Log:     log,
		MaxBody: 1 << 20,
		Version: "test-1.0",
	}
	s.SetAuth(auth.New(users, time.Minute))
	s.SetPolicy(pol)
	s.Metrics = metrics.New(metrics.Sources{
		Load:        eng.Load,
		PolicySHA:   func() string { return s.Policy().SHA256 },
		BuildLabels: map[string]string{"version": "test-1.0"},
	})

	var docID string
	if withDocs {
		store, err := docs.Open(filepath.Join(dir, "docs"))
		if err != nil {
			t.Fatal(err)
		}
		d, _, err := store.Create(docs.Doc{
			Header: docs.Header{
				Title:       "Orders Revenue Guide",
				Description: "How to calculate gross revenue from sales.main.orders.",
			},
			Context: docs.Context{
				Tables: []string{"sales.main.orders"},
				Body:   "Sum the amount column from sales.main.orders.",
			},
		}, "admin", nil)
		if err != nil {
			t.Fatal(err)
		}
		docID = d.ID
		s.Docs = store
	}

	h := mcp.NewHandler(s.Handler(), mcp.Options{
		Version:     "test-1.0",
		DocsEnabled: withDocs,
	})
	return &testEnv{srv: s, handler: h, docID: docID}
}

type rpcEnvelope struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  json.RawMessage `json:"result"`
	Error   *struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

type toolCallResult struct {
	Content []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	} `json:"content"`
	IsError bool `json:"isError"`
}

func postMCP(t *testing.T, h http.Handler, user string, headers map[string]string, body string) (*httptest.ResponseRecorder, rpcEnvelope) {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if user != "" {
		req.SetBasicAuth(user, user+"-pw")
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	var env rpcEnvelope
	if rec.Body.Len() > 0 {
		_ = json.Unmarshal(rec.Body.Bytes(), &env)
	}
	return rec, env
}

func decodeToolResult(t *testing.T, env rpcEnvelope) toolCallResult {
	t.Helper()
	if env.Error != nil {
		t.Fatalf("unexpected JSON-RPC error: %+v", env.Error)
	}
	var res toolCallResult
	if err := json.Unmarshal(env.Result, &res); err != nil {
		t.Fatalf("decode tool result: %v (raw=%s)", err, env.Result)
	}
	if len(res.Content) == 0 {
		t.Fatalf("expected non-empty content in tool result")
	}
	return res
}

func TestMCPProtocolLifecycleAndTools(t *testing.T) {
	env := newTestEnv(t, true)

	// Method not allowed on GET.
	getRec := httptest.NewRecorder()
	env.handler.ServeHTTP(getRec, httptest.NewRequest(http.MethodGet, "/mcp", nil))
	if getRec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET /mcp status=%d want 405", getRec.Code)
	}

	// initialize
	rec, resp := postMCP(t, env.handler, "analyst", nil, `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`)
	if rec.Code != http.StatusOK || resp.Error != nil {
		t.Fatalf("initialize failed: code=%d err=%+v body=%s", rec.Code, resp.Error, rec.Body.String())
	}
	var initRes struct {
		ProtocolVersion string `json:"protocolVersion"`
		ServerInfo      struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		} `json:"serverInfo"`
		Capabilities map[string]any `json:"capabilities"`
	}
	if err := json.Unmarshal(resp.Result, &initRes); err != nil {
		t.Fatal(err)
	}
	if initRes.ProtocolVersion != mcp.ProtocolVersion || initRes.ServerInfo.Name != "curral" || initRes.ServerInfo.Version != "test-1.0" {
		t.Fatalf("unexpected initialize result: %+v", initRes)
	}
	if _, ok := initRes.Capabilities["tools"]; !ok {
		t.Fatalf("missing tools capability: %+v", initRes.Capabilities)
	}

	// notifications/initialized -> 202 Accepted, empty body.
	rec, _ = postMCP(t, env.handler, "analyst", nil, `{"jsonrpc":"2.0","method":"notifications/initialized"}`)
	if rec.Code != http.StatusAccepted || rec.Body.Len() != 0 {
		t.Fatalf("notifications/initialized: code=%d body=%q", rec.Code, rec.Body.String())
	}

	// ping
	rec, resp = postMCP(t, env.handler, "analyst", nil, `{"jsonrpc":"2.0","id":2,"method":"ping"}`)
	if rec.Code != http.StatusOK || resp.Error != nil || string(resp.Result) != "{}" {
		t.Fatalf("ping: code=%d result=%s err=%+v", rec.Code, resp.Result, resp.Error)
	}

	// tools/list (with docs enabled -> 6 tools).
	rec, resp = postMCP(t, env.handler, "analyst", nil, `{"jsonrpc":"2.0","id":3,"method":"tools/list"}`)
	if rec.Code != http.StatusOK || resp.Error != nil {
		t.Fatalf("tools/list: code=%d err=%+v", rec.Code, resp.Error)
	}
	var listRes struct {
		Tools []struct {
			Name string `json:"name"`
		} `json:"tools"`
	}
	if err := json.Unmarshal(resp.Result, &listRes); err != nil {
		t.Fatal(err)
	}
	if len(listRes.Tools) != 6 {
		t.Fatalf("expected 6 tools with docs enabled, got %d: %+v", len(listRes.Tools), listRes.Tools)
	}

	// curral_capabilities
	_, resp = postMCP(t, env.handler, "analyst", nil, `{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"curral_capabilities","arguments":{}}}`)
	res := decodeToolResult(t, resp)
	if res.IsError || !strings.Contains(res.Content[0].Text, `"subject":"analyst"`) {
		t.Fatalf("curral_capabilities: %+v", res)
	}

	// curral_schema
	_, resp = postMCP(t, env.handler, "analyst", nil, `{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"curral_schema","arguments":{"database":"sales"}}}`)
	res = decodeToolResult(t, resp)
	if res.IsError || !strings.Contains(res.Content[0].Text, `"orders"`) || strings.Contains(res.Content[0].Text, `"salaries"`) {
		t.Fatalf("curral_schema: %+v", res)
	}

	// curral_dry_run (allowed)
	_, resp = postMCP(t, env.handler, "analyst", nil, `{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"curral_dry_run","arguments":{"sql":"SELECT id, amount FROM orders"}}}`)
	res = decodeToolResult(t, resp)
	if res.IsError || !strings.Contains(res.Content[0].Text, `"decision":"allow"`) {
		t.Fatalf("curral_dry_run: %+v", res)
	}

	// curral_query (parameterized)
	_, resp = postMCP(t, env.handler, "analyst", nil, `{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"curral_query","arguments":{"sql":"SELECT id, amount FROM orders WHERE id = $1","params":[2]}}}`)
	res = decodeToolResult(t, resp)
	if res.IsError || !strings.Contains(res.Content[0].Text, `"id":2`) || !strings.Contains(res.Content[0].Text, `"row_count":1`) {
		t.Fatalf("curral_query: %+v", res)
	}

	// curral_query truncated by max_rows -> includes warning prefix!
	_, resp = postMCP(t, env.handler, "analyst", nil, `{"jsonrpc":"2.0","id":8,"method":"tools/call","params":{"name":"curral_query","arguments":{"sql":"SELECT id FROM orders ORDER BY id","max_rows":1}}}`)
	res = decodeToolResult(t, resp)
	if !strings.Contains(res.Content[0].Text, "WARNING:") || !strings.Contains(res.Content[0].Text, "row limit reached") {
		t.Fatalf("expected truncation warning in curral_query, got: %+v", res)
	}

	// curral_query policy denial (403 -> isError: true)
	_, resp = postMCP(t, env.handler, "analyst", nil, `{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"curral_query","arguments":{"sql":"SELECT * FROM salaries"}}}`)
	res = decodeToolResult(t, resp)
	if !res.IsError || !strings.Contains(res.Content[0].Text, "HTTP 403") {
		t.Fatalf("expected HTTP 403 isError tool result, got: %+v", res)
	}

	// curral_search_docs
	_, resp = postMCP(t, env.handler, "analyst", nil, `{"jsonrpc":"2.0","id":10,"method":"tools/call","params":{"name":"curral_search_docs","arguments":{"q":"gross revenue orders"}}}`)
	res = decodeToolResult(t, resp)
	if res.IsError || !strings.Contains(res.Content[0].Text, env.docID) {
		t.Fatalf("curral_search_docs: %+v", res)
	}

	// curral_get_doc
	_, resp = postMCP(t, env.handler, "analyst", nil, `{"jsonrpc":"2.0","id":11,"method":"tools/call","params":{"name":"curral_get_doc","arguments":{"id":"`+env.docID+`"}}}`)
	res = decodeToolResult(t, resp)
	if res.IsError || !strings.Contains(res.Content[0].Text, "Orders Revenue Guide") {
		t.Fatalf("curral_get_doc: %+v", res)
	}

	// curral_get_doc path traversal rejection
	for _, badID := range []string{"../etc/passwd", "abc", "UPPERCASE123", "id/with/slash", "validid123?foo=bar"} {
		b, _ := json.Marshal(map[string]any{
			"jsonrpc": "2.0",
			"id":      12,
			"method":  "tools/call",
			"params": map[string]any{
				"name":      "curral_get_doc",
				"arguments": map[string]any{"id": badID},
			},
		})
		_, resp = postMCP(t, env.handler, "analyst", nil, string(b))
		res = decodeToolResult(t, resp)
		if !res.IsError || !strings.Contains(res.Content[0].Text, "invalid document id") {
			t.Fatalf("badID %q should be rejected, got: %+v", badID, res)
		}
	}
}

func TestMCPDocsDisabledHidesDocTools(t *testing.T) {
	env := newTestEnv(t, false)
	_, resp := postMCP(t, env.handler, "analyst", nil, `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)
	if resp.Error != nil {
		t.Fatalf("tools/list error: %+v", resp.Error)
	}
	var listRes struct {
		Tools []struct {
			Name string `json:"name"`
		} `json:"tools"`
	}
	if err := json.Unmarshal(resp.Result, &listRes); err != nil {
		t.Fatal(err)
	}
	if len(listRes.Tools) != 4 {
		t.Fatalf("expected 4 tools with docs disabled, got %d: %+v", len(listRes.Tools), listRes.Tools)
	}
	_, resp = postMCP(t, env.handler, "analyst", nil, `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"curral_search_docs","arguments":{"q":"orders"}}}`)
	if resp.Error == nil || resp.Error.Code != -32602 {
		t.Fatalf("expected -32602 for disabled docs tool, got resp=%+v", resp)
	}
}

func TestMCPDelegatedExecution(t *testing.T) {
	env := newTestEnv(t, false)
	key, hash, err := auth.NewAPIKey()
	if err != nil {
		t.Fatal(err)
	}
	subject := "portal:user:42"
	env.srv.SetAuth(auth.New(&config.Users{
		APIKeys: []config.APIKey{{
			Name:       "portal",
			KeyHash:    hash,
			Roles:      []string{"admin"},
			Delegation: true,
		}},
		Identities: []config.Identity{{
			Match: subject,
			Roles: []string{"analyst"},
		}},
	}, time.Minute))

	ctxJSON, _ := json.Marshal(map[string]any{"subject": subject, "kind": "user"})
	execCtx := base64.RawURLEncoding.EncodeToString(ctxJSON)

	headers := map[string]string{
		"Authorization":              "Bearer " + key,
		"X-Curral-Execution-Context": execCtx,
	}

	// Allowed query propagates X-Curral-Effective-Subject on outer HTTP response.
	rec, resp := postMCP(t, env.handler, "", headers, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"curral_query","arguments":{"sql":"SELECT id FROM orders ORDER BY id"}}}`)
	res := decodeToolResult(t, resp)
	if res.IsError {
		t.Fatalf("delegated query failed: %+v", res)
	}
	if got := rec.Header().Get("X-Curral-Effective-Subject"); got != subject {
		t.Fatalf("X-Curral-Effective-Subject=%q want %q", got, subject)
	}

	// Denied table for delegated analyst (even though API key has admin role).
	_, resp = postMCP(t, env.handler, "", headers, `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"curral_query","arguments":{"sql":"SELECT * FROM salaries"}}}`)
	res = decodeToolResult(t, resp)
	if !res.IsError || !strings.Contains(res.Content[0].Text, "HTTP 403") {
		t.Fatalf("delegated query on salaries must be denied, got: %+v", res)
	}
}

func TestRunStdioEndToEnd(t *testing.T) {
	env := newTestEnv(t, true)
	ts := httptest.NewServer(env.srv.Handler())
	defer ts.Close()

	input := strings.Join([]string{
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		`{"jsonrpc":"2.0","id":2,"method":"ping"}`,
		`{"jsonrpc":"2.0","id":3,"method":"tools/list"}`,
		`{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"curral_query","arguments":{"sql":"SELECT id FROM orders WHERE id = $1","params":[1]}}}`,
		`{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"curral_get_doc","arguments":{"id":"` + env.docID + `"}}}`,
		`{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"curral_query","arguments":{"sql":"SELECT * FROM salaries"}}}`,
		``,
	}, "\n")

	var out bytes.Buffer
	err := mcp.RunStdio(context.Background(), strings.NewReader(input), &out, mcp.ClientConfig{
		URL:      ts.URL,
		User:     "analyst",
		Password: "analyst-pw",
		Timeout:  5 * time.Second,
		Version:  "stdio-test",
	})
	if err != nil {
		t.Fatalf("RunStdio error: %v", err)
	}

	// Credentials must never leak to stdout.
	if strings.Contains(out.String(), "analyst-pw") {
		t.Fatalf("password leaked to stdio output")
	}

	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	// 6 responses (notifications/initialized produces no output).
	if len(lines) != 6 {
		t.Fatalf("expected 6 response lines, got %d:\n%s", len(lines), out.String())
	}

	// Check initialize response.
	var r1 rpcEnvelope
	if err := json.Unmarshal([]byte(lines[0]), &r1); err != nil || r1.Error != nil || !strings.Contains(string(r1.Result), `"version":"stdio-test"`) {
		t.Fatalf("line 0 (initialize): %s", lines[0])
	}

	// Check ping response.
	var r2 rpcEnvelope
	if err := json.Unmarshal([]byte(lines[1]), &r2); err != nil || string(r2.Result) != "{}" {
		t.Fatalf("line 1 (ping): %s", lines[1])
	}

	// Check tools/list auto-detected docs.enabled=true -> 6 tools.
	var r3 rpcEnvelope
	if err := json.Unmarshal([]byte(lines[2]), &r3); err != nil {
		t.Fatalf("line 2: %v", err)
	}
	var listRes struct {
		Tools []struct{ Name string } `json:"tools"`
	}
	_ = json.Unmarshal(r3.Result, &listRes)
	if len(listRes.Tools) != 6 {
		t.Fatalf("expected 6 tools via stdio capability probe, got %d: %s", len(listRes.Tools), lines[2])
	}

	// Check curral_query result.
	var r4 rpcEnvelope
	_ = json.Unmarshal([]byte(lines[3]), &r4)
	qRes := decodeToolResult(t, r4)
	if qRes.IsError || !strings.Contains(qRes.Content[0].Text, `"id":1`) {
		t.Fatalf("line 3 (curral_query): %+v", qRes)
	}

	// Check curral_get_doc result.
	var r5 rpcEnvelope
	_ = json.Unmarshal([]byte(lines[4]), &r5)
	dRes := decodeToolResult(t, r5)
	if dRes.IsError || !strings.Contains(dRes.Content[0].Text, "Orders Revenue Guide") {
		t.Fatalf("line 4 (curral_get_doc): %+v", dRes)
	}

	// Check 403 policy denial via stdio.
	var r6 rpcEnvelope
	_ = json.Unmarshal([]byte(lines[5]), &r6)
	denyRes := decodeToolResult(t, r6)
	if !denyRes.IsError || !strings.Contains(denyRes.Content[0].Text, "HTTP 403") {
		t.Fatalf("line 5 (403 denial): %+v", denyRes)
	}
}

func TestRunStdioDocsDisabled(t *testing.T) {
	env := newTestEnv(t, false)
	ts := httptest.NewServer(env.srv.Handler())
	defer ts.Close()

	input := `{"jsonrpc":"2.0","id":1,"method":"tools/list"}` + "\n"
	var out bytes.Buffer
	if err := mcp.RunStdio(context.Background(), strings.NewReader(input), &out, mcp.ClientConfig{
		URL:      ts.URL,
		User:     "analyst",
		Password: "analyst-pw",
	}); err != nil {
		t.Fatalf("RunStdio: %v", err)
	}
	var r rpcEnvelope
	if err := json.Unmarshal(bytes.TrimSpace(out.Bytes()), &r); err != nil {
		t.Fatal(err)
	}
	var listRes struct {
		Tools []struct{ Name string } `json:"tools"`
	}
	_ = json.Unmarshal(r.Result, &listRes)
	if len(listRes.Tools) != 4 {
		t.Fatalf("expected 4 tools when remote docs disabled, got %d: %s", len(listRes.Tools), out.String())
	}

	// Ensure EOF on empty reader returns nil cleanly.
	if err := mcp.RunStdio(context.Background(), io.LimitReader(strings.NewReader(""), 0), io.Discard, mcp.ClientConfig{URL: ts.URL}); err != nil {
		t.Fatalf("empty stdio returned error: %v", err)
	}
}
