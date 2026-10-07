package server

import (
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	_ "github.com/duckdb/duckdb-go/v2"

	"curral/internal/audit"
	"curral/internal/auth"
	"curral/internal/config"
	"curral/internal/engine"
	"curral/internal/policy"
)

func newServer(t *testing.T) *httptest.Server {
	t.Helper()
	ts, _ := newServerWithAudit(t, "")
	return ts
}

// newServerWithAudit starts a server; with auditPath set it also writes
// audit events there.
func newServerWithAudit(t *testing.T, auditPath string) (*httptest.Server, *audit.Writer) {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("CURRAL_DATA", dir)
	for file, stmts := range map[string][]string{
		"sales.duckdb": {
			"CREATE TABLE orders(id INT, amount DECIMAL(10,2))",
			"INSERT INTO orders VALUES (1, 10.50), (2, 20)",
			"CREATE TABLE salaries(name VARCHAR, value INT)",
		},
		"logs.duckdb": {"CREATE TABLE events(id INT)"},
	} {
		db, err := sql.Open("duckdb", filepath.Join(dir, file))
		if err != nil {
			t.Fatal(err)
		}
		for _, s := range stmts {
			if _, err := db.Exec(s); err != nil {
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
	s := &Server{Engine: eng, Auth: auth.New(users, time.Minute), Policy: pol, Log: log, MaxBody: 1 << 20, Version: "test"}
	var aw *audit.Writer
	if auditPath != "" {
		if aw, err = audit.Open(auditPath, 64, log); err != nil {
			t.Fatal(err)
		}
		s.Audit = aw
	}
	ts := httptest.NewServer(s.Handler())
	t.Cleanup(ts.Close)
	return ts, aw
}

type result struct {
	status  int
	body    string
	header  http.Header
	trailer http.Header
}

func do(t *testing.T, ts *httptest.Server, user, body string) result {
	t.Helper()
	req, _ := http.NewRequest("POST", ts.URL+"/v1/query", strings.NewReader(body))
	if user != "" {
		req.SetBasicAuth(user, user+"-pw")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return result{resp.StatusCode, string(b), resp.Header, resp.Trailer}
}

func TestQueryAPI(t *testing.T) {
	ts := newServer(t)
	cases := []struct {
		name, user, body string
		status           int
		contains         string
	}{
		{"csv", "analyst", `{"sql":"SELECT id, amount FROM orders ORDER BY id","format":"csv"}`, 200, "id,amount\n1,10.5\n2,20\n"},
		{"json", "analyst", `{"sql":"SELECT id FROM orders WHERE id = $1","params":[2]}`, 200, `"data":[{"id":2}],"row_count":1}`},
		{"ndjson", "analyst", `{"sql":"SELECT id FROM orders ORDER BY id","format":"ndjson"}`, 200, "{\"id\":1}\n{\"id\":2}\n"},
		{"other db", "analyst", `{"sql":"SELECT count(*) AS n FROM events","database":"logs"}`, 200, `[{"n":0}]`},
		{"no auth", "", `{"sql":"SELECT 1"}`, 401, "invalid credentials"},
		{"analyst delete", "analyst", `{"sql":"DELETE FROM orders"}`, 403, "forbidden"},
		{"analyst denied table", "analyst", `{"sql":"SELECT * FROM salaries"}`, 403, "forbidden"},
		{"analyst denied via join", "analyst", `{"sql":"SELECT * FROM orders o JOIN salaries s ON true"}`, 403, "forbidden"},
		{"analyst range", "analyst", `{"sql":"SELECT count(*) AS n FROM range(10)"}`, 200, `"n":10`},
		{"analyst non-allowed function", "analyst", `{"sql":"SELECT * FROM duckdb_settings()"}`, 403, "forbidden"},
		{"etl insert", "etl", `{"sql":"INSERT INTO orders VALUES (3, 1)"}`, 200, `"Count":1`},
		{"etl write logs", "etl", `{"sql":"INSERT INTO logs.events VALUES (1)"}`, 403, "forbidden"},
		{"etl ddl", "etl", `{"sql":"DROP TABLE orders"}`, 403, "forbidden"},
		{"admin ddl", "admin", `{"sql":"CREATE TABLE t AS SELECT 1 AS x"}`, 200, ""},
		{"admin attach", "admin", `{"sql":"ATTACH ':memory:' AS m"}`, 403, "ATTACH statements are not allowed"},
		{"read only db", "admin", `{"sql":"INSERT INTO logs.events VALUES (1)"}`, 400, "read-only"},
		{"bad sql", "analyst", `{"sql":"SELEC 1"}`, 400, "syntax error"},
		{"multi statement", "admin", `{"sql":"SELECT 1; SELECT 2"}`, 400, "multi-statement"},
		{"bad format", "analyst", `{"sql":"SELECT 1","format":"xml"}`, 400, "unsupported format"},
		{"unknown field", "analyst", `{"sql":"SELECT 1","foo":1}`, 400, "unknown field"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := do(t, ts, c.user, c.body)
			if r.status != c.status || !strings.Contains(r.body, c.contains) {
				t.Fatalf("status=%d body=%s", r.status, r.body)
			}
		})
	}
}

func TestStreamingHeaders(t *testing.T) {
	ts := newServer(t)
	r := do(t, ts, "analyst", `{"sql":"SELECT * FROM orders","format":"csv"}`)
	if r.header.Get("Content-Type") != "text/csv; charset=utf-8" ||
		r.header.Get("X-Curral-Statement-Type") != "SELECT" ||
		r.trailer.Get("X-Curral-Row-Count") != "2" {
		t.Fatalf("headers=%v trailer=%v", r.header, r.trailer)
	}
}

func TestDatabasesAndHealth(t *testing.T) {
	ts := newServer(t)
	req, _ := http.NewRequest("GET", ts.URL+"/v1/databases", nil)
	req.SetBasicAuth("analyst", "analyst-pw")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	var out struct{ Databases []engine.DatabaseInfo }
	json.NewDecoder(resp.Body).Decode(&out)
	resp.Body.Close()
	if len(out.Databases) != 2 || !out.Databases[1].ReadOnly {
		t.Fatalf("%+v", out)
	}
	resp, err = http.Get(ts.URL + "/healthz")
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("health: %v %v", resp.StatusCode, err)
	}
	resp.Body.Close()
}

func readAudit(t *testing.T, path string) []audit.Event {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var out []audit.Event
	for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		var ev audit.Event
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			t.Fatalf("bad line %q: %v", line, err)
		}
		out = append(out, ev)
	}
	return out
}

func TestAuditEvents(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	ts, aw := newServerWithAudit(t, path)

	r1 := do(t, ts, "analyst", `{"sql":"SELECT id FROM orders WHERE amount > 15 AND id <> 99","format":"csv"}`)
	do(t, ts, "analyst", `{"sql":"SELECT * FROM salaries WHERE name = 'Maria Silva'"}`)
	do(t, ts, "admin", `{"sql":"ATTACH ':memory:' AS m"}`)
	do(t, ts, "analyst", `{"sql":"SELEC 1"}`)
	do(t, ts, "analyst", `{"sql":"SELECT 1", "nope": 1}`)
	req, _ := http.NewRequest("POST", ts.URL+"/v1/query", strings.NewReader(`{"sql":"SELECT 1"}`))
	req.SetBasicAuth("analyst", "wrong")
	resp, _ := http.DefaultClient.Do(req)
	resp.Body.Close()
	if err := aw.Close(); err != nil {
		t.Fatal(err)
	}

	evs := readAudit(t, path)
	if len(evs) != 6 {
		t.Fatalf("%d events: %+v", len(evs), evs)
	}
	ok := evs[0]
	if ok.Decision != "allow" || ok.DecidedBy != "policy" || ok.Status != 200 || ok.Rows != 1 || ok.Bytes == 0 ||
		ok.User != "analyst" || ok.RequestID != r1.header.Get("X-Request-Id") || len(ok.PolicySHA256) != 64 ||
		ok.Resolved == nil || !*ok.Resolved || len(ok.Tables) != 1 || ok.Tables[0] != "sales.main.orders" ||
		ok.SQL != "SELECT id FROM orders WHERE amount > ? AND id <> ?" || len(ok.SQLSHA256) != 64 ||
		ok.TimingMS["total"] <= 0 || ok.Version != "test" {
		t.Errorf("allow event: %+v", ok)
	}
	deny := evs[1]
	if deny.Decision != "deny" || deny.DecidedBy != "policy" || deny.Status != 403 ||
		strings.Contains(deny.SQL, "Maria") || deny.Tables[0] != "sales.main.salaries" {
		t.Errorf("policy deny event: %+v", deny)
	}
	if e := evs[2]; e.Decision != "deny" || e.DecidedBy != "engine" || e.Status != 403 || e.User != "admin" {
		t.Errorf("engine deny event: %+v", e)
	}
	if e := evs[3]; e.Decision != "error" || e.DecidedBy != "engine" || e.Status != 400 {
		t.Errorf("syntax error event: %+v", e)
	}
	if e := evs[4]; e.Decision != "error" || e.DecidedBy != "request" || e.Status != 400 {
		t.Errorf("bad request event: %+v", e)
	}
	if e := evs[5]; e.Event != "auth_failure" || e.User != "analyst" || e.Decision != "deny" || e.Status != 401 {
		t.Errorf("auth failure event: %+v", e)
	}
	raw, _ := os.ReadFile(path)
	if strings.Contains(string(raw), "wrong") || strings.Contains(string(raw), "Maria") {
		t.Error("password or literal leaked into the audit log")
	}
}

// With the audit sink failing, nothing executes: the INSERT must not apply.
func TestAuditFailClosed(t *testing.T) {
	if _, err := os.Stat("/dev/full"); err != nil {
		t.Skip("no /dev/full")
	}
	ts, aw := newServerWithAudit(t, "/dev/full")
	defer aw.Close()
	// The first event fails to write and marks the sink unhealthy.
	do(t, ts, "analyst", `{"sql":"SELECT 1"}`)
	deadline := time.Now().Add(2 * time.Second)
	for aw.Healthy() == nil && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	r := do(t, ts, "etl", `{"sql":"INSERT INTO orders VALUES (99, 1)"}`)
	if r.status != 503 || !strings.Contains(r.body, "audit") {
		t.Fatalf("status=%d body=%s", r.status, r.body)
	}
	r = do(t, ts, "admin", `{"sql":"SELECT count(*) AS n FROM orders WHERE id = 99"}`)
	if r.status != 503 {
		t.Fatalf("read while audit down: %d", r.status)
	}
}
