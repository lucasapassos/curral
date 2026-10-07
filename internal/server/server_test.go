package server

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"database/sql"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	_ "github.com/duckdb/duckdb-go/v2"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jwt"

	"curral/internal/audit"
	"curral/internal/auth"
	"curral/internal/config"
	"curral/internal/engine"
	"curral/internal/metrics"
	"curral/internal/policy"
)

func newServer(t testing.TB) *httptest.Server {
	t.Helper()
	ts, _ := newServerWithAudit(t, "")
	return ts
}

// newServerWithAudit starts a server; with auditPath set it also writes
// audit events there.
func newServerWithAudit(t testing.TB, auditPath string) (*httptest.Server, *audit.Writer) {
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
	s := &Server{Engine: eng, Log: log, MaxBody: 1 << 20, Version: "test"}
	s.SetAuth(auth.New(users, time.Minute))
	s.SetPolicy(pol)
	s.Metrics = metrics.New(metrics.Sources{
		Load: eng.Load, PolicySHA: func() string { return s.Policy().SHA256 },
		BuildLabels: map[string]string{"version": "test"},
	})
	lastServer = s
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
	req.SetBasicAuth("analyst", "s3cret-typo-91")
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
	if strings.Contains(string(raw), "s3cret-typo-91") || strings.Contains(string(raw), "Maria") {
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

// lastServer is the most recent server built by newServerWithAudit, for
// tests that need its internals (metrics handler).
var lastServer *Server

func TestMetrics(t *testing.T) {
	ts := newServer(t)
	s := lastServer
	do(t, ts, "analyst", `{"sql":"SELECT id FROM orders"}`)
	do(t, ts, "analyst", `{"sql":"SELECT id FROM orders"}`)
	do(t, ts, "analyst", `{"sql":"DELETE FROM orders"}`)
	do(t, ts, "admin", `{"sql":"ATTACH ':memory:' AS m"}`)
	do(t, ts, "analyst", `{"sql":"SELECT 1","nope":1}`)
	do(t, ts, "", `{"sql":"SELECT 1"}`)

	rec := httptest.NewRecorder()
	s.Metrics.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/metrics", nil))
	body := rec.Body.String()
	for _, want := range []string{
		`curral_queries_total{decided_by="policy",decision="allow",statement_type="SELECT",status="200"} 2`,
		`curral_queries_total{decided_by="policy",decision="deny",statement_type="DELETE",status="403"} 1`,
		`curral_queries_total{decided_by="engine",decision="deny",statement_type="none",status="403"} 1`,
		`curral_queries_total{decided_by="request",decision="error",statement_type="none",status="400"} 1`,
		`curral_policy_decisions_total{decision="allow",role="analyst"} 2`,
		`curral_policy_decisions_total{decision="deny",role="analyst"} 1`,
		`curral_auth_failures_total{method="none"} 1`,
		`curral_rows_returned_total 4`,
		`curral_query_slots 4`,
		`curral_queries_running 0`,
		`curral_query_stage_seconds_count{stage="total"} 5`,
		`curral_build_info{version="test"} 1`,
		`curral_policy_info{sha256="` + s.Policy().SHA256 + `"} 1`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("missing %s", want)
		}
	}
	if t.Failed() {
		for _, l := range strings.Split(body, "\n") {
			if strings.HasPrefix(l, "curral_") {
				t.Log(l)
			}
		}
	}
}

func TestReload(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	ts, aw := newServerWithAudit(t, path)
	s := lastServer
	before := s.Policy().SHA256

	if r := do(t, ts, "analyst", `{"sql":"SELECT id FROM orders"}`); r.status != 200 {
		t.Fatalf("before reload: %d", r.status)
	}

	// A broken policy file keeps the previous policy in effect.
	dir := t.TempDir()
	bad := filepath.Join(dir, "bad.rego")
	os.WriteFile(bad, []byte("package curral\nallow if {"), 0o600)
	_, err := policy.Load(context.Background(), "data.curral.allow", []string{bad})
	s.Reload(nil, nil, err)
	if s.Policy().SHA256 != before {
		t.Fatal("failed reload replaced the policy")
	}

	// New policy: deny everything for non-admins; new users file without analyst.
	strict := filepath.Join(dir, "strict.rego")
	os.WriteFile(strict, []byte("package curral\nimport rego.v1\ndefault allow := false\nallow if \"admin\" in input.roles\n"), 0o600)
	pol, err := policy.Load(context.Background(), "data.curral.allow", []string{strict})
	if err != nil {
		t.Fatal(err)
	}
	all, _ := config.LoadUsers("../../examples/users.yaml")
	var kept config.Users
	for _, u := range all.Users {
		if u.Name != "analyst" {
			kept.Users = append(kept.Users, u)
		}
	}
	s.Reload(auth.New(&kept, time.Minute), pol, nil)

	if r := do(t, ts, "analyst", `{"sql":"SELECT id FROM orders"}`); r.status != 401 {
		t.Fatalf("removed user still authenticates (cached?): %d", r.status)
	}
	if r := do(t, ts, "etl", `{"sql":"INSERT INTO orders VALUES (5, 1)"}`); r.status != 403 {
		t.Fatalf("new policy not applied: %d", r.status)
	}
	if r := do(t, ts, "admin", `{"sql":"SELECT 1"}`); r.status != 200 {
		t.Fatalf("admin after reload: %d", r.status)
	}

	aw.Close()
	var reloads []audit.Event
	var last audit.Event
	for _, ev := range readAudit(t, path) {
		if ev.Event == "config_reload" {
			reloads = append(reloads, ev)
		}
		last = ev
	}
	if len(reloads) != 2 || reloads[0].Decision != "error" || reloads[0].PolicySHA256 != before ||
		reloads[1].Decision != "allow" || reloads[1].PolicySHA256 != pol.SHA256 {
		t.Fatalf("reload events: %+v", reloads)
	}
	if last.PolicySHA256 != pol.SHA256 {
		t.Fatalf("queries after reload must record the new policy hash: %+v", last)
	}
}

func TestDryRun(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	ts, aw := newServerWithAudit(t, path)
	type resp struct {
		DryRun    bool     `json:"dry_run"`
		Decision  string   `json:"decision"`
		DecidedBy string   `json:"decided_by"`
		Tables    []string `json:"tables"`
		Targets   []string `json:"targets"`
		Resolved  bool     `json:"resolved"`
	}
	check := func(user, body string, status int, want resp) {
		t.Helper()
		r := do(t, ts, user, body)
		var got resp
		json.Unmarshal([]byte(r.body), &got)
		if r.status != status || (status == 200 && (got.Decision != want.Decision || got.DecidedBy != want.DecidedBy ||
			!slices.Equal(got.Tables, want.Tables) || !slices.Equal(got.Targets, want.Targets))) {
			t.Errorf("%s %s: status=%d body=%s", user, body, r.status, r.body)
		}
	}
	check("analyst", `{"sql":"SELECT * FROM orders","dry_run":true}`, 200,
		resp{Decision: "allow", DecidedBy: "policy", Tables: []string{"sales.main.orders"}, Targets: []string{}})
	check("analyst", `{"sql":"SELECT * FROM salaries","dry_run":true}`, 200,
		resp{Decision: "deny", DecidedBy: "policy", Tables: []string{"sales.main.salaries"}, Targets: []string{}})
	check("etl", `{"sql":"DELETE FROM orders WHERE id = 1","dry_run":true}`, 200,
		resp{Decision: "allow", DecidedBy: "policy", Tables: []string{"sales.main.orders"}, Targets: []string{"sales.main.orders"}})
	check("admin", `{"sql":"ATTACH ':memory:' AS m","dry_run":true}`, 200,
		resp{Decision: "deny", DecidedBy: "engine", Tables: []string{}, Targets: []string{}})
	check("analyst", `{"sql":"SELEC 1","dry_run":true}`, 400, resp{})

	// The allowed DELETE must not have run.
	if r := do(t, ts, "admin", `{"sql":"SELECT count(*) AS n FROM orders"}`); !strings.Contains(r.body, `"n":2`) {
		t.Fatalf("dry run executed: %s", r.body)
	}
	aw.Close()
	var dry int
	for _, ev := range readAudit(t, path) {
		if ev.Event == "dry_run" {
			dry++
		}
	}
	if dry != 5 {
		t.Fatalf("dry_run audit events = %d", dry)
	}
}

func TestPolicyLimits(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	ts, aw := newServerWithAudit(t, path)
	f := filepath.Join(t.TempDir(), "limits.rego")
	os.WriteFile(f, []byte(`package curral
import rego.v1
allow := true
limits := {"timeout": "100ms", "max_rows": 1} if "analyst" in input.roles
`), 0o600)
	pol, err := policy.Load(context.Background(), "data.curral.allow", []string{f}, "data.curral.limits")
	if err != nil {
		t.Fatal(err)
	}
	lastServer.SetPolicy(pol)

	r := do(t, ts, "analyst", `{"sql":"SELECT * FROM range(5)","format":"ndjson"}`)
	if r.status != 200 || strings.Count(r.body, "\n") != 1 || r.trailer.Get("X-Curral-Error") != "row limit reached" {
		t.Fatalf("max_rows: status=%d body=%q trailer=%v", r.status, r.body, r.trailer)
	}
	if r := do(t, ts, "admin", `{"sql":"SELECT * FROM range(5)","format":"ndjson"}`); strings.Count(r.body, "\n") != 5 {
		t.Fatalf("admin must be unlimited: %q", r.body)
	}
	start := time.Now()
	if r := do(t, ts, "analyst", `{"sql":"SELECT count(*) FROM range(10000000000)"}`); r.status != 504 || time.Since(start) > 5*time.Second {
		t.Fatalf("timeout: status=%d after %v", r.status, time.Since(start))
	}
	r = do(t, ts, "analyst", `{"sql":"SELECT 1","dry_run":true}`)
	if !strings.Contains(r.body, `"limits":{"max_rows":1,"timeout":"100ms"}`) {
		t.Fatalf("dry run limits: %s", r.body)
	}

	// A limits rule that fails to evaluate denies the request.
	os.WriteFile(f, []byte(`package curral
import rego.v1
allow := true
limits := {"timeout": "soon"}
`), 0o600)
	pol, _ = policy.Load(context.Background(), "data.curral.allow", []string{f}, "data.curral.limits")
	lastServer.SetPolicy(pol)
	if r := do(t, ts, "admin", `{"sql":"SELECT 1"}`); r.status != 500 {
		t.Fatalf("broken limits must fail closed: %d %s", r.status, r.body)
	}

	aw.Close()
	var limited bool
	for _, ev := range readAudit(t, path) {
		if ev.User == "analyst" && ev.Limits["max_rows"] == float64(1) {
			limited = true
		}
	}
	if !limited {
		t.Fatal("limits missing from audit events")
	}
}

func TestAPIKeyAndJWT(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	ts, aw := newServerWithAudit(t, path)
	s := lastServer

	// API key for the etl role, reloaded like any users-file change.
	key, hash, _ := auth.NewAPIKey()
	users, _ := config.LoadUsers("../../examples/users.yaml")
	users.APIKeys = []config.APIKey{{Name: "etl-job", KeyHash: hash, Roles: []string{"etl"}}}
	s.SetAuth(auth.New(users, time.Minute))

	// OIDC provider issuing analyst tokens.
	raw, _ := rsa.GenerateKey(rand.Reader, 2048)
	priv, _ := jwk.Import(raw)
	priv.Set(jwk.KeyIDKey, "k1")
	priv.Set(jwk.AlgorithmKey, jwa.RS256())
	pub, _ := priv.PublicKey()
	set := jwk.NewSet()
	set.AddKey(pub)
	mux := http.NewServeMux()
	idp := httptest.NewServer(mux)
	defer idp.Close()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{"issuer": idp.URL, "jwks_uri": idp.URL + "/jwks"})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) { json.NewEncoder(w).Encode(set) })
	o, err := auth.NewOIDC(context.Background(), auth.OIDCConfig{Issuer: idp.URL, Audience: "curral", UserClaim: "email", RolesClaim: "groups"})
	if err != nil {
		t.Fatal(err)
	}
	tok, _ := jwt.NewBuilder().Issuer(idp.URL).Audience([]string{"curral"}).Subject("x").
		Expiration(time.Now().Add(time.Hour)).Build()
	tok.Set("email", "ana@example.com")
	tok.Set("groups", []string{"analyst"})
	signed, _ := jwt.Sign(tok, jwt.WithKey(jwa.RS256(), priv))

	bearer := func(cred, body string) result {
		req, _ := http.NewRequest("POST", ts.URL+"/v1/query", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+cred)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return result{resp.StatusCode, string(b), resp.Header, resp.Trailer}
	}

	if r := bearer(string(signed), `{"sql":"SELECT 1"}`); r.status != 401 {
		t.Fatalf("jwt without OIDC configured: %d", r.status)
	}
	s.OIDC = o

	cases := []struct {
		cred, sql string
		status    int
	}{
		{key, "INSERT INTO orders VALUES (3, 1)", 200},
		{key, "INSERT INTO logs.events VALUES (9)", 403},
		{key + "x", "SELECT 1", 401},
		{string(signed), "SELECT id FROM orders", 200},
		{string(signed), "SELECT * FROM salaries", 403},
		{string(signed) + "x", "SELECT 1", 401},
		{"not-a-token", "SELECT 1", 401},
	}
	for _, c := range cases {
		if r := bearer(c.cred, `{"sql":"`+c.sql+`"}`); r.status != c.status {
			t.Errorf("%.20s… %s: %d %s", c.cred, c.sql, r.status, r.body)
		}
	}

	aw.Close()
	methods := map[string]int{}
	for _, ev := range readAudit(t, path) {
		if ev.Event == "query" {
			methods[ev.AuthMethod+"/"+ev.User]++
		}
		if ev.Event == "auth_failure" {
			methods["fail/"+ev.AuthMethod]++
		}
	}
	want := map[string]int{"api_key/etl-job": 2, "jwt/ana@example.com": 2, "fail/api_key": 1, "fail/jwt": 3}
	for k, v := range want {
		if methods[k] != v {
			t.Errorf("audit %s = %d, want %d (all: %v)", k, methods[k], v, methods)
		}
	}
}
