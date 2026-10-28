package server

import (
	"bytes"
	"context"
	"crypto/tls"
	"database/sql"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lucasapassos/curral/internal/auth"
	"github.com/lucasapassos/curral/internal/config"
	"github.com/lucasapassos/curral/internal/docs"
	"github.com/lucasapassos/curral/internal/engine"
	"github.com/lucasapassos/curral/internal/metrics"
	"github.com/lucasapassos/curral/internal/policy"
	"github.com/lucasapassos/curral/internal/rls"
)

// newAgentServer is a server as an AI agent meets it: the example policy
// with limits, masks and document writes, a row filter on orders for
// analysts, semantic documents and a 5-row server limit.
func newAgentServer(t testing.TB) *httptest.Server {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("CURRAL_DATA", dir)
	for file, stmts := range map[string][]string{
		"sales.duckdb": {
			"CREATE TABLE orders(id INT, amount DECIMAL(10,2), customer VARCHAR)",
			"INSERT INTO orders SELECT range, range * 100, 'c' || (range % 3) FROM range(10)",
			"COMMENT ON TABLE orders IS 'one row per order'",
			"CREATE TABLE salaries(name VARCHAR, value INT)",
			"CREATE VIEW big_orders AS SELECT * FROM orders WHERE amount > 300",
		},
		"logs.duckdb": {"CREATE TABLE events AS SELECT range AS id FROM range(20)"},
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
	pol, err := policy.LoadQueries(ctx, []string{"../../examples/policy.rego", "../../examples/roles.json"},
		policy.Queries{Allow: "data.curral.allow", Limits: "data.curral.limits", Masks: "data.curral.masks", Docs: "data.curral.docs_allow"})
	if err != nil {
		t.Fatal(err)
	}
	log := slog.New(slog.DiscardHandler)
	eng, err := engine.Open(ctx, cat, engine.Options{MaxConcurrency: 4, QueueTimeout: time.Second}, log)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { eng.Close() })
	rf := filepath.Join(t.TempDir(), "rls.yaml")
	os.WriteFile(rf, []byte("tables:\n  sales.main.orders:\n    rules:\n      - roles: [analyst]\n        where: \"amount < 500\"\n"), 0o600)
	rules, err := rls.Load(rf)
	if err != nil {
		t.Fatal(err)
	}
	store, err := docs.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{Engine: eng, Log: log, MaxBody: 1 << 20, MaxRows: 5, Version: "test", Docs: store}
	s.SetAuth(auth.New(users, time.Minute))
	s.SetPolicy(pol)
	s.SetRowFilters(rules)
	s.Metrics = metrics.New(metrics.Sources{Load: eng.Load, PolicySHA: func() string { return s.Policy().SHA256 }})
	ts := httptest.NewServer(s.Handler())
	t.Cleanup(ts.Close)
	return ts
}

func get(t *testing.T, ts *httptest.Server, path string, hdr ...string) (int, string, http.Header) {
	t.Helper()
	req, _ := http.NewRequest("GET", ts.URL+path, nil)
	for i := 0; i+1 < len(hdr); i += 2 {
		req.Header.Set(hdr[i], hdr[i+1])
	}
	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(body), resp.Header
}

// The skill's documentation is served to agents that only know the server's
// URL, without credentials, byte for byte as it lives in the repository;
// the scripts only when the operator asks for it, over TLS or to loopback.
func TestSkillEndpoints(t *testing.T) {
	ts := newAgentServer(t) // default mode: docs

	status, body, h := get(t, ts, "/")
	if status != 200 || !strings.Contains(h.Get("Content-Type"), "json") {
		t.Fatalf("index: %d %s", status, body)
	}
	var index struct {
		Version   string            `json:"version"`
		Agents    map[string]string `json:"agents"`
		Endpoints map[string]string `json:"endpoints"`
	}
	if err := json.Unmarshal([]byte(body), &index); err != nil {
		t.Fatal(err)
	}
	raw := "https://raw.githubusercontent.com/lucasapassos/curral/main/skills/curral"
	if index.Version != "test" || index.Agents["start_here"] != "/skill/SKILL.md" || index.Endpoints["docs"] == "" || index.Endpoints["query"] == "" ||
		!strings.Contains(index.Agents["install"], raw+"/scripts/install.sh") || !strings.Contains(index.Agents["install"], "CURRAL_SKILL_REF=main") {
		t.Errorf("index: %s", body)
	}

	for name, f := range skillFiles {
		want, err := os.ReadFile("../../skills/curral/" + name)
		if err != nil {
			t.Fatal(err)
		}
		status, body, h := get(t, ts, "/skill/"+name)
		if f.code {
			if status != 404 || !strings.Contains(body, raw+"/"+name) {
				t.Errorf("/skill/%s in docs mode: %d %s", name, status, body)
			}
			continue
		}
		if status != 200 || body != string(want) || h.Get("Content-Type") != f.ctype {
			t.Errorf("/skill/%s: %d %s %d bytes", name, status, h.Get("Content-Type"), len(body))
		}
	}
	if status, body, _ := get(t, ts, "/skill"); status != 200 || !strings.HasPrefix(body, "---\nname: curral\n") {
		t.Errorf("/skill: %d %.40q", status, body)
	}
	for _, p := range []string{"/skill/nope.md", "/skill/scripts/", "/skill/embed.go", "/v1", "/skill.md"} {
		if status, _, _ := get(t, ts, p); status != 404 {
			t.Errorf("%s: %d, want 404", p, status)
		}
	}
	// Nothing outside the skill is reachable through it.
	noRedirect := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	if resp, err := noRedirect.Get(ts.URL + "/skill/scripts/../../../go.mod"); err != nil || resp.StatusCode == 200 {
		t.Errorf("path escape: %v %v", resp, err)
	}

	// A release build points at its own tag.
	if ref := (&Server{Version: "v0.8.0"}).skillRef(); ref != "v0.8.0" {
		t.Errorf("release ref: %s", ref)
	}

	// --serve-skill all: the scripts too, and the installer downloads from
	// this server (the test server is loopback, so plain HTTP is fine).
	all := httptest.NewServer((&Server{ServeSkill: SkillAll, Log: slog.New(slog.DiscardHandler), Version: "test"}).Handler())
	defer all.Close()
	for name, f := range skillFiles {
		want, _ := os.ReadFile("../../skills/curral/" + name)
		status, body, h := get(t, all, "/skill/"+name, "X-Forwarded-Proto", "https")
		if name == "scripts/install.sh" {
			host := strings.TrimPrefix(all.URL, "http://")
			if status != 200 || !strings.Contains(body, "\nCURRAL_SKILL_SOURCE=${CURRAL_SKILL_SOURCE:-https://"+host+"/skill}\n") {
				t.Errorf("install.sh: %d %s", status, body)
			}
			continue
		}
		if status != 200 || body != string(want) || h.Get("Content-Type") != f.ctype {
			t.Errorf("all /skill/%s: %d %s", name, status, h.Get("Content-Type"))
		}
	}
	if _, body, _ := get(t, all, "/"); !strings.Contains(body, `"/skill/scripts/install.sh`) {
		t.Errorf("all index: %s", body)
	}

	// Over plain HTTP from another machine, code is refused.
	s := &Server{ServeSkill: SkillAll}
	s.TrustedProxies = []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}
	for _, c := range []struct {
		remote, proto string
		tls, want     bool
	}{
		{"127.0.0.1:5", "", false, true},
		{"[::1]:5", "", false, true},
		{"192.168.1.9:5", "", false, false},
		{"192.168.1.9:5", "https", false, false}, // not a trusted proxy: the header means nothing
		{"192.168.1.9:5", "", true, true},
		{"10.1.2.3:5", "https", false, true},
		{"10.1.2.3:5", "http", false, false},
	} {
		r := httptest.NewRequest("GET", "/skill/scripts/curral.sh", nil)
		r.RemoteAddr = c.remote
		if c.proto != "" {
			r.Header.Set("X-Forwarded-Proto", c.proto)
		}
		if c.tls {
			r.TLS = &tls.ConnectionState{}
		}
		if got := s.secureTransport(r); got != c.want {
			t.Errorf("secureTransport(%s, proto=%q, tls=%v) = %v", c.remote, c.proto, c.tls, got)
		}
	}
	r := httptest.NewRequest("GET", "/skill/scripts/curral.sh", nil)
	r.RemoteAddr = "192.168.1.9:5"
	r.SetPathValue("file", "scripts/curral.sh")
	w := httptest.NewRecorder()
	s.skillFile(w, r)
	if w.Code != 403 || !strings.Contains(w.Body.String(), "TLS") {
		t.Errorf("plain HTTP from afar: %d %s", w.Code, w.Body.String())
	}

	// --serve-skill off leaves both routes out.
	off := httptest.NewServer((&Server{ServeSkill: SkillOff, Log: slog.New(slog.DiscardHandler)}).Handler())
	defer off.Close()
	for _, p := range []string{"/", "/skill", "/skill/SKILL.md"} {
		if status, _, _ := get(t, off, p); status != 404 {
			t.Errorf("off %s: %d", p, status)
		}
	}
}

// DESCRIBE and SHOW of a table with row filters or masks return its columns
// (as GET /v1/schema does for the same caller) instead of a refusal, and a
// dry run reports what a run would refuse.
func TestProtectedMetadata(t *testing.T) {
	ts := newAgentServer(t)
	for _, c := range []struct {
		sql      string
		status   int
		contains string
	}{
		{"DESCRIBE orders", 200, `"column_name":"amount"`},
		{"SHOW orders", 200, `"column_name":"customer"`},
		{"DESCRIBE big_orders", 200, `"column_name":"amount"`},
		{"SUMMARIZE orders", 200, `"count":5`}, // filtered rows (amount < 500), masked amount
		{"SELECT count(*) AS n, count(amount) AS a FROM orders", 200, `"n":5,"a":0`},
		{"EXPLAIN SELECT * FROM orders", 403, "only be read with SELECT"},
		{"SELECT * FROM big_orders", 403, "indirectly"},
	} {
		r := do(t, ts, "analyst", `{"sql":`+jsonString(c.sql)+`}`)
		if r.status != c.status || !strings.Contains(r.body, c.contains) {
			t.Errorf("%s: %d %s", c.sql, r.status, r.body)
		}
	}
	r := do(t, ts, "analyst", `{"sql":"EXPLAIN SELECT * FROM orders","dry_run":true}`)
	if r.status != 200 || !strings.Contains(r.body, `"decision":"deny","decided_by":"protection"`) || !strings.Contains(r.body, `"row_filters":["sales.main.orders"]`) {
		t.Errorf("dry run of a refused protected statement: %d %s", r.status, r.body)
	}
	r = do(t, ts, "analyst", `{"sql":"DESCRIBE orders","dry_run":true}`)
	if r.status != 200 || !strings.Contains(r.body, `"decision":"allow"`) {
		t.Errorf("dry run of DESCRIBE: %d %s", r.status, r.body)
	}
	r = do(t, ts, "admin", `{"sql":"SELECT 1; SELECT 2"}`)
	if r.status != 400 || !strings.Contains(r.body, "one statement per request") {
		t.Errorf("multi-statement: %d %s", r.status, r.body)
	}
}

func jsonString(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

// The shell client of the skill against a real server: connection set-up
// without secrets in the command line, every command, and the exit codes
// SKILL.md promises.
func TestSkillShellClient(t *testing.T) {
	for _, bin := range []string{"sh", "curl"} {
		if _, err := exec.LookPath(bin); err != nil {
			t.Skipf("%s not installed", bin)
		}
	}
	ts := newAgentServer(t)
	script, err := filepath.Abs("../../skills/curral/scripts/curral.sh")
	if err != nil {
		t.Fatal(err)
	}
	home := t.TempDir()
	run := func(stdin string, env []string, args ...string) (int, string, string) {
		t.Helper()
		cmd := exec.Command("sh", append([]string{script}, args...)...)
		cmd.Env = append([]string{"HOME=" + home, "PATH=" + os.Getenv("PATH")}, env...)
		cmd.Stdin = strings.NewReader(stdin)
		var out, errb bytes.Buffer
		cmd.Stdout, cmd.Stderr = &out, &errb
		err := cmd.Run()
		code := 0
		if ee, ok := err.(*exec.ExitError); ok {
			code = ee.ExitCode()
		} else if err != nil {
			t.Fatal(err)
		}
		return code, out.String(), errb.String()
	}
	analyst := []string{"CURRAL_URL=" + ts.URL, "CURRAL_USER=analyst", "CURRAL_PASSWORD=analyst-pw"}
	poet := []string{"CURRAL_URL=" + ts.URL, "CURRAL_USER=poet", "CURRAL_PASSWORD=poet-pw"}
	check := func(name string, code, wantCode int, got, want string) {
		t.Helper()
		if code != wantCode || !strings.Contains(got, want) {
			t.Errorf("%s: exit %d (want %d); output %q lacks %q", name, code, wantCode, got, want)
		}
	}

	// No connection: exit 5 and the login command the user must run.
	code, _, stderr := run("", nil, "status")
	check("unconfigured", code, 5, stderr, script+" login")
	code, _, stderr = run("", []string{"CURRAL_URL=" + ts.URL}, "status")
	check("url only", code, 5, stderr, "no CURRAL_TOKEN or CURRAL_USER")
	code, _, stderr = run("", nil, "login")
	check("login needs a terminal", code, 2, stderr, "interactive")
	code, _, stderr = run("", nil)
	check("usage", code, 2, stderr, "curral.sh status")
	code, _, stderr = run("", analyst, "schema", "bogus=1")
	check("bad filter", code, 2, stderr, "invalid filter")
	code, _, stderr = run("", append(analyst, "CURRAL_CA=/nonexistent.pem"), "status")
	check("missing CA", code, 2, stderr, "CURRAL_CA")

	// status never shows the secret.
	code, stdout, stderr := run("", analyst, "status")
	check("status", code, 0, stdout, `"name":"sales"`)
	if !strings.Contains(stderr, "user analyst (from environment)") || strings.Contains(stderr, "analyst-pw") {
		t.Errorf("status stderr: %q", stderr)
	}
	code, _, stderr = run("", []string{"CURRAL_URL=" + ts.URL, "CURRAL_USER=analyst", "CURRAL_PASSWORD=nope"}, "status")
	check("bad password", code, 1, stderr, "HTTP 401")
	code, stdout, _ = run("", analyst, "capabilities")
	check("capabilities", code, 0, stdout, `"subject":"analyst"`)

	// The credentials file written by login, with its permission check.
	cfg := filepath.Join(home, ".config", "curral", "credentials")
	os.MkdirAll(filepath.Dir(cfg), 0o700)
	os.WriteFile(cfg, []byte("CURRAL_URL="+ts.URL+"\nCURRAL_USER=analyst\nCURRAL_PASSWORD=analyst-pw\n"), 0o644)
	code, stdout, stderr = run("", nil, "status")
	check("from file", code, 0, stdout, `"name":"sales"`)
	if !strings.Contains(stderr, "from "+cfg) || !strings.Contains(stderr, "chmod 600") {
		t.Errorf("file stderr: %q", stderr)
	}
	os.Chmod(cfg, 0o600)
	if _, _, stderr = run("", nil, "status"); strings.Contains(stderr, "chmod") {
		t.Errorf("mode 600 still warned: %q", stderr)
	}
	os.WriteFile(cfg, []byte("CURRAL_URL="+ts.URL+"\nCURRAL_TOKEN=curral_XICI32AYJPBF3NO24LOFD75YEEGCMVJ6ZSRLZ2G2NDHF77VSRRVA\n"), 0o600)
	code, _, stderr = run("", nil, "status")
	check("api key from file", code, 0, stderr, "API key/token")

	// Discovery and queries.
	code, stdout, _ = run("", analyst, "schema", "table=orders")
	check("schema", code, 0, stdout, `"comment":"one row per order"`)
	if strings.Contains(stdout, "salaries") || !strings.Contains(stdout, `"row_filtered":true`) || !strings.Contains(stdout, `"masked":true`) {
		t.Errorf("schema: %s", stdout)
	}
	code, stdout, _ = run("", analyst, "query", "SELECT count(*) AS n FROM orders")
	check("query", code, 0, stdout, `"n":5`)
	code, stdout, _ = run("", analyst, "query", "-p", "2", "-p", "x", "SELECT id, $2 AS tag FROM orders WHERE id = $1")
	check("params", code, 0, stdout, `"id":2,"tag":"x"`)
	code, stdout, stderr = run("", analyst, "query", "-m", "2", "-f", "csv", "SELECT id FROM orders ORDER BY id")
	check("sample", code, 0, stderr, "sample of 2 rows")
	if stdout != "id\n0\n1\n" {
		t.Errorf("sample csv: %q", stdout)
	}
	code, _, stderr = run("", analyst, "query", "-f", "csv", "-d", "logs", "SELECT id FROM events")
	check("truncated", code, 3, stderr, "TRUNCATED at 5 rows (limit 5)")
	out := filepath.Join(t.TempDir(), "o.csv")
	code, _, stderr = run("", analyst, "query", "-f", "csv", "-o", out, "SELECT id FROM orders WHERE id < 2")
	check("to file", code, 0, stderr, "2 rows in "+out)
	code, _, stderr = run("", analyst, "query", "SELECT * FROM salaries")
	check("forbidden", code, 1, stderr, "HTTP 403")
	code, stdout, _ = run("", analyst, "dry-run", "DELETE FROM orders")
	check("dry-run", code, 0, stdout, `"decision":"deny"`)
	code, stdout, _ = run("", analyst, "query", "DESCRIBE orders")
	check("describe protected", code, 0, stdout, `"column_name":"amount"`)
	code, _, stderr = run("", analyst, "query", "SELECT 1; SELECT 2")
	check("multi", code, 1, stderr, "one statement per request")
	code, _, stderr = run("", analyst, "query", "-m", "x", "SELECT 1")
	check("bad -m", code, 2, stderr, "integer")

	// Semantic documents.
	code, stdout, _ = run("", analyst, "docs")
	check("docs empty", code, 0, stdout, `{"docs":[]}`)
	doc := `{"header":{"title":"Orders","used_for":["order counts"]},"context":{"tables":["sales.main.orders"],"body":"amount is masked for analysts"}}`
	code, _, stderr = run(doc, analyst, "doc-create", "-")
	check("analyst cannot write", code, 1, stderr, "HTTP 403")
	code, stdout, stderr = run(doc, poet, "doc-create", "-")
	check("poet creates", code, 0, stderr, "ETag:")
	var created struct {
		ID string `json:"id"`
	}
	json.Unmarshal([]byte(stdout), &created)
	if created.ID == "" {
		t.Fatalf("create: %s", stdout)
	}
	etag := strings.TrimSpace(strings.TrimPrefix(stderr, "curral: ETag: "))
	code, stdout, _ = run("", analyst, "doc", created.ID)
	check("doc", code, 0, stdout, `"title":"Orders"`)
	code, stdout, _ = run("", analyst, "search", "fields=header", "how many orders")
	check("search", code, 0, stdout, `"id":"`+created.ID+`"`)
	code, stdout, _ = run("", analyst, "docs", "table=orders", "fields=header")
	check("docs filter", code, 0, stdout, created.ID)
	code, _, stderr = run("", analyst, "doc", "../x")
	check("bad id", code, 2, stderr, "invalid document id")
	code, _, stderr = run(`{"header":{"used_for":["reports"]}}`, poet, "doc-patch", "-e", `"stale"`, created.ID, "-")
	check("stale etag", code, 1, stderr, "HTTP 412")
	code, _, stderr = run(`{"header":{"used_for":["reports"]}}`, poet, "doc-patch", "-e", etag, created.ID, "-")
	check("patch", code, 0, stderr, "ETag:")
	code, _, _ = run("", poet, "doc-delete", created.ID)
	check("delete", code, 0, "", "")
	code, stdout, _ = run("", poet, "schema", "table=orders")
	check("poet reads what it documents", code, 0, stdout, `"name":"orders"`)

	// A server without --docs-dir: a clear message, not a bare 404 page.
	plain := newServer(t)
	code, _, stderr = run("", []string{"CURRAL_URL=" + plain.URL, "CURRAL_USER=analyst", "CURRAL_PASSWORD=analyst-pw"}, "search", "anything")
	check("docs disabled", code, 1, stderr, "not enabled on this server")
}
