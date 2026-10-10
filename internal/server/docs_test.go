package server

import (
	"context"
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

	"github.com/lucasapassos/curral/internal/audit"
	"github.com/lucasapassos/curral/internal/auth"
	"github.com/lucasapassos/curral/internal/config"
	"github.com/lucasapassos/curral/internal/docs"
	"github.com/lucasapassos/curral/internal/policy"
)

// newDocsServer starts a server with only /v1/docs (no engine needed), the
// example users and policy, and an audit log at auditPath.
func newDocsServer(t *testing.T, dir, auditPath string) (*httptest.Server, *audit.Writer) {
	t.Helper()
	users, err := config.LoadUsers("../../examples/users.yaml")
	if err != nil {
		t.Fatal(err)
	}
	pol, err := policy.LoadQueries(context.Background(),
		[]string{"../../examples/policy.rego", "../../examples/roles.json"},
		policy.Queries{Allow: "data.curral.allow", Docs: "data.curral.docs_allow"})
	if err != nil {
		t.Fatal(err)
	}
	store, err := docs.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	log := slog.New(slog.DiscardHandler)
	aw, err := audit.Open(auditPath, 64, log)
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{Log: log, MaxBody: 1 << 10, Version: "test", Docs: store, Audit: aw}
	s.SetAuth(auth.New(users, time.Minute))
	s.SetPolicy(pol)
	ts := httptest.NewServer(s.Handler())
	t.Cleanup(ts.Close)
	return ts, aw
}

func docReq(t *testing.T, ts *httptest.Server, method, user, path, body string, hdr ...string) result {
	t.Helper()
	req, _ := http.NewRequest(method, ts.URL+path, strings.NewReader(body))
	if user != "" {
		req.SetBasicAuth(user, user+"-pw")
	}
	for i := 0; i+1 < len(hdr); i += 2 {
		req.Header.Set(hdr[i], hdr[i+1])
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return result{status: resp.StatusCode, body: string(b), header: resp.Header}
}

const sampleDoc = `{
  "header": {"title": "Monthly revenue", "description": "Gross revenue per month", "used_for": ["finance reports"]},
  "context": {
    "tables": ["sales.main.orders"],
    "body": "orders.amount is the gross value of each order.",
    "sqls": [{"sql": "SELECT sum(amount) FROM sales.main.orders", "description": "total revenue"}]
  }
}`

func TestDocsAPI(t *testing.T) {
	dir := t.TempDir()
	auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
	ts, aw := newDocsServer(t, dir, auditPath)

	if r := docReq(t, ts, "GET", "", "/v1/docs", ""); r.status != 401 {
		t.Fatalf("anonymous list: %d", r.status)
	}
	if r := docReq(t, ts, "POST", "analyst", "/v1/docs", sampleDoc); r.status != 403 {
		t.Fatalf("analyst create: %d %s", r.status, r.body)
	}
	if r := docReq(t, ts, "POST", "poet", "/v1/docs", `{"header":{"title":"x"},"context":{"body":"b"},"extra":1}`); r.status != 400 {
		t.Fatalf("unknown field: %d %s", r.status, r.body)
	}
	if r := docReq(t, ts, "POST", "poet", "/v1/docs", `{"header":{"title":"x"},"context":{"body":"`+strings.Repeat("x", 2000)+`"}}`); r.status != 413 {
		t.Fatalf("oversized body: %d %s", r.status, r.body)
	}

	r := docReq(t, ts, "POST", "poet", "/v1/docs", sampleDoc)
	if r.status != 201 {
		t.Fatalf("create: %d %s", r.status, r.body)
	}
	var d docs.Doc
	json.Unmarshal([]byte(r.body), &d)
	if d.Header.Author != "poet" || d.Header.CreatedAt.IsZero() || r.header.Get("Location") != "/v1/docs/"+d.ID {
		t.Fatalf("created: %+v %v", d, r.header)
	}
	tag := r.header.Get("ETag")
	if _, err := os.Stat(filepath.Join(dir, d.ID+".json")); err != nil {
		t.Fatal(err)
	}

	// Any authenticated user reads.
	if r := docReq(t, ts, "GET", "analyst", "/v1/docs/"+d.ID, ""); r.status != 200 || r.header.Get("ETag") != tag {
		t.Fatalf("analyst get: %d %s", r.status, r.body)
	}
	var list struct{ Docs []map[string]any }
	r = docReq(t, ts, "GET", "analyst", "/v1/docs?table=orders&fields=header", "")
	json.Unmarshal([]byte(r.body), &list)
	if r.status != 200 || len(list.Docs) != 1 || list.Docs[0]["context"].(map[string]any)["body"] != nil {
		t.Fatalf("list: %d %s", r.status, r.body)
	}
	r = docReq(t, ts, "GET", "analyst", "/v1/docs?table=customers", "")
	if json.Unmarshal([]byte(r.body), &list); len(list.Docs) != 0 {
		t.Fatalf("filtered list: %s", r.body)
	}
	for _, path := range []string{"/v1/docs/nope", "/v1/docs/..%2Fetc", "/v1/docs/0000000000000000"} {
		if r := docReq(t, ts, "GET", "analyst", path, ""); r.status != 404 {
			t.Fatalf("%s: %d", path, r.status)
		}
	}

	// Writes by anyone the policy allows; If-Match guards concurrent edits.
	if r := docReq(t, ts, "PATCH", "analyst", "/v1/docs/"+d.ID, `{"header":{"title":"x"}}`); r.status != 403 {
		t.Fatalf("analyst patch: %d", r.status)
	}
	if r := docReq(t, ts, "PATCH", "admin", "/v1/docs/"+d.ID, `{"header":{"title":"x"}}`, "If-Match", `"stale"`); r.status != 412 {
		t.Fatalf("stale patch: %d %s", r.status, r.body)
	}
	r = docReq(t, ts, "PATCH", "admin", "/v1/docs/"+d.ID, `{"header":{"title":"Revenue by month"}}`,
		"If-Match", tag, "Content-Type", "application/merge-patch+json")
	json.Unmarshal([]byte(r.body), &d)
	if r.status != 200 || d.Header.Title != "Revenue by month" || d.Header.Author != "poet" || d.Header.UpdatedBy != "admin" ||
		len(d.Context.SQLs) != 1 || r.header.Get("ETag") == tag {
		t.Fatalf("patch: %d %s", r.status, r.body)
	}
	r = docReq(t, ts, "PUT", "poet", "/v1/docs/"+d.ID, `{"header":{"title":"Replaced"},"context":{"body":"new body"}}`)
	d = docs.Doc{}
	json.Unmarshal([]byte(r.body), &d)
	if r.status != 200 || d.Header.Title != "Replaced" || d.Context.SQLs != nil || d.Header.Author != "poet" {
		t.Fatalf("put: %d %s", r.status, r.body)
	}

	if r := docReq(t, ts, "DELETE", "analyst", "/v1/docs/"+d.ID, ""); r.status != 403 {
		t.Fatalf("analyst delete: %d", r.status)
	}
	if r := docReq(t, ts, "DELETE", "poet", "/v1/docs/"+d.ID, ""); r.status != 204 {
		t.Fatalf("delete: %d %s", r.status, r.body)
	}
	if r := docReq(t, ts, "DELETE", "poet", "/v1/docs/"+d.ID, ""); r.status != 404 {
		t.Fatalf("second delete: %d", r.status)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Fatalf("files left: %v", entries)
	}

	if err := aw.Close(); err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, ev := range readAudit(t, auditPath) {
		got = append(got, ev.Event+":"+ev.User+":"+ev.Decision)
		if ev.Event == "doc_create" && ev.Decision == "allow" && ev.Doc != d.ID {
			t.Errorf("create event doc %q", ev.Doc)
		}
	}
	want := []string{
		"auth_failure::deny",
		"doc_create:analyst:deny", "doc_create:poet:error", "doc_create:poet:error", "doc_create:poet:allow",
		"doc_update:analyst:deny", "doc_update:admin:error", "doc_update:admin:allow", "doc_update:poet:allow",
		"doc_delete:analyst:deny", "doc_delete:poet:allow", "doc_delete:poet:error",
	}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("audit events:\n got %v\nwant %v", got, want)
	}
}

func TestDocsDisabled(t *testing.T) {
	ts := newServer(t)
	req, _ := http.NewRequest("GET", ts.URL+"/v1/docs", nil)
	req.SetBasicAuth("admin", "admin-pw")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 404 {
		t.Fatalf("status %d", resp.StatusCode)
	}
}
