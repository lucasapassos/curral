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
	"slices"
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
// example users and policy, and an audit log at auditPath. setup, if given,
// adjusts the server before it starts.
func newDocsServer(t *testing.T, dir, auditPath string, setup ...func(*Server)) (*httptest.Server, *audit.Writer) {
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
	for _, f := range setup {
		f(s)
	}
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
	// Lists match any name, repeated or comma-separated; not with the
	// single form, and capped.
	for _, query := range []string{"?tables=customers,orders", "?tables=customers&tables=orders", "?tables=,orders,"} {
		r = docReq(t, ts, "GET", "analyst", "/v1/docs"+query, "")
		if json.Unmarshal([]byte(r.body), &list); r.status != 200 || len(list.Docs) != 1 {
			t.Fatalf("%s: %d %s", query, r.status, r.body)
		}
	}
	r = docReq(t, ts, "GET", "analyst", "/v1/docs?tables=orders&schemas=main", "")
	if json.Unmarshal([]byte(r.body), &list); r.status != 200 || len(list.Docs) != 0 {
		t.Fatalf("tables and schemas both apply: %d %s", r.status, r.body)
	}
	for _, query := range []string{"?table=orders&tables=orders", "?schema=a&schemas=b", "?tables=" + strings.Repeat("t,", maxFilterNames) + "t"} {
		if r := docReq(t, ts, "GET", "analyst", "/v1/docs"+query, ""); r.status != 400 {
			t.Fatalf("%s: %d %s", query, r.status, r.body)
		}
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

// A policy scoped to some tables must see the document before and after an
// update; otherwise changing tables would take over any document.
func TestDocsPolicySeesBothVersions(t *testing.T) {
	tmp := t.TempDir()
	rego := `package curral
import rego.v1
docs_allow if "admin" in input.roles
docs_allow if {
	"sales_poet" in input.roles
	not other_tables
}
other_tables if { some t in input.doc.tables; not startswith(t, "sales.") }
other_tables if { some t in input.current.tables; not startswith(t, "sales.") }
`
	users, err := config.LoadUsers("../../examples/users.yaml")
	if err != nil {
		t.Fatal(err)
	}
	for i := range users.Users {
		if users.Users[i].Name == "poet" {
			users.Users[i].Roles = []string{"sales_poet"}
		}
	}
	policyPath := filepath.Join(tmp, "docs.rego")
	os.WriteFile(policyPath, []byte(rego), 0o600)
	pol, err := policy.LoadQueries(context.Background(), []string{policyPath},
		policy.Queries{Allow: "data.curral.docs_allow", Docs: "data.curral.docs_allow"})
	if err != nil {
		t.Fatal(err)
	}
	store, err := docs.Open(filepath.Join(tmp, "docs"))
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{Log: slog.New(slog.DiscardHandler), MaxBody: 1 << 20, Docs: store}
	s.SetAuth(auth.New(users, time.Minute))
	s.SetPolicy(pol)
	ts := httptest.NewServer(s.Handler())
	t.Cleanup(ts.Close)

	doc := func(table string) string {
		return `{"header":{"title":"t"},"context":{"tables":["` + table + `"],"body":"b"}}`
	}
	id := func(r result) string {
		var d docs.Doc
		json.Unmarshal([]byte(r.body), &d)
		return d.ID
	}
	if r := docReq(t, ts, "POST", "poet", "/v1/docs", doc("crm.main.customers")); r.status != 403 {
		t.Fatalf("create outside scope: %d", r.status)
	}
	own := docReq(t, ts, "POST", "poet", "/v1/docs", doc("sales.main.orders"))
	if own.status != 201 {
		t.Fatalf("create in scope: %d %s", own.status, own.body)
	}
	other := docReq(t, ts, "POST", "admin", "/v1/docs", doc("crm.main.customers"))
	for _, c := range []struct{ method, body string }{
		{"PATCH", `{"context":{"tables":["sales.main.orders"]}}`},
		{"PUT", doc("sales.main.orders")},
		{"DELETE", ""},
	} {
		if r := docReq(t, ts, c.method, "poet", "/v1/docs/"+id(other), c.body); r.status != 403 {
			t.Errorf("%s of a document outside scope: %d %s", c.method, r.status, r.body)
		}
	}
	if r := docReq(t, ts, "PATCH", "poet", "/v1/docs/"+id(own), `{"context":{"tables":["crm.main.customers"]}}`); r.status != 403 {
		t.Errorf("moving a document out of scope: %d", r.status)
	}
	if r := docReq(t, ts, "DELETE", "poet", "/v1/docs/"+id(own), ""); r.status != 204 {
		t.Errorf("delete in scope: %d %s", r.status, r.body)
	}
}

// With --docs-scope schema, a document about tables is served only to a
// caller who may read one of them; documents about no table reach everyone,
// and an out-of-scope id reads as missing.
func TestDocsScopeSchema(t *testing.T) {
	store, err := docs.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	ts, _ := newServerWithAudit(t, "", func(s *Server) { s.Docs, s.DocsScope = store, DocsScopeSchema })
	pol, err := policy.LoadQueries(context.Background(),
		[]string{"../../examples/policy.rego", "../../examples/roles.json"},
		policy.Queries{Allow: "data.curral.allow", Docs: "data.curral.docs_allow"})
	if err != nil {
		t.Fatal(err)
	}
	lastServer.SetPolicy(pol)

	ids := map[string]string{}
	for name, context := range map[string]string{"orders": `"tables":["sales.main.orders"]`, "salaries": `"tables":["salaries"]`, "general": `"tables":[]`,
		"sales schema": `"schemas":["sales.main"]`, "hr schema": `"schemas":["hr.main"]`} {
		r := docReq(t, ts, "POST", "poet", "/v1/docs", `{"header":{"title":"`+name+` notes"},"context":{`+context+`,"body":"about `+name+`"}}`)
		if r.status != 201 {
			t.Fatalf("create %s: %d %s", name, r.status, r.body)
		}
		var d docs.Doc
		json.Unmarshal([]byte(r.body), &d)
		ids[name] = d.ID
	}
	titles := func(r result) []string {
		var out struct {
			Docs    []docs.Doc
			Results []struct{ Doc docs.Doc }
		}
		json.Unmarshal([]byte(r.body), &out)
		var ts []string
		for _, d := range out.Docs {
			ts = append(ts, d.Header.Title)
		}
		for _, h := range out.Results {
			ts = append(ts, h.Doc.Header.Title)
		}
		return ts
	}
	// The analyst reads orders (so the sales schema), not salaries; nobody
	// here reads an hr schema, so that document is served to no one.
	if r := docReq(t, ts, "GET", "analyst", "/v1/docs", ""); r.status != 200 || len(titles(r)) != 3 ||
		slices.Contains(titles(r), "salaries notes") || slices.Contains(titles(r), "hr schema notes") {
		t.Fatalf("analyst list: %d %v", r.status, titles(r))
	}
	if r := docReq(t, ts, "GET", "analyst", "/v1/docs/"+ids["salaries"], ""); r.status != 404 {
		t.Fatalf("analyst get out of scope: %d %s", r.status, r.body)
	}
	if r := docReq(t, ts, "GET", "analyst", "/v1/docs/"+ids["general"], ""); r.status != 200 {
		t.Fatalf("analyst get general: %d %s", r.status, r.body)
	}
	if r := docReq(t, ts, "POST", "analyst", "/v1/docs/search", `{"q":"salaries notes"}`); r.status != 200 || slices.Contains(titles(r), "salaries notes") {
		t.Fatalf("analyst search: %d %v", r.status, titles(r))
	}
	// The admin reads everything about existing tables.
	if r := docReq(t, ts, "GET", "admin", "/v1/docs", ""); r.status != 200 || len(titles(r)) != 4 || slices.Contains(titles(r), "hr schema notes") {
		t.Fatalf("admin list: %d %v", r.status, titles(r))
	}
	if r := docReq(t, ts, "POST", "admin", "/v1/docs/search", `{"q":"salaries notes"}`); r.status != 200 || !slices.Contains(titles(r), "salaries notes") {
		t.Fatalf("admin search: %d %v", r.status, titles(r))
	}
	if r := docReq(t, ts, "GET", "admin", "/v1/docs?fields=bogus", ""); r.status != 400 {
		t.Fatalf("fields=bogus: %d %s", r.status, r.body)
	}

	// Writes see the same scope. To the poet, who may query no table, and
	// to the analyst, who may not write, an out-of-scope id is missing
	// with every method: a PATCH cannot read the document back, and no
	// status tells an out-of-scope id from an unknown one.
	bodies := map[string]string{"PATCH": `{}`, "PUT": `{"header":{"title":"x"},"context":{"body":"b"}}`, "DELETE": ""}
	missing := strings.Repeat("0", len(ids["orders"]))
	for method, body := range bodies {
		for user, out := range map[string][]string{"poet": {ids["salaries"], ids["orders"], missing}, "analyst": {ids["salaries"], missing}} {
			for _, id := range out {
				if r := docReq(t, ts, method, user, "/v1/docs/"+id, body); r.status != 404 {
					t.Fatalf("%s %s as %s: %d %s", method, id, user, r.status, r.body)
				}
			}
		}
	}
	// In scope, the poet writes as usual: a document about nothing, with
	// the client's If-Match honored, and the admin reaches every document.
	if r := docReq(t, ts, "PATCH", "poet", "/v1/docs/"+ids["general"], `{"header":{"title":"general notes, revised"}}`, "If-Match", `"stale"`); r.status != 412 {
		t.Fatalf("stale If-Match in scope: %d %s", r.status, r.body)
	}
	if r := docReq(t, ts, "PATCH", "poet", "/v1/docs/"+ids["general"], `{"context":{"body":{"nested":1}}}`); r.status != 400 {
		t.Fatalf("patch of a field with an object: %d %s", r.status, r.body)
	}
	if r := docReq(t, ts, "POST", "poet", "/v1/docs", sampleDoc+"{}"); r.status != 400 {
		t.Fatalf("trailing data: %d %s", r.status, r.body)
	}
	if r := docReq(t, ts, "PATCH", "poet", "/v1/docs/not-an-id", `{}`); r.status != 404 {
		t.Fatalf("invalid id: %d %s", r.status, r.body)
	}
	r := docReq(t, ts, "PATCH", "poet", "/v1/docs/"+ids["general"], `{"header":{"title":"general notes, revised"}}`, "If-Match", "*")
	if r.status != 200 || !strings.Contains(r.body, "general notes, revised") {
		t.Fatalf("patch in scope: %d %s", r.status, r.body)
	}
	if r := docReq(t, ts, "DELETE", "poet", "/v1/docs/"+ids["general"], "", "If-Match", r.header.Get("ETag")); r.status != 204 {
		t.Fatalf("delete in scope: %d %s", r.status, r.body)
	}
	if r := docReq(t, ts, "PATCH", "admin", "/v1/docs/"+ids["salaries"], `{}`); r.status != 200 {
		t.Fatalf("admin patch: %d %s", r.status, r.body)
	}

	// Scope all: the analyst reads everything again.
	lastServer.DocsScope = DocsScopeAll
	if r := docReq(t, ts, "GET", "analyst", "/v1/docs", ""); r.status != 200 || len(titles(r)) != 4 {
		t.Fatalf("analyst list, scope all: %d %v", r.status, titles(r))
	}
}

// seedScoped stores a document about orders and one about nothing in a new
// store, for servers that scope by schema.
func seedScoped(t *testing.T) (store *docs.Store, scoped, general docs.Doc) {
	t.Helper()
	store, err := docs.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if scoped, _, err = store.Create(docs.Doc{Header: docs.Header{Title: "orders notes"},
		Context: docs.Context{Tables: []string{"sales.main.orders"}, Body: "b"}}, "admin", nil); err != nil {
		t.Fatal(err)
	}
	if general, _, err = store.Create(docs.Doc{Header: docs.Header{Title: "general notes"},
		Context: docs.Context{Body: "b"}}, "admin", nil); err != nil {
		t.Fatal(err)
	}
	return store, scoped, general
}

// scopedCalls are the requests that need the caller's scope: every read
// of a document about tables, known or not, searches and writes.
func scopedCalls(scoped docs.Doc) []struct{ method, path, body string } {
	missing := strings.Repeat("0", len(scoped.ID))
	return []struct{ method, path, body string }{
		{"GET", "/v1/docs", ""}, {"GET", "/v1/docs/" + scoped.ID, ""}, {"GET", "/v1/docs/" + missing, ""},
		{"POST", "/v1/docs/search", `{"q":"orders"}`}, {"PATCH", "/v1/docs/" + scoped.ID, `{}`}, {"DELETE", "/v1/docs/" + missing, ""},
	}
}

// With the audit sink failing, scoped documents are not served (as the
// schema is not listed), with Retry-After; one about nothing still is.
func TestDocsScopeFailClosed(t *testing.T) {
	if _, err := os.Stat("/dev/full"); err != nil {
		t.Skip("no /dev/full")
	}
	store, scoped, general := seedScoped(t)
	ts, aw := newServerWithAudit(t, "/dev/full", func(s *Server) { s.Docs, s.DocsScope = store, DocsScopeSchema })
	defer aw.Close()
	// The first event fails to write and marks the sink unhealthy.
	docReq(t, ts, "GET", "admin", "/v1/docs", "")
	deadline := time.Now().Add(2 * time.Second)
	for aw.Healthy() == nil && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	for _, c := range scopedCalls(scoped) {
		r := docReq(t, ts, c.method, "admin", c.path, c.body)
		if r.status != 503 || r.header.Get("Retry-After") == "" || !strings.Contains(r.body, "audit") {
			t.Fatalf("%s %s while audit down: %d %v %s", c.method, c.path, r.status, r.header, r.body)
		}
	}
	if r := docReq(t, ts, "GET", "admin", "/v1/docs/"+general.ID, ""); r.status != 200 {
		t.Fatalf("a document in every scope needs no listing: %d %s", r.status, r.body)
	}
	// Under scope all, listing and search still annotate each document with
	// the caller's tables, so they need the listing too; a single document
	// does not.
	lastServer.DocsScope = DocsScopeAll
	for _, c := range scopedCalls(scoped)[:1] {
		if r := docReq(t, ts, c.method, "admin", c.path, c.body); r.status != 503 {
			t.Fatalf("%s %s under scope all while audit down: %d %s", c.method, c.path, r.status, r.body)
		}
	}
	if r := docReq(t, ts, "POST", "admin", "/v1/docs/search", `{"q":"orders"}`); r.status != 503 {
		t.Fatalf("search under scope all while audit down: %d %s", r.status, r.body)
	}
	if r := docReq(t, ts, "GET", "admin", "/v1/docs/"+scoped.ID, ""); r.status != 200 {
		t.Fatalf("one document under scope all: %d %s", r.status, r.body)
	}
}

// Listed and searched documents say which of their tables the caller may
// query, in both scopes; a document about no table has two empty lists.
func TestDocsAccessAnnotation(t *testing.T) {
	store, err := docs.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	ts, _ := newServerWithAudit(t, "", func(s *Server) { s.Docs = store })
	for title, tables := range map[string][]string{
		"payroll": {"sales.main.salaries", "Orders", "nope"}, "salaries": {"salaries"}, "general": nil,
	} {
		if _, _, err := store.Create(docs.Doc{Header: docs.Header{Title: title}, Context: docs.Context{Tables: tables, Body: "about " + title}}, "poet", nil); err != nil {
			t.Fatal(err)
		}
	}
	type annotated struct {
		Header             struct{ Title string }
		Context            map[string]any
		AccessibleTables   []string `json:"accessible_tables"`
		InaccessibleTables []string `json:"inaccessible_tables"`
	}
	byTitle := func(r result) map[string]annotated {
		t.Helper()
		if r.status != 200 {
			t.Fatalf("%d %s", r.status, r.body)
		}
		var out struct {
			Docs    []annotated
			Results []struct{ Doc annotated }
		}
		json.Unmarshal([]byte(r.body), &out)
		for _, h := range out.Results {
			out.Docs = append(out.Docs, h.Doc)
		}
		m := map[string]annotated{}
		for _, d := range out.Docs {
			m[d.Header.Title] = d
		}
		return m
	}
	check := func(name string, got map[string]annotated, title string, accessible, inaccessible []string) {
		t.Helper()
		d, ok := got[title]
		if !ok {
			t.Fatalf("%s: %s not listed in %v", name, title, got)
		}
		if !slices.Equal(d.AccessibleTables, accessible) || !slices.Equal(d.InaccessibleTables, inaccessible) {
			t.Errorf("%s: %s accessible %v inaccessible %v, want %v and %v", name, title, d.AccessibleTables, d.InaccessibleTables, accessible, inaccessible)
		}
	}
	for _, scope := range []string{DocsScopeAll, DocsScopeSchema} {
		lastServer.DocsScope = scope
		for name, r := range map[string]result{
			"list":   docReq(t, ts, "GET", "analyst", "/v1/docs", ""),
			"header": docReq(t, ts, "GET", "analyst", "/v1/docs?fields=header", ""),
			"search": docReq(t, ts, "POST", "analyst", "/v1/docs/search", `{"q":"about payroll salaries general","limit":10}`),
		} {
			got := byTitle(r)
			check(scope+" "+name, got, "payroll", []string{"Orders"}, []string{"sales.main.salaries", "nope"})
			check(scope+" "+name, got, "general", []string{}, []string{})
			if _, listed := got["salaries"]; listed != (scope == DocsScopeAll) {
				t.Errorf("%s %s: salaries listed=%v", scope, name, listed)
			}
			if scope == DocsScopeAll {
				check(scope+" "+name, got, "salaries", []string{}, []string{"salaries"})
			}
			if name == "header" && got["payroll"].Context["body"] != nil {
				t.Errorf("header view has a body: %v", got["payroll"].Context)
			}
		}
		got := byTitle(docReq(t, ts, "GET", "admin", "/v1/docs", ""))
		check(scope+" admin", got, "payroll", []string{"sales.main.salaries", "Orders"}, []string{"nope"})
		check(scope+" admin", got, "salaries", []string{"salaries"}, []string{})
	}
}

// A policy that fails to evaluate scopes nothing: every scoped request is
// an error, reads and writes alike.
func TestDocsScopePolicyError(t *testing.T) {
	store, scoped, _ := seedScoped(t)
	ts, _ := newServerWithAudit(t, "", func(s *Server) { s.Docs, s.DocsScope = store, DocsScopeSchema })
	lastServer.SetPolicy(loadRego(t, "allow if to_number(input.user) > 0\ndocs_allow := true"))
	for _, c := range scopedCalls(scoped) {
		if r := docReq(t, ts, c.method, "admin", c.path, c.body); r.status != 500 || !strings.Contains(r.body, "policy") {
			t.Fatalf("%s %s: %d %s", c.method, c.path, r.status, r.body)
		}
	}
}

// loadRego compiles rules in package curral with both decisions.
func loadRego(t *testing.T, rules string) *policy.Policy {
	t.Helper()
	path := filepath.Join(t.TempDir(), "p.rego")
	os.WriteFile(path, []byte("package curral\nimport rego.v1\n"+rules+"\n"), 0o600)
	pol, err := policy.LoadQueries(context.Background(), []string{path},
		policy.Queries{Allow: "data.curral.allow", Docs: "data.curral.docs_allow"})
	if err != nil {
		t.Fatal(err)
	}
	return pol
}

// A docs decision that fails to evaluate, or a store that cannot save,
// refuse the write with a 500 that says which.
func TestDocsWriteErrors(t *testing.T) {
	ts, _ := newDocsServer(t, t.TempDir(), filepath.Join(t.TempDir(), "audit.log"), func(s *Server) {
		s.SetPolicy(loadRego(t, "docs_allow if to_number(input.user) > 0"))
	})
	if r := docReq(t, ts, "POST", "poet", "/v1/docs", sampleDoc); r.status != 500 || !strings.Contains(r.body, "policy") {
		t.Fatalf("policy error: %d %s", r.status, r.body)
	}
	if os.Geteuid() == 0 {
		t.Skip("root writes anywhere")
	}
	dir := t.TempDir()
	ts, _ = newDocsServer(t, dir, filepath.Join(t.TempDir(), "audit.log"))
	os.Chmod(dir, 0o500)
	t.Cleanup(func() { os.Chmod(dir, 0o700) })
	if r := docReq(t, ts, "POST", "poet", "/v1/docs", sampleDoc); r.status != 500 || !strings.Contains(r.body, "could not save") {
		t.Fatalf("store error: %d %s", r.status, r.body)
	}
}

// /v1/schema counts the documents about each table, matching names as the
// document filters do. Under --docs-scope schema only documents the caller
// may read count, so a count never reveals a hidden document.
func TestSchemaDocCount(t *testing.T) {
	store, err := docs.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	ts, _ := newServerWithAudit(t, "", func(s *Server) { s.Docs = store })
	// A second salaries table the analyst may read makes the short name
	// ambiguous: it fits the denied sales.main.salaries too.
	for _, ddl := range []string{"CREATE SCHEMA sales.hr", "CREATE TABLE sales.hr.salaries(name VARCHAR)"} {
		if r := do(t, ts, "admin", `{"sql":"`+ddl+`"}`); r.status != 200 {
			t.Fatalf("%s: %d %s", ddl, r.status, r.body)
		}
	}
	for title, tables := range map[string][]string{
		"orders short": {"orders"}, "orders qualified": {"Sales.Main.Orders", "orders"},
		"salaries short": {"salaries"}, "payroll": {"sales.main.salaries", "orders"}, "general": nil,
	} {
		if _, _, err := store.Create(docs.Doc{Header: docs.Header{Title: title}, Context: docs.Context{Tables: tables, Body: "b"}}, "poet", nil); err != nil {
			t.Fatal(err)
		}
	}
	counts := func(user, query string) map[string]int {
		t.Helper()
		status, out := getSchema(t, ts, user, query)
		if status != 200 {
			t.Fatalf("%s schema: %d", user, status)
		}
		got := map[string]int{}
		for _, tb := range out.Tables {
			got[tb.Qualified()] = tb.Docs
		}
		return got
	}
	type want map[string]int
	check := func(name string, got map[string]int, w want) {
		t.Helper()
		for table, n := range w {
			if got[table] != n {
				t.Errorf("%s: %s has %d docs, want %d (%v)", name, table, got[table], n, got)
			}
		}
	}
	// Scope all: every document counts, once per table however many of its
	// names fit; a table no document names has no count (omitted).
	check("admin", counts("admin", ""), want{"sales.main.orders": 3, "sales.main.salaries": 2, "sales.hr.salaries": 1, "logs.main.events": 0})
	check("analyst", counts("analyst", ""), want{"sales.main.orders": 3, "sales.hr.salaries": 1})
	check("filtered", counts("admin", "?table=orders"), want{"sales.main.orders": 3})
	status, out := getSchema(t, ts, "admin", "?table=events")
	if b, _ := json.Marshal(out.Tables); status != 200 || strings.Contains(string(b), `"docs"`) {
		t.Errorf("a table without documents: %d %s", status, b)
	}

	// Scope schema: the analyst may not read the "salaries short" document
	// (its only name also fits the denied table), so sales.hr.salaries
	// counts none for them and still one for the admin.
	lastServer.DocsScope = DocsScopeSchema
	check("admin scoped", counts("admin", ""), want{"sales.main.orders": 3, "sales.main.salaries": 2, "sales.hr.salaries": 1})
	check("analyst scoped", counts("analyst", ""), want{"sales.main.orders": 3, "sales.hr.salaries": 0})

	// Without documents enabled nothing is counted.
	lastServer.Docs = nil
	check("disabled", counts("admin", ""), want{"sales.main.orders": 0})
}

// With --docs-validate-names, writes resolve tables and schemas to their
// qualified catalog names: strict refuses what fits none or several
// objects, warn keeps it, off saves everything as written. The policy sees
// the resolved names.
func TestDocsValidateNames(t *testing.T) {
	store, err := docs.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	ts, _ := newServerWithAudit(t, "", func(s *Server) { s.Docs, s.DocsValidateNames = store, DocsNamesStrict })
	lastServer.SetPolicy(loadRego(t, `allow if "admin" in input.roles
docs_allow if "poet" in input.roles
docs_allow if { "admin" in input.roles; every t in input.doc.tables { startswith(t, "sales.") } }`))
	for _, ddl := range []string{"CREATE SCHEMA sales.hr", "CREATE TABLE sales.hr.salaries(name VARCHAR)"} {
		if r := do(t, ts, "admin", `{"sql":"`+ddl+`"}`); r.status != 200 {
			t.Fatalf("%s: %d %s", ddl, r.status, r.body)
		}
	}
	body := func(tables, schemas string) string {
		return `{"header":{"title":"t"},"context":{"tables":` + tables + `,"schemas":` + schemas + `,"body":"b"}}`
	}
	created := func(r result) docs.Doc {
		t.Helper()
		if r.status != 201 && r.status != 200 {
			t.Fatalf("write: %d %s", r.status, r.body)
		}
		var d docs.Doc
		json.Unmarshal([]byte(r.body), &d)
		return d
	}
	// The poet, who may query nothing, still resolves names: that is the
	// documented cost of the check.
	d := created(docReq(t, ts, "POST", "poet", "/v1/docs", body(`["orders","Sales.Main.Orders","main.events"]`, `["sales.main","logs.MAIN"]`)))
	if !slices.Equal(d.Context.Tables, []string{"sales.main.orders", "logs.main.events"}) || !slices.Equal(d.Context.Schemas, []string{"sales.main", "logs.main"}) {
		t.Fatalf("resolved: %+v", d.Context)
	}
	for _, c := range []struct{ tables, schemas, want string }{
		{`["nope"]`, `[]`, `"nope" is not a table`},
		{`["salaries"]`, `[]`, `"salaries" fits several tables`},
		{`[]`, `["main"]`, `"main" fits several schemas`},
		{`[]`, `["sales"]`, `"sales" is not a schema`},
	} {
		r := docReq(t, ts, "POST", "poet", "/v1/docs", body(c.tables, c.schemas))
		var e struct{ Error string }
		json.Unmarshal([]byte(r.body), &e)
		if r.status != 400 || !strings.Contains(e.Error, c.want) {
			t.Errorf("%s %s: %d %s", c.tables, c.schemas, r.status, r.body)
		}
	}
	// Updates resolve too, and the policy judges the resolved names: the
	// admin may write about sales tables, by whatever name.
	d = created(docReq(t, ts, "PATCH", "admin", "/v1/docs/"+d.ID, `{"context":{"tables":["hr.salaries"],"schemas":null}}`))
	if !slices.Equal(d.Context.Tables, []string{"sales.hr.salaries"}) || d.Context.Schemas != nil {
		t.Fatalf("patched: %+v", d.Context)
	}
	if r := docReq(t, ts, "PUT", "admin", "/v1/docs/"+d.ID, body(`["events"]`, `[]`)); r.status != 403 {
		t.Fatalf("policy on resolved names: %d %s", r.status, r.body)
	}
	if r := docReq(t, ts, "PUT", "admin", "/v1/docs/"+d.ID, body(`["nope"]`, `[]`)); r.status != 400 {
		t.Fatalf("put strict: %d %s", r.status, r.body)
	}

	// Warn qualifies what resolves and keeps the rest; off touches nothing.
	lastServer.DocsValidateNames = DocsNamesWarn
	d = created(docReq(t, ts, "POST", "poet", "/v1/docs", body(`["orders","salaries","nope"]`, `["main"]`)))
	if !slices.Equal(d.Context.Tables, []string{"sales.main.orders", "salaries", "nope"}) || !slices.Equal(d.Context.Schemas, []string{"main"}) {
		t.Fatalf("warn: %+v", d.Context)
	}
	lastServer.DocsValidateNames = DocsNamesOff
	d = created(docReq(t, ts, "POST", "poet", "/v1/docs", body(`["orders","nope"]`, `[]`)))
	if !slices.Equal(d.Context.Tables, []string{"orders", "nope"}) {
		t.Fatalf("off: %+v", d.Context)
	}
}
