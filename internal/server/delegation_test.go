package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lucasapassos/curral/internal/auth"
	"github.com/lucasapassos/curral/internal/config"
	"github.com/lucasapassos/curral/internal/docs"
	"github.com/lucasapassos/curral/internal/policy"
	"github.com/lucasapassos/curral/internal/rls"
)

func contextHeader(fields map[string]any) string {
	b, _ := json.Marshal(fields)
	return base64.RawURLEncoding.EncodeToString(b)
}

type delegatedCall func(method, path string, headers map[string]string, body string) (int, http.Header, string)

func delegatedClient(t *testing.T, ts *httptest.Server, key string) delegatedCall {
	return func(method, path string, headers map[string]string, body string) (int, http.Header, string) {
		t.Helper()
		r, _ := http.NewRequest(method, ts.URL+path, strings.NewReader(body))
		r.Header.Set("Authorization", "Bearer "+key)
		for k, v := range headers {
			r.Header.Set(k, v)
		}
		resp, err := http.DefaultClient.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, resp.Header, string(b)
	}
}

func TestDelegationHTTP(t *testing.T) {
	ts := newServer(t)
	key, hash, _ := auth.NewAPIKey()
	subject := "portal:user:42"
	lastServer.SetAuth(auth.New(&config.Users{
		APIKeys: []config.APIKey{{Name: "portal", KeyHash: hash, Roles: []string{"admin"}, Delegation: true,
			Attributes: map[string]string{"tenant": "tenant-a"}}},
		Identities: []config.Identity{{Match: subject, Roles: []string{"analyst"}}},
	}, time.Minute))
	call := delegatedClient(t, ts, key)
	as := map[string]string{executionContextHeader: contextHeader(map[string]any{"subject": subject, "kind": "user"})}

	status, _, body := call("GET", "/v1/capabilities", nil, "")
	var capa map[string]any
	json.Unmarshal([]byte(body), &capa)
	if status != 200 || capa["execution_context_version"] != 1.0 || capa["delegation_required"] != true ||
		capa["subject"] != "portal" || capa["attributes"].(map[string]any)["tenant"] != "tenant-a" ||
		capa["docs"].(map[string]any)["enabled"] != false {
		t.Fatalf("capabilities %d %s", status, body)
	}
	status, h, body := call("POST", "/v1/query", as, `{"sql":"SELECT * FROM orders"}`)
	if status != 200 || h.Get(effectiveSubjectHeader) != subject {
		t.Fatalf("query %d %s", status, body)
	}
	for _, sql := range []string{"SELECT * FROM salaries", "DELETE FROM orders"} {
		b, _ := json.Marshal(map[string]any{"sql": sql})
		if status, _, body = call("POST", "/v1/query", as, string(b)); status != 403 {
			t.Fatalf("must not inherit the key's roles: %s: %d %s", sql, status, body)
		}
	}
	status, h, body = call("GET", "/v1/schema", as, "")
	if status != 200 || strings.Contains(body, `"name":"salaries"`) || h.Get(effectiveSubjectHeader) != subject {
		t.Fatalf("schema %d %s", status, body)
	}
	status, _, body = call("POST", "/v1/query", as, `{"sql":"SELECT * FROM orders","dry_run":true}`)
	if status != 200 || !strings.Contains(body, `"decision":"allow"`) {
		t.Fatalf("dry run %d %s", status, body)
	}
	if status, h, _ = call("GET", "/v1/databases", as, ""); status != 200 || h.Get(effectiveSubjectHeader) != subject {
		t.Fatalf("databases %d", status)
	}
	for name, headers := range map[string]map[string]string{
		"no identity":    nil,
		"not base64":     {executionContextHeader: "not-base64!"},
		"asserted roles": {executionContextHeader: contextHeader(map[string]any{"subject": subject, "roles": []string{"admin"}})},
		"no subject":     {executionContextHeader: contextHeader(map[string]any{"kind": "user"})},
		"both contexts":  {executionContextHeader: as[executionContextHeader], callerContextHeader: as[executionContextHeader]},
		"caller context": {callerContextHeader: as[executionContextHeader]},
	} {
		if status, _, body = call("POST", "/v1/query", headers, `{"sql":"SELECT * FROM orders"}`); status != 403 {
			t.Fatalf("%s: %d %s", name, status, body)
		}
	}
	if status, _, _ = call("GET", "/v1/capabilities", as, ""); status != 403 {
		t.Fatalf("capabilities must not take an identity: %d", status)
	}
}

// The policy, row filters and masks all see the structured identity and the
// delegating key as input.actor.
func TestDelegatedRowFiltersAndMasks(t *testing.T) {
	ts := newServer(t)
	s := lastServer
	key, hash, _ := auth.NewAPIKey()
	var ids []config.Identity
	for _, kind := range []string{"user", "page", "guest"} {
		ids = append(ids, config.Identity{Match: "portal:" + kind + ":7", Roles: []string{"live"}})
	}
	s.SetAuth(auth.New(&config.Users{APIKeys: []config.APIKey{{Name: "portal", KeyHash: hash, Delegation: true,
		Attributes: map[string]string{"organization_id": "org-a"}}}, Identities: ids}, 0))
	dir := t.TempDir()
	pf := filepath.Join(dir, "policy.rego")
	os.WriteFile(pf, []byte(`package curral
import rego.v1
default allow := false
allow if {
 input.actor.name == "portal"
 input.identity.organization.id == input.actor.attributes.organization_id
 startswith(input.user, "portal:")
 input.statement_type == "SELECT"
 input.resolved
 every t in input.tables { t == "sales.main.orders" }
}
masks := {"sales.main.orders":{"amount":"null"}} if input.identity.kind != "user"
row_filters := {"sales.main.orders":"id > 0"} if input.identity.kind in {"user","guest","page"}
`), 0600)
	pol, err := policy.LoadQueries(context.Background(), []string{pf}, policy.Queries{Allow: "data.curral.allow", Masks: "data.curral.masks", Filters: "data.curral.row_filters"})
	if err != nil {
		t.Fatal(err)
	}
	s.SetPolicy(pol)
	rf := filepath.Join(dir, "rls.yaml")
	os.WriteFile(rf, []byte(`tables:
  sales.main.orders:
    rules:
      - roles: [live]
        where: "id = CASE WHEN json_extract_string(getvariable('curral_identity'), '$.kind') = 'user' THEN 1 ELSE 2 END"
`), 0600)
	rules, err := rls.Load(rf)
	if err != nil {
		t.Fatal(err)
	}
	s.SetRowFilters(rules)
	call := delegatedClient(t, ts, key)
	body := `{"sql":"WITH dataset AS (SELECT id,amount FROM sales.main.orders) SELECT count(*) n,sum(amount) total FROM (SELECT * FROM dataset) q"}`
	for _, kind := range []string{"user", "page", "guest"} {
		identity := map[string]any{"subject": "portal:" + kind + ":7", "kind": kind, "organization": map[string]any{"id": "org-a"}}
		if root := os.Getenv("CURRAL_CONTRACT_CLIENT"); root != "" {
			// Optional cross-repository check: a delegating client's own
			// contract test runs against this server.
			raw, _ := json.Marshal(identity)
			cmd := exec.Command("node", root)
			cmd.Env = append(os.Environ(), "CURRAL_TEST_URL="+ts.URL, "CURRAL_TEST_KEY="+key, "CURRAL_TEST_IDENTITY="+string(raw))
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("contract client %s: %v: %s", kind, err, out)
			}
		}
		status, _, got := call("POST", "/v1/query", map[string]string{executionContextHeader: contextHeader(identity)}, body)
		want := `"total":null`
		if kind == "user" {
			want = `"total":"10.5"`
		}
		if status != 200 || !strings.Contains(got, `"n":1`) || !strings.Contains(got, want) {
			t.Fatalf("%s: %d %s, want %s", kind, status, got, want)
		}
	}
	other := map[string]any{"subject": "portal:user:7", "kind": "user", "organization": map[string]any{"id": "org-b"}}
	if status, _, got := call("POST", "/v1/query", map[string]string{executionContextHeader: contextHeader(other)}, body); status != 403 {
		t.Fatalf("other organization: %d %s", status, got)
	}
}

// A shared key may say who it calls for; that changes nothing but the audit
// trail, and makes the request read-only.
func TestCallerContext(t *testing.T) {
	auditPath := filepath.Join(t.TempDir(), "audit.log")
	ts, _ := newServerWithAudit(t, auditPath)
	key, hash, _ := auth.NewAPIKey()
	lastServer.SetAuth(auth.New(&config.Users{APIKeys: []config.APIKey{{Name: "shared", KeyHash: hash, Roles: []string{"analyst"}}}}, 0))
	call := delegatedClient(t, ts, key)
	caller := map[string]string{callerContextHeader: contextHeader(map[string]any{"subject": "portal:user:42"})}
	status, h, body := call("POST", "/v1/query", caller, `{"sql":"SELECT * FROM orders"}`)
	if status != 200 || h.Get(effectiveSubjectHeader) != "shared" {
		t.Fatalf("%d %s", status, body)
	}
	if status, _, _ = call("POST", "/v1/query", caller, `{"sql":"DELETE FROM orders"}`); status != 403 {
		t.Fatalf("caller context must be read-only: %d", status)
	}
	if status, _, _ = call("POST", "/v1/query", map[string]string{executionContextHeader: caller[callerContextHeader]}, `{"sql":"SELECT 1"}`); status != 403 {
		t.Fatalf("a shared key cannot delegate: %d", status)
	}
	var found bool
	for _, ev := range readAudit(t, auditPath) {
		if ev.Event == "query" && ev.User == "shared" && ev.Caller != nil {
			found = strings.Contains(string(must(json.Marshal(ev.Caller))), "portal:user:42")
		}
	}
	if !found {
		t.Fatal("caller context missing from the audit log")
	}
}

func must[T any](v T, _ error) T { return v }

func TestDelegatedDocs(t *testing.T) {
	key, hash, _ := auth.NewAPIKey()
	ts, _ := newDocsServer(t, t.TempDir(), filepath.Join(t.TempDir(), "audit.log"), func(s *Server) {
		s.SetAuth(auth.New(&config.Users{APIKeys: []config.APIKey{{Name: "portal", KeyHash: hash, Roles: []string{"admin", "poet"}, Delegation: true}},
			Identities: []config.Identity{{Match: "portal:user:42", Roles: []string{"poet"}}}}, 0))
	})
	call := delegatedClient(t, ts, key)
	as := map[string]string{executionContextHeader: contextHeader(map[string]any{"subject": "portal:user:42"})}
	if status, h, body := call("GET", "/v1/docs", as, ""); status != 200 || h.Get(effectiveSubjectHeader) != "portal:user:42" {
		t.Fatalf("list %d %s", status, body)
	}
	status, _, body := call("GET", "/v1/capabilities", nil, "")
	var capa map[string]any
	json.Unmarshal([]byte(body), &capa)
	if d := capa["docs"].(map[string]any); status != 200 || d["enabled"] != true || d["scope"] != "all" || d["delegated_writes"] != false {
		t.Fatalf("capabilities %d %s", status, body)
	}
	for _, headers := range []map[string]string{as, nil} {
		if status, _, body := call("POST", "/v1/docs", headers, `{}`); status != 403 {
			t.Fatalf("writes are not delegated without docs_write: %d %s", status, body)
		}
	}
}

// A delegating key marked docs_write writes documents as the identity it
// names, and only when the docs policy allows that identity (here, the
// poet role mapped to it). The author is the identity, not the key.
func TestDelegatedDocsWrite(t *testing.T) {
	key, hash, _ := auth.NewAPIKey()
	ts, _ := newDocsServer(t, t.TempDir(), filepath.Join(t.TempDir(), "audit.log"), func(s *Server) {
		s.SetAuth(auth.New(&config.Users{APIKeys: []config.APIKey{{Name: "portal", KeyHash: hash, Roles: []string{"admin", "poet"}, Delegation: true, DocsWrite: true}},
			Identities: []config.Identity{{Match: "portal:user:42", Roles: []string{"poet"}}}}, 0))
	})
	call := delegatedClient(t, ts, key)
	poet := map[string]string{executionContextHeader: contextHeader(map[string]any{"subject": "portal:user:42"})}
	reader := map[string]string{executionContextHeader: contextHeader(map[string]any{"subject": "portal:user:7"})}

	status, _, body := call("GET", "/v1/capabilities", nil, "")
	var capa map[string]any
	json.Unmarshal([]byte(body), &capa)
	if status != 200 || capa["docs"].(map[string]any)["delegated_writes"] != true {
		t.Fatalf("capabilities %d %s", status, body)
	}
	if status, _, body := call("POST", "/v1/docs", nil, sampleDoc); status != 403 {
		t.Fatalf("the key itself never writes: %d %s", status, body)
	}
	if status, _, body := call("POST", "/v1/docs", reader, sampleDoc); status != 403 {
		t.Fatalf("an identity the policy refuses: %d %s", status, body)
	}
	status, h, body := call("POST", "/v1/docs", poet, sampleDoc)
	var d docs.Doc
	json.Unmarshal([]byte(body), &d)
	if status != 201 || d.Header.Author != "portal:user:42" || h.Get(effectiveSubjectHeader) != "portal:user:42" {
		t.Fatalf("delegated create: %d %s", status, body)
	}
	if status, _, body := call("DELETE", "/v1/docs/"+d.ID, reader, ""); status != 403 {
		t.Fatalf("delegated delete by another identity: %d %s", status, body)
	}
	if status, _, body := call("DELETE", "/v1/docs/"+d.ID, poet, ""); status != 204 {
		t.Fatalf("delegated delete: %d %s", status, body)
	}
}
