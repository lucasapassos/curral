package policytest

import (
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/lucasapassos/curral/internal/auth"
)

func writeTempYAML(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "suite.yaml")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatalf("write temp yaml: %v", err)
	}
	return p
}

func TestLoadValid(t *testing.T) {
	path := writeTempYAML(t, `
cases:
  - name: analyst reads orders
    user: alice
    roles: [analyst]
    database: sales
    sql: SELECT * FROM orders
    max_rows: 100
    expect:
      decision: allow
      decided_by: policy
      row_filters: [sales.main.orders]
      masked_columns:
        sales.main.orders: [email, ssn]
      max_rows: 100
      timeout: 30s
  - name: delegated read
    actor: bi-app
    actor_attributes:
      tenant: acme
    roles: [analyst]
    identity:
      subject: bob@acme.com
      kind: user
      department: finance
    sql: SELECT 1
    expect:
      decision: allow
  - name: bad sql
    user: alice
    sql: SELECT FROM
    expect:
      decision: error
`)

	s, err := Load(path)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	if len(s.Cases) != 3 {
		t.Fatalf("got %d cases, want 3", len(s.Cases))
	}
	c0 := s.Cases[0]
	if c0.Name != "analyst reads orders" || c0.User != "alice" || c0.Database != "sales" || c0.MaxRows != 100 {
		t.Fatalf("unexpected first case: %+v", c0)
	}
	if c0.Expect.MaxRows == nil || *c0.Expect.MaxRows != 100 {
		t.Fatalf("unexpected expect.max_rows: %v", c0.Expect.MaxRows)
	}
	if c0.Expect.Timeout != "30s" {
		t.Fatalf("unexpected expect.timeout: %q", c0.Expect.Timeout)
	}
}

func TestLoadInvalid(t *testing.T) {
	tests := []struct {
		name    string
		yaml    string
		wantErr string
	}{
		{
			name:    "empty cases",
			yaml:    "cases: []\n",
			wantErr: "at least one case",
		},
		{
			name: "missing sql",
			yaml: `
cases:
  - name: no sql
    user: alice
    expect:
      decision: allow
`,
			wantErr: "sql is required",
		},
		{
			name: "invalid decision",
			yaml: `
cases:
  - name: bad decision
    user: alice
    sql: SELECT 1
    expect:
      decision: maybe
`,
			wantErr: "expect.decision",
		},
		{
			name: "unknown field rejected",
			yaml: `
cases:
  - name: typo
    user: alice
    sql: SELECT 1
    bogus_field: true
    expect:
      decision: allow
`,
			wantErr: "bogus_field",
		},
		{
			name: "negative max_rows",
			yaml: `
cases:
  - name: neg
    user: alice
    sql: SELECT 1
    max_rows: -5
    expect:
      decision: allow
`,
			wantErr: "max_rows",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			path := writeTempYAML(t, tc.yaml)
			_, err := Load(path)
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error %q does not contain %q", err.Error(), tc.wantErr)
			}
		})
	}

	if _, err := Load(filepath.Join(t.TempDir(), "does-not-exist.yaml")); err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestBuildPrincipal(t *testing.T) {
	t.Run("direct user", func(t *testing.T) {
		c := Case{User: "alice", Roles: []string{"analyst", "reader"}}
		p, err := BuildPrincipal(c)
		if err != nil {
			t.Fatalf("BuildPrincipal: %v", err)
		}
		if p.Name != "alice" || p.Method != auth.MethodBasic || p.Delegation || p.Identity != nil {
			t.Fatalf("unexpected principal: %+v", p)
		}
		if !slices.Equal(p.Roles, []string{"analyst", "reader"}) {
			t.Fatalf("unexpected roles: %v", p.Roles)
		}
	})

	t.Run("delegated identity", func(t *testing.T) {
		c := Case{
			Actor:      "bi-gateway",
			ActorAttrs: map[string]string{"tenant": "acme", "env": "prod"},
			Roles:      []string{"analyst"},
			Identity: map[string]any{
				"subject": "bob@acme.com",
				"kind":    "user",
				"region":  "us-east",
			},
		}
		p, err := BuildPrincipal(c)
		if err != nil {
			t.Fatalf("BuildPrincipal: %v", err)
		}
		if p.Name != "bob@acme.com" || p.Method != auth.MethodAPIKey || !p.Delegation {
			t.Fatalf("unexpected principal: %+v", p)
		}
		if p.Actor != "bi-gateway" || p.Attributes["tenant"] != "acme" {
			t.Fatalf("unexpected actor metadata: actor=%q attrs=%v", p.Actor, p.Attributes)
		}
		if p.Identity == nil || p.Identity.Subject != "bob@acme.com" || p.Identity.Kind != "user" {
			t.Fatalf("unexpected identity: %+v", p.Identity)
		}
		if p.Identity.Fields["region"] != "us-east" {
			t.Fatalf("missing custom identity field: %v", p.Identity.Fields)
		}
	})

	t.Run("missing subject", func(t *testing.T) {
		_, err := BuildPrincipal(Case{Actor: "svc", Identity: map[string]any{"region": "eu"}})
		if err == nil || !strings.Contains(err.Error(), "subject") {
			t.Fatalf("expected subject error, got %v", err)
		}
	})

	t.Run("non-string subject", func(t *testing.T) {
		_, err := BuildPrincipal(Case{Actor: "svc", Identity: map[string]any{"subject": 123}})
		if err == nil || !strings.Contains(err.Error(), "subject") {
			t.Fatalf("expected subject error, got %v", err)
		}
	})

	t.Run("reserved identity field", func(t *testing.T) {
		_, err := BuildPrincipal(Case{
			Actor:    "svc",
			Identity: map[string]any{"subject": "bob", "roles": []string{"admin"}},
		})
		if err == nil || !strings.Contains(err.Error(), "reserved") {
			t.Fatalf("expected reserved field error, got %v", err)
		}
	})
}

func int64Ptr(v int64) *int64 { return &v }

func TestRunAssertions(t *testing.T) {
	eval := func(_ context.Context, p *auth.Principal, sql, db string, maxRows int64) (DryRunResult, int, error) {
		switch sql {
		case "SELECT * FROM orders":
			return DryRunResult{
				Decision:   "allow",
				DecidedBy:  "policy",
				RowFilters: []string{"sales.main.orders", "sales.main.customers"},
				MaskedColumns: map[string][]string{
					"sales.main.orders": {"ssn", "email"},
				},
				MaxRows: 500,
				Limits:  map[string]any{"timeout": "1m0s", "max_rows": int64(500)},
			}, http.StatusOK, nil
		case "DROP TABLE orders":
			return DryRunResult{
				Decision:  "deny",
				DecidedBy: "policy",
			}, http.StatusOK, nil
		case "SELECT * FROM secret_view":
			return DryRunResult{
				Decision:  "deny",
				DecidedBy: "protection",
				Reason:    "table may be read indirectly",
			}, http.StatusOK, nil
		case "SELECT FROM":
			return DryRunResult{}, http.StatusBadRequest, nil
		case "EXPLODE":
			return DryRunResult{}, http.StatusInternalServerError, errors.New("opa failure")
		case "SELECT delegated":
			if p.Identity == nil || p.Actor != "bi" || p.Name != "carol" {
				return DryRunResult{Decision: "deny", DecidedBy: "policy"}, http.StatusOK, nil
			}
			return DryRunResult{Decision: "allow", DecidedBy: "policy"}, http.StatusOK, nil
		default:
			return DryRunResult{Decision: "allow", DecidedBy: "policy"}, http.StatusOK, nil
		}
	}

	suite := &Suite{
		Cases: []Case{
			{
				Name: "allow with filters masks and limits (order-independent)",
				User: "alice",
				SQL:  "SELECT * FROM orders",
				Expect: Expect{
					Decision:   "allow",
					DecidedBy:  "policy",
					RowFilters: []string{"sales.main.customers", "sales.main.orders"},
					MaskedColumns: map[string][]string{
						"sales.main.orders": {"email", "ssn"},
					},
					MaxRows: int64Ptr(500),
					Timeout: "60s", // equivalent to 1m0s
				},
			},
			{
				Name: "deny by policy",
				User: "alice",
				SQL:  "DROP TABLE orders",
				Expect: Expect{
					Decision:  "deny",
					DecidedBy: "policy",
				},
			},
			{
				Name: "deny by protection",
				User: "alice",
				SQL:  "SELECT * FROM secret_view",
				Expect: Expect{
					Decision:  "deny",
					DecidedBy: "protection",
				},
			},
			{
				Name: "syntax error (400)",
				User: "alice",
				SQL:  "SELECT FROM",
				Expect: Expect{
					Decision: "error",
				},
			},
			{
				Name:     "delegated principal passed to evaluator",
				Actor:    "bi",
				Identity: map[string]any{"subject": "carol"},
				SQL:      "SELECT delegated",
				Expect: Expect{
					Decision:  "allow",
					DecidedBy: "policy",
				},
			},
			{
				Name: "mismatched expectations report all failures",
				User: "alice",
				SQL:  "SELECT * FROM orders",
				Expect: Expect{
					Decision:   "deny",
					DecidedBy:  "engine",
					RowFilters: []string{}, // expects none
					MaskedColumns: map[string][]string{
						"sales.main.orders": {"email"},
					},
					MaxRows: int64Ptr(100),
					Timeout: "10s",
				},
			},
			{
				Name: "evaluator internal error fails case",
				User: "alice",
				SQL:  "EXPLODE",
				Expect: Expect{
					Decision: "error",
				},
			},
			{
				Name:     "invalid identity fails case",
				Actor:    "bi",
				Identity: map[string]any{},
				SQL:      "SELECT 1",
				Expect: Expect{
					Decision: "allow",
				},
			},
		},
	}

	results := Run(context.Background(), eval, suite)
	if len(results) != len(suite.Cases) {
		t.Fatalf("got %d results, want %d", len(results), len(suite.Cases))
	}

	for i := 0; i < 5; i++ {
		if !results[i].Passed {
			t.Errorf("case %q failed unexpectedly: %v", results[i].Name, results[i].Failures)
		}
	}

	// Case 5: all 6 assertions should fail.
	mismatch := results[5]
	if mismatch.Passed {
		t.Fatal("expected mismatch case to fail")
	}
	if len(mismatch.Failures) != 6 {
		t.Fatalf("expected 6 failures, got %d: %v", len(mismatch.Failures), mismatch.Failures)
	}

	// Case 6: evaluator error.
	if results[6].Passed || len(results[6].Failures) != 1 || !strings.Contains(results[6].Failures[0], "opa failure") {
		t.Fatalf("unexpected result for evaluator error: %+v", results[6])
	}

	// Case 7: invalid identity.
	if results[7].Passed || len(results[7].Failures) != 1 || !strings.Contains(results[7].Failures[0], "subject") {
		t.Fatalf("unexpected result for invalid identity: %+v", results[7])
	}
}
