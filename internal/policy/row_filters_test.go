package policy

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestPolicyRowFilters(t *testing.T) {
	for _, tc := range []struct {
		rule      string
		wantError bool
	}{
		{`row_filters := {"sales.main.orders":"id = 1"}`, false},
		{`row_filters := {"orders":"id = 1"}`, true},
		{`row_filters := {"sales.main.orders":false}`, true},
		{`row_filters := {"sales.main.orders":""}`, true},
		{`row_filters := "not an object"`, true},
		{`row_filters := {"sales.main.orders":"region = 'x') OR ('1'='1'"}`, true},
		{`row_filters := {"sales.main.orders":"id = 1; SELECT 1"}`, true},
	} {
		t.Run(tc.rule, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "policy.rego")
			os.WriteFile(path, []byte("package curral\nimport rego.v1\nallow := true\n"+tc.rule), 0600)
			p, err := LoadQueries(context.Background(), []string{path}, Queries{Allow: "data.curral.allow", Filters: "data.curral.row_filters"})
			if err != nil {
				t.Fatal(err)
			}
			filters, err := p.RowFilters(context.Background(), map[string]any{"user": "effective-user"})
			if (err != nil) != tc.wantError {
				t.Fatalf("filters=%v err=%v", filters, err)
			}
			if !tc.wantError && filters["sales.main.orders"] != "id = 1" {
				t.Fatal(filters)
			}
		})
	}
}
