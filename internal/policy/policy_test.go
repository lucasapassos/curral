package policy

import (
	"context"
	"testing"
)

func load(t testing.TB) *Policy {
	t.Helper()
	p, err := Load(context.Background(), "data.curral.allow",
		[]string{"../../examples/policy.rego", "../../examples/roles.json"})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func input(roles []string, typ string, tables, targets []string, resolved bool, funcs ...string) map[string]any {
	if funcs == nil {
		funcs = []string{}
	}
	return map[string]any{
		"user": "u", "roles": roles, "statement_type": typ,
		"tables": tables, "targets": targets, "functions": funcs, "resolved": resolved,
	}
}

func TestExamplePolicy(t *testing.T) {
	p := load(t)
	none := []string{}
	cases := []struct {
		name string
		in   map[string]any
		want bool
	}{
		{"admin anything", input([]string{"admin"}, "DROP", none, []string{"sales.main.orders"}, false), true},
		{"analyst select", input([]string{"analyst"}, "SELECT", []string{"sales.main.orders", "logs.main.events"}, none, true), true},
		{"analyst constant select", input([]string{"analyst"}, "SELECT", none, none, true), true},
		{"analyst denied table", input([]string{"analyst"}, "SELECT", []string{"sales.main.salaries"}, none, true), false},
		{"analyst unknown db", input([]string{"analyst"}, "SELECT", []string{"lake.ns.t"}, none, true), false},
		{"analyst unresolved", input([]string{"analyst"}, "SELECT", []string{"sales.main.orders"}, none, false), false},
		{"analyst insert", input([]string{"analyst"}, "INSERT", none, []string{"sales.main.orders"}, true), false},
		{"etl insert", input([]string{"etl"}, "INSERT", []string{"logs.main.events"}, []string{"sales.main.orders"}, true), true},
		{"etl insert other db", input([]string{"etl"}, "INSERT", none, []string{"logs.main.events"}, true), false},
		{"etl create", input([]string{"etl"}, "CREATE", none, []string{"sales.main.x"}, true), false},
		{"no roles", input([]string{}, "SELECT", none, none, true), false},
		{"unknown role", input([]string{"ghost"}, "SELECT", none, none, true), false},
		{"analyst allowed function", input([]string{"analyst"}, "SELECT", none, none, true, "range"), true},
		{"analyst file function", input([]string{"analyst"}, "SELECT", none, none, true, "read_parquet"), false},
		{"etl insert from file", input([]string{"etl"}, "INSERT", none, []string{"sales.main.orders"}, true, "read_csv"), false},
	}
	for _, c := range cases {
		got, err := p.Allow(context.Background(), c.in)
		if err != nil {
			t.Fatal(err)
		}
		if got != c.want {
			t.Errorf("%s: got %v", c.name, got)
		}
	}
}

func TestPolicyHash(t *testing.T) {
	a, b := load(t), load(t)
	if len(a.SHA256) != 64 || a.SHA256 != b.SHA256 {
		t.Fatalf("hash %q vs %q", a.SHA256, b.SHA256)
	}
	c, err := Load(context.Background(), "data.curral.allow", []string{"../../examples/policy.rego", "../../examples/roles.r2.json"})
	if err != nil {
		t.Fatal(err)
	}
	if c.SHA256 == a.SHA256 {
		t.Fatal("different data files must hash differently")
	}
}

func TestLoadErrors(t *testing.T) {
	if _, err := Load(context.Background(), "data.curral.allow", nil); err == nil {
		t.Fatal("expected error without files")
	}
	if _, err := Load(context.Background(), "data.curral.allow", []string{"missing.rego"}); err == nil {
		t.Fatal("expected error for missing file")
	}
}

func BenchmarkAllow(b *testing.B) {
	p := load(b)
	in := input([]string{"analyst"}, "SELECT", []string{"sales.main.orders", "logs.main.events"}, []string{}, true)
	for b.Loop() {
		if ok, _ := p.Allow(context.Background(), in); !ok {
			b.Fatal("denied")
		}
	}
}
