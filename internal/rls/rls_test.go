package rls

import (
	"os"
	"path/filepath"
	"testing"
)

func write(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "rls.yaml")
	os.WriteFile(p, []byte(body), 0o600)
	return p
}

func TestFilter(t *testing.T) {
	r, err := Load(write(t, `
tables:
  lake.analytics.Customers:
    rules:
      - roles: [north]
        where: "region = 'north'"
      - roles: [south]
        where: "region = 'south'"
      - users: ["ana@gmail.com", "*@corp.com"]
        where: "state = 'CA'"
`))
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		table, user string
		roles       []string
		want        string
		ok          bool
	}{
		{"lake.analytics.customers", "x", []string{"north"}, "(region = 'north')", true},
		{"LAKE.analytics.customers", "x", []string{"north", "south"}, "(region = 'north') OR (region = 'south')", true},
		{"lake.analytics.customers", "ANA@gmail.com", nil, "(state = 'CA')", true},
		{"lake.analytics.customers", "bob@corp.com", []string{"south"}, "(region = 'south') OR (state = 'CA')", true},
		{"lake.analytics.customers", "bob@corp.com.evil", []string{"other"}, "", false}, // no rule: not limited
		{"lake.analytics.other", "x", []string{"north"}, "", false},
	}
	for _, c := range cases {
		got, ok := r.Filter(c.table, c.user, c.roles)
		if got != c.want || ok != c.ok {
			t.Errorf("%s %s %v: got %q %v", c.table, c.user, c.roles, got, ok)
		}
	}
	var nilR *Rules
	if _, ok := nilR.Filter("a.b.c", "x", nil); ok {
		t.Error("nil rules filter")
	}
}

func TestLoadErrors(t *testing.T) {
	for name, body := range map[string]string{
		"unqualified":   "tables: {t: {rules: [{roles: [a], where: x}]}}",
		"no where":      "tables: {a.b.c: {rules: [{roles: [a]}]}}",
		"nobody":        "tables: {a.b.c: {rules: [{where: x}]}}",
		"bad user":      "tables: {a.b.c: {rules: [{users: ['a*b'], where: x}]}}",
		"unknown field": "tables: {a.b.c: {rules: [{roles: [a], where: x, oops: 1}]}}",
		"duplicate":     "tables: {a.b.c: {rules: []}, A.B.C: {rules: []}}",
	} {
		if _, err := Load(write(t, body)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
