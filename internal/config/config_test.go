package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestExpandEnv(t *testing.T) {
	t.Setenv("CURRAL_T_KEY", "s3cr'et")
	got, err := ExpandEnv("k=${CURRAL_T_KEY} r=${CURRAL_T_MISSING:-us-east-1}")
	if err != nil || got != "k=s3cr'et r=us-east-1" {
		t.Fatalf("got %q, %v", got, err)
	}
	if _, err := ExpandEnv("${CURRAL_T_MISSING}"); err == nil || !strings.Contains(err.Error(), "CURRAL_T_MISSING") {
		t.Fatalf("missing var: %v", err)
	}
}

func writeFile(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "f.yaml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadCatalog(t *testing.T) {
	t.Setenv("CURRAL_T_SECRET", "abc")
	c, err := LoadCatalog(writeFile(t, `
extensions: [httpfs]
secrets:
  - name: s
    type: s3
    params: { SECRET: "${CURRAL_T_SECRET}", SCOPE: ["s3://a", "s3://b"] }
databases:
  - name: lake
    path: wh
    options: { TYPE: iceberg, READ_ONLY: true }
`))
	if err != nil {
		t.Fatal(err)
	}
	if len(c.EnvRefs) != 1 || c.EnvRefs[0] != "CURRAL_T_SECRET" {
		t.Fatalf("env refs = %v", c.EnvRefs)
	}
	if c.Default != "lake" || c.Secrets[0].Params["SECRET"] != "abc" {
		t.Fatalf("%+v", c)
	}
	if c.Databases[0].Type() != "iceberg" || !c.Databases[0].ReadOnly() {
		t.Fatal("type/read_only not detected")
	}

	bad := map[string]string{
		"no databases":    `databases: []`,
		"bad ident":       "databases: [{name: \"x; DROP\", path: p}]",
		"bad option key":  "databases: [{name: x, path: p, options: {\"A B\": 1}}]",
		"unknown field":   "databases: [{name: x, path: p, oops: 1}]",
		"missing env":     "databases: [{name: x, path: \"${CURRAL_T_NOPE}\"}]",
		"unknown default": "databases: [{name: x, path: p}]\ndefault: y",
		"duplicate":       "databases: [{name: x, path: p}, {name: X, path: q}]",
		"bad cache_ttl":   "databases: [{name: x, path: p, cache_ttl: soon}]",
		"cache non-ice":   "databases: [{name: x, path: p, cache_ttl: 30s}]",
	}
	for name, body := range bad {
		if _, err := LoadCatalog(writeFile(t, body)); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}

func TestIdentities(t *testing.T) {
	cases := []struct {
		match, user string
		want        bool
	}{
		{"ana@gmail.com", "ana@gmail.com", true},
		{"ana@gmail.com", "ANA@Gmail.com", true},
		{"ana@gmail.com", "ana@gmail.com.evil", false},
		{"*@example.com", "bia@example.com", true},
		{"*@Example.com", "BIA@EXAMPLE.COM", true},
		{"*@example.com", "bia@sub.example.com", false},
		{"*@example.com", "bia@example.com.evil", false},
		{"*@example.com", "example.com", false},
		{"*@example.com", "@example.com", false},
	}
	for _, c := range cases {
		if got := (Identity{Match: c.match}).Matches(c.user); got != c.want {
			t.Errorf("%q vs %q: got %v", c.match, c.user, got)
		}
	}
	for _, body := range []string{
		"identities: [{match: \"\", roles: [a]}]",
		"identities: [{match: \"*\", roles: [a]}]",
		"identities: [{match: \"a*@x.com\", roles: [a]}]",
		"identities: [{match: \"*@\", roles: [a]}]",
		"identities: [{match: \"a@x.com\"}]",
	} {
		if _, err := LoadUsers(writeFile(t, body)); err == nil {
			t.Errorf("%s: expected error", body)
		}
	}
	u, err := LoadUsers(writeFile(t, "identities: [{match: \"*@x.com\", roles: [analyst]}]"))
	if err != nil || len(u.Identities) != 1 {
		t.Fatalf("%+v %v", u, err)
	}
}
