package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
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

func TestAPIKeyDelegation(t *testing.T) {
	key := "api_keys: [{name: portal, key_sha256: " + strings.Repeat("a", 64) + ", delegation: true, attributes: %s}]"
	for _, attrs := range []string{"{\"bad-name\": x}", "{tenant: \"a\\nb\"}", "{tenant: \"" + strings.Repeat("x", 257) + "\"}"} {
		if _, err := LoadUsers(writeFile(t, fmt.Sprintf(key, attrs))); err == nil {
			t.Errorf("%s: expected error", attrs)
		}
	}
	u, err := LoadUsers(writeFile(t, fmt.Sprintf(key, "{tenant: tenant-a}")))
	if err != nil || !u.APIKeys[0].Delegation || u.APIKeys[0].Attributes["tenant"] != "tenant-a" {
		t.Fatalf("%+v %v", u, err)
	}
	hash := strings.Repeat("a", 64)
	for _, body := range []string{
		"users: [{name: a}]",
		"users: [{name: a, password_hash: x}, {name: a, password_hash: x}]",
		"api_keys: [{name: x, key_sha256: short}]",
		"api_keys: [{name: x, key_sha256: " + hash + "}, {name: x, key_sha256: " + hash + "}]",
		"users: [{name: x, password_hash: h}]\napi_keys: [{name: x, key_sha256: " + hash + "}]",
		"api_keys: [{name: x, key_sha256: " + hash + ", expires: nope}]",
	} {
		if _, err := LoadUsers(writeFile(t, body)); err == nil {
			t.Errorf("%s: expected error", body)
		}
	}
	if _, err := LoadUsers(filepath.Join(t.TempDir(), "missing.yaml")); err == nil {
		t.Error("missing file: expected error")
	}
	// docs_write only means something on a delegating key.
	writer := "api_keys: [{name: portal, key_sha256: " + strings.Repeat("a", 64) + ", docs_write: true%s}]"
	if _, err := LoadUsers(writeFile(t, fmt.Sprintf(writer, ""))); err == nil || !strings.Contains(err.Error(), "docs_write needs delegation") {
		t.Errorf("docs_write without delegation: %v", err)
	}
	u, err = LoadUsers(writeFile(t, fmt.Sprintf(writer, ", delegation: true")))
	if err != nil || !u.APIKeys[0].DocsWrite {
		t.Fatalf("%+v %v", u, err)
	}
}

func TestStandaloneExpr(t *testing.T) {
	for s, want := range map[string]bool{
		"region = 'north'":                   true,
		"id IN (1, (2))":                     true,
		"name = 'it''s (open'":               true,
		`"we(ird" = 1`:                       true,
		`regexp_replace(x, '\d', '*') <> ''`: true,
		`x = E'\'' AND (y)`:                  true,
		"region = 'x') OR ('1'='1'":          false,
		"1=1) OR (1=1":                       false,
		"(1=1":                               false,
		"a = 1; DROP TABLE t":                false,
		"a = 1 -- )":                         false,
		"a = 1 /* ) */":                      false,
		"a = $$x$$":                          false,
		"a = 'unterminated":                  false,
		`x = E'\') OR (true'`:                true,
		`x = E'\'') OR (true`:                false,
		"json_extract_string(getvariable('curral_identity'), '$.page.slug') = 'x'": true,
	} {
		if got := StandaloneExpr(s); got != want {
			t.Errorf("%q: got %v, want %v", s, got, want)
		}
	}
}

func TestLoadOIDCProviders(t *testing.T) {
	ps, err := LoadOIDCProviders(writeFile(t, `
providers:
  - issuer: https://accounts.google.com
    audience: client-1
    user_claim: email
    roles_claim: groups
    role_prefix: "corp:"
    skew: 45s
    require_email_verified: true
    hosted_domains: [example.com]
  - issuer: https://token.actions.githubusercontent.com
    audience: curral
    user_claim: sub
    roles_claim: job_workflow_ref
    role_prefix: "gh:"
`))
	if err != nil {
		t.Fatal(err)
	}
	if len(ps) != 2 {
		t.Fatalf("got %d providers, want 2", len(ps))
	}
	if ps[0].Issuer != "https://accounts.google.com" || ps[0].Audience != "client-1" ||
		ps[0].UserClaim != "email" || ps[0].RolesClaim != "groups" || ps[0].RolePrefix != "corp:" ||
		ps[0].Skew != 45*time.Second || !ps[0].RequireEmailVerified ||
		len(ps[0].HostedDomains) != 1 || ps[0].HostedDomains[0] != "example.com" {
		t.Fatalf("unexpected provider[0]: %+v", ps[0])
	}
	if ps[1].Issuer != "https://token.actions.githubusercontent.com" || ps[1].RolePrefix != "gh:" {
		t.Fatalf("unexpected provider[1]: %+v", ps[1])
	}

	bad := map[string]string{
		"empty list":    `providers: []`,
		"missing iss":   `providers: [{audience: curral}]`,
		"missing aud":   `providers: [{issuer: https://a}]`,
		"duplicate iss": `providers: [{issuer: https://a, audience: x}, {issuer: https://a, audience: y}]`,
		"unknown field": `providers: [{issuer: https://a, audience: x, typo: 1}]`,
		"negative skew": `providers: [{issuer: https://a, audience: x, skew: -5s}]`,
	}
	for name, body := range bad {
		if _, err := LoadOIDCProviders(writeFile(t, body)); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
	if _, err := LoadOIDCProviders(filepath.Join(t.TempDir(), "missing.yaml")); err == nil {
		t.Error("missing file: expected error")
	}
}
