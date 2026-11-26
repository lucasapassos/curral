package main

import (
	"slices"
	"strings"
	"testing"

	"github.com/lucasapassos/curral/internal/server"
)

func TestParseFlagsDocsScope(t *testing.T) {
	base := []string{"--catalog", "c.yaml", "--users", "u.yaml", "--policy", "p.rego"}
	f, err := parseFlags(base)
	if err != nil || f.docsScope != server.DocsScopeAll {
		t.Fatalf("default: %+v %v", f, err)
	}
	if _, err := parseFlags(slices.Concat(base, []string{"--docs-scope", "bogus"})); err == nil || !strings.Contains(err.Error(), "--docs-scope must be") {
		t.Fatalf("bogus scope: %v", err)
	}
	if _, err := parseFlags(slices.Concat(base, []string{"--docs-scope", "schema"})); err == nil || !strings.Contains(err.Error(), "needs --docs-dir") {
		t.Fatalf("scope without docs: %v", err)
	}
	if f, err := parseFlags(slices.Concat(base, []string{"--docs-scope", "schema", "--docs-dir", "docs"})); err != nil || f.docsScope != server.DocsScopeSchema {
		t.Fatalf("scope with docs: %+v %v", f, err)
	}
	if f, err := parseFlags(base); err != nil || f.docsNames != server.DocsNamesOff {
		t.Fatalf("default names: %+v %v", f, err)
	}
	if _, err := parseFlags(slices.Concat(base, []string{"--docs-validate-names", "bogus"})); err == nil || !strings.Contains(err.Error(), "--docs-validate-names must be") {
		t.Fatalf("bogus names: %v", err)
	}
	if _, err := parseFlags(slices.Concat(base, []string{"--docs-validate-names", "strict"})); err == nil || !strings.Contains(err.Error(), "needs --docs-dir") {
		t.Fatalf("names without docs: %v", err)
	}
	if f, err := parseFlags(slices.Concat(base, []string{"--docs-validate-names", "warn", "--docs-dir", "docs"})); err != nil || f.docsNames != server.DocsNamesWarn {
		t.Fatalf("names with docs: %+v %v", f, err)
	}
	if _, err := parseFlags(nil); err == nil || !strings.Contains(err.Error(), "missing required flags: --catalog, --users, --policy") {
		t.Fatalf("no flags: %v", err)
	}
	if _, err := parseFlags(slices.Concat(base, []string{"--tls-cert", "c.pem"})); err == nil || !strings.Contains(err.Error(), "go together") {
		t.Fatalf("tls cert alone: %v", err)
	}
	if _, err := parseFlags(slices.Concat(base, []string{"--jev-threshold", "2"})); err == nil || !strings.Contains(err.Error(), "--jev-threshold must be") {
		t.Fatalf("jev threshold: %v", err)
	}
	if f, err := parseFlags(slices.Concat(base, []string{"--row-filters-missing", "warn"})); err != nil || f.rowFiltersMissing != "warn" {
		t.Fatalf("row-filters-missing warn: %+v %v", f, err)
	}
	if _, err := parseFlags(slices.Concat(base, []string{"--row-filters-missing", "bogus"})); err == nil || !strings.Contains(err.Error(), "--row-filters-missing must be") {
		t.Fatalf("row-filters-missing bogus: %v", err)
	}
	if _, err := parseFlags(slices.Concat(base, []string{"--docs-validate-sql", "bogus"})); err == nil || !strings.Contains(err.Error(), "--docs-validate-sql must be") {
		t.Fatalf("docs-validate-sql bogus: %v", err)
	}
	if _, err := parseFlags(slices.Concat(base, []string{"--docs-validate-sql", "strict"})); err == nil || !strings.Contains(err.Error(), "needs --docs-dir") {
		t.Fatalf("docs-validate-sql without docs: %v", err)
	}
	if f, err := parseFlags(slices.Concat(base, []string{"--docs-validate-sql", "strict", "--docs-dir", "docs", "--mask-salt", "s3cr3t", "--mcp", "--policy-tests", "tests.yaml", "--oidc-providers", "oidc.yaml"})); err != nil ||
		f.docsSQL != server.DocsSQLStrict || f.maskSalt != "s3cr3t" || !f.mcpEnabled || f.policyTests != "tests.yaml" || f.oidcProviders != "oidc.yaml" {
		t.Fatalf("new flags: %+v %v", f, err)
	}
	if _, err := parseFlags(slices.Concat(base, []string{"--oidc-providers", "oidc.yaml", "--oidc-issuer", "https://accounts.google.com"})); err == nil || !strings.Contains(err.Error(), "mutually exclusive") {
		t.Fatalf("oidc-providers + oidc-issuer: %v", err)
	}
}
