package auth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jwt"
)

type fakeIdP struct {
	srv *httptest.Server
	key jwk.Key // private signing key
}

func newIdP(t *testing.T) *fakeIdP {
	t.Helper()
	raw, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	priv, _ := jwk.Import(raw)
	priv.Set(jwk.KeyIDKey, "k1")
	priv.Set(jwk.AlgorithmKey, jwa.RS256())
	pub, _ := priv.PublicKey()
	set := jwk.NewSet()
	set.AddKey(pub)

	idp := &fakeIdP{key: priv}
	mux := http.NewServeMux()
	idp.srv = httptest.NewServer(mux)
	t.Cleanup(idp.srv.Close)
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{"issuer": idp.srv.URL, "jwks_uri": idp.srv.URL + "/jwks"})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(set)
	})
	return idp
}

func (i *fakeIdP) token(t *testing.T, key jwk.Key, mutate func(jwt.Token)) string {
	t.Helper()
	tok, _ := jwt.NewBuilder().
		Issuer(i.srv.URL).Audience([]string{"curral"}).Subject("u-123").
		IssuedAt(time.Now()).Expiration(time.Now().Add(time.Hour)).Build()
	tok.Set("email", "ana@example.com")
	tok.Set("realm_access", map[string]any{"roles": []string{"analyst", "etl"}})
	if mutate != nil {
		mutate(tok)
	}
	b, err := jwt.Sign(tok, jwt.WithKey(jwa.RS256(), key))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestOIDC(t *testing.T) {
	idp := newIdP(t)
	o, err := NewOIDC(context.Background(), OIDCConfig{
		Issuer: idp.srv.URL, Audience: "curral", UserClaim: "email", RolesClaim: "realm_access.roles",
	})
	if err != nil {
		t.Fatal(err)
	}
	p, err := o.Authenticate(idp.token(t, idp.key, nil))
	if err != nil || p.Name != "ana@example.com" || p.Method != MethodJWT ||
		strings.Join(p.Roles, ",") != "analyst,etl" {
		t.Fatalf("valid token: %+v %v", p, err)
	}

	other, _ := rsa.GenerateKey(rand.Reader, 2048)
	otherKey, _ := jwk.Import(other)
	otherKey.Set(jwk.KeyIDKey, "k1") // same kid, different key
	bad := map[string]string{
		"wrong audience": idp.token(t, idp.key, func(tk jwt.Token) { tk.Set(jwt.AudienceKey, []string{"other"}) }),
		"wrong issuer":   idp.token(t, idp.key, func(tk jwt.Token) { tk.Set(jwt.IssuerKey, "https://evil") }),
		"expired":        idp.token(t, idp.key, func(tk jwt.Token) { tk.Set(jwt.ExpirationKey, time.Now().Add(-time.Hour)) }),
		"not yet valid":  idp.token(t, idp.key, func(tk jwt.Token) { tk.Set(jwt.NotBeforeKey, time.Now().Add(time.Hour)) }),
		"foreign key":    idp.token(t, otherKey, nil),
		"no user claim":  idp.token(t, idp.key, func(tk jwt.Token) { tk.Remove("email") }),
		"garbage":        "a.b.c",
	}
	// alg=none: unsigned header.payload.
	parts := strings.Split(idp.token(t, idp.key, nil), ".")
	bad["alg none"] = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0." + parts[1] + "."
	for name, tok := range bad {
		if p, err := o.Authenticate(tok); err == nil {
			t.Errorf("%s: accepted as %+v", name, p)
		}
	}
}

func TestOIDCDiscoveryErrors(t *testing.T) {
	idp := newIdP(t)
	if _, err := NewOIDC(context.Background(), OIDCConfig{Issuer: idp.srv.URL + "/other", Audience: "a"}); err == nil {
		t.Error("issuer mismatch / missing discovery must fail")
	}
	if _, err := NewOIDC(context.Background(), OIDCConfig{Issuer: idp.srv.URL}); err == nil {
		t.Error("missing audience must fail")
	}
}

func TestOIDCEmailVerifiedAndHostedDomain(t *testing.T) {
	idp := newIdP(t)
	o, err := NewOIDC(context.Background(), OIDCConfig{
		Issuer: idp.srv.URL, Audience: "curral", UserClaim: "email",
		RequireEmailVerified: true, HostedDomains: []string{"corp.com"},
	})
	if err != nil {
		t.Fatal(err)
	}
	tok := func(verified any, hd string) string {
		return idp.token(t, idp.key, func(tk jwt.Token) {
			if verified != nil {
				tk.Set("email_verified", verified)
			}
			if hd != "" {
				tk.Set("hd", hd)
			}
		})
	}
	ok := []string{tok(true, "corp.com"), tok("true", "CORP.com")}
	for i, tk := range ok {
		if _, err := o.Authenticate(tk); err != nil {
			t.Errorf("ok[%d]: %v", i, err)
		}
	}
	bad := map[string]string{
		"not verified":      tok(false, "corp.com"),
		"no verified":       tok(nil, "corp.com"),
		"verified string":   tok("false", "corp.com"),
		"other domain":      tok(true, "evil.com"),
		"no domain (gmail)": tok(true, ""),
	}
	for name, tk := range bad {
		if _, err := o.Authenticate(tk); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestOIDCRolePrefix(t *testing.T) {
	idp := newIdP(t)
	o, err := NewOIDC(context.Background(), OIDCConfig{
		Issuer: idp.srv.URL, Audience: "curral", UserClaim: "email",
		RolesClaim: "realm_access.roles", RolePrefix: "corp:",
	})
	if err != nil {
		t.Fatal(err)
	}
	p, err := o.Authenticate(idp.token(t, idp.key, nil))
	if err != nil || strings.Join(p.Roles, ",") != "corp:analyst,corp:etl" {
		t.Fatalf("array roles with prefix: %+v %v", p, err)
	}

	// Space-separated string roles claim (e.g. scope).
	o2, err := NewOIDC(context.Background(), OIDCConfig{
		Issuer: idp.srv.URL, Audience: "curral", UserClaim: "sub",
		RolesClaim: "scope", RolePrefix: "gh:",
	})
	if err != nil {
		t.Fatal(err)
	}
	tok := idp.token(t, idp.key, func(tk jwt.Token) { tk.Set("scope", "deploy read") })
	p2, err := o2.Authenticate(tok)
	if err != nil || strings.Join(p2.Roles, ",") != "gh:deploy,gh:read" {
		t.Fatalf("string roles with prefix: %+v %v", p2, err)
	}
}

func TestMultiOIDC(t *testing.T) {
	idpA := newIdP(t)
	idpB := newIdP(t)

	multi, err := NewMultiOIDC(context.Background(), []OIDCConfig{
		{
			Issuer:     idpA.srv.URL,
			Audience:   "curral-a",
			UserClaim:  "email",
			RolesClaim: "realm_access.roles",
			RolePrefix: "corp:",
		},
		{
			Issuer:     idpB.srv.URL,
			Audience:   "curral-b",
			UserClaim:  "sub",
			RolesClaim: "scope",
			RolePrefix: "gh:",
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	// Valid token from IdP A.
	tokA := idpA.token(t, idpA.key, func(tk jwt.Token) {
		tk.Set(jwt.AudienceKey, []string{"curral-a"})
	})
	pA, err := multi.Authenticate(tokA)
	if err != nil || pA.Name != "ana@example.com" || pA.Method != MethodJWT ||
		strings.Join(pA.Roles, ",") != "corp:analyst,corp:etl" {
		t.Fatalf("IdP A valid token: %+v %v", pA, err)
	}

	// Valid token from IdP B.
	tokB := idpB.token(t, idpB.key, func(tk jwt.Token) {
		tk.Set(jwt.AudienceKey, []string{"curral-b"})
		tk.Set(jwt.SubjectKey, "repo:org/app:ref:refs/heads/main")
		tk.Set("scope", "deploy")
	})
	pB, err := multi.Authenticate(tokB)
	if err != nil || pB.Name != "repo:org/app:ref:refs/heads/main" || pB.Method != MethodJWT ||
		strings.Join(pB.Roles, ",") != "gh:deploy" {
		t.Fatalf("IdP B valid token: %+v %v", pB, err)
	}

	// Cross-issuer key confusion: token signed with IdP A's private key claiming iss: IdP B MUST be rejected.
	confused := idpB.token(t, idpA.key, func(tk jwt.Token) {
		tk.Set(jwt.IssuerKey, idpB.srv.URL)
		tk.Set(jwt.AudienceKey, []string{"curral-b"})
	})
	if p, err := multi.Authenticate(confused); err == nil {
		t.Fatalf("cross-issuer key confusion accepted as %+v", p)
	}

	// Unknown issuer MUST be rejected.
	unknown := idpA.token(t, idpA.key, func(tk jwt.Token) {
		tk.Set(jwt.IssuerKey, "https://unknown.example.com")
	})
	if p, err := multi.Authenticate(unknown); err == nil {
		t.Fatalf("unknown issuer accepted as %+v", p)
	}

	// Token missing iss claim MUST be rejected.
	noIss := idpA.token(t, idpA.key, func(tk jwt.Token) {
		tk.Remove(jwt.IssuerKey)
	})
	if p, err := multi.Authenticate(noIss); err == nil {
		t.Fatalf("missing iss accepted as %+v", p)
	}

	// Malformed / non-JWT tokens MUST be rejected.
	for _, bad := range []string{"", "not-a-jwt", "a.b", "a.!!!.c", "a.e30.c", ".."} {
		if p, err := multi.Authenticate(bad); err == nil {
			t.Errorf("malformed %q accepted as %+v", bad, p)
		}
	}
}

func TestNewMultiOIDCErrors(t *testing.T) {
	idp := newIdP(t)
	if _, err := NewMultiOIDC(context.Background(), nil); err == nil {
		t.Error("empty providers must fail")
	}
	if _, err := NewMultiOIDC(context.Background(), []OIDCConfig{
		{Issuer: idp.srv.URL, Audience: "a"},
		{Issuer: idp.srv.URL, Audience: "b"},
	}); err == nil {
		t.Error("duplicate issuer must fail")
	}
	if _, err := NewMultiOIDC(context.Background(), []OIDCConfig{
		{Issuer: "", Audience: "a"},
	}); err == nil {
		t.Error("missing issuer must fail")
	}
}
