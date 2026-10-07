package auth

import (
	"strings"
	"testing"
	"time"

	"curral/internal/config"
)

func TestAuthenticate(t *testing.T) {
	h, err := Hash("pw")
	if err != nil {
		t.Fatal(err)
	}
	a := New(&config.Users{Users: []config.User{{Name: "u", PasswordHash: h, Roles: []string{"r"}}}}, time.Minute)

	if p := a.Authenticate("u", "pw"); p == nil || p.Roles[0] != "r" {
		t.Fatalf("valid credentials rejected: %v", p)
	}
	start := time.Now()
	if a.Authenticate("u", "pw") == nil || time.Since(start) > 5*time.Millisecond {
		t.Fatal("second check should hit the cache")
	}
	if a.Authenticate("u", "wrong") != nil || a.Authenticate("ghost", "pw") != nil || a.Authenticate("", "") != nil {
		t.Fatal("invalid credentials accepted")
	}
}

func TestAPIKeys(t *testing.T) {
	key, hash, err := NewAPIKey()
	if err != nil || !strings.HasPrefix(key, APIKeyPrefix) || len(hash) != 64 {
		t.Fatalf("%q %q %v", key, hash, err)
	}
	oldKey, oldHash, _ := NewAPIKey()
	a := New(&config.Users{APIKeys: []config.APIKey{
		{Name: "etl-job", KeyHash: strings.ToUpper(hash), Roles: []string{"etl"}},
		{Name: "old-job", KeyHash: oldHash, Expires: "2020-01-01"},
	}}, time.Minute)
	if p := a.AuthenticateAPIKey(key); p == nil || p.Name != "etl-job" || p.Method != MethodAPIKey || p.Roles[0] != "etl" {
		t.Fatalf("valid key: %+v", p)
	}
	for name, k := range map[string]string{
		"expired": oldKey, "unknown": APIKeyPrefix + "AAAA", "no prefix": strings.TrimPrefix(key, APIKeyPrefix), "empty": "",
	} {
		if a.AuthenticateAPIKey(k) != nil {
			t.Errorf("%s key accepted", name)
		}
	}
}

func TestMapIdentity(t *testing.T) {
	a := New(&config.Users{Identities: []config.Identity{
		{Match: "ana@gmail.com", Roles: []string{"analyst"}},
		{Match: "*@corp.com", Roles: []string{"analyst", "etl"}},
	}}, 0)
	in := &Principal{Name: "ana@gmail.com", Roles: []string{"from-token"}, Method: MethodJWT}
	out := a.MapIdentity(in)
	if strings.Join(out.Roles, ",") != "from-token,analyst" || len(in.Roles) != 1 {
		t.Fatalf("out=%v in=%v", out.Roles, in.Roles)
	}
	if got := a.MapIdentity(&Principal{Name: "bob@corp.com", Roles: []string{"analyst"}}).Roles; strings.Join(got, ",") != "analyst,etl" {
		t.Fatalf("dedupe: %v", got)
	}
	if got := a.MapIdentity(&Principal{Name: "eve@gmail.com"}).Roles; len(got) != 0 {
		t.Fatalf("unmapped user got roles %v", got)
	}
}
