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
