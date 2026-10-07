package auth

import (
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
