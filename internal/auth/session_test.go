package auth

import (
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"github.com/lucasapassos/curral/internal/config"
)

func TestSessions(t *testing.T) {
	h1, _ := Hash("pw1")
	h2, _ := Hash("pw2")
	users := func(hash string, roles ...string) *Authenticator {
		return New(&config.Users{Users: []config.User{{Name: "u", PasswordHash: hash, Roles: roles}}}, 0)
	}
	a := users(h1, "r1")
	s := NewSessions(time.Hour)
	tok, ok := s.Issue(a, a.Authenticate("u", "pw1"))
	if !ok || !strings.HasPrefix(tok, SessionPrefix) {
		t.Fatalf("issue: %q %v", tok, ok)
	}
	if p := s.Check(a, tok); p == nil || p.Name != "u" || p.Method != MethodBasic {
		t.Fatalf("check: %+v", p)
	}
	// Roles come from the users file in effect, not from the token.
	if p := s.Check(users(h1, "r2"), tok); p == nil || len(p.Roles) != 1 || p.Roles[0] != "r2" {
		t.Fatalf("roles after reload: %+v", p)
	}
	if p := s.Check(users(h2, "r1"), tok); p != nil {
		t.Fatal("token survived a password change")
	}
	if p := s.Check(New(&config.Users{}, 0), tok); p != nil {
		t.Fatal("token survived the user's removal")
	}
	if p := NewSessions(time.Hour).Check(a, tok); p != nil {
		t.Fatal("token accepted with another key (restart)")
	}
	// Tampering with the payload (another user, a later expiry) breaks the
	// signature.
	payload, sig, _ := strings.Cut(strings.TrimPrefix(tok, SessionPrefix), ".")
	raw, _ := base64.RawURLEncoding.DecodeString(payload)
	parts := strings.Split(string(raw), "\x00")
	parts[1] += "0" // ten times later
	forged := base64.RawURLEncoding.EncodeToString([]byte(strings.Join(parts, "\x00")))
	if p := s.Check(a, SessionPrefix+forged+"."+sig); p != nil {
		t.Fatal("tampered token accepted")
	}
	expired, _ := (&Sessions{key: s.key, ttl: -time.Second}).Issue(a, a.Authenticate("u", "pw1"))
	if p := s.Check(a, expired); p != nil {
		t.Fatal("expired token accepted")
	}
	// Only password logins get a session.
	if _, ok := s.Issue(a, &Principal{Name: "u", Method: MethodAPIKey}); ok {
		t.Fatal("session issued for an api key")
	}
}
