package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"strconv"
	"strings"
	"time"
)

// SessionPrefix marks session tokens, telling them apart from API keys and
// JWTs.
const SessionPrefix = "curral-session."

// Sessions issues bearer tokens standing for a successful Basic login, so a
// client that keeps a connection open (Flight SQL) checks its password once
// instead of on every call. A token carries its user, its expiry and a
// fingerprint of the user's password hash, signed (HMAC-SHA256) with a key
// that only lives in memory: a restart, a changed password or a removed user
// (after a reload) voids it, and the roles always come from the users file
// in effect.
type Sessions struct {
	key [32]byte
	ttl time.Duration
}

// NewSessions returns an issuer of tokens valid for ttl.
func NewSessions(ttl time.Duration) *Sessions {
	s := &Sessions{ttl: ttl}
	rand.Read(s.key[:])
	return s
}

// Issue returns a token for p, a principal a.Authenticate just returned; ok
// is false for principals that did not log in with a password.
func (s *Sessions) Issue(a *Authenticator, p *Principal) (token string, ok bool) {
	u, found := a.users[p.Name]
	if !found || p.Method != MethodBasic {
		return "", false
	}
	payload := strings.Join([]string{u.Name, strconv.FormatInt(time.Now().Add(s.ttl).Unix(), 10), fingerprint(u.PasswordHash)}, "\x00")
	enc := base64.RawURLEncoding
	return SessionPrefix + enc.EncodeToString([]byte(payload)) + "." + enc.EncodeToString(s.mac(payload)), true
}

// Check returns the principal of a valid token, with its current roles from
// a, or nil.
func (s *Sessions) Check(a *Authenticator, token string) *Principal {
	rest, ok := strings.CutPrefix(token, SessionPrefix)
	if !ok {
		return nil
	}
	encPayload, encSig, ok := strings.Cut(rest, ".")
	if !ok {
		return nil
	}
	enc := base64.RawURLEncoding
	payload, err := enc.DecodeString(encPayload)
	if err != nil {
		return nil
	}
	sig, err := enc.DecodeString(encSig)
	if err != nil || !hmac.Equal(sig, s.mac(string(payload))) {
		return nil
	}
	parts := strings.Split(string(payload), "\x00")
	if len(parts) != 3 {
		return nil
	}
	exp, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil || time.Now().Unix() >= exp {
		return nil
	}
	u, found := a.users[parts[0]]
	if !found || fingerprint(u.PasswordHash) != parts[2] {
		return nil
	}
	return &Principal{Name: u.Name, Roles: u.Roles, Method: MethodBasic}
}

func (s *Sessions) mac(payload string) []byte {
	m := hmac.New(sha256.New, s.key[:])
	m.Write([]byte(payload))
	return m.Sum(nil)
}

// fingerprint identifies a password hash without revealing it.
func fingerprint(hash string) string {
	sum := sha256.Sum256([]byte(hash))
	return hex.EncodeToString(sum[:8])
}
