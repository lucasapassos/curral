// Package auth authenticates requests: local users (Basic), API keys and
// OIDC-issued JWTs.
package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/hex"
	"runtime"
	"slices"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"

	"curral/internal/config"
)

// Principal is an authenticated user or service.
type Principal struct {
	Name   string
	Roles  []string
	Method string // basic, api_key, jwt
}

// Authentication methods.
const (
	MethodBasic  = "basic"
	MethodAPIKey = "api_key"
	MethodJWT    = "jwt"
)

// APIKeyPrefix marks curral API keys, telling them apart from JWTs.
const APIKeyPrefix = "curral_"

type cacheEntry struct {
	p       *Principal
	expires time.Time
}

// Authenticator checks bcrypt hashes and caches successful verifications so
// repeated requests do not pay bcrypt's cost (tens of ms) every time.
type Authenticator struct {
	users map[string]config.User
	keys  map[[32]byte]apiKey
	ids   []config.Identity
	// bcrypt is deliberately slow; bound how many run at once so a flood of
	// wrong passwords cannot take every CPU.
	bcryptSlots chan struct{}
	ttl         time.Duration
	cache       sync.Map // [32]byte -> cacheEntry
	dummy       []byte
}

func New(users *config.Users, ttl time.Duration) *Authenticator {
	a := &Authenticator{users: map[string]config.User{}, keys: map[[32]byte]apiKey{}, ids: users.Identities, ttl: ttl,
		bcryptSlots: make(chan struct{}, runtime.NumCPU())}
	for _, u := range users.Users {
		a.users[u.Name] = u
	}
	for _, k := range users.APIKeys {
		var h [32]byte
		hex.Decode(h[:], []byte(strings.ToLower(k.KeyHash)))
		exp, _ := k.ExpiresAt()
		a.keys[h] = apiKey{p: &Principal{Name: k.Name, Roles: k.Roles, Method: MethodAPIKey}, expires: exp}
	}
	// Unknown users still pay one bcrypt so timing does not reveal them.
	a.dummy, _ = bcrypt.GenerateFromPassword([]byte("curral-dummy"), bcrypt.DefaultCost)
	return a
}

// Authenticate returns the principal, or nil if the credentials are wrong.
func (a *Authenticator) Authenticate(user, pass string) *Principal {
	key := cacheKey(user, pass)
	if v, ok := a.cache.Load(key); ok {
		e := v.(cacheEntry)
		if time.Now().Before(e.expires) {
			return e.p
		}
		a.cache.Delete(key)
	}

	a.bcryptSlots <- struct{}{}
	defer func() { <-a.bcryptSlots }()
	u, ok := a.users[user]
	if !ok {
		_ = bcrypt.CompareHashAndPassword(a.dummy, []byte(pass))
		return nil
	}
	if bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(pass)) != nil {
		return nil
	}
	p := &Principal{Name: u.Name, Roles: u.Roles, Method: MethodBasic}
	if a.ttl > 0 {
		a.cache.Store(key, cacheEntry{p: p, expires: time.Now().Add(a.ttl)})
	}
	return p
}

type apiKey struct {
	p       *Principal
	expires time.Time
}

// AuthenticateAPIKey checks a bearer API key. Keys are random and long, so a
// plain SHA-256 lookup is enough (no bcrypt cost per request).
func (a *Authenticator) AuthenticateAPIKey(key string) *Principal {
	if !strings.HasPrefix(key, APIKeyPrefix) {
		return nil
	}
	k, ok := a.keys[sha256.Sum256([]byte(key))]
	if !ok || (!k.expires.IsZero() && time.Now().After(k.expires)) {
		return nil
	}
	return k.p
}

// MapIdentity returns p with the roles of every identity entry matching its
// name added to the roles it already has (e.g. from a token claim). The
// input is not modified.
func (a *Authenticator) MapIdentity(p *Principal) *Principal {
	roles := slices.Clone(p.Roles)
	for _, id := range a.ids {
		if id.Matches(p.Name) {
			for _, r := range id.Roles {
				if !slices.Contains(roles, r) {
					roles = append(roles, r)
				}
			}
		}
	}
	out := *p
	out.Roles = roles
	return &out
}

// NewAPIKey returns a new random key and the hash to put in the users file.
func NewAPIKey() (key, hash string, err error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", "", err
	}
	key = APIKeyPrefix + base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b)
	sum := sha256.Sum256([]byte(key))
	return key, hex.EncodeToString(sum[:]), nil
}

func cacheKey(user, pass string) [32]byte {
	h := sha256.New()
	h.Write([]byte(user))
	h.Write([]byte{0})
	h.Write([]byte(pass))
	var k [32]byte
	h.Sum(k[:0])
	return k
}

// Hash produces a bcrypt hash for the users file.
func Hash(pass string) (string, error) {
	b, err := bcrypt.GenerateFromPassword([]byte(pass), bcrypt.DefaultCost)
	return string(b), err
}
