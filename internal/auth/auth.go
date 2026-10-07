// Package auth verifies local user/password credentials.
package auth

import (
	"crypto/sha256"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"

	"curral/internal/config"
)

// Principal is an authenticated user.
type Principal struct {
	Name  string
	Roles []string
}

type cacheEntry struct {
	p       *Principal
	expires time.Time
}

// Authenticator checks bcrypt hashes and caches successful verifications so
// repeated requests do not pay bcrypt's cost (tens of ms) every time.
type Authenticator struct {
	users map[string]config.User
	ttl   time.Duration
	cache sync.Map // [32]byte -> cacheEntry
	dummy []byte
}

func New(users *config.Users, ttl time.Duration) *Authenticator {
	a := &Authenticator{users: map[string]config.User{}, ttl: ttl}
	for _, u := range users.Users {
		a.users[u.Name] = u
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

	u, ok := a.users[user]
	if !ok {
		_ = bcrypt.CompareHashAndPassword(a.dummy, []byte(pass))
		return nil
	}
	if bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(pass)) != nil {
		return nil
	}
	p := &Principal{Name: u.Name, Roles: u.Roles}
	if a.ttl > 0 {
		a.cache.Store(key, cacheEntry{p: p, expires: time.Now().Add(a.ttl)})
	}
	return p
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
