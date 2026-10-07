package auth

import (
	"sync"
	"time"
)

// LimiterConfig sets when repeated authentication failures block a key.
type LimiterConfig struct {
	MaxFailures int           // failures within Window that trigger a block; 0 disables
	Window      time.Duration // how far back failures count
	Lockout     time.Duration // how long a block lasts
	MaxKeys     int           // bound on tracked keys (memory); oldest are dropped
}

type failures struct {
	count   int
	start   time.Time // window start
	blocked time.Time // blocked until
	seen    time.Time
}

// Limiter counts authentication failures per key (a client IP, a user name)
// and blocks keys that fail too often. Checking happens before credentials
// are verified, so blocked attempts cost no bcrypt time.
type Limiter struct {
	cfg  LimiterConfig
	mu   sync.Mutex
	keys map[string]*failures
	now  func() time.Time
}

func NewLimiter(cfg LimiterConfig) *Limiter {
	if cfg.MaxKeys <= 0 {
		cfg.MaxKeys = 100_000
	}
	return &Limiter{cfg: cfg, keys: map[string]*failures{}, now: time.Now}
}

// Blocked reports whether key is locked out and for how much longer.
func (l *Limiter) Blocked(key string) (time.Duration, bool) {
	if l == nil || l.cfg.MaxFailures <= 0 || key == "" {
		return 0, false
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	f, ok := l.keys[key]
	if !ok {
		return 0, false
	}
	if left := f.blocked.Sub(l.now()); left > 0 {
		return left, true
	}
	return 0, false
}

// Fail records a failure for key and reports whether it is now blocked.
func (l *Limiter) Fail(key string) bool {
	if l == nil || l.cfg.MaxFailures <= 0 || key == "" {
		return false
	}
	now := l.now()
	l.mu.Lock()
	defer l.mu.Unlock()
	f, ok := l.keys[key]
	if !ok {
		if len(l.keys) >= l.cfg.MaxKeys {
			l.evictLocked(now)
		}
		f = &failures{start: now}
		l.keys[key] = f
	}
	f.seen = now
	if now.Sub(f.start) > l.cfg.Window {
		f.count, f.start = 0, now
	}
	f.count++
	if f.count >= l.cfg.MaxFailures && now.After(f.blocked) {
		f.blocked = now.Add(l.cfg.Lockout)
		f.count, f.start = 0, now
		return true
	}
	return false
}

// evictLocked drops expired entries, and if that is not enough, the
// least recently seen ones that are not currently blocked.
func (l *Limiter) evictLocked(now time.Time) {
	for k, f := range l.keys {
		if now.After(f.blocked) && now.Sub(f.start) > l.cfg.Window {
			delete(l.keys, k)
		}
	}
	for len(l.keys) >= l.cfg.MaxKeys {
		var oldest string
		var t time.Time
		for k, f := range l.keys {
			if now.Before(f.blocked) {
				continue
			}
			if oldest == "" || f.seen.Before(t) {
				oldest, t = k, f.seen
			}
		}
		if oldest == "" {
			return // everything is blocked: keep the blocks
		}
		delete(l.keys, oldest)
	}
}

// Sweep removes entries that no longer matter; call it periodically.
func (l *Limiter) Sweep() {
	if l == nil {
		return
	}
	now := l.now()
	l.mu.Lock()
	defer l.mu.Unlock()
	for k, f := range l.keys {
		if now.After(f.blocked) && now.Sub(f.start) > l.cfg.Window {
			delete(l.keys, k)
		}
	}
}
