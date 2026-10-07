package auth

import (
	"fmt"
	"testing"
	"time"
)

func TestLimiter(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	l := NewLimiter(LimiterConfig{MaxFailures: 3, Window: time.Minute, Lockout: 10 * time.Minute})
	l.now = func() time.Time { return now }

	for i := range 2 {
		if l.Fail("ip") {
			t.Fatalf("blocked after %d failures", i+1)
		}
	}
	// Failures outside the window do not add up.
	now = now.Add(2 * time.Minute)
	if l.Fail("ip") {
		t.Fatal("old failures counted")
	}
	l.Fail("ip")
	if !l.Fail("ip") {
		t.Fatal("not blocked after 3 failures in the window")
	}
	if left, ok := l.Blocked("ip"); !ok || left != 10*time.Minute {
		t.Fatalf("blocked=%v left=%v", ok, left)
	}
	if _, ok := l.Blocked("other"); ok {
		t.Fatal("other key blocked")
	}
	now = now.Add(10*time.Minute + time.Second)
	if _, ok := l.Blocked("ip"); ok {
		t.Fatal("block did not expire")
	}

	var nilL *Limiter
	if nilL.Fail("x") {
		t.Fatal("nil limiter blocks")
	}
	if _, ok := NewLimiter(LimiterConfig{}).Blocked("x"); ok {
		t.Fatal("disabled limiter blocks")
	}
}

func TestLimiterMemoryBound(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	l := NewLimiter(LimiterConfig{MaxFailures: 1, Window: time.Minute, Lockout: time.Hour, MaxKeys: 100})
	l.now = func() time.Time { return now }
	l.Fail("attacker") // blocked
	for i := range 1000 {
		now = now.Add(time.Millisecond)
		l.cfg.MaxFailures = 5 // later keys are not blocked
		l.Fail(fmt.Sprint("k", i))
	}
	if len(l.keys) > 100 {
		t.Fatalf("%d keys tracked", len(l.keys))
	}
	if _, ok := l.Blocked("attacker"); !ok {
		t.Fatal("eviction dropped an active block")
	}
}
