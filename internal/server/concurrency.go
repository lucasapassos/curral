package server

import "sync"

// groupSlots counts running queries per concurrency group (a user, or a
// group named by the policy) so one caller cannot occupy every engine slot.
type groupSlots struct {
	mu     sync.Mutex
	active map[string]int
}

// tryAcquire takes a slot for group if fewer than max are in use. It never
// waits: a caller over its share is refused instead of holding a global
// slot and a transaction while it queues.
func (g *groupSlots) tryAcquire(group string, max int64) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.active == nil {
		g.active = map[string]int{}
	}
	if int64(g.active[group]) >= max {
		return false
	}
	g.active[group]++
	return true
}

func (g *groupSlots) release(group string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.active[group] <= 1 {
		delete(g.active, group)
		return
	}
	g.active[group]--
}

// running is the number of groups with queries in flight.
func (g *groupSlots) running() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return len(g.active)
}
