package engine

import (
	"container/list"
	"sync"
)

// lru is a small fixed-size least-recently-used cache.
type lru[V any] struct {
	mu    sync.Mutex
	max   int
	order *list.List // front = most recent; values are *lruEntry[V]
	items map[string]*list.Element
}

type lruEntry[V any] struct {
	key string
	val V
}

func newLRU[V any](max int) *lru[V] {
	return &lru[V]{max: max, order: list.New(), items: map[string]*list.Element{}}
}

func (c *lru[V]) get(key string) (V, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if el, ok := c.items[key]; ok {
		c.order.MoveToFront(el)
		return el.Value.(*lruEntry[V]).val, true
	}
	var zero V
	return zero, false
}

func (c *lru[V]) put(key string, val V) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if el, ok := c.items[key]; ok {
		el.Value.(*lruEntry[V]).val = val
		c.order.MoveToFront(el)
		return
	}
	c.items[key] = c.order.PushFront(&lruEntry[V]{key: key, val: val})
	for c.order.Len() > c.max {
		old := c.order.Back()
		c.order.Remove(old)
		delete(c.items, old.Value.(*lruEntry[V]).key)
	}
}

func (c *lru[V]) len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.order.Len()
}
