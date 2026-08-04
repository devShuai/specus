package client

import (
	"container/list"
	"sync"
)

const recentStreamTombstoneLimit = 1024

// recentStreamTombstones keeps a bounded, per-data-connection history of
// closed stream IDs. A peer may race a final RST with local cleanup; retaining
// the ID makes that late RST idempotent without allowing unbounded state.
type recentStreamTombstones struct {
	mu       sync.Mutex
	capacity int
	order    *list.List
	entries  map[uint32]*list.Element
}

func newRecentStreamTombstones(capacity int) recentStreamTombstones {
	if capacity <= 0 {
		capacity = recentStreamTombstoneLimit
	}
	return recentStreamTombstones{capacity: capacity}
}

func (t *recentStreamTombstones) add(streamID uint32) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.ensureLocked()
	if element := t.entries[streamID]; element != nil {
		t.order.Remove(element)
	}
	t.entries[streamID] = t.order.PushBack(streamID)
	if t.order.Len() > t.capacity {
		oldest := t.order.Front()
		delete(t.entries, oldest.Value.(uint32))
		t.order.Remove(oldest)
	}
}

func (t *recentStreamTombstones) contains(streamID uint32) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	_, ok := t.entries[streamID]
	return ok
}

func (t *recentStreamTombstones) remove(streamID uint32) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if element := t.entries[streamID]; element != nil {
		delete(t.entries, streamID)
		t.order.Remove(element)
	}
}

func (t *recentStreamTombstones) clear() {
	t.mu.Lock()
	t.order = nil
	t.entries = nil
	t.mu.Unlock()
}

func (t *recentStreamTombstones) len() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.entries)
}

func (t *recentStreamTombstones) ensureLocked() {
	if t.capacity <= 0 {
		t.capacity = recentStreamTombstoneLimit
	}
	if t.order == nil {
		t.order = list.New()
	}
	if t.entries == nil {
		t.entries = make(map[uint32]*list.Element, t.capacity)
	}
}
