package control

import "sync"

// WriteBackpressureGate tracks bytes queued or currently being written and exposes a
// Netty-style writable signal using high/low water marks. Callers add bytes before a
// serialized write and release them when the write completes, so writers waiting for the
// write lock also contribute to backpressure.
type WriteBackpressureGate struct {
	mu            sync.Mutex
	lowWaterMark  int64
	highWaterMark int64
	pendingBytes  int64
	backpressured bool
	nextListener  int
	listeners     map[int]func(bool)
}

// NewWriteBackpressureGate returns a gate with sane high/low water marks. Negative values
// are normalized to zero, and high is always greater than low.
func NewWriteBackpressureGate(lowWaterMark, highWaterMark int) *WriteBackpressureGate {
	low := int64(lowWaterMark)
	if low < 0 {
		low = 0
	}
	high := int64(highWaterMark)
	if high <= low {
		high = low + 1
	}
	return &WriteBackpressureGate{
		lowWaterMark:  low,
		highWaterMark: high,
		listeners:     make(map[int]func(bool)),
	}
}

// AddListener subscribes to backpressure transitions and returns an unsubscribe function.
func (g *WriteBackpressureGate) AddListener(listener func(bool)) func() {
	if listener == nil {
		return func() {}
	}
	g.mu.Lock()
	id := g.nextListener
	g.nextListener++
	g.listeners[id] = listener
	g.mu.Unlock()
	return func() {
		g.mu.Lock()
		delete(g.listeners, id)
		g.mu.Unlock()
	}
}

// AddPending records bytes that are about to be written. It returns the number of bytes that
// must later be passed to ReleasePending.
func (g *WriteBackpressureGate) AddPending(bytes int) int {
	if bytes <= 0 {
		return 0
	}
	var listeners []func(bool)
	g.mu.Lock()
	g.pendingBytes += int64(bytes)
	if !g.backpressured && g.pendingBytes >= g.highWaterMark {
		g.backpressured = true
		listeners = g.listenerSnapshotLocked()
	}
	g.mu.Unlock()
	notifyBackpressureListeners(listeners, true)
	return bytes
}

// ReleasePending releases previously tracked bytes and emits a low-water transition when
// the pending total drops back under the low water mark.
func (g *WriteBackpressureGate) ReleasePending(bytes int) {
	if bytes <= 0 {
		return
	}
	var listeners []func(bool)
	g.mu.Lock()
	g.pendingBytes -= int64(bytes)
	if g.pendingBytes < 0 {
		g.pendingBytes = 0
	}
	if g.backpressured && g.pendingBytes <= g.lowWaterMark {
		g.backpressured = false
		listeners = g.listenerSnapshotLocked()
	}
	g.mu.Unlock()
	notifyBackpressureListeners(listeners, false)
}

// IsBackpressured reports whether the pending bytes are currently above the high/low
// hysteresis window.
func (g *WriteBackpressureGate) IsBackpressured() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.backpressured
}

// PendingBytes reports the current tracked byte count.
func (g *WriteBackpressureGate) PendingBytes() int64 {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.pendingBytes
}

func (g *WriteBackpressureGate) listenerSnapshotLocked() []func(bool) {
	listeners := make([]func(bool), 0, len(g.listeners))
	for _, listener := range g.listeners {
		listeners = append(listeners, listener)
	}
	return listeners
}

func notifyBackpressureListeners(listeners []func(bool), backpressured bool) {
	for _, listener := range listeners {
		func() {
			defer func() { _ = recover() }()
			listener(backpressured)
		}()
	}
}
