package control

import "sync"

// ReadGate is a single-connection "are reads armed" switch. When paused, the read loop must
// stop pulling frames until Resume is called; this lets a slow downstream apply TCP
// backpressure to the peer without dropping bytes. It mirrors the C# ReadGate.
type ReadGate struct {
	mu     sync.Mutex
	paused bool
	wait   chan struct{}
}

// NewReadGate returns an armed (not paused) gate.
func NewReadGate() *ReadGate {
	return &ReadGate{}
}

// Pause stops reads. Idempotent.
func (g *ReadGate) Pause() {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.paused {
		return
	}
	g.paused = true
	g.wait = make(chan struct{})
}

// Resume re-arms reads, returning true if this call transitioned paused -> running.
func (g *ReadGate) Resume() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if !g.paused {
		return false
	}
	g.paused = false
	if g.wait != nil {
		close(g.wait)
		g.wait = nil
	}
	return true
}

// IsPaused reports the current state.
func (g *ReadGate) IsPaused() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.paused
}

// Wait blocks while paused, returning when resumed or when done is closed.
func (g *ReadGate) Wait(done <-chan struct{}) {
	g.mu.Lock()
	if !g.paused {
		g.mu.Unlock()
		return
	}
	wait := g.wait
	g.mu.Unlock()
	select {
	case <-wait:
	case <-done:
	}
}
