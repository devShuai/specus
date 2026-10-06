package httpshare

import (
	"sync"
	"time"
)

// Streams is this instance's registry of in-flight share streams (HTTP requests and WebSockets).
// It bounds the streams per share and lets a revocation, an expiry or a recheck cut them at once.
type Streams struct {
	mu      sync.Mutex
	max     int
	byShare map[string]map[*Lease]struct{}
}

// Lease is one registered stream. Cut is called at most once, from any goroutine.
type Lease struct {
	streams   *Streams
	shareID   string
	expiresAt time.Time
	cut       func()
	cutOnce   sync.Once
	released  sync.Once
	wasCut    bool
	mu        sync.Mutex
}

// NewStreams builds a registry admitting at most maxPerShare streams per share.
func NewStreams(maxPerShare int) *Streams {
	return &Streams{max: maxPerShare, byShare: make(map[string]map[*Lease]struct{})}
}

// Acquire registers a stream of shareID that must end by expiresAt; cut aborts it. It fails when
// the share already has the maximum number of streams on this instance.
func (s *Streams) Acquire(shareID string, expiresAt time.Time, cut func()) (*Lease, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	leases := s.byShare[shareID]
	if len(leases) >= s.max {
		return nil, false
	}
	if leases == nil {
		leases = make(map[*Lease]struct{})
		s.byShare[shareID] = leases
	}
	lease := &Lease{streams: s, shareID: shareID, expiresAt: expiresAt, cut: cut}
	leases[lease] = struct{}{}
	return lease, true
}

// Release unregisters the stream when it ends on its own.
func (l *Lease) Release() {
	l.released.Do(func() {
		s := l.streams
		s.mu.Lock()
		defer s.mu.Unlock()
		if leases := s.byShare[l.shareID]; leases != nil {
			delete(leases, l)
			if len(leases) == 0 {
				delete(s.byShare, l.shareID)
			}
		}
	})
}

// Cut aborts the stream because its share ended.
func (l *Lease) Cut() {
	l.cutOnce.Do(func() {
		l.mu.Lock()
		l.wasCut = true
		l.mu.Unlock()
		if l.cut != nil {
			l.cut()
		}
	})
}

// WasCut reports whether the share ended while the stream was running.
func (l *Lease) WasCut() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.wasCut
}

func (s *Streams) snapshot(shareID string) []*Lease {
	s.mu.Lock()
	defer s.mu.Unlock()
	var leases []*Lease
	for lease := range s.byShare[shareID] {
		leases = append(leases, lease)
	}
	return leases
}

// Cut aborts every in-flight stream of shareID on this instance and returns how many there were.
func (s *Streams) Cut(shareID string) int {
	leases := s.snapshot(shareID)
	for _, lease := range leases {
		lease.Cut()
		lease.Release()
	}
	return len(leases)
}

// CutExpired aborts the streams whose share expired at or before now.
func (s *Streams) CutExpired(now time.Time) {
	s.mu.Lock()
	var expired []*Lease
	for _, leases := range s.byShare {
		for lease := range leases {
			if !now.Before(lease.expiresAt) {
				expired = append(expired, lease)
			}
		}
	}
	s.mu.Unlock()
	for _, lease := range expired {
		lease.Cut()
		lease.Release()
	}
}

// Shares lists the shares that have in-flight streams on this instance.
func (s *Streams) Shares() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	ids := make([]string, 0, len(s.byShare))
	for id := range s.byShare {
		ids = append(ids, id)
	}
	return ids
}

// Count returns the in-flight streams of shareID on this instance.
func (s *Streams) Count(shareID string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.byShare[shareID])
}
