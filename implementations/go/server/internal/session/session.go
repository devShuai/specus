// Package session tracks the live control connection per client name and enforces the
// "newest login wins" rule, mirroring the C# SessionRegistry.
package session

import (
	"context"
	"sort"
	"sync"
	"time"

	"github.com/devShuai/specus/implementations/go/server/internal/protocol"
)

// Session is a control connection that can be addressed by client name, written to, and closed.
type Session interface {
	// ClientName returns the authenticated client name bound to this session.
	ClientName() string
	// LoginTimeMs returns the unix-ms timestamp when the session logged in.
	LoginTimeMs() int64
	// Send writes a packet to the connection.
	Send(packet protocol.Packet) error
	// Close tears down the connection, stamping the given disconnect reason.
	Close(reason string)
}

// Registry maps client name to the currently bound session.
type Registry struct {
	mu       sync.Mutex
	controls map[string]Session
	data     map[string]Session
	closedAt map[string]time.Time
	changed  chan struct{}
	// Fixed stripes bound memory independently of attacker-controlled client names. These
	// leases never hold mu: lifecycle work may query storage and send to other sessions.
	controlLeases [256]chan struct{}
}

// NewRegistry builds an empty registry.
func NewRegistry() *Registry {
	registry := &Registry{
		controls: make(map[string]Session),
		data:     make(map[string]Session),
		closedAt: make(map[string]time.Time),
		changed:  make(chan struct{}),
	}
	for i := range registry.controlLeases {
		registry.controlLeases[i] = make(chan struct{}, 1)
		registry.controlLeases[i] <- struct{}{}
	}
	return registry
}

// AcquireControlLease serializes control replacement, report admission, companion data
// attachment and teardown for one canonical client name. Waiting is cancellable/bounded by
// the caller; unlike mu, this lease may span DB work. Release is idempotent.
func (r *Registry) AcquireControlLease(ctx context.Context, name string) (func(), error) {
	return r.AcquireControlLeases(ctx, name)
}

func controlLeaseIndex(name string) int {
	hash := uint32(2166136261)
	for i := 0; i < len(name); i++ {
		hash = (hash ^ uint32(name[i])) * 16777619
	}
	return int(hash % 256)
}

// AcquireControlLeases obtains the distinct stripes in one global order. Callers must not
// already hold a control lease: acquiring a second endpoint after holding the first would
// deadlock opposite-direction signals, and two different names can share one stripe.
// No registry mutex is held during waiting, DB work or socket writes.
func (r *Registry) AcquireControlLeases(ctx context.Context, names ...string) (func(), error) {
	seen := make(map[int]bool, len(names))
	indices := make([]int, 0, len(names))
	for _, name := range names {
		index := controlLeaseIndex(name)
		if !seen[index] {
			seen[index] = true
			indices = append(indices, index)
		}
	}
	sort.Ints(indices)
	held := make([]int, 0, len(indices))
	var once sync.Once
	release := func() {
		once.Do(func() {
			for i := len(held) - 1; i >= 0; i-- {
				r.controlLeases[held[i]] <- struct{}{}
			}
		})
	}
	for _, index := range indices {
		if err := ctx.Err(); err != nil {
			release()
			return nil, err
		}
		select {
		case <-ctx.Done():
			release()
			return nil, ctx.Err()
		case <-r.controlLeases[index]:
			held = append(held, index)
		}
	}
	if err := ctx.Err(); err != nil {
		release()
		return nil, err
	}
	return release, nil
}

// Replace binds session under its client name, returning any previously bound session that
// was displaced (the caller should close it with REPLACED_BY_NEW_LOGIN).
func (r *Registry) Replace(session Session) (displaced Session) {
	r.mu.Lock()
	defer r.mu.Unlock()
	name := session.ClientName()
	previous := r.controls[name]
	r.controls[name] = session
	if _, dataReady := r.data[name]; dataReady {
		delete(r.closedAt, name)
	}
	r.notifyLocked()
	if previous != nil && previous != session {
		return previous
	}
	return nil
}

// ReplaceData binds the mandatory v2 data connection without displacing the control session.
func (r *Registry) ReplaceData(session Session) (displaced Session) {
	r.mu.Lock()
	defer r.mu.Unlock()
	name := session.ClientName()
	previous := r.data[name]
	r.data[name] = session
	if _, controlReady := r.controls[name]; controlReady {
		delete(r.closedAt, name)
	}
	r.notifyLocked()
	if previous != nil && previous != session {
		return previous
	}
	return nil
}

// Unbind removes the binding for name only if it still points at session.
func (r *Registry) Unbind(name string, session Session) {
	r.mu.Lock()
	defer r.mu.Unlock()
	changed := false
	if current, ok := r.controls[name]; ok && current == session {
		delete(r.controls, name)
		changed = true
	}
	if current, ok := r.data[name]; ok && current == session {
		delete(r.data, name)
		changed = true
	}
	if changed {
		r.closedAt[name] = time.Now()
		r.notifyLocked()
	}
}

// Find returns the session bound to name, if any.
func (r *Registry) Find(name string) (Session, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	session, ok := r.controls[name]
	return session, ok
}

// FindData returns the dedicated data connection bound to name.
func (r *Registry) FindData(name string) (Session, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	session, ok := r.data[name]
	return session, ok
}

// CurrentDataControl snapshots the pairing under the short registry mutex, without
// waiting on control lifecycle work or holding that mutex across any stream I/O.
// Namespace retirement must still guard work that outlives this admission snapshot.
func (r *Registry) CurrentDataControl(data Session) (Session, bool) {
	if data == nil {
		return nil, false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	name := data.ClientName()
	if r.data[name] != data {
		return nil, false
	}
	control, ok := r.controls[name]
	return control, ok
}

// WaitForDataReconnect blocks until the named data connection is registered or the
// context ends. Unknown clients fail immediately; only partially connected or recently
// disconnected clients consume the grace period.
func (r *Registry) WaitForDataReconnect(
	ctx context.Context,
	name string,
	reconnectGrace time.Duration,
) bool {
	for {
		r.mu.Lock()
		_, controlReady := r.controls[name]
		_, dataReady := r.data[name]
		closedAt, disconnected := r.closedAt[name]
		changed := r.changed
		r.mu.Unlock()
		if dataReady {
			return true
		}
		recentlyDisconnected := disconnected &&
			reconnectGrace > 0 &&
			time.Since(closedAt) <= reconnectGrace
		if !controlReady && !dataReady && !recentlyDisconnected {
			return false
		}
		select {
		case <-ctx.Done():
			return false
		case <-changed:
		}
	}
}

func (r *Registry) notifyLocked() {
	close(r.changed)
	r.changed = make(chan struct{})
}

// IsBound reports whether session is the one currently registered for its client name.
func (r *Registry) IsBound(session Session) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	current, ok := r.controls[session.ClientName()]
	return ok && current == session
}

// Names returns the set of online client names (used by the management overview).
func (r *Registry) Names() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	names := make([]string, 0, len(r.controls))
	for name := range r.controls {
		names = append(names, name)
	}
	return names
}
