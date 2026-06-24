// Package session tracks the live control connection per client name and enforces the
// "newest login wins" rule, mirroring the C# SessionRegistry.
package session

import (
	"sync"

	"github.com/devShuai/shuai-tunnel/tunnel-server-go/internal/protocol"
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
	sessions map[string]Session
}

// NewRegistry builds an empty registry.
func NewRegistry() *Registry {
	return &Registry{sessions: make(map[string]Session)}
}

// Replace binds session under its client name, returning any previously bound session that
// was displaced (the caller should close it with REPLACED_BY_NEW_LOGIN).
func (r *Registry) Replace(session Session) (displaced Session) {
	r.mu.Lock()
	defer r.mu.Unlock()
	name := session.ClientName()
	previous := r.sessions[name]
	r.sessions[name] = session
	if previous != nil && previous != session {
		return previous
	}
	return nil
}

// Unbind removes the binding for name only if it still points at session.
func (r *Registry) Unbind(name string, session Session) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if current, ok := r.sessions[name]; ok && current == session {
		delete(r.sessions, name)
	}
}

// Find returns the session bound to name, if any.
func (r *Registry) Find(name string) (Session, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	session, ok := r.sessions[name]
	return session, ok
}

// IsBound reports whether session is the one currently registered for its client name.
func (r *Registry) IsBound(session Session) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	current, ok := r.sessions[session.ClientName()]
	return ok && current == session
}

// Names returns the set of online client names (used by the management overview).
func (r *Registry) Names() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	names := make([]string, 0, len(r.sessions))
	for name := range r.sessions {
		names = append(names, name)
	}
	return names
}
