package nat

import (
	"fmt"
	"net"
	"sync"
	"sync/atomic"
)

// Limits captures the three-tier external-connection admission caps. A value <= 0 means
// unlimited (matching the C# semantics).
type Limits struct {
	Global              int
	PerClient           int
	PerPort             int
	WriteBufferLowMark  int
	WriteBufferHighMark int
}

// RemotePortManager owns the public-port TCP listeners and enforces the global external
// connection cap shared across all clients. Mirrors the C# RemotePortServerManager.
type RemotePortManager struct {
	globalMax int

	mu    sync.Mutex
	ports map[int]*portListener

	active   atomic.Int64
	rejected atomic.Int64
}

// NewRemotePortManager builds a manager with the given global connection cap.
func NewRemotePortManager(globalMax int) *RemotePortManager {
	return &RemotePortManager{globalMax: globalMax, ports: make(map[int]*portListener)}
}

// Bind opens a public TCP listener on port and invokes onAccept for each accepted connection.
// It fails if the port is already bound by this process.
func (m *RemotePortManager) Bind(port int, onAccept func(net.Conn)) (*portListener, error) {
	m.mu.Lock()
	if _, exists := m.ports[port]; exists {
		m.mu.Unlock()
		return nil, fmt.Errorf("port %d already in use", port)
	}
	m.mu.Unlock()

	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		return nil, fmt.Errorf("bind public port %d: %w", port, err)
	}
	pl := &portListener{port: port, listener: listener, onAccept: onAccept, done: make(chan struct{})}

	m.mu.Lock()
	if _, exists := m.ports[port]; exists {
		m.mu.Unlock()
		listener.Close()
		return nil, fmt.Errorf("port %d already in use", port)
	}
	m.ports[port] = pl
	m.mu.Unlock()

	go pl.acceptLoop()
	return pl, nil
}

// Release stops and removes a port listener.
func (m *RemotePortManager) Release(pl *portListener) {
	if pl == nil {
		return
	}
	m.mu.Lock()
	if current, ok := m.ports[pl.port]; ok && current == pl {
		delete(m.ports, pl.port)
	}
	m.mu.Unlock()
	pl.close()
}

// HasBinding reports whether a listener is currently bound on port (used by tests).
func (m *RemotePortManager) HasBinding(port int) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, ok := m.ports[port]
	return ok
}

// TryAcquireGlobal reserves a global external-connection slot; returns false when at capacity.
func (m *RemotePortManager) TryAcquireGlobal() bool {
	if m.globalMax <= 0 {
		m.active.Add(1)
		return true
	}
	for {
		current := m.active.Load()
		if current >= int64(m.globalMax) {
			m.rejected.Add(1)
			return false
		}
		if m.active.CompareAndSwap(current, current+1) {
			return true
		}
	}
}

// ReleaseGlobal returns a global slot.
func (m *RemotePortManager) ReleaseGlobal() {
	for {
		current := m.active.Load()
		if current <= 0 {
			return
		}
		if m.active.CompareAndSwap(current, current-1) {
			return
		}
	}
}

// RecordRejected increments the rejected-connection counter.
func (m *RemotePortManager) RecordRejected() { m.rejected.Add(1) }

// ActiveExternalConnections returns the current global external connection count.
func (m *RemotePortManager) ActiveExternalConnections() int64 { return m.active.Load() }

// RejectedExternalConnections returns the cumulative rejected count.
func (m *RemotePortManager) RejectedExternalConnections() int64 { return m.rejected.Load() }

type portListener struct {
	port     int
	listener net.Listener
	onAccept func(net.Conn)
	done     chan struct{}
	once     sync.Once
}

func (pl *portListener) acceptLoop() {
	for {
		conn, err := pl.listener.Accept()
		if err != nil {
			select {
			case <-pl.done:
				return
			default:
				return
			}
		}
		if tcp, ok := conn.(*net.TCPConn); ok {
			_ = tcp.SetNoDelay(true)
			_ = tcp.SetKeepAlive(true)
		}
		go pl.onAccept(conn)
	}
}

func (pl *portListener) close() {
	pl.once.Do(func() {
		close(pl.done)
		pl.listener.Close()
	})
}
