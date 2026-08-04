package nat

import (
	"context"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"syscall"
)

type RemotePortOptions struct {
	BossThreads   int
	WorkerThreads int
	SOBacklog     int
	ReuseAddress  bool
	KeepAlive     bool
	TCPNoDelay    bool
}

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
// connection cap shared across all clients. Mirrors the Java RemotePortServerManager,
// including per-tenant active/rejected telemetry.
type RemotePortManager struct {
	globalMax int
	options   RemotePortOptions

	mu    sync.Mutex
	ports map[int]*portListener

	active   atomic.Int64
	rejected atomic.Int64

	tenantMu         sync.Mutex
	activeByTenant   map[string]*atomic.Int64
	rejectedByTenant map[string]*atomic.Int64
}

// NewRemotePortManager builds a manager with the given global connection cap.
func NewRemotePortManager(globalMax int) *RemotePortManager {
	return NewRemotePortManagerWithOptions(globalMax, RemotePortOptions{
		BossThreads: 1, SOBacklog: 8192, ReuseAddress: true, KeepAlive: true, TCPNoDelay: true,
	})
}

func NewRemotePortManagerWithOptions(globalMax int, options RemotePortOptions) *RemotePortManager {
	if options.BossThreads < 1 {
		options.BossThreads = 1
	}
	return &RemotePortManager{
		globalMax:        globalMax,
		options:          options,
		ports:            make(map[int]*portListener),
		activeByTenant:   make(map[string]*atomic.Int64),
		rejectedByTenant: make(map[string]*atomic.Int64),
	}
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

	listenConfig := net.ListenConfig{Control: func(_, _ string, raw syscall.RawConn) error {
		var optionErr error
		if err := raw.Control(func(fd uintptr) { optionErr = setReuseAddress(fd, m.options.ReuseAddress) }); err != nil {
			return err
		}
		return optionErr
	}}
	listener, err := listenConfig.Listen(context.Background(), "tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		return nil, fmt.Errorf("bind public port %d: %w", port, err)
	}
	pl := &portListener{port: port, listener: listener, onAccept: onAccept, done: make(chan struct{}),
		bossThreads: m.options.BossThreads, keepAlive: m.options.KeepAlive, tcpNoDelay: m.options.TCPNoDelay}

	m.mu.Lock()
	if _, exists := m.ports[port]; exists {
		m.mu.Unlock()
		listener.Close()
		return nil, fmt.Errorf("port %d already in use", port)
	}
	m.ports[port] = pl
	m.mu.Unlock()

	for range pl.bossThreads {
		go pl.acceptLoop()
	}
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

// TryAcquire reserves a global external-connection slot; returns false when at capacity.
// It also tracks per-tenant counts to mirror Java RemotePortServerManager.tryAcquireExternalConnection.
func (m *RemotePortManager) TryAcquire(tenantID string) bool {
	if m.globalMax <= 0 {
		m.active.Add(1)
		m.tenantActive(tenantID).Add(1)
		return true
	}
	for {
		current := m.active.Load()
		if current >= int64(m.globalMax) {
			m.rejected.Add(1)
			m.tenantRejected(tenantID).Add(1)
			return false
		}
		if m.active.CompareAndSwap(current, current+1) {
			m.tenantActive(tenantID).Add(1)
			return true
		}
	}
}

// ReleaseExternal returns a global slot and decrements the per-tenant counter.
func (m *RemotePortManager) ReleaseExternal(tenantID string) {
	for {
		current := m.active.Load()
		if current <= 0 {
			return
		}
		if m.active.CompareAndSwap(current, current-1) {
			ta := m.tenantActive(tenantID)
			for {
				tc := ta.Load()
				if tc <= 0 {
					break
				}
				if ta.CompareAndSwap(tc, tc-1) {
					break
				}
			}
			return
		}
	}
}

// RecordRejected increments the rejected-connection counter (global + per-tenant).
func (m *RemotePortManager) RecordRejected(tenantID string) {
	m.rejected.Add(1)
	m.tenantRejected(tenantID).Add(1)
}

func (m *RemotePortManager) tenantActive(tenantID string) *atomic.Int64 {
	if tenantID == "" {
		tenantID = "default"
	}
	m.tenantMu.Lock()
	defer m.tenantMu.Unlock()
	a, ok := m.activeByTenant[tenantID]
	if !ok {
		a = &atomic.Int64{}
		m.activeByTenant[tenantID] = a
	}
	return a
}

func (m *RemotePortManager) tenantRejected(tenantID string) *atomic.Int64 {
	if tenantID == "" {
		tenantID = "default"
	}
	m.tenantMu.Lock()
	defer m.tenantMu.Unlock()
	r, ok := m.rejectedByTenant[tenantID]
	if !ok {
		r = &atomic.Int64{}
		m.rejectedByTenant[tenantID] = r
	}
	return r
}

// ActiveExternalConnections returns the current global external connection count.
func (m *RemotePortManager) ActiveExternalConnections() int64 { return m.active.Load() }

// RejectedExternalConnections returns the cumulative rejected count.
func (m *RemotePortManager) RejectedExternalConnections() int64 { return m.rejected.Load() }

// ActiveExternalConnectionsByTenant returns the current external connection count for a tenant.
func (m *RemotePortManager) ActiveExternalConnectionsByTenant(tenantID string) int64 {
	if tenantID == "" {
		tenantID = "default"
	}
	m.tenantMu.Lock()
	defer m.tenantMu.Unlock()
	if a, ok := m.activeByTenant[tenantID]; ok {
		return a.Load()
	}
	return 0
}

// RejectedExternalConnectionsByTenant returns the cumulative rejected count for a tenant.
func (m *RemotePortManager) RejectedExternalConnectionsByTenant(tenantID string) int64 {
	if tenantID == "" {
		tenantID = "default"
	}
	m.tenantMu.Lock()
	defer m.tenantMu.Unlock()
	if r, ok := m.rejectedByTenant[tenantID]; ok {
		return r.Load()
	}
	return 0
}

type portListener struct {
	port        int
	listener    net.Listener
	onAccept    func(net.Conn)
	done        chan struct{}
	once        sync.Once
	bossThreads int
	keepAlive   bool
	tcpNoDelay  bool
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
			_ = tcp.SetNoDelay(pl.tcpNoDelay)
			_ = tcp.SetKeepAlive(pl.keepAlive)
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
