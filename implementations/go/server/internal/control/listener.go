package control

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"sync"
	"syscall"
)

type ListenerOptions struct {
	MaxFrameSize        int
	PreAuthMaxFrameSize int
	WriteLowWaterMark   int
	WriteHighWaterMark  int
	BossThreads         int
	WorkerThreads       int
	SOBacklog           int
	ReuseAddress        bool
	KeepAlive           bool
	TCPNoDelay          bool
}

// Listener accepts control-channel TCP connections and runs each through a Handler.
type Listener struct {
	maxFrameSize        int
	preAuthMaxFrameSize int
	writeLowWaterMark   int
	writeHighWaterMark  int
	handler             Handler
	tlsConfig           *tls.Config
	bossThreads         int
	workerThreads       int
	soBacklog           int
	reuseAddress        bool
	keepAlive           bool
	tcpNoDelay          bool

	mu        sync.Mutex
	listener  net.Listener
	boundPort int
}

// NewListener builds a control-channel listener that dispatches to handler.
func NewListener(options ListenerOptions, handler Handler) *Listener {
	bossThreads := options.BossThreads
	if bossThreads < 1 {
		bossThreads = 1
	}
	return &Listener{
		maxFrameSize:        options.MaxFrameSize,
		preAuthMaxFrameSize: options.PreAuthMaxFrameSize,
		writeLowWaterMark:   options.WriteLowWaterMark,
		writeHighWaterMark:  options.WriteHighWaterMark,
		bossThreads:         bossThreads,
		workerThreads:       options.WorkerThreads,
		soBacklog:           options.SOBacklog,
		reuseAddress:        options.ReuseAddress,
		keepAlive:           options.KeepAlive,
		tcpNoDelay:          options.TCPNoDelay,
		handler:             handler,
	}
}

// SetTLS enables TLS on the control channel using the given config (nil disables TLS).
func (l *Listener) SetTLS(config *tls.Config) { l.tlsConfig = config }

// Start binds the TCP listener on the given address (host:port). A port of 0 binds an
// ephemeral port; BoundPort then reports the chosen port. When TLS is configured the accepted
// connections are wrapped in a TLS server.
func (l *Listener) Start(address string) error {
	listenConfig := net.ListenConfig{Control: func(_, _ string, raw syscall.RawConn) error {
		var optionErr error
		if err := raw.Control(func(fd uintptr) { optionErr = setReuseAddress(fd, l.reuseAddress) }); err != nil {
			return err
		}
		return optionErr
	}}
	listener, err := listenConfig.Listen(context.Background(), "tcp", address)
	if err != nil {
		return fmt.Errorf("bind control channel on %s: %w", address, err)
	}
	l.mu.Lock()
	if tcpAddr, ok := listener.Addr().(*net.TCPAddr); ok {
		l.boundPort = tcpAddr.Port
	}
	if l.tlsConfig != nil {
		listener = tls.NewListener(listener, l.tlsConfig)
	}
	l.listener = listener
	l.mu.Unlock()
	return nil
}

// BoundPort returns the actual listening port (useful when port 0 was requested), or 0.
func (l *Listener) BoundPort() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.boundPort
}

// Serve accepts connections until ctx is cancelled or the listener is closed.
func (l *Listener) Serve(ctx context.Context) error {
	l.mu.Lock()
	listener := l.listener
	l.mu.Unlock()
	if listener == nil {
		return fmt.Errorf("control listener not started")
	}

	go func() {
		<-ctx.Done()
		listener.Close()
	}()

	var workers sync.WaitGroup
	for range l.bossThreads {
		workers.Add(1)
		go func() {
			defer workers.Done()
			l.acceptLoop(ctx, listener)
		}()
	}
	workers.Wait()
	return nil
}

func (l *Listener) acceptLoop(ctx context.Context, listener net.Listener) {
	for {
		netConn, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			// Transient accept errors: keep serving.
			continue
		}
		socketConn := netConn
		if secureConn, ok := netConn.(*tls.Conn); ok {
			socketConn = secureConn.NetConn()
		}
		if tcp, ok := socketConn.(*net.TCPConn); ok {
			_ = tcp.SetNoDelay(l.tcpNoDelay)
			_ = tcp.SetKeepAlive(l.keepAlive)
		}
		conn := newConn(netConn, l.maxFrameSize, l.preAuthMaxFrameSize,
			l.writeLowWaterMark, l.writeHighWaterMark, ctx)
		go conn.run(l.handler)
	}
}

// Close stops the listener.
func (l *Listener) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.listener != nil {
		return l.listener.Close()
	}
	return nil
}
