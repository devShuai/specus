package control

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"sync"
)

// Listener accepts control-channel TCP connections and runs each through a Handler.
type Listener struct {
	maxFrameSize       int
	writeLowWaterMark  int
	writeHighWaterMark int
	handler            Handler
	tlsConfig          *tls.Config

	mu        sync.Mutex
	listener  net.Listener
	boundPort int
}

// NewListener builds a control-channel listener that dispatches to handler.
func NewListener(maxFrameSize, writeLowWaterMark, writeHighWaterMark int, handler Handler) *Listener {
	return &Listener{
		maxFrameSize:       maxFrameSize,
		writeLowWaterMark:  writeLowWaterMark,
		writeHighWaterMark: writeHighWaterMark,
		handler:            handler,
	}
}

// SetTLS enables TLS on the control channel using the given config (nil disables TLS).
func (l *Listener) SetTLS(config *tls.Config) { l.tlsConfig = config }

// Start binds the TCP listener on the given address (host:port). A port of 0 binds an
// ephemeral port; BoundPort then reports the chosen port. When TLS is configured the accepted
// connections are wrapped in a TLS server.
func (l *Listener) Start(address string) error {
	listener, err := net.Listen("tcp", address)
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

	for {
		netConn, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			// Transient accept errors: keep serving.
			continue
		}
		if tcp, ok := netConn.(*net.TCPConn); ok {
			_ = tcp.SetNoDelay(true)
			_ = tcp.SetKeepAlive(true)
		}
		conn := newConn(netConn, l.maxFrameSize, l.writeLowWaterMark, l.writeHighWaterMark, ctx)
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
