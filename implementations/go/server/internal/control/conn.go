package control

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/devShuai/shuai-tunnel/tunnel-server-go/internal/protocol"
	"github.com/devShuai/shuai-tunnel/tunnel-server-go/internal/store"
)

const (
	readerIdle       = 60 * time.Second
	writerIdle       = 30 * time.Second
	idleTickInterval = time.Second
)

// Handler receives per-connection lifecycle and packet events from the read loop. All
// callbacks for a single connection run on that connection's read-loop goroutine.
type Handler interface {
	OnConnect(conn *Conn)
	OnPacket(conn *Conn, packet protocol.Packet) error
	OnDisconnect(conn *Conn)
}

// Conn is one control-channel connection: a serialized writer, an idle/heartbeat watchdog,
// and per-connection mutable login state. It implements session.Session.
type Conn struct {
	netConn net.Conn
	writer  *bufio.Writer
	writeMu sync.Mutex

	ctx    context.Context
	cancel context.CancelFunc

	channelID     string
	remoteAddress string
	maxFrameSize  int

	ReadGate *ReadGate

	reasonOnce sync.Once
	reason     atomic.Value // string

	clientName atomic.Value // string
	loginTime  atomic.Int64
	recordID   atomic.Int64

	lastReadUnixNano  atomic.Int64
	lastWriteUnixNano atomic.Int64
}

func newConn(netConn net.Conn, maxFrameSize int, parent context.Context) *Conn {
	ctx, cancel := context.WithCancel(parent)
	conn := &Conn{
		netConn:      netConn,
		writer:       bufio.NewWriter(netConn),
		ctx:          ctx,
		cancel:       cancel,
		channelID:    newChannelID(),
		maxFrameSize: maxFrameSize,
		ReadGate:     NewReadGate(),
	}
	if addr := netConn.RemoteAddr(); addr != nil {
		conn.remoteAddress = addr.String()
	}
	now := time.Now().UnixNano()
	conn.lastReadUnixNano.Store(now)
	conn.lastWriteUnixNano.Store(now)
	return conn
}

func newChannelID() string {
	var raw [16]byte
	_, _ = rand.Read(raw[:])
	return hex.EncodeToString(raw[:])
}

// Context returns the connection lifetime context, cancelled when the connection closes.
func (c *Conn) Context() context.Context { return c.ctx }

// ChannelID returns the stable per-connection identifier recorded in the audit row.
func (c *Conn) ChannelID() string { return c.channelID }

// RemoteAddress returns the peer endpoint string.
func (c *Conn) RemoteAddress() string { return c.remoteAddress }

// ClientName returns the authenticated client name, or "" before login.
func (c *Conn) ClientName() string {
	if v, ok := c.clientName.Load().(string); ok {
		return v
	}
	return ""
}

// LoginTimeMs returns the unix-ms login timestamp, or 0 before login.
func (c *Conn) LoginTimeMs() int64 { return c.loginTime.Load() }

// ConnectionRecordID returns the audit row id, or 0 if none.
func (c *Conn) ConnectionRecordID() int64 { return c.recordID.Load() }

// SetConnectionRecordID stores the audit row id.
func (c *Conn) SetConnectionRecordID(id int64) { c.recordID.Store(id) }

// OnLoginSuccess records the authenticated client name and login time.
func (c *Conn) OnLoginSuccess(clientName string, loginTimeMs int64) {
	c.clientName.Store(clientName)
	c.loginTime.Store(loginTimeMs)
}

// MarkReason records the disconnect reason; only the first call wins.
func (c *Conn) MarkReason(reason string) {
	c.reasonOnce.Do(func() { c.reason.Store(reason) })
}

// Reason returns the recorded disconnect reason, or "" if none was stamped.
func (c *Conn) Reason() string {
	if v, ok := c.reason.Load().(string); ok {
		return v
	}
	return ""
}

// Close stamps the reason (first-wins) and tears down the connection.
func (c *Conn) Close(reason string) {
	if reason != "" {
		c.MarkReason(reason)
	}
	c.cancel()
}

// Send serializes and writes a packet, updating the write-idle timestamp. It is safe to call
// from multiple goroutines.
func (c *Conn) Send(packet protocol.Packet) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if err := protocol.WritePacket(c.writer, packet); err != nil {
		return err
	}
	if err := c.writer.Flush(); err != nil {
		return err
	}
	c.lastWriteUnixNano.Store(time.Now().UnixNano())
	return nil
}

// run drives the read loop and the idle watchdog until the connection closes.
func (c *Conn) run(handler Handler) {
	defer c.netConn.Close()
	handler.OnConnect(c)
	defer handler.OnDisconnect(c)

	go c.idleWatchdog()

	reader := bufio.NewReader(c.netConn)
	done := c.ctx.Done()
	for {
		select {
		case <-done:
			return
		default:
		}

		c.ReadGate.Wait(done)
		if c.ctx.Err() != nil {
			return
		}

		command, body, err := protocol.ReadFrame(reader)
		if err != nil {
			// Distinguish a clean peer close from a protocol/IO error for the audit row.
			if c.ctx.Err() == nil {
				c.MarkReason(store.ReasonClientClosed)
			}
			return
		}
		c.lastReadUnixNano.Store(time.Now().UnixNano())

		packet, err := protocol.Decode(command, body)
		if err != nil {
			c.MarkReason(store.ReasonProtocolViolation)
			return
		}
		if err := handler.OnPacket(c, packet); err != nil {
			if c.Reason() == "" {
				c.MarkReason(store.ReasonIOError)
			}
			return
		}
	}
}

func (c *Conn) idleWatchdog() {
	ticker := time.NewTicker(idleTickInterval)
	defer ticker.Stop()
	done := c.ctx.Done()
	for {
		select {
		case <-done:
			return
		case <-ticker.C:
		}
		now := time.Now().UnixNano()
		if time.Duration(now-c.lastReadUnixNano.Load()) >= readerIdle {
			c.MarkReason(store.ReasonIdleTimeout)
			c.cancel()
			return
		}
		if time.Duration(now-c.lastWriteUnixNano.Load()) >= writerIdle {
			// Java's SocketIdleStateHandler sends a HeartbeatResponse as keep-alive bytes.
			if err := c.Send(protocol.HeartbeatResponse{}); err != nil {
				c.MarkReason(store.ReasonHeartbeatWriteFail)
				c.cancel()
				return
			}
		}
	}
}
