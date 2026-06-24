package nat

import (
	"log/slog"
	"net"
	"strconv"
	"sync"

	"github.com/devShuai/shuai-tunnel/tunnel-server-go/internal/control"
	"github.com/devShuai/shuai-tunnel/tunnel-server-go/internal/protocol"
	"github.com/devShuai/shuai-tunnel/tunnel-server-go/internal/store"
)

const externalReadBuffer = 16 * 1024

// Coordinator routes NAT messages to a per-connection clientSession and tears them down on
// disconnect. Mirrors the C# NatServerHandler.
type Coordinator struct {
	manager *RemotePortManager
	traffic *TrafficService
	limits  Limits
	logger  *slog.Logger

	mu       sync.Mutex
	sessions map[*control.Conn]*clientSession
}

// NewCoordinator builds the NAT coordinator.
func NewCoordinator(manager *RemotePortManager, traffic *TrafficService, limits Limits, logger *slog.Logger) *Coordinator {
	return &Coordinator{manager: manager, traffic: traffic, limits: limits, logger: logger, sessions: make(map[*control.Conn]*clientSession)}
}

// Handle processes one NAT message for a control connection.
func (c *Coordinator) Handle(conn *control.Conn, message protocol.NatMessage) error {
	c.mu.Lock()
	session, ok := c.sessions[conn]
	if !ok {
		session = newClientSession(conn, c.manager, c.traffic, c.limits, c.logger)
		c.sessions[conn] = session
	}
	c.mu.Unlock()
	return session.handle(message)
}

// Close releases all NAT state for a control connection on disconnect.
func (c *Coordinator) Close(conn *control.Conn) {
	c.mu.Lock()
	session, ok := c.sessions[conn]
	if ok {
		delete(c.sessions, conn)
	}
	c.mu.Unlock()
	if ok {
		session.dispose()
	}
}

type clientSession struct {
	conn    *control.Conn
	manager *RemotePortManager
	traffic *TrafficService
	limits  Limits
	logger  *slog.Logger

	mu             sync.Mutex
	bindings       map[int]*portListener
	externals      map[string]*externalConn
	activeExternal int
	portCounts     map[int]int
	registered     bool
}

func newClientSession(conn *control.Conn, manager *RemotePortManager, traffic *TrafficService,
	limits Limits, logger *slog.Logger) *clientSession {
	return &clientSession{
		conn:       conn,
		manager:    manager,
		traffic:    traffic,
		limits:     limits,
		logger:     logger,
		bindings:   make(map[int]*portListener),
		externals:  make(map[string]*externalConn),
		portCounts: make(map[int]int),
	}
}

func (s *clientSession) handle(message protocol.NatMessage) error {
	switch message.Type {
	case protocol.NatRegister:
		return s.handleRegister(message)
	case protocol.NatUnregister:
		s.handleUnregister(message)
		return nil
	case protocol.NatKeepalive, protocol.NatHTTPRoutesReport:
		return nil
	case protocol.NatData:
		if !s.isRegistered() {
			return s.protocolViolation()
		}
		s.handleData(message)
		return nil
	case protocol.NatDisconnected:
		if !s.isRegistered() {
			return s.protocolViolation()
		}
		s.handleClientDisconnect(message)
		return nil
	default:
		return s.protocolViolation()
	}
}

func (s *clientSession) protocolViolation() error {
	s.conn.MarkReason(store.ReasonProtocolViolation)
	s.conn.Close(store.ReasonProtocolViolation)
	return nil
}

func (s *clientSession) isRegistered() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.registered
}

func (s *clientSession) handleRegister(message protocol.NatMessage) error {
	port, hasPort := asInt(message.Metadata, "port")
	tunnelPort, hasTunnelPort := asInt(message.Metadata, "tunnelPort")
	tunnelAddress := asString(message.Metadata, "tunnelAddress")
	requestedName := asString(message.Metadata, "clientName")

	result := map[string]any{}
	if hasPort {
		result["port"] = port
	}
	if !hasPort || !hasTunnelPort || tunnelAddress == "" || requestedName == "" {
		result["success"] = false
		result["reason"] = "missing required metadata"
		_ = s.sendRegisterResult(result)
		s.conn.Close(store.ReasonRegisterFailed)
		return nil
	}
	if requestedName != s.conn.ClientName() {
		s.logger.Warn("REGISTER clientName mismatch", "session", s.conn.ClientName(), "claimed", requestedName)
		s.conn.Close(store.ReasonProtocolViolation)
		return nil
	}

	s.mu.Lock()
	_, bound := s.bindings[port]
	s.mu.Unlock()
	if bound {
		result["success"] = false
		result["reason"] = "port " + strconv.Itoa(port) + " already in use"
		return s.sendRegisterResult(result)
	}

	listener, err := s.manager.Bind(port, func(conn net.Conn) { s.acceptExternal(port, conn) })
	if err != nil {
		result["success"] = false
		result["reason"] = err.Error()
		_ = s.sendRegisterResult(result)
		s.conn.Close(store.ReasonRegisterFailed)
		return nil
	}

	s.mu.Lock()
	s.bindings[port] = listener
	s.registered = true
	s.mu.Unlock()

	result["success"] = true
	s.logger.Info("tunnel registered", "port", port, "target", tunnelAddress+":"+strconv.Itoa(tunnelPort), "client", s.conn.ClientName())
	return s.sendRegisterResult(result)
}

func (s *clientSession) handleUnregister(message protocol.NatMessage) {
	port, ok := asInt(message.Metadata, "port")
	if !ok {
		return
	}
	s.mu.Lock()
	listener := s.bindings[port]
	delete(s.bindings, port)
	s.mu.Unlock()
	s.manager.Release(listener)
}

func (s *clientSession) handleData(message protocol.NatMessage) {
	if len(message.Data) == 0 {
		return
	}
	channelID := asString(message.Metadata, "channelId")
	if channelID == "" {
		return
	}
	s.mu.Lock()
	external := s.externals[channelID]
	s.mu.Unlock()
	if external == nil {
		return
	}
	if external.write(message.Data) {
		s.traffic.RecordUpload(s.conn.ClientName(), int64(len(message.Data)))
	}
}

func (s *clientSession) handleClientDisconnect(message protocol.NatMessage) {
	channelID := asString(message.Metadata, "channelId")
	if channelID == "" {
		return
	}
	s.mu.Lock()
	external := s.externals[channelID]
	delete(s.externals, channelID)
	s.mu.Unlock()
	if external != nil {
		external.close()
	}
}

func (s *clientSession) sendRegisterResult(meta map[string]any) error {
	return s.conn.Send(protocol.NatMessage{Type: protocol.NatRegisterResult, Metadata: meta})
}

func (s *clientSession) acceptExternal(port int, netConn net.Conn) {
	if !s.acquire(port) {
		netConn.Close()
		return
	}
	external := newExternalConn(netConn, s.conn)
	s.mu.Lock()
	s.externals[external.channelID] = external
	s.mu.Unlock()

	// Announce the new external connection, then pump its bytes to the client as DATA.
	if err := s.conn.Send(protocol.NatMessage{
		Type:     protocol.NatConnected,
		Metadata: map[string]any{"channelId": external.channelID, "port": port},
	}); err != nil {
		s.removeExternal(port, external)
		return
	}

	external.pumpToClient(s.traffic, s.conn.ClientName())
	s.removeExternal(port, external)
}

func (s *clientSession) removeExternal(port int, external *externalConn) {
	s.mu.Lock()
	if current, ok := s.externals[external.channelID]; ok && current == external {
		delete(s.externals, external.channelID)
	}
	s.mu.Unlock()
	external.close()
	external.sendDisconnect()
	s.release(port)
}

func (s *clientSession) acquire(port int) bool {
	if !s.manager.TryAcquireGlobal() {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if reached(s.activeExternal, s.limits.PerClient) || reached(s.portCounts[port], s.limits.PerPort) {
		s.manager.ReleaseGlobal()
		s.manager.RecordRejected()
		return false
	}
	s.activeExternal++
	s.portCounts[port]++
	return true
}

func (s *clientSession) release(port int) {
	s.mu.Lock()
	if s.activeExternal > 0 {
		s.activeExternal--
	}
	if count := s.portCounts[port]; count <= 1 {
		delete(s.portCounts, port)
	} else {
		s.portCounts[port] = count - 1
	}
	s.mu.Unlock()
	s.manager.ReleaseGlobal()
}

func (s *clientSession) dispose() {
	s.mu.Lock()
	bindings := s.bindings
	externals := s.externals
	s.bindings = make(map[int]*portListener)
	s.externals = make(map[string]*externalConn)
	s.mu.Unlock()

	for _, listener := range bindings {
		s.manager.Release(listener)
	}
	for _, external := range externals {
		external.close()
	}
}

func reached(current, max int) bool { return max > 0 && current >= max }

func asString(meta map[string]any, key string) string {
	if meta == nil {
		return ""
	}
	if value, ok := meta[key]; ok {
		if s, ok := value.(string); ok {
			return s
		}
	}
	return ""
}

func asInt(meta map[string]any, key string) (int, bool) {
	if meta == nil {
		return 0, false
	}
	value, ok := meta[key]
	if !ok || value == nil {
		return 0, false
	}
	switch v := value.(type) {
	case float64:
		return int(v), true
	case int:
		return v, true
	case int64:
		return int(v), true
	case string:
		if n, err := strconv.Atoi(v); err == nil {
			return n, true
		}
	}
	return 0, false
}

// externalConn bridges a single external TCP connection over the control channel.
type externalConn struct {
	netConn   net.Conn
	control   *control.Conn
	channelID string
	closeOnce sync.Once
}

func newExternalConn(netConn net.Conn, ctrl *control.Conn) *externalConn {
	return &externalConn{netConn: netConn, control: ctrl, channelID: newChannelID()}
}

// pumpToClient reads external bytes and forwards them as DATA frames until EOF or error.
// Because control.Send writes synchronously under a mutex, a slow client naturally throttles
// this read loop (TCP backpressure), bounding server memory without dropping bytes.
func (e *externalConn) pumpToClient(traffic *TrafficService, clientName string) {
	buffer := make([]byte, externalReadBuffer)
	done := e.control.Context().Done()
	for {
		select {
		case <-done:
			return
		default:
		}
		read, err := e.netConn.Read(buffer)
		if read > 0 {
			payload := make([]byte, read)
			copy(payload, buffer[:read])
			traffic.RecordDownload(clientName, int64(read))
			if sendErr := e.control.Send(protocol.NatMessage{
				Type:     protocol.NatData,
				Metadata: map[string]any{"channelId": e.channelID},
				Data:     payload,
			}); sendErr != nil {
				return
			}
		}
		if err != nil {
			return
		}
	}
}

// write delivers client bytes to the external socket; returns false on failure (and closes).
func (e *externalConn) write(data []byte) bool {
	if _, err := e.netConn.Write(data); err != nil {
		e.close()
		return false
	}
	return true
}

func (e *externalConn) close() {
	e.closeOnce.Do(func() { e.netConn.Close() })
}

// sendDisconnect notifies the client that the external connection closed (best effort).
func (e *externalConn) sendDisconnect() {
	if e.control.Context().Err() != nil {
		return
	}
	_ = e.control.Send(protocol.NatMessage{
		Type:     protocol.NatDisconnected,
		Metadata: map[string]any{"channelId": e.channelID},
	})
}

func newChannelID() string {
	return randomHex16()
}
