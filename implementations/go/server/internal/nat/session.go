package nat

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"sync"

	"github.com/devShuai/shuai-tunnel/implementations/go/server/internal/control"
	"github.com/devShuai/shuai-tunnel/implementations/go/server/internal/protocol"
	"github.com/devShuai/shuai-tunnel/implementations/go/server/internal/store"
)

const (
	externalReadBuffer    = 16 * 1024
	natInitialWindowBytes = 1024 * 1024
	natMaximumWindowBytes = 16 * 1024 * 1024
)

// DetailRecorder optionally persists full TCP frame details.
type DetailRecorder interface {
	RecordTCPFrame(ctx context.Context, record store.TCPFrameRecord) error
	ReleaseTCPStream(channelID string)
}

// Coordinator routes NAT messages to a per-connection clientSession and tears them down on
// disconnect. Mirrors the C# NatServerHandler.
type Coordinator struct {
	manager    *RemotePortManager
	traffic    *TrafficService
	detail     DetailRecorder
	detailOpts store.TrafficDetailOptions
	limits     Limits
	logger     *slog.Logger

	mu       sync.Mutex
	sessions map[*control.Conn]*clientSession
	byName   map[string]*clientSession
}

// NewCoordinator builds the NAT coordinator.
func NewCoordinator(manager *RemotePortManager, traffic *TrafficService, detail DetailRecorder,
	detailOpts store.TrafficDetailOptions, limits Limits, logger *slog.Logger) *Coordinator {
	return &Coordinator{manager: manager, traffic: traffic, detail: detail, detailOpts: detailOpts,
		limits: limits, logger: logger, sessions: make(map[*control.Conn]*clientSession),
		byName: make(map[string]*clientSession)}
}

// Attach creates the per-client stream namespace immediately after authentication.
func (c *Coordinator) Attach(conn *control.Conn) {
	if conn == nil || conn.ClientName() == "" {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, exists := c.sessions[conn]; exists {
		return
	}
	session := newClientSession(conn, c.manager, c.traffic, c.detail, c.detailOpts, c.limits, c.logger)
	c.sessions[conn] = session
	c.byName[conn.ClientName()] = session
}

// OpenHTTPStream allocates one stream in the authenticated client's NAT v2 namespace.
func (c *Coordinator) OpenHTTPStream(clientName string, metadata map[string]any) (*HTTPStream, error) {
	c.mu.Lock()
	session := c.byName[clientName]
	c.mu.Unlock()
	if session == nil {
		return nil, fmt.Errorf("client is offline: %s", clientName)
	}
	return session.openHTTPStream(metadata)
}

// Handle processes one NAT message for a control connection.
func (c *Coordinator) Handle(conn *control.Conn, message protocol.NatMessage) error {
	c.Attach(conn)
	c.mu.Lock()
	session, ok := c.sessions[conn]
	if !ok {
		session = newClientSession(conn, c.manager, c.traffic, c.detail, c.detailOpts, c.limits, c.logger)
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
		if c.byName[conn.ClientName()] == session {
			delete(c.byName, conn.ClientName())
		}
	}
	c.mu.Unlock()
	if ok {
		session.dispose()
	}
}

type clientSession struct {
	conn       *control.Conn
	manager    *RemotePortManager
	traffic    *TrafficService
	detail     DetailRecorder
	detailOpts store.TrafficDetailOptions
	limits     Limits
	logger     *slog.Logger

	mu             sync.Mutex
	bindings       map[int]*portListener
	externals      map[uint32]*externalConn
	httpStreams    map[uint32]*HTTPStream
	nextStreamID   uint32
	activeExternal int
	portCounts     map[int]int
	registered     bool

	controlBackpressureUnsubscribe func()
}

func newClientSession(conn *control.Conn, manager *RemotePortManager, traffic *TrafficService,
	detail DetailRecorder, detailOpts store.TrafficDetailOptions, limits Limits, logger *slog.Logger) *clientSession {
	session := &clientSession{
		conn:         conn,
		manager:      manager,
		traffic:      traffic,
		detail:       detail,
		detailOpts:   detailOpts,
		limits:       limits,
		logger:       logger,
		bindings:     make(map[int]*portListener),
		externals:    make(map[uint32]*externalConn),
		httpStreams:  make(map[uint32]*HTTPStream),
		nextStreamID: 1,
		portCounts:   make(map[int]int),
	}
	session.controlBackpressureUnsubscribe = conn.WriteBackpressure.AddListener(func(bool) {
		session.updateExternalReadsForControlWritability()
		session.updateControlReadForWritability()
	})
	return session
}

func (s *clientSession) handle(message protocol.NatMessage) error {
	switch message.Type {
	case protocol.NatRegister:
		return s.handleRegister(message)
	case protocol.NatUnregister:
		s.handleUnregister(message)
		return nil
	case protocol.NatKeepalive:
		return nil
	case protocol.NatData:
		if s.handleHTTPData(message) {
			return nil
		}
		if !s.isRegistered() {
			return s.protocolViolation()
		}
		s.handleData(message)
		return nil
	case protocol.NatFin, protocol.NatRST:
		if s.handleHTTPEnd(message) {
			return nil
		}
		if !s.isRegistered() {
			return s.protocolViolation()
		}
		s.handleClientClose(message)
		return nil
	case protocol.NatWindowUpdate:
		return s.handleWindowUpdate(message)
	case protocol.NatOpen:
		if s.handleHTTPResponseOpen(message) {
			return nil
		}
		return s.protocolViolation()
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
	s.mu.Lock()
	external := s.externals[message.StreamID]
	s.mu.Unlock()
	if external == nil {
		return
	}
	if external.write(message.Data) {
		s.traffic.RecordTCPUpload(s.conn.ClientName(), external.port, int64(len(message.Data)))
		s.recordTCPFrame(protocol.NatData, external, message.Data, store.TCPDirectionClientToPublic)
		_ = s.conn.SendPriority(protocol.NatMessage{
			Type: protocol.NatWindowUpdate, StreamID: message.StreamID, Value: uint32(len(message.Data)),
		})
		if message.Flags&protocol.NatFlagEndStream != 0 {
			s.finishClientDirection(external)
		}
	}
}

func (s *clientSession) handleClientClose(message protocol.NatMessage) {
	s.mu.Lock()
	external := s.externals[message.StreamID]
	s.mu.Unlock()
	if external == nil {
		return
	}
	if message.Type == protocol.NatRST {
		s.cleanupExternal(external)
		return
	}
	s.finishClientDirection(external)
}

func (s *clientSession) finishClientDirection(external *externalConn) {
	external.shutdownWrite()
	if external.markClientFinished() {
		s.cleanupExternal(external)
	}
}

func (s *clientSession) handleWindowUpdate(message protocol.NatMessage) error {
	s.mu.Lock()
	httpStream := s.httpStreams[message.StreamID]
	external := s.externals[message.StreamID]
	s.mu.Unlock()
	if httpStream != nil {
		if !httpStream.addSendCredit(message.Value) {
			return s.protocolViolation()
		}
		return nil
	}
	if external == nil {
		return nil
	}
	if !external.addSendCredit(message.Value) {
		return s.protocolViolation()
	}
	return nil
}

func (s *clientSession) openHTTPStream(metadata map[string]any) (*HTTPStream, error) {
	streamID := s.allocateStreamID()
	stream := newHTTPStream(s.conn, streamID, s.removeHTTPStream)
	s.mu.Lock()
	s.httpStreams[streamID] = stream
	s.mu.Unlock()
	if err := s.conn.Send(protocol.NatMessage{
		Type: protocol.NatOpen, StreamID: streamID, Metadata: metadata,
	}); err != nil {
		stream.Close()
		return nil, err
	}
	return stream, nil
}

func (s *clientSession) handleHTTPResponseOpen(message protocol.NatMessage) bool {
	if asString(message.Metadata, "source") != "http" || asString(message.Metadata, "phase") != "response" {
		return false
	}
	s.mu.Lock()
	stream := s.httpStreams[message.StreamID]
	s.mu.Unlock()
	return stream != nil && stream.onHead(message.Metadata)
}

func (s *clientSession) handleHTTPData(message protocol.NatMessage) bool {
	s.mu.Lock()
	stream := s.httpStreams[message.StreamID]
	s.mu.Unlock()
	if stream == nil {
		return false
	}
	if !stream.onData(message.Data) {
		s.protocolViolation()
	}
	return true
}

func (s *clientSession) handleHTTPEnd(message protocol.NatMessage) bool {
	s.mu.Lock()
	stream := s.httpStreams[message.StreamID]
	s.mu.Unlock()
	if stream == nil {
		return false
	}
	if message.Type == protocol.NatRST {
		stream.onReset(asString(message.Metadata, "reason"))
	} else if !stream.onEnd(message.Metadata) {
		s.protocolViolation()
	}
	return true
}

func (s *clientSession) removeHTTPStream(streamID uint32, expected *HTTPStream) {
	s.mu.Lock()
	if s.httpStreams[streamID] == expected {
		delete(s.httpStreams, streamID)
	}
	s.mu.Unlock()
}

func (s *clientSession) allocateStreamID() uint32 {
	s.mu.Lock()
	defer s.mu.Unlock()
	for {
		streamID := s.nextStreamID
		s.nextStreamID++
		if s.nextStreamID == 0 {
			s.nextStreamID = 1
		}
		if streamID != 0 && s.externals[streamID] == nil && s.httpStreams[streamID] == nil {
			return streamID
		}
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
	streamID := s.allocateStreamID()
	external := newExternalConn(netConn, s.conn, streamID, port,
		s.limits.WriteBufferLowMark, s.limits.WriteBufferHighMark)
	external.writeBackpressureUnsubscribe = external.writeBackpressure.AddListener(func(bool) {
		s.updateControlReadForWritability()
	})
	if s.conn.WriteBackpressure.IsBackpressured() {
		external.readGate.Pause()
	}
	s.mu.Lock()
	s.externals[external.streamID] = external
	s.mu.Unlock()
	s.updateControlReadForWritability()

	// Announce the new external connection, then pump its bytes to the client as DATA.
	if err := s.conn.Send(protocol.NatMessage{
		Type:     protocol.NatOpen,
		StreamID: external.streamID,
		Metadata: map[string]any{"channelId": external.channelID, "port": port},
	}); err != nil {
		s.cleanupExternal(external)
		return
	}

	external.pumpToClient(s.traffic, s.detail, s.detailOpts, s.conn.ClientName())
	external.sendFin()
	if external.markPublicFinished() {
		s.cleanupExternal(external)
	}
}

func (s *clientSession) cleanupExternal(external *externalConn) {
	if !external.beginCleanup() {
		return
	}
	s.mu.Lock()
	if current, ok := s.externals[external.streamID]; ok && current == external {
		delete(s.externals, external.streamID)
	}
	s.mu.Unlock()
	external.stopBackpressureListener()
	external.close()
	s.releaseTCPStream(external.channelID)
	s.updateControlReadForWritability()
	s.release(external.port)
}

func (s *clientSession) recordTCPFrame(_ int, external *externalConn, payload []byte, direction string) {
	if s.detail == nil || external == nil {
		return
	}
	sourceAddress, sourcePort := splitAddr(external.netConn.LocalAddr())
	destinationAddress, destinationPort := splitAddr(external.netConn.RemoteAddr())
	if direction == store.TCPDirectionPublicToClient {
		sourceAddress, sourcePort = splitAddr(external.netConn.RemoteAddr())
		destinationAddress, destinationPort = splitAddr(external.netConn.LocalAddr())
	}
	_ = s.detail.RecordTCPFrame(s.conn.Context(), store.TCPFrameRecord{
		ClientName:         s.conn.ClientName(),
		ListenPort:         external.port,
		ChannelID:          external.channelID,
		Direction:          direction,
		SourceAddress:      sourceAddress,
		SourcePort:         sourcePort,
		DestinationAddress: destinationAddress,
		DestinationPort:    destinationPort,
		Payload:            payload,
		Options:            s.detailOpts,
	})
}

func (s *clientSession) releaseTCPStream(channelID string) {
	if s.detail != nil {
		s.detail.ReleaseTCPStream(channelID)
	}
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
	if s.controlBackpressureUnsubscribe != nil {
		s.controlBackpressureUnsubscribe()
		s.controlBackpressureUnsubscribe = nil
	}
	s.mu.Lock()
	bindings := s.bindings
	externals := s.externals
	httpStreams := s.httpStreams
	s.bindings = make(map[int]*portListener)
	s.externals = make(map[uint32]*externalConn)
	s.httpStreams = make(map[uint32]*HTTPStream)
	s.mu.Unlock()

	for _, listener := range bindings {
		s.manager.Release(listener)
	}
	for _, external := range externals {
		external.stopBackpressureListener()
		external.close()
	}
	for _, stream := range httpStreams {
		stream.onReset("control channel closed")
	}
}

func (s *clientSession) updateExternalReadsForControlWritability() {
	controlWritable := !s.conn.WriteBackpressure.IsBackpressured()
	s.mu.Lock()
	externals := make([]*externalConn, 0, len(s.externals))
	for _, external := range s.externals {
		externals = append(externals, external)
	}
	s.mu.Unlock()
	for _, external := range externals {
		if controlWritable {
			external.readGate.Resume()
		} else {
			external.readGate.Pause()
		}
	}
}

func (s *clientSession) updateControlReadForWritability() {
	controlWritable := !s.conn.WriteBackpressure.IsBackpressured()
	externalsWritable := true
	s.mu.Lock()
	for _, external := range s.externals {
		if external.writeBackpressure.IsBackpressured() {
			externalsWritable = false
			break
		}
	}
	s.mu.Unlock()
	if controlWritable && externalsWritable {
		s.conn.ReadGate.Resume()
		return
	}
	s.conn.ReadGate.Pause()
}

func reached(current, max int) bool { return max > 0 && current >= max }

func asString(meta map[string]any, key string) string {
	if meta == nil {
		return ""
	}
	value, ok := meta[key]
	if !ok || value == nil {
		return ""
	}
	return fmt.Sprint(value)
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
	case float32:
		return int(v), true
	case int:
		return v, true
	case int64:
		return int(v), true
	case int32:
		return int(v), true
	case json.Number:
		n, err := strconv.ParseInt(v.String(), 10, 32)
		if err == nil {
			return int(n), true
		}
		f, err := strconv.ParseFloat(v.String(), 64)
		if err == nil {
			return int(f), true
		}
	case string:
		if n, err := strconv.Atoi(v); err == nil {
			return n, true
		}
	}
	return 0, false
}

// externalConn bridges a single external TCP connection over the control channel.
type externalConn struct {
	netConn                      net.Conn
	control                      *control.Conn
	port                         int
	streamID                     uint32
	channelID                    string
	readGate                     *control.ReadGate
	writeBackpressure            *control.WriteBackpressureGate
	writeBackpressureUnsubscribe func()
	closeOnce                    sync.Once
	creditMu                     sync.Mutex
	creditCond                   *sync.Cond
	sendCredit                   uint64
	closed                       bool
	stateMu                      sync.Mutex
	publicFinished               bool
	clientFinished               bool
	cleanupStarted               bool
}

func newExternalConn(netConn net.Conn, ctrl *control.Conn, streamID uint32,
	port, lowWaterMark, highWaterMark int) *externalConn {
	external := &externalConn{
		netConn:           netConn,
		control:           ctrl,
		port:              port,
		streamID:          streamID,
		channelID:         newChannelID(),
		readGate:          control.NewReadGate(),
		writeBackpressure: control.NewWriteBackpressureGate(lowWaterMark, highWaterMark),
		sendCredit:        natInitialWindowBytes,
	}
	external.creditCond = sync.NewCond(&external.creditMu)
	return external
}

// pumpToClient reads external bytes and forwards them as DATA frames until EOF or error.
// External reads are paused when the control-channel write buffer is above its high water mark,
// mirroring Java/Netty auto-read backpressure without dropping bytes.
func (e *externalConn) pumpToClient(traffic *TrafficService, detail DetailRecorder,
	detailOpts store.TrafficDetailOptions, clientName string) {
	buffer := make([]byte, externalReadBuffer)
	done := e.control.Context().Done()
	for {
		select {
		case <-done:
			return
		default:
		}
		e.readGate.Wait(done)
		if e.control.Context().Err() != nil {
			return
		}
		read, err := e.netConn.Read(buffer)
		if read > 0 {
			payload := make([]byte, read)
			copy(payload, buffer[:read])
			traffic.RecordTCPDownload(clientName, e.port, int64(read))
			if detail != nil {
				sourceAddress, sourcePort := splitAddr(e.netConn.RemoteAddr())
				destinationAddress, destinationPort := splitAddr(e.netConn.LocalAddr())
				_ = detail.RecordTCPFrame(e.control.Context(), store.TCPFrameRecord{
					ClientName:         clientName,
					ListenPort:         e.port,
					ChannelID:          e.channelID,
					Direction:          store.TCPDirectionPublicToClient,
					SourceAddress:      sourceAddress,
					SourcePort:         sourcePort,
					DestinationAddress: destinationAddress,
					DestinationPort:    destinationPort,
					Payload:            payload,
					Options:            detailOpts,
				})
			}
			if !e.takeSendCredit(read) {
				return
			}
			if sendErr := e.control.Send(protocol.NatMessage{
				Type: protocol.NatData, StreamID: e.streamID, Data: payload,
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
	trackedBytes := e.writeBackpressure.AddPending(len(data))
	defer e.writeBackpressure.ReleasePending(trackedBytes)
	if _, err := e.netConn.Write(data); err != nil {
		e.close()
		return false
	}
	return true
}

func (e *externalConn) close() {
	e.closeOnce.Do(func() {
		e.creditMu.Lock()
		e.closed = true
		e.creditCond.Broadcast()
		e.creditMu.Unlock()
		e.netConn.Close()
	})
}

func (e *externalConn) takeSendCredit(size int) bool {
	if size <= 0 || size > natMaximumWindowBytes {
		return false
	}
	e.creditMu.Lock()
	defer e.creditMu.Unlock()
	needed := uint64(size)
	for e.sendCredit < needed && !e.closed {
		e.creditCond.Wait()
	}
	if e.closed {
		return false
	}
	e.sendCredit -= needed
	return true
}

func (e *externalConn) addSendCredit(credit uint32) bool {
	if credit == 0 || credit > natMaximumWindowBytes {
		return false
	}
	e.creditMu.Lock()
	defer e.creditMu.Unlock()
	if e.closed || e.sendCredit+uint64(credit) > natMaximumWindowBytes {
		return false
	}
	e.sendCredit += uint64(credit)
	e.creditCond.Broadcast()
	return true
}

func (e *externalConn) shutdownWrite() {
	if tcp, ok := e.netConn.(*net.TCPConn); ok {
		_ = tcp.CloseWrite()
		return
	}
	e.close()
}

func (e *externalConn) markPublicFinished() bool {
	e.stateMu.Lock()
	defer e.stateMu.Unlock()
	e.publicFinished = true
	return e.clientFinished
}

func (e *externalConn) markClientFinished() bool {
	e.stateMu.Lock()
	defer e.stateMu.Unlock()
	e.clientFinished = true
	return e.publicFinished
}

func (e *externalConn) beginCleanup() bool {
	e.stateMu.Lock()
	defer e.stateMu.Unlock()
	if e.cleanupStarted {
		return false
	}
	e.cleanupStarted = true
	return true
}

func (e *externalConn) stopBackpressureListener() {
	if e.writeBackpressureUnsubscribe != nil {
		e.writeBackpressureUnsubscribe()
		e.writeBackpressureUnsubscribe = nil
	}
}

// sendFin notifies the client that the external connection reached EOF (best effort).
func (e *externalConn) sendFin() {
	if e.control.Context().Err() != nil {
		return
	}
	e.stateMu.Lock()
	cleanupStarted := e.cleanupStarted
	e.stateMu.Unlock()
	if cleanupStarted {
		return
	}
	_ = e.control.Send(protocol.NatMessage{
		Type: protocol.NatFin, StreamID: e.streamID,
	})
}

func newChannelID() string {
	return randomHex16()
}

func splitAddr(addr net.Addr) (string, *int) {
	if tcp, ok := addr.(*net.TCPAddr); ok {
		port := tcp.Port
		if tcp.IP != nil {
			return tcp.IP.String(), &port
		}
		return tcp.String(), &port
	}
	if addr == nil {
		return "", nil
	}
	return addr.String(), nil
}
