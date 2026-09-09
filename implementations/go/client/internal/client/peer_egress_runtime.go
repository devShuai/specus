package client

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"log"
	"net"
	"strconv"
	"sync"
	"time"
)

// The egress data plane: the only place authorization turns into a connect().
//
// Everything under it is pure. The TCP state machine, the datagram codec, the judgment layer and
// the flow table hold no sockets and read no clock. This file is where they meet real ones, so it
// is also where every resource is acquired and released, and the reason the layers below could stay
// testable without a network.
//
// One mutex serialises the whole plane. The flow table documents that it expects a single caller,
// and a finer lock would let a socket goroutine hold a flow pointer past the moment the table
// stopped vouching for it, which is exactly the window a revocation must not have.

// egressDialFunc opens the real outbound socket. It is injected so the fault-injection suite can
// produce refusals, timeouts and mid-connection failures without a network, and so the platform
// files can bind the socket to a physical interface.
type egressDialFunc func(protocol string, address string, timeout time.Duration) (net.Conn, error)

// egressSendFunc delivers one SPEG1 frame to a consumer. The runtime knows consumers by client ID
// and nothing about mesh sessions or paths.
//
// It must not block: the plane's single mutex is held across it, so a send that waits on anything
// which itself needs the plane would stop every flow on this node. Queue and return.
type egressSendFunc func(consumer int64, frame []byte) error

const (
	// egressConnectTimeout bounds a flow's opening connect. A consumer waiting on a black-holed
	// destination should get a reset it can act on rather than a socket held until the operating
	// system gives up.
	egressConnectTimeout = 10 * time.Second

	// egressDefaultPathMTU is used until the mesh reports a measured one. It is the conservative
	// value the path-MTU prober starts from.
	egressDefaultPathMTU = 1280
)

type egressTCPFlow struct {
	conn   *tcpConn
	socket net.Conn
}

type egressUDPFlow struct {
	socket net.Conn
}

// egressStats is what the periodic egress-report carries, alongside the per-code refusal counts.
type egressStats struct {
	TotalFlows int64
	BytesIn    int64
	BytesOut   int64
}

type egressRuntime struct {
	mu     sync.Mutex
	logger *log.Logger

	enabled bool
	policy  egressPolicy
	context egressContext
	pathMTU int

	// peerACLAllows reports whether the mesh still authorises this consumer. It lives outside the
	// policy because the mesh ACL and the egress policy are revoked independently.
	//
	// Usually nil, and that is correct rather than lax: a frame only reaches this plane over a
	// session the mesh already authenticated, and withdrawal arrives as a revokeConsumer call
	// rather than as something to poll. Polling would mean reaching for the mesh's lock from
	// under this one.
	peerACLAllows func(consumer int64) bool

	// revision is the last accepted egress-config snapshot.
	revision int64

	// localInterfaces are the networks this host owns. Forwarding into one would loop back into
	// this node's own capture path.
	localInterfaces []string

	flows      *egressFlowTable
	rejections *egressRejectionLog
	stats      egressStats

	dial egressDialFunc
	send egressSendFunc

	closed bool
}

func newEgressRuntime(logger *log.Logger, send egressSendFunc, dial egressDialFunc) *egressRuntime {
	if logger == nil {
		logger = log.Default()
	}
	if dial == nil {
		dial = dialEgressTarget
	}
	return &egressRuntime{
		logger:     logger,
		context:    newEgressContext(),
		pathMTU:    egressDefaultPathMTU,
		flows:      newEgressFlowTable(0),
		rejections: newEgressRejectionLog(),
		dial:       dial,
		send:       send,
	}
}

// applyPolicy installs a pushed policy and closes whatever it no longer allows.
//
// Both gates are off by default, so a runtime that has received nothing forwards nothing. Turning
// the switch off drains every flow rather than waiting for idle expiry: an operator who disables
// the egress means now.
func (r *egressRuntime) applyPolicy(policy egressPolicy, context egressContext, now time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return
	}
	r.policy = policy
	r.context = context
	r.enabled = policy.Enabled
	r.flows.idleTimeout = egressIdleTimeoutFor(policy)

	if !policy.Enabled {
		r.releaseAll(egressRevocationsFor(r.flows.drain(), egressCodeDisabled), now)
		return
	}
	r.releaseAll(r.flows.reauthorize(policy, r.peerACLAllows, context, r.localInterfaceCIDRs()), now)
}

func egressIdleTimeoutFor(policy egressPolicy) time.Duration {
	if policy.Limits.IdleTimeoutSeconds > 0 {
		return time.Duration(policy.Limits.IdleTimeoutSeconds) * time.Second
	}
	return egressDefaultIdleTimeout
}

// revokeConsumer closes a consumer's flows the moment the mesh withdraws its authorization.
func (r *egressRuntime) revokeConsumer(consumer int64, now time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.releaseAll(egressRevocationsFor(r.flows.revokeConsumer(consumer), egressCodePeerACLDenied), now)
}

// shutdown releases everything. After it returns the runtime forwards nothing, so a caller can rely
// on it to have stopped traffic rather than merely to have asked it to stop.
func (r *egressRuntime) shutdown(now time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.closed = true
	r.enabled = false
	r.releaseAll(egressRevocationsFor(r.flows.drain(), egressCodeDisabled), now)
}

// handleFrame is the SPEG1 entry point: one decrypted payload from one consumer.
//
// It returns false when the payload is not an egress frame at all, so the mesh dispatch can go on
// to its other cases. A payload that carries the magic but nothing valid returns true, because it
// was addressed here and has already been refused with its own code.
func (r *egressRuntime) handleFrame(consumer int64, payload []byte, now time.Time) bool {
	if !looksLikePeerEgressFrame(payload) {
		return false
	}
	frame, code := parsePeerEgressFrame(payload)
	if code != "" {
		r.refuse(consumer, egressFlowKey{}, code, now)
		return true
	}
	switch frame.Type {
	case peerEgressTypeIPPacket:
		r.handleInnerPacket(consumer, frame, now)
	case peerEgressTypeControl:
		r.handleControl(consumer, frame, now)
	}
	return true
}

func (r *egressRuntime) handleInnerPacket(consumer int64, frame peerEgressFrame, now time.Time) {
	switch frame.Inner.Protocol {
	case ipv4ProtocolTCP:
		if segment, ok := parseTCPSegment(frame.Body); ok {
			r.handleSegment(consumer, segment, now)
			return
		}
	case ipv4ProtocolUDP:
		if datagram, ok := parseUDPDatagram(frame.Body); ok {
			r.handleDatagram(consumer, datagram, now)
			return
		}
	default:
		// ICMP and anything else this version does not carry. Refusing rather than passing it
		// through is the spec's rule: silently forwarding a protocol we do not account for
		// would leak traffic past the policy.
		r.refuse(consumer, egressFlowKey{
			protocol:   frame.Inner.Protocol,
			remotePort: uint16(frame.Inner.DestinationPort),
		}, egressCodeProtocolDenied, now)
		return
	}
	r.refuse(consumer, egressFlowKey{protocol: frame.Inner.Protocol}, egressCodeFrameTruncated, now)
}

func (r *egressRuntime) handleControl(consumer int64, frame peerEgressFrame, now time.Time) {
	control, ok := decodePeerEgressControl(frame.Body)
	if !ok {
		return
	}
	// flow-reject travels egress to consumer. Receiving one means the peer is confused about
	// which end it is, and acting on it would let a consumer close flows by assertion.
	if control.Type != peerEgressControlFlowPurge {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	// Scoped to the sender: a purge speaks for its own flows, not for every other consumer's.
	r.releaseAll(egressRevocationsFor(r.flows.purgeConsumerDestinations(consumer, control.Destinations), ""), now)
}

// handleSegment drives one TCP segment from a consumer.
func (r *egressRuntime) handleSegment(consumer int64, segment tcpSegment, now time.Time) {
	key := egressFlowKey{
		protocol:     ipv4ProtocolTCP,
		consumerIP:   segment.SourceIP,
		consumerPort: segment.SourcePort,
		remoteIP:     segment.DestinationIP,
		remotePort:   segment.DestinationPort,
	}

	r.mu.Lock()
	flow, known := r.flows.lookup(key)
	if !known {
		// Only a SYN opens a flow. A stray segment for something we never opened gets a reset,
		// which is what tells a consumer holding stale state to give up rather than retry.
		if !segment.has(tcpFlagSYN) || segment.has(tcpFlagACK) {
			r.mu.Unlock()
			if !segment.has(tcpFlagRST) {
				r.emitSegment(consumer, buildTCPReset(segment))
			}
			return
		}
		r.mu.Unlock()
		r.openTCPFlow(consumer, key, segment, now)
		return
	}

	handle, ok := flow.Handle.(*egressTCPFlow)
	if !ok {
		r.mu.Unlock()
		return
	}
	flow.LastSeen = now
	output := handle.conn.onSegment(segment, now)
	r.applyTCPOutput(consumer, flow, handle, output, now)
	r.mu.Unlock()
}

// openTCPFlow authorises, connects and completes the handshake.
//
// The connect happens outside the lock: it can take as long as egressConnectTimeout, and holding
// the plane for that would stall every other flow. The reservation is taken first so the quota is
// charged for the whole attempt, not only after it succeeds; a consumer opening a thousand flows to
// a black hole would otherwise pass every limit check.
func (r *egressRuntime) openTCPFlow(consumer int64, key egressFlowKey, syn tcpSegment, now time.Time) {
	r.mu.Lock()
	flow, code := r.reserve(consumer, key, now)
	if code != egressCodeAllowed {
		r.mu.Unlock()
		r.refuse(consumer, key, code, now)
		r.emitSegment(consumer, buildTCPReset(syn))
		return
	}
	address := net.JoinHostPort(formatEgressAddress(key.remoteIP), strconv.Itoa(int(key.remotePort)))
	dial, mtu := r.dial, r.pathMTU
	r.mu.Unlock()

	socket, err := dial("tcp", address, egressConnectTimeout)

	r.mu.Lock()
	// The flow can have been revoked, purged or drained while the connect was in flight. Closing
	// the socket we just opened is the only correct outcome: the authorization it was opened
	// under no longer exists.
	if current, still := r.flows.lookup(key); !still || current != flow || r.closed {
		r.mu.Unlock()
		if socket != nil {
			_ = socket.Close()
		}
		return
	}
	if err != nil {
		r.flows.close(key)
		r.mu.Unlock()
		r.unreachable(consumer, key, err)
		r.emitSegment(consumer, buildTCPReset(syn))
		return
	}

	conn, output := acceptTCPSyn(syn, newEgressISS(), mtu, r.flows.idleTimeout, now)
	handle := &egressTCPFlow{conn: conn, socket: socket}
	flow.Handle = handle
	r.stats.TotalFlows++
	r.applyTCPOutput(consumer, flow, handle, output, now)
	r.startTCPReader(consumer, flow, handle)
	r.mu.Unlock()
}

// startTCPReader pumps the real socket into the state machine. Called with the lock held.
func (r *egressRuntime) startTCPReader(consumer int64, flow *egressFlow, handle *egressTCPFlow) {
	go func() {
		buffer := make([]byte, 32*1024)
		for {
			read, err := handle.socket.Read(buffer)
			if read > 0 {
				r.mu.Lock()
				if current, still := r.flows.lookup(flow.Key); !still || current != flow {
					r.mu.Unlock()
					return
				}
				flow.LastSeen = time.Now()
				flow.BytesFromRemote += int64(read)
				r.stats.BytesIn += int64(read)
				output := handle.conn.onAppData(append([]byte(nil), buffer[:read]...), time.Now())
				r.applyTCPOutput(consumer, flow, handle, output, time.Now())
				r.mu.Unlock()
			}
			if err != nil {
				r.mu.Lock()
				if current, still := r.flows.lookup(flow.Key); !still || current != flow {
					r.mu.Unlock()
					return
				}
				now := time.Now()
				// A clean EOF is a half-close the consumer should see as a FIN. Any other
				// error ended the connection abnormally, which is a reset.
				var output tcpOutput
				if errors.Is(err, net.ErrClosed) {
					r.mu.Unlock()
					return
				}
				if isEgressEOF(err) {
					output = handle.conn.onAppClose(now)
				} else {
					output = handle.conn.abort()
				}
				r.applyTCPOutput(consumer, flow, handle, output, now)
				r.mu.Unlock()
				return
			}
		}
	}()
}

// applyTCPOutput performs everything the state machine asked for. Called with the lock held.
func (r *egressRuntime) applyTCPOutput(consumer int64, flow *egressFlow, handle *egressTCPFlow,
	output tcpOutput, now time.Time) {
	for _, packet := range output.Segments {
		r.emitSegment(consumer, packet)
	}
	if len(output.Deliver) > 0 && handle.socket != nil {
		if _, err := handle.socket.Write(output.Deliver); err != nil {
			// The socket died under us. Reset rather than leaving the consumer waiting for
			// data that will never arrive.
			for _, packet := range handle.conn.abort().Segments {
				r.emitSegment(consumer, packet)
			}
			r.release(flow)
			return
		}
		flow.BytesToRemote += int64(len(output.Deliver))
		r.stats.BytesOut += int64(len(output.Deliver))
	}
	if output.CloseApp && handle.socket != nil {
		// The consumer finished sending but still expects replies, so only the write side
		// closes. Closing both would discard a response the application is still producing.
		if half, ok := handle.socket.(interface{ CloseWrite() error }); ok {
			_ = half.CloseWrite()
		}
	}
	if output.Done || output.Reset {
		r.release(flow)
	}
}

// handleDatagram drives one UDP datagram from a consumer. UDP has no handshake, so the first
// datagram of a four-tuple is the authorization point and every later one rides that decision.
func (r *egressRuntime) handleDatagram(consumer int64, datagram udpDatagram, now time.Time) {
	key := egressFlowKey{
		protocol:     ipv4ProtocolUDP,
		consumerIP:   datagram.SourceIP,
		consumerPort: datagram.SourcePort,
		remoteIP:     datagram.DestinationIP,
		remotePort:   datagram.DestinationPort,
	}

	r.mu.Lock()
	flow, known := r.flows.lookup(key)
	if !known {
		reserved, code := r.reserve(consumer, key, now)
		if code != egressCodeAllowed {
			r.mu.Unlock()
			r.refuse(consumer, key, code, now)
			return
		}
		address := net.JoinHostPort(formatEgressAddress(key.remoteIP), strconv.Itoa(int(key.remotePort)))
		dial := r.dial
		r.mu.Unlock()

		socket, err := dial("udp", address, egressConnectTimeout)

		r.mu.Lock()
		if current, still := r.flows.lookup(key); !still || current != reserved || r.closed {
			r.mu.Unlock()
			if socket != nil {
				_ = socket.Close()
			}
			return
		}
		if err != nil {
			r.flows.close(key)
			r.mu.Unlock()
			r.unreachable(consumer, key, err)
			return
		}
		handle := &egressUDPFlow{socket: socket}
		reserved.Handle = handle
		r.stats.TotalFlows++
		r.startUDPReader(consumer, reserved, handle)
		flow = reserved
	}

	handle, ok := flow.Handle.(*egressUDPFlow)
	if !ok {
		r.mu.Unlock()
		return
	}
	flow.LastSeen = now
	socket := handle.socket
	payload := datagram.Payload
	flow.BytesToRemote += int64(len(payload))
	r.stats.BytesOut += int64(len(payload))
	r.mu.Unlock()

	if _, err := socket.Write(payload); err != nil {
		r.mu.Lock()
		r.releaseKey(key)
		r.mu.Unlock()
	}
}

// startUDPReader returns the socket's replies to the consumer. Called with the lock held.
func (r *egressRuntime) startUDPReader(consumer int64, flow *egressFlow, handle *egressUDPFlow) {
	go func() {
		buffer := make([]byte, udpMaxPayload)
		for {
			read, err := handle.socket.Read(buffer)
			if err != nil {
				return
			}
			r.mu.Lock()
			current, still := r.flows.lookup(flow.Key)
			if !still || current != flow {
				r.mu.Unlock()
				return
			}
			flow.LastSeen = time.Now()
			flow.BytesFromRemote += int64(read)
			r.stats.BytesIn += int64(read)
			r.mu.Unlock()

			// Addresses are mirrored from the flow key rather than read off the socket, so a
			// reply can only ever claim the address the consumer asked us to contact.
			r.emitSegment(consumer, buildUDPDatagram(udpDatagram{
				SourceIP:        flow.Key.remoteIP,
				DestinationIP:   flow.Key.consumerIP,
				SourcePort:      flow.Key.remotePort,
				DestinationPort: flow.Key.consumerPort,
				Payload:         append([]byte(nil), buffer[:read]...),
			}))
		}
	}()
}

// onTick advances timers: TCP retransmission and the idle expiry that is the only thing ending a
// UDP session. Called with no lock held.
func (r *egressRuntime) onTick(now time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return
	}
	for _, flow := range r.flowSnapshot() {
		handle, ok := flow.Handle.(*egressTCPFlow)
		if !ok {
			continue
		}
		r.applyTCPOutput(flow.Consumer, flow, handle, handle.conn.onTick(now), now)
	}
	// An expired session ended the way UDP sessions end. Recording it as a refusal would put
	// normal life cycle events into the counts an operator reads as blocked traffic.
	r.releaseAll(egressRevocationsFor(r.flows.expire(now), ""), now)
}

// flowSnapshot copies the live flows so a tick can release entries while iterating.
func (r *egressRuntime) flowSnapshot() []*egressFlow {
	snapshot := make([]*egressFlow, 0, len(r.flows.flows))
	for _, flow := range r.flows.flows {
		snapshot = append(snapshot, flow)
	}
	sortEgressFlows(snapshot)
	return snapshot
}

// reserve runs the judgment layer and, on approval, takes the quota slot. Called with the lock
// held. The reservation exists before the socket does so that a slow or failing connect still
// counts against the limits for its whole duration.
func (r *egressRuntime) reserve(consumer int64, key egressFlowKey, now time.Time) (*egressFlow, string) {
	if r.closed || !r.enabled {
		return nil, egressCodeDisabled
	}
	peerAllowed := true
	if r.peerACLAllows != nil {
		peerAllowed = r.peerACLAllows(consumer)
	}
	forConsumer, total := r.flows.counts(consumer)
	decision := authorizeEgressFlow(egressRequest{
		ConsumerClientID:       consumer,
		DestinationIP:          formatEgressAddress(key.remoteIP),
		DestinationPort:        int(key.remotePort),
		Protocol:               key.protocolName(),
		ActiveFlowsForConsumer: forConsumer,
		ActiveFlowsTotal:       total,
		LocalInterfaceCIDRs:    r.localInterfaceCIDRs(),
	}, r.policy, peerAllowed, r.context)
	if !decision.Allowed {
		return nil, decision.Code
	}
	flow, _ := r.flows.open(key, consumer, now)
	return flow, egressCodeAllowed
}

// refuse records a refusal and tells the consumer why. Called with no lock held.
//
// The control message is diagnostic only. A refused TCP flow is ended by the reset the caller also
// sends, because an application waits on its own stack, not on a message it never sees.
func (r *egressRuntime) refuse(consumer int64, key egressFlowKey, code string, now time.Time) {
	r.mu.Lock()
	write, suppressed := r.rejections.record(consumer, code, now)
	logger := r.logger
	r.mu.Unlock()

	if write && logger != nil {
		if suppressed > 0 {
			logger.Printf("[peer-egress] refused consumer=%d protocol=%s destination=%s:%d code=%s suppressed=%d",
				consumer, key.protocolName(), formatEgressAddress(key.remoteIP), key.remotePort, code, suppressed)
		} else {
			logger.Printf("[peer-egress] refused consumer=%d protocol=%s destination=%s:%d code=%s",
				consumer, key.protocolName(), formatEgressAddress(key.remoteIP), key.remotePort, code)
		}
	}
	body, err := encodePeerEgressControl(peerEgressControl{
		Type:            peerEgressControlFlowReject,
		Protocol:        key.protocolName(),
		SourceIP:        formatEgressAddress(key.consumerIP),
		SourcePort:      int(key.consumerPort),
		DestinationIP:   formatEgressAddress(key.remoteIP),
		DestinationPort: int(key.remotePort),
		Code:            code,
	})
	if err == nil {
		r.emitFrame(consumer, peerEgressTypeControl, body)
	}
}

// unreachable reports a flow the policy allowed but the network did not deliver. Called with no
// lock held.
//
// Deliberately not a refusal. The spec's codes all describe an authorization or validation outcome,
// and reporting a refused connection as EGRESS_DEST_DENIED would send an operator hunting for a
// policy rule that never fired, while inflating the refusal counts the server aggregates. The
// consumer learns what happened from the reset its own stack receives, which is what the
// application waits on anyway.
func (r *egressRuntime) unreachable(consumer int64, key egressFlowKey, cause error) {
	r.mu.Lock()
	logger := r.logger
	r.mu.Unlock()
	if logger != nil {
		logger.Printf("[peer-egress] connect failed consumer=%d protocol=%s destination=%s:%d err=%v",
			consumer, key.protocolName(), formatEgressAddress(key.remoteIP), key.remotePort, cause)
	}
}

// release closes one flow's socket and drops its table entry. Called with the lock held.
func (r *egressRuntime) release(flow *egressFlow) {
	if _, ok := r.flows.lookup(flow.Key); !ok {
		return
	}
	r.flows.close(flow.Key)
	closeEgressHandle(flow.Handle)
}

func (r *egressRuntime) releaseKey(key egressFlowKey) {
	if flow, ok := r.flows.close(key); ok {
		closeEgressHandle(flow.Handle)
	}
}

// releaseAll closes flows the table already removed. Called with the lock held.
//
// The reason travels to the consumer so an operator sees a blocked connection explained rather than
// merely dropped, and so a client can distinguish a revoked flow from a network failure.
func (r *egressRuntime) releaseAll(revoked []egressRevocation, now time.Time) {
	for _, entry := range revoked {
		flow := entry.Flow
		if handle, ok := flow.Handle.(*egressTCPFlow); ok && handle.conn != nil {
			// The reset is what the application actually reacts to. Without it a consumer
			// sits waiting on a connection this node has already stopped serving.
			for _, packet := range handle.conn.abort().Segments {
				r.emitSegment(flow.Consumer, packet)
			}
		}
		closeEgressHandle(flow.Handle)
		if entry.Code == "" {
			continue
		}
		r.rejections.record(flow.Consumer, entry.Code, now)
		if body, err := encodePeerEgressControl(peerEgressControl{
			Type:            peerEgressControlFlowReject,
			Protocol:        flow.Key.protocolName(),
			SourceIP:        formatEgressAddress(flow.Key.consumerIP),
			SourcePort:      int(flow.Key.consumerPort),
			DestinationIP:   formatEgressAddress(flow.Key.remoteIP),
			DestinationPort: int(flow.Key.remotePort),
			Code:            entry.Code,
		}); err == nil {
			r.emitFrame(flow.Consumer, peerEgressTypeControl, body)
		}
	}
}

func closeEgressHandle(handle any) {
	switch typed := handle.(type) {
	case *egressTCPFlow:
		if typed.socket != nil {
			_ = typed.socket.Close()
		}
	case *egressUDPFlow:
		if typed.socket != nil {
			_ = typed.socket.Close()
		}
	}
}

func (r *egressRuntime) emitSegment(consumer int64, packet []byte) {
	r.emitFrame(consumer, peerEgressTypeIPPacket, packet)
}

// emitFrame wraps a body and hands it to the sender. hop stays clear: this node is acting as an
// egress, not forwarding as a consumer of another one.
func (r *egressRuntime) emitFrame(consumer int64, frameType byte, body []byte) {
	if r.send == nil {
		return
	}
	_ = r.send(consumer, encodePeerEgressFrame(frameType, false, body))
}

// localInterfaceCIDRs are the networks owned by this node's own tunnel and virtual interfaces.
// Called with the lock held.
func (r *egressRuntime) localInterfaceCIDRs() []string {
	return r.localInterfaces
}

// setPathMTU records the budget a returning segment has to fit. Only ever lowered towards what the
// path actually measured; a value below the IPv4 minimum is ignored rather than applied, since a
// bad measurement should not be able to shrink every flow's segments to nothing.
func (r *egressRuntime) setPathMTU(mtu int) {
	if mtu < ipv4MinHeaderLen+tcpMinHeaderLen+tcpDefaultMSS {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.pathMTU = mtu
}

func (r *egressRuntime) setLocalInterfaceCIDRs(networks []string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.localInterfaces = networks
}

// acceptRevision applies the spec's monotonic guard: a snapshot at or below the last accepted one
// is ignored, so a reordered or replayed push cannot walk the policy backwards. A revision of zero
// is accepted, since a server that numbers nothing must still be able to configure the node.
func (r *egressRuntime) acceptRevision(revision int64) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if revision != 0 && revision <= r.revision {
		return false
	}
	r.revision = revision
	return true
}

// newEgressISS picks an initial send sequence number.
//
// Random rather than counted: a predictable ISS lets anyone who can guess the four-tuple inject
// segments a flow will accept. Falling back to the clock keeps a flow openable if the entropy
// source fails, which is worse than random but better than a fixed value.
func newEgressISS() uint32 {
	var raw [4]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return uint32(time.Now().UnixNano())
	}
	return binary.BigEndian.Uint32(raw[:])
}

// dialEgressTarget is the default dialer. bindEgressSocket is supplied per platform and is what
// keeps the outbound socket on a physical interface rather than back through the tunnel.
func dialEgressTarget(protocol string, address string, timeout time.Duration) (net.Conn, error) {
	dialer := net.Dialer{Timeout: timeout, Control: bindEgressSocket}
	return dialer.Dial(protocol, address)
}

func isEgressEOF(err error) bool { return errors.Is(err, io.EOF) }
