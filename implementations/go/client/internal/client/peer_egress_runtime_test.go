package client

import (
	"errors"
	"io"
	"log"
	"net"
	"sync"
	"testing"
	"time"
)

// Fault injection for the egress data plane.
//
// The layers below this one are pure and already have conformance suites. What is left to prove is
// the part that owns real resources: that a refused flow never reaches a socket, that a socket is
// released on every path including the ones nobody plans for, and that a revocation takes effect
// while traffic is in flight rather than at the next idle sweep.
//
// The dialer is injected, so an unreachable target, a hung connect and a connection that breaks
// mid-stream are all produced without a network.

type fakeEgressConn struct {
	mu         sync.Mutex
	writes     [][]byte
	writeErr   error
	closed     bool
	wroteClose bool
	reads      chan []byte
	readErr    chan error
}

func newFakeEgressConn() *fakeEgressConn {
	return &fakeEgressConn{reads: make(chan []byte, 16), readErr: make(chan error, 1)}
}

func (c *fakeEgressConn) Read(buffer []byte) (int, error) {
	select {
	case chunk := <-c.reads:
		return copy(buffer, chunk), nil
	case err := <-c.readErr:
		return 0, err
	}
}

func (c *fakeEgressConn) Write(payload []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.writeErr != nil {
		return 0, c.writeErr
	}
	c.writes = append(c.writes, append([]byte(nil), payload...))
	return len(payload), nil
}

func (c *fakeEgressConn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.closed {
		c.closed = true
		select {
		case c.readErr <- net.ErrClosed:
		default:
		}
	}
	return nil
}

func (c *fakeEgressConn) CloseWrite() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.wroteClose = true
	return nil
}

func (c *fakeEgressConn) isClosed() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closed
}

func (c *fakeEgressConn) written() [][]byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([][]byte(nil), c.writes...)
}

func (c *fakeEgressConn) LocalAddr() net.Addr              { return nil }
func (c *fakeEgressConn) RemoteAddr() net.Addr             { return nil }
func (c *fakeEgressConn) SetDeadline(time.Time) error      { return nil }
func (c *fakeEgressConn) SetReadDeadline(time.Time) error  { return nil }
func (c *fakeEgressConn) SetWriteDeadline(time.Time) error { return nil }

type egressHarness struct {
	t       *testing.T
	runtime *egressRuntime

	mu      sync.Mutex
	frames  [][]byte
	dialed  []string
	conns   []*fakeEgressConn
	dialErr error
	// gate blocks the dialer so a test can act while a connect is still in flight.
	gate chan struct{}
}

func newEgressHarness(t *testing.T, destinations ...string) *egressHarness {
	t.Helper()
	if len(destinations) == 0 {
		destinations = []string{"203.0.113.0/24"}
	}
	harness := &egressHarness{t: t}
	harness.runtime = newEgressRuntime(log.New(io.Discard, "", 0),
		func(_ int64, frame []byte) error {
			harness.mu.Lock()
			defer harness.mu.Unlock()
			harness.frames = append(harness.frames, append([]byte(nil), frame...))
			return nil
		},
		func(_ string, address string, _ time.Duration) (net.Conn, error) {
			harness.mu.Lock()
			harness.dialed = append(harness.dialed, address)
			failure, gate := harness.dialErr, harness.gate
			harness.mu.Unlock()
			if gate != nil {
				<-gate
			}
			if failure != nil {
				return nil, failure
			}
			socket := newFakeEgressConn()
			harness.mu.Lock()
			harness.conns = append(harness.conns, socket)
			harness.mu.Unlock()
			return socket, nil
		})
	harness.runtime.applyPolicy(testEgressPolicy(destinations...), newEgressContext(), flowEpoch)
	return harness
}

func (h *egressHarness) dialCount() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.dialed)
}

func (h *egressHarness) socket(index int) *fakeEgressConn {
	h.mu.Lock()
	defer h.mu.Unlock()
	if index >= len(h.conns) {
		h.t.Fatalf("no socket at index %d, only %d opened", index, len(h.conns))
	}
	return h.conns[index]
}

// segments returns every TCP segment the runtime sent back to a consumer.
func (h *egressHarness) segments() []tcpSegment {
	h.mu.Lock()
	defer h.mu.Unlock()
	var out []tcpSegment
	for _, raw := range h.frames {
		frame, code := parsePeerEgressFrame(raw)
		if code != "" || frame.Type != peerEgressTypeIPPacket {
			continue
		}
		if segment, ok := parseTCPSegment(frame.Body); ok {
			out = append(out, segment)
		}
	}
	return out
}

func (h *egressHarness) datagrams() []udpDatagram {
	h.mu.Lock()
	defer h.mu.Unlock()
	var out []udpDatagram
	for _, raw := range h.frames {
		frame, code := parsePeerEgressFrame(raw)
		if code != "" || frame.Type != peerEgressTypeIPPacket {
			continue
		}
		if datagram, ok := parseUDPDatagram(frame.Body); ok {
			out = append(out, datagram)
		}
	}
	return out
}

func (h *egressHarness) controls() []peerEgressControl {
	h.mu.Lock()
	defer h.mu.Unlock()
	var out []peerEgressControl
	for _, raw := range h.frames {
		frame, code := parsePeerEgressFrame(raw)
		if code != "" || frame.Type != peerEgressTypeControl {
			continue
		}
		if control, ok := decodePeerEgressControl(frame.Body); ok {
			out = append(out, control)
		}
	}
	return out
}

func (h *egressHarness) rejectCodes() []string {
	var codes []string
	for _, control := range h.controls() {
		if control.Type == peerEgressControlFlowReject {
			codes = append(codes, control.Code)
		}
	}
	return codes
}

func (h *egressHarness) sawReset() bool {
	for _, segment := range h.segments() {
		if segment.has(tcpFlagRST) {
			return true
		}
	}
	return false
}

func (h *egressHarness) reset() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.frames = nil
}

// waitFor polls a condition the socket goroutines satisfy asynchronously.
func (h *egressHarness) waitFor(what string, condition func() bool) {
	h.t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	h.t.Fatalf("timed out waiting for %s", what)
}

func egressSyn(t *testing.T, source string, sourcePort int, destination string, destinationPort int) tcpSegment {
	t.Helper()
	return tcpSegment{
		SourceIP: testAddr(t, source), DestinationIP: testAddr(t, destination),
		SourcePort: uint16(sourcePort), DestinationPort: uint16(destinationPort),
		Seq: 1000, Flags: tcpFlagSYN, Window: 65535, MSS: 1360,
	}
}

func egressFrameFor(packet []byte) []byte {
	return encodePeerEgressFrame(peerEgressTypeIPPacket, false, packet)
}

// The happy path, present so the failure cases below are read against something known to work.
func TestEgressRuntimeOpensAndForwardsATCPFlow(t *testing.T) {
	harness := newEgressHarness(t)
	syn := egressSyn(t, "100.96.0.1", 40000, "203.0.113.10", 443)
	harness.runtime.handleFrame(7, egressFrameFor(buildTCPSegment(syn)), flowEpoch)

	if harness.dialCount() != 1 {
		t.Fatalf("dialed %d times, want 1", harness.dialCount())
	}
	var synAck bool
	for _, segment := range harness.segments() {
		if segment.has(tcpFlagSYN) && segment.has(tcpFlagACK) {
			synAck = true
		}
	}
	if !synAck {
		t.Fatal("the consumer never received a SYN-ACK")
	}

	// Complete the handshake, then send a byte and confirm it reaches the real socket.
	handshake := harness.segments()[0]
	ack := tcpSegment{
		SourceIP: syn.SourceIP, DestinationIP: syn.DestinationIP,
		SourcePort: syn.SourcePort, DestinationPort: syn.DestinationPort,
		Seq: syn.Seq + 1, Ack: handshake.Seq + 1, Flags: tcpFlagACK, Window: 65535,
	}
	harness.runtime.handleFrame(7, egressFrameFor(buildTCPSegment(ack)), flowEpoch)

	data := ack
	data.Flags = tcpFlagACK | tcpFlagPSH
	data.Payload = []byte("GET / HTTP/1.0\r\n\r\n")
	harness.runtime.handleFrame(7, egressFrameFor(buildTCPSegment(data)), flowEpoch)

	harness.waitFor("payload to reach the socket", func() bool {
		return len(harness.socket(0).written()) > 0
	})
	if got := string(harness.socket(0).written()[0]); got != string(data.Payload) {
		t.Errorf("socket received %q", got)
	}
}

// A refused flow must never reach a socket. Dialing first and checking after would leak a connection
// to a destination the policy forbids, which is the whole failure this layer exists to prevent.
func TestEgressRuntimeRefusesBeforeDialing(t *testing.T) {
	harness := newEgressHarness(t, "203.0.113.0/24")
	syn := egressSyn(t, "100.96.0.1", 40000, "198.51.100.10", 443)
	harness.runtime.handleFrame(7, egressFrameFor(buildTCPSegment(syn)), flowEpoch)

	if harness.dialCount() != 0 {
		t.Error("a refused flow opened a socket")
	}
	if !harness.sawReset() {
		t.Error("the consumer was not reset, so its application waits on a flow that will never open")
	}
	if codes := harness.rejectCodes(); len(codes) != 1 || codes[0] != egressCodeDestinationDenied {
		t.Errorf("reject codes = %v", codes)
	}
}

// The forced-deny list has to hold against a policy broad enough to cover the address, which is the
// case it exists for.
func TestEgressRuntimeRefusesForcedDenyUnderABroadPolicy(t *testing.T) {
	harness := newEgressHarness(t, "0.0.0.0/0")
	syn := egressSyn(t, "100.96.0.1", 40000, "169.254.169.254", 80)
	harness.runtime.handleFrame(7, egressFrameFor(buildTCPSegment(syn)), flowEpoch)

	if harness.dialCount() != 0 {
		t.Error("cloud metadata was dialled")
	}
	if codes := harness.rejectCodes(); len(codes) != 1 || codes[0] != egressCodeForbiddenDestType {
		t.Errorf("reject codes = %v", codes)
	}
}

// The quota is charged at reservation, before the connect. A consumer aiming a burst at a black hole
// would otherwise pass every limit check, because no flow would ever be counted as open.
func TestEgressRuntimeChargesQuotaWhileConnectIsInFlight(t *testing.T) {
	harness := newEgressHarness(t)
	policy := testEgressPolicy("203.0.113.0/24")
	policy.Limits = egressLimits{MaxFlowsPerConsumer: 1}
	harness.runtime.applyPolicy(policy, newEgressContext(), flowEpoch)

	harness.mu.Lock()
	harness.gate = make(chan struct{})
	harness.mu.Unlock()

	first := egressSyn(t, "100.96.0.1", 40000, "203.0.113.10", 443)
	go harness.runtime.handleFrame(7, egressFrameFor(buildTCPSegment(first)), flowEpoch)
	harness.waitFor("the first connect to start", func() bool { return harness.dialCount() == 1 })

	second := egressSyn(t, "100.96.0.1", 40001, "203.0.113.10", 443)
	harness.runtime.handleFrame(7, egressFrameFor(buildTCPSegment(second)), flowEpoch)

	if harness.dialCount() != 1 {
		t.Error("the second flow dialled despite the quota being held by a pending connect")
	}
	if codes := harness.rejectCodes(); len(codes) != 1 || codes[0] != egressCodeLimitExceeded {
		t.Errorf("reject codes = %v", codes)
	}
	close(harness.gate)
}

// A connect that fails is not a refusal. Reporting it as one would send an operator hunting for a
// policy rule that never fired, and would inflate the refusal counts the server aggregates.
func TestEgressRuntimeSeparatesAnUnreachableTargetFromARefusal(t *testing.T) {
	harness := newEgressHarness(t)
	harness.mu.Lock()
	harness.dialErr = errors.New("connection refused")
	harness.mu.Unlock()

	syn := egressSyn(t, "100.96.0.1", 40000, "203.0.113.10", 443)
	harness.runtime.handleFrame(7, egressFrameFor(buildTCPSegment(syn)), flowEpoch)

	if !harness.sawReset() {
		t.Error("an unreachable target left the consumer without a reset")
	}
	if codes := harness.rejectCodes(); len(codes) != 0 {
		t.Errorf("a network failure was reported as a refusal: %v", codes)
	}
	if counts := harness.runtime.rejections.drainCounts(); len(counts) != 0 {
		t.Errorf("a network failure entered the refusal aggregate: %v", counts)
	}
	// The reservation must come back, or a flapping destination would exhaust the quota.
	if harness.runtime.flows.size() != 0 {
		t.Errorf("%d flows left after a failed connect", harness.runtime.flows.size())
	}
}

// A connection that dies mid-stream has to reach the consumer as a reset. Silence would leave the
// application waiting for data that is never coming.
func TestEgressRuntimeResetsWhenTheConnectionBreaks(t *testing.T) {
	harness := newEgressHarness(t)
	syn := egressSyn(t, "100.96.0.1", 40000, "203.0.113.10", 443)
	harness.runtime.handleFrame(7, egressFrameFor(buildTCPSegment(syn)), flowEpoch)
	harness.waitFor("the flow to open", func() bool { return harness.runtime.flows.size() == 1 })
	harness.reset()

	harness.socket(0).readErr <- errors.New("connection reset by peer")

	harness.waitFor("the flow to be released", func() bool {
		harness.runtime.mu.Lock()
		defer harness.runtime.mu.Unlock()
		return harness.runtime.flows.size() == 0
	})
	if !harness.sawReset() {
		t.Error("a broken connection produced no reset for the consumer")
	}
	if !harness.socket(0).isClosed() {
		t.Error("the socket was not closed")
	}
}

// completeHandshake acknowledges the SYN-ACK so the flow reaches ESTABLISHED.
func (h *egressHarness) completeHandshake(consumer int64, syn tcpSegment) {
	h.t.Helper()
	segments := h.segments()
	if len(segments) == 0 {
		h.t.Fatal("no SYN-ACK to acknowledge")
	}
	h.runtime.handleFrame(consumer, egressFrameFor(buildTCPSegment(tcpSegment{
		SourceIP: syn.SourceIP, DestinationIP: syn.DestinationIP,
		SourcePort: syn.SourcePort, DestinationPort: syn.DestinationPort,
		Seq: syn.Seq + 1, Ack: segments[0].Seq + 1, Flags: tcpFlagACK, Window: 65535,
	})), flowEpoch)
}

func (h *egressHarness) sawFin() bool {
	for _, segment := range h.segments() {
		if segment.has(tcpFlagFIN) {
			return true
		}
	}
	return false
}

// A clean EOF is a half-close, not a failure. Turning it into a reset would discard a response the
// consumer is still entitled to read.
func TestEgressRuntimeTurnsSocketEOFIntoAFin(t *testing.T) {
	harness := newEgressHarness(t)
	syn := egressSyn(t, "100.96.0.1", 40000, "203.0.113.10", 443)
	harness.runtime.handleFrame(7, egressFrameFor(buildTCPSegment(syn)), flowEpoch)
	harness.waitFor("the flow to open", func() bool { return harness.runtime.flows.size() == 1 })
	harness.completeHandshake(7, syn)
	harness.reset()

	harness.socket(0).readErr <- io.EOF

	harness.waitFor("a FIN for the consumer", harness.sawFin)
	if harness.sawReset() {
		t.Error("a clean EOF was reported as a reset")
	}
}

// A socket that ends while the handshake is still in flight owes the consumer a FIN as soon as the
// handshake completes. Sending it earlier would run ahead of a sequence space the consumer has not
// acknowledged; never sending it leaves the flow open until the idle timer collects it, with the
// consumer waiting on a connection that is already over.
func TestEgressRuntimeDefersAFinUntilTheHandshakeCompletes(t *testing.T) {
	harness := newEgressHarness(t)
	syn := egressSyn(t, "100.96.0.1", 40000, "203.0.113.10", 443)
	harness.runtime.handleFrame(7, egressFrameFor(buildTCPSegment(syn)), flowEpoch)
	harness.waitFor("the flow to open", func() bool { return harness.runtime.flows.size() == 1 })

	harness.socket(0).readErr <- io.EOF
	// Wait for the reader goroutine to have taken the error, so the check below is about what the
	// state machine decided rather than about whether it has looked yet.
	harness.waitFor("the reader to observe the EOF", func() bool {
		return len(harness.socket(0).readErr) == 0
	})
	if harness.sawFin() {
		t.Fatal("a FIN was sent before the consumer acknowledged the SYN-ACK")
	}

	harness.completeHandshake(7, syn)
	harness.waitFor("the deferred FIN", harness.sawFin)
	if harness.sawReset() {
		t.Error("the deferred close was turned into a reset")
	}
}

// Revocation must take effect while traffic is in flight, not at the next idle sweep.
func TestEgressRuntimeRevokesLiveFlowsImmediately(t *testing.T) {
	harness := newEgressHarness(t)
	harness.runtime.handleFrame(7, egressFrameFor(buildTCPSegment(
		egressSyn(t, "100.96.0.1", 40000, "203.0.113.10", 443))), flowEpoch)
	harness.runtime.handleFrame(9, egressFrameFor(buildTCPSegment(
		egressSyn(t, "100.96.0.2", 40000, "203.0.113.11", 443))), flowEpoch)
	harness.waitFor("both flows to open", func() bool { return harness.runtime.flows.size() == 2 })
	harness.reset()

	harness.runtime.revokeConsumer(7, flowEpoch)

	if harness.runtime.flows.size() != 1 {
		t.Errorf("%d flows left, want the other consumer untouched", harness.runtime.flows.size())
	}
	if !harness.socket(0).isClosed() {
		t.Error("the revoked flow's socket stayed open")
	}
	if harness.socket(1).isClosed() {
		t.Error("revoking one consumer closed another's socket")
	}
	if codes := harness.rejectCodes(); len(codes) != 1 || codes[0] != egressCodePeerACLDenied {
		t.Errorf("reject codes = %v", codes)
	}
	if !harness.sawReset() {
		t.Error("the revoked consumer got no reset")
	}
}

// Turning the switch off means now, not at the next idle sweep.
func TestEgressRuntimeDrainsWhenTheSwitchGoesOff(t *testing.T) {
	harness := newEgressHarness(t)
	harness.runtime.handleFrame(7, egressFrameFor(buildTCPSegment(
		egressSyn(t, "100.96.0.1", 40000, "203.0.113.10", 443))), flowEpoch)
	harness.waitFor("the flow to open", func() bool { return harness.runtime.flows.size() == 1 })

	disabled := testEgressPolicy("203.0.113.0/24")
	disabled.Enabled = false
	harness.runtime.applyPolicy(disabled, newEgressContext(), flowEpoch)

	if harness.runtime.flows.size() != 0 {
		t.Errorf("%d flows survived the switch going off", harness.runtime.flows.size())
	}
	if !harness.socket(0).isClosed() {
		t.Error("a socket survived the switch going off")
	}
	// A further attempt must be refused rather than opening on a disabled egress.
	harness.reset()
	harness.runtime.handleFrame(7, egressFrameFor(buildTCPSegment(
		egressSyn(t, "100.96.0.1", 40002, "203.0.113.10", 443))), flowEpoch)
	if codes := harness.rejectCodes(); len(codes) != 1 || codes[0] != egressCodeDisabled {
		t.Errorf("reject codes after disable = %v", codes)
	}
}

// A narrowed policy closes the flows it no longer covers, and tells each one why.
func TestEgressRuntimeClosesFlowsANarrowedPolicyDrops(t *testing.T) {
	harness := newEgressHarness(t, "203.0.113.0/24", "198.51.100.0/24")
	harness.runtime.handleFrame(7, egressFrameFor(buildTCPSegment(
		egressSyn(t, "100.96.0.1", 40000, "203.0.113.10", 443))), flowEpoch)
	harness.runtime.handleFrame(7, egressFrameFor(buildTCPSegment(
		egressSyn(t, "100.96.0.1", 40001, "198.51.100.10", 443))), flowEpoch)
	harness.waitFor("both flows to open", func() bool { return harness.runtime.flows.size() == 2 })
	harness.reset()

	harness.runtime.applyPolicy(testEgressPolicy("203.0.113.0/24"), newEgressContext(), flowEpoch)

	if harness.runtime.flows.size() != 1 {
		t.Errorf("%d flows left, want the one the policy still covers", harness.runtime.flows.size())
	}
	if codes := harness.rejectCodes(); len(codes) != 1 || codes[0] != egressCodeDestinationDenied {
		t.Errorf("reject codes = %v", codes)
	}
}

// A purge speaks for its sender's flows. Acting on it for everyone would let any consumer tear down
// every other consumer's traffic with one message.
func TestEgressRuntimePurgeOnlyTouchesItsSender(t *testing.T) {
	harness := newEgressHarness(t)
	harness.runtime.handleFrame(7, egressFrameFor(buildTCPSegment(
		egressSyn(t, "100.96.0.1", 40000, "203.0.113.10", 443))), flowEpoch)
	harness.runtime.handleFrame(9, egressFrameFor(buildTCPSegment(
		egressSyn(t, "100.96.0.2", 40000, "203.0.113.10", 443))), flowEpoch)
	harness.waitFor("both flows to open", func() bool { return harness.runtime.flows.size() == 2 })

	body, err := encodePeerEgressControl(peerEgressControl{
		Type: peerEgressControlFlowPurge, Destinations: []string{"203.0.113.0/24"},
	})
	if err != nil {
		t.Fatal(err)
	}
	harness.runtime.handleFrame(7, encodePeerEgressFrame(peerEgressTypeControl, false, body), flowEpoch)

	if harness.runtime.flows.size() != 1 {
		t.Errorf("%d flows left, want only the sender's closed", harness.runtime.flows.size())
	}
	if harness.socket(1).isClosed() {
		t.Error("one consumer's purge closed another consumer's socket")
	}
}

// UDP has no handshake, so the first datagram is the authorization point and the reply path has to
// be built from the flow key rather than from whatever the socket reports.
func TestEgressRuntimeCarriesAUDPSession(t *testing.T) {
	harness := newEgressHarness(t)
	query := udpDatagram{
		SourceIP: testAddr(t, "100.96.0.1"), DestinationIP: testAddr(t, "203.0.113.53"),
		SourcePort: 51000, DestinationPort: 53, Payload: []byte("query"),
	}
	harness.runtime.handleFrame(7, egressFrameFor(buildUDPDatagram(query)), flowEpoch)

	harness.waitFor("the query to reach the socket", func() bool {
		return harness.dialCount() == 1 && len(harness.socket(0).written()) == 1
	})
	harness.socket(0).reads <- []byte("answer")

	harness.waitFor("the reply to reach the consumer", func() bool {
		return len(harness.datagrams()) > 0
	})
	reply := harness.datagrams()[0]
	if reply.SourceIP != query.DestinationIP || reply.DestinationIP != query.SourceIP {
		t.Error("the reply did not mirror the flow's addresses")
	}
	if reply.SourcePort != query.DestinationPort || reply.DestinationPort != query.SourcePort {
		t.Errorf("reply ports = %d -> %d", reply.SourcePort, reply.DestinationPort)
	}
	if string(reply.Payload) != "answer" {
		t.Errorf("reply payload = %q", reply.Payload)
	}
}

// Nothing in UDP says a session ended, so without this the socket would be held forever.
func TestEgressRuntimeExpiresAnIdleUDPSession(t *testing.T) {
	harness := newEgressHarness(t)
	policy := testEgressPolicy("203.0.113.0/24")
	policy.Limits = egressLimits{IdleTimeoutSeconds: 30}
	harness.runtime.applyPolicy(policy, newEgressContext(), flowEpoch)

	harness.runtime.handleFrame(7, egressFrameFor(buildUDPDatagram(udpDatagram{
		SourceIP: testAddr(t, "100.96.0.1"), DestinationIP: testAddr(t, "203.0.113.53"),
		SourcePort: 51000, DestinationPort: 53, Payload: []byte("query"),
	})), flowEpoch)
	harness.waitFor("the session to open", func() bool { return harness.runtime.flows.size() == 1 })

	harness.runtime.onTick(flowEpoch.Add(10 * time.Second))
	if harness.runtime.flows.size() != 1 {
		t.Fatal("the session expired before its timeout")
	}
	harness.runtime.onTick(flowEpoch.Add(31 * time.Second))
	if harness.runtime.flows.size() != 0 {
		t.Error("the session outlived its idle timeout")
	}
	if !harness.socket(0).isClosed() {
		t.Error("an expired session left its socket open")
	}
	// An expiring session is the normal end of life, not something to report as blocked traffic.
	if counts := harness.runtime.rejections.drainCounts(); len(counts) != 0 {
		t.Errorf("idle expiry entered the refusal aggregate: %v", counts)
	}
}

// A stray segment for a flow that was never opened gets a reset, which is what tells a consumer
// holding stale state to give up rather than retry into silence.
func TestEgressRuntimeResetsSegmentsForUnknownFlows(t *testing.T) {
	harness := newEgressHarness(t)
	stray := tcpSegment{
		SourceIP: testAddr(t, "100.96.0.1"), DestinationIP: testAddr(t, "203.0.113.10"),
		SourcePort: 40000, DestinationPort: 443, Seq: 5000, Ack: 9000,
		Flags: tcpFlagACK, Window: 65535, Payload: []byte("stale"),
	}
	harness.runtime.handleFrame(7, egressFrameFor(buildTCPSegment(stray)), flowEpoch)

	if harness.dialCount() != 0 {
		t.Error("a stray segment opened a socket")
	}
	if !harness.sawReset() {
		t.Error("a stray segment got no reset")
	}
}

// Shutdown has to have stopped traffic by the time it returns, not merely have asked it to stop.
func TestEgressRuntimeShutdownReleasesEverything(t *testing.T) {
	harness := newEgressHarness(t)
	harness.runtime.handleFrame(7, egressFrameFor(buildTCPSegment(
		egressSyn(t, "100.96.0.1", 40000, "203.0.113.10", 443))), flowEpoch)
	harness.runtime.handleFrame(7, egressFrameFor(buildUDPDatagram(udpDatagram{
		SourceIP: testAddr(t, "100.96.0.1"), DestinationIP: testAddr(t, "203.0.113.53"),
		SourcePort: 51000, DestinationPort: 53, Payload: []byte("query"),
	})), flowEpoch)
	harness.waitFor("both flows to open", func() bool { return harness.runtime.flows.size() == 2 })

	harness.runtime.shutdown(flowEpoch)

	if harness.runtime.flows.size() != 0 {
		t.Errorf("%d flows survived shutdown", harness.runtime.flows.size())
	}
	for index := 0; index < 2; index++ {
		if !harness.socket(index).isClosed() {
			t.Errorf("socket %d survived shutdown", index)
		}
	}
	harness.reset()
	harness.runtime.handleFrame(7, egressFrameFor(buildTCPSegment(
		egressSyn(t, "100.96.0.1", 40003, "203.0.113.10", 443))), flowEpoch)
	if harness.dialCount() != 2 {
		t.Error("a shut-down runtime opened a new socket")
	}
}

// Forwarding a protocol the egress does not account for would leak traffic past the policy, so it
// is refused rather than passed through.
func TestEgressRuntimeRefusesProtocolsItDoesNotCarry(t *testing.T) {
	harness := newEgressHarness(t, "0.0.0.0/0")
	// A minimal ICMP echo request; only the IPv4 header matters to the dispatch.
	packet := make([]byte, 28)
	packet[0] = 0x45
	packet[2], packet[3] = 0, 28
	packet[9] = ipv4ProtocolICMP
	copy(packet[12:16], []byte{100, 96, 0, 1})
	copy(packet[16:20], []byte{203, 0, 113, 10})
	packet[20] = 8

	harness.runtime.handleFrame(7, egressFrameFor(packet), flowEpoch)

	if harness.dialCount() != 0 {
		t.Error("an unsupported protocol opened a socket")
	}
	if codes := harness.rejectCodes(); len(codes) != 1 || codes[0] != egressCodeProtocolDenied {
		t.Errorf("reject codes = %v", codes)
	}
}
