package client

import (
	"bytes"
	"testing"
	"time"
)

// Conformance suite for the user-space TCP termination stack.
//
// The state machine performs no I/O and reads no clock, so every case here drives it directly:
// segments in, segments and delivered bytes out, time supplied by the test. Loss and reordering are
// expressed by simply not feeding a segment, which is why none of this needs a network.
//
// P4 ports this stack to Java and .NET. These scenarios are the contract those ports have to meet,
// so they are written against protocol behaviour -- handshake, sequence space, half-close, reset,
// window edges -- and never against Go-specific structure.

const (
	testConsumerIP  = "100.96.0.1"
	testEgressIP    = "203.0.113.200"
	testConsumerPrt = 54321
	testTargetPort  = 443
	testPathMTU     = 1280
	testIdle        = 60 * time.Second
)

type tcpHarness struct {
	t        *testing.T
	conn     *tcpConn
	now      time.Time
	peerSeq  uint32
	peerWnd  uint16
	localIP  uint32
	remoteIP uint32
}

// newTCPHarness completes a handshake and hands back a flow in ESTABLISHED.
func newTCPHarness(t *testing.T) *tcpHarness {
	t.Helper()
	h := &tcpHarness{
		t:        t,
		now:      time.Unix(1_800_000_000, 0),
		peerSeq:  1000,
		peerWnd:  65535,
		localIP:  testAddr(t, testEgressIP),
		remoteIP: testAddr(t, testConsumerIP),
	}
	syn := tcpSegment{
		SourceIP: h.remoteIP, DestinationIP: h.localIP,
		SourcePort: testConsumerPrt, DestinationPort: testTargetPort,
		Seq: h.peerSeq, Flags: tcpFlagSYN, Window: h.peerWnd, MSS: 1200,
	}
	conn, output := acceptTCPSyn(syn, 5000, testPathMTU, testIdle, h.now)
	h.conn = conn

	synAck := h.expectOne(output, "SYN-ACK")
	if !synAck.has(tcpFlagSYN) || !synAck.has(tcpFlagACK) {
		t.Fatalf("expected SYN-ACK, flags = %#x", synAck.Flags)
	}
	if synAck.Ack != h.peerSeq+1 {
		t.Fatalf("SYN-ACK ack = %d, want %d", synAck.Ack, h.peerSeq+1)
	}
	h.peerSeq++

	// Consumer completes the handshake.
	h.feed(tcpSegment{Seq: h.peerSeq, Ack: synAck.Seq + 1, Flags: tcpFlagACK})
	if conn.state != tcpStateEstablished {
		t.Fatalf("state after handshake = %s", conn.state)
	}
	return h
}

// segment fills in the four-tuple and window a consumer segment always carries.
func (h *tcpHarness) segment(s tcpSegment) tcpSegment {
	s.SourceIP, s.DestinationIP = h.remoteIP, h.localIP
	s.SourcePort, s.DestinationPort = testConsumerPrt, testTargetPort
	if s.Window == 0 {
		s.Window = h.peerWnd
	}
	return s
}

func (h *tcpHarness) feed(s tcpSegment) tcpOutput {
	h.t.Helper()
	return h.conn.onSegment(h.segment(s), h.now)
}

func (h *tcpHarness) parse(output tcpOutput) []tcpSegment {
	h.t.Helper()
	parsed := make([]tcpSegment, 0, len(output.Segments))
	for _, packet := range output.Segments {
		segment, ok := parseTCPSegment(packet)
		if !ok {
			h.t.Fatal("the stack emitted a segment it cannot parse back")
		}
		parsed = append(parsed, segment)
	}
	return parsed
}

func (h *tcpHarness) expectOne(output tcpOutput, what string) tcpSegment {
	h.t.Helper()
	segments := h.parse(output)
	if len(segments) != 1 {
		h.t.Fatalf("expected one %s, got %d segments", what, len(segments))
	}
	return segments[0]
}

func (h *tcpHarness) advance(d time.Duration) { h.now = h.now.Add(d) }

// The real socket can end before the consumer acknowledges the SYN-ACK. A FIN sent then would run
// ahead of a sequence space the consumer has not accepted, so it is owed until the handshake
// completes. Dropping it instead leaves the flow open until the idle timer collects it, with the
// consumer waiting on a connection that is already over.
func TestTCPDefersAFinRaisedDuringTheHandshake(t *testing.T) {
	syn := tcpSegment{
		SourceIP: testAddr(t, testConsumerIP), DestinationIP: testAddr(t, testEgressIP),
		SourcePort: testConsumerPrt, DestinationPort: testTargetPort,
		Seq: 1000, Flags: tcpFlagSYN, Window: 65535, MSS: 1200,
	}
	now := time.Unix(1_800_000_000, 0)
	conn, output := acceptTCPSyn(syn, 5000, testPathMTU, testIdle, now)
	synAck, ok := parseTCPSegment(output.Segments[0])
	if !ok {
		t.Fatal("the SYN-ACK did not parse")
	}

	if closed := conn.onAppClose(now); len(closed.Segments) != 0 {
		t.Fatalf("a FIN was emitted before the handshake completed: %d segments", len(closed.Segments))
	}
	if conn.state != tcpStateSynReceived {
		t.Fatalf("state = %s, want the handshake still pending", conn.state)
	}

	completed := conn.onSegment(tcpSegment{
		SourceIP: syn.SourceIP, DestinationIP: syn.DestinationIP,
		SourcePort: syn.SourcePort, DestinationPort: syn.DestinationPort,
		Seq: syn.Seq + 1, Ack: synAck.Seq + 1, Flags: tcpFlagACK, Window: 65535,
	}, now)

	var sawFin bool
	for _, packet := range completed.Segments {
		if segment, parsed := parseTCPSegment(packet); parsed && segment.has(tcpFlagFIN) {
			sawFin = true
		}
	}
	if !sawFin {
		t.Error("the owed FIN was never sent")
	}
	if conn.state != tcpStateFinWait1 {
		t.Errorf("state = %s, want FIN_WAIT_1", conn.state)
	}
}

// A full handshake, a byte each way, and an orderly close from the consumer side.
func TestTCPFlowCompletesHandshakeDataAndClose(t *testing.T) {
	h := newTCPHarness(t)

	output := h.feed(tcpSegment{Seq: h.peerSeq, Ack: 5001, Flags: tcpFlagACK | tcpFlagPSH,
		Payload: []byte("GET / HTTP/1.1\r\n")})
	if !bytes.Equal(output.Deliver, []byte("GET / HTTP/1.1\r\n")) {
		t.Fatalf("delivered %q", output.Deliver)
	}
	h.peerSeq += 16
	if ack := h.expectOne(output, "ACK"); ack.Ack != h.peerSeq {
		t.Errorf("ack = %d, want %d", ack.Ack, h.peerSeq)
	}

	reply := h.conn.onAppData([]byte("HTTP/1.1 200 OK\r\n"), h.now)
	data := h.expectOne(reply, "data segment")
	if !bytes.Equal(data.Payload, []byte("HTTP/1.1 200 OK\r\n")) {
		t.Errorf("sent %q", data.Payload)
	}

	// Consumer closes; we owe a FIN once the real socket drains.
	output = h.feed(tcpSegment{Seq: h.peerSeq, Ack: data.Seq + uint32(len(data.Payload)), Flags: tcpFlagACK | tcpFlagFIN})
	if !output.CloseApp {
		t.Error("a FIN from the consumer must half-close the real socket")
	}
	if h.conn.state != tcpStateCloseWait {
		t.Fatalf("state = %s, want CLOSE_WAIT", h.conn.state)
	}
	h.peerSeq++

	closing := h.conn.onAppClose(h.now)
	fin := h.expectOne(closing, "FIN")
	if !fin.has(tcpFlagFIN) {
		t.Fatalf("expected FIN, flags = %#x", fin.Flags)
	}
	if h.conn.state != tcpStateLastAck {
		t.Fatalf("state = %s, want LAST_ACK", h.conn.state)
	}

	final := h.feed(tcpSegment{Seq: h.peerSeq, Ack: fin.Seq + 1, Flags: tcpFlagACK})
	if !final.Done || !h.conn.done() {
		t.Errorf("flow should be finished: done=%v state=%s", final.Done, h.conn.state)
	}
}

// Half-close: the consumer stops sending but must still receive. Closing the whole flow here would
// truncate a response the application is still writing.
func TestTCPHalfCloseKeepsTheReturnDirectionOpen(t *testing.T) {
	h := newTCPHarness(t)

	output := h.feed(tcpSegment{Seq: h.peerSeq, Ack: 5001, Flags: tcpFlagACK | tcpFlagFIN})
	if !output.CloseApp {
		t.Fatal("FIN did not half-close the application side")
	}
	if output.Done {
		t.Fatal("a half-close must not finish the flow")
	}
	h.peerSeq++

	reply := h.conn.onAppData([]byte("still writing"), h.now)
	data := h.expectOne(reply, "post-FIN data")
	if !bytes.Equal(data.Payload, []byte("still writing")) {
		t.Errorf("payload after half-close = %q", data.Payload)
	}
	if h.conn.state != tcpStateCloseWait {
		t.Errorf("state = %s, want CLOSE_WAIT", h.conn.state)
	}
}

// Out-of-order arrival must be buffered and released once the hole fills, not delivered early.
func TestTCPReordersOutOfOrderSegments(t *testing.T) {
	h := newTCPHarness(t)
	base := h.peerSeq

	// "world" arrives before "hello ".
	late := h.feed(tcpSegment{Seq: base + 6, Ack: 5001, Flags: tcpFlagACK, Payload: []byte("world")})
	if len(late.Deliver) != 0 {
		t.Fatalf("out-of-order payload was delivered early: %q", late.Deliver)
	}
	if ack := h.expectOne(late, "duplicate ACK"); ack.Ack != base {
		t.Errorf("ack = %d, want the still-missing %d", ack.Ack, base)
	}

	filled := h.feed(tcpSegment{Seq: base, Ack: 5001, Flags: tcpFlagACK, Payload: []byte("hello ")})
	if !bytes.Equal(filled.Deliver, []byte("hello world")) {
		t.Fatalf("delivered %q, want the reassembled stream", filled.Deliver)
	}
	if ack := h.expectOne(filled, "cumulative ACK"); ack.Ack != base+11 {
		t.Errorf("ack = %d, want %d", ack.Ack, base+11)
	}
}

// A retransmitted segment we already have must be acknowledged, never delivered twice.
func TestTCPDropsDuplicateDataButStillAcknowledges(t *testing.T) {
	h := newTCPHarness(t)
	base := h.peerSeq

	first := h.feed(tcpSegment{Seq: base, Ack: 5001, Flags: tcpFlagACK, Payload: []byte("abcd")})
	if !bytes.Equal(first.Deliver, []byte("abcd")) {
		t.Fatalf("delivered %q", first.Deliver)
	}

	again := h.feed(tcpSegment{Seq: base, Ack: 5001, Flags: tcpFlagACK, Payload: []byte("abcd")})
	if len(again.Deliver) != 0 {
		t.Errorf("duplicate was delivered a second time: %q", again.Deliver)
	}
	if ack := h.expectOne(again, "ACK"); ack.Ack != base+4 {
		t.Errorf("ack = %d, want %d", ack.Ack, base+4)
	}

	// A partial overlap: two of the four bytes are new.
	overlap := h.feed(tcpSegment{Seq: base + 2, Ack: 5001, Flags: tcpFlagACK, Payload: []byte("cdef")})
	if !bytes.Equal(overlap.Deliver, []byte("ef")) {
		t.Errorf("overlapping segment delivered %q, want only the new bytes", overlap.Deliver)
	}
}

// Unacknowledged data is resent after the RTO, and the flow gives up rather than retrying forever.
func TestTCPRetransmitsAndEventuallyGivesUp(t *testing.T) {
	h := newTCPHarness(t)

	sent := h.conn.onAppData([]byte("payload"), h.now)
	original := h.expectOne(sent, "data segment")

	// Nothing acknowledges it; the first tick before the RTO must stay quiet.
	quiet := h.conn.onTick(h.now.Add(tcpInitialRTO / 2))
	if len(quiet.Segments) != 0 {
		t.Fatal("retransmitted before the RTO elapsed")
	}

	h.advance(tcpInitialRTO)
	again := h.conn.onTick(h.now)
	resent := h.expectOne(again, "retransmission")
	if resent.Seq != original.Seq || !bytes.Equal(resent.Payload, original.Payload) {
		t.Errorf("retransmission did not match the original: seq %d vs %d", resent.Seq, original.Seq)
	}

	// Keep the flow silent past the retry ceiling; it must reset rather than retry indefinitely.
	for i := 0; i < tcpMaxRetransmits+2; i++ {
		h.advance(tcpMaxRTO)
		if out := h.conn.onTick(h.now); out.Reset {
			if !out.Done {
				t.Error("a reset flow must also be marked done")
			}
			return
		}
	}
	t.Fatal("the flow never gave up on an unacknowledged segment")
}

// Karn: a retransmitted segment yields an ambiguous RTT, so it must not feed the estimator.
func TestTCPKarnIgnoresAmbiguousRoundTripSamples(t *testing.T) {
	h := newTCPHarness(t)

	h.conn.onAppData([]byte("first"), h.now)
	h.advance(40 * time.Millisecond)
	h.feed(tcpSegment{Seq: h.peerSeq, Ack: 5001 + 5, Flags: tcpFlagACK})
	clean := h.conn.rto
	if h.conn.srtt == 0 {
		t.Fatal("a clean acknowledgement should have produced an RTT sample")
	}

	// Send again, let it retransmit, then acknowledge. The sample is ambiguous and must be dropped.
	before := h.conn.srtt
	h.conn.onAppData([]byte("second"), h.now)
	h.advance(tcpInitialRTO * 4)
	h.conn.onTick(h.now)
	h.advance(5 * time.Second)
	h.feed(tcpSegment{Seq: h.peerSeq, Ack: h.conn.sndNxt, Flags: tcpFlagACK})

	if h.conn.srtt != before {
		t.Errorf("srtt moved on an ambiguous sample: %v -> %v", before, h.conn.srtt)
	}
	if clean == 0 {
		t.Error("expected a usable RTO from the clean sample")
	}
}

// A reset inside the window ends the flow; one outside it is ignored, which is what stops a blind
// off-path attacker from tearing down flows by guessing sequence numbers.
func TestTCPAcceptsInWindowResetAndIgnoresOthers(t *testing.T) {
	h := newTCPHarness(t)

	stray := h.feed(tcpSegment{Seq: h.peerSeq + 500_000, Ack: 5001, Flags: tcpFlagRST})
	if stray.Done || stray.Reset {
		t.Fatal("an out-of-window reset tore down the flow")
	}
	if h.conn.done() {
		t.Fatal("flow closed on an out-of-window reset")
	}

	valid := h.feed(tcpSegment{Seq: h.peerSeq, Ack: 5001, Flags: tcpFlagRST})
	if !valid.Reset || !valid.Done {
		t.Errorf("in-window reset did not end the flow: %+v", valid)
	}
	if !h.conn.done() {
		t.Error("state should be CLOSED after a valid reset")
	}
}

// Data beyond the advertised window is refused, and the acknowledgement re-syncs the peer.
func TestTCPRefusesDataOutsideTheReceiveWindow(t *testing.T) {
	h := newTCPHarness(t)

	beyond := h.feed(tcpSegment{
		Seq: h.peerSeq + tcpReceiveWindow + 1, Ack: 5001,
		Flags: tcpFlagACK, Payload: []byte("too far ahead"),
	})
	if len(beyond.Deliver) != 0 {
		t.Fatalf("payload past the window was delivered: %q", beyond.Deliver)
	}
	if ack := h.expectOne(beyond, "window ACK"); ack.Ack != h.peerSeq {
		t.Errorf("ack = %d, want the window edge %d", ack.Ack, h.peerSeq)
	}

	// The edge itself is inside the window and must be accepted.
	edge := h.feed(tcpSegment{Seq: h.peerSeq, Ack: 5001, Flags: tcpFlagACK, Payload: []byte("ok")})
	if !bytes.Equal(edge.Deliver, []byte("ok")) {
		t.Errorf("window-edge payload was refused: %q", edge.Deliver)
	}
}

// An acknowledgement for something never sent is ignored rather than answered with a reset: a
// delayed duplicate would otherwise be able to kill a healthy flow.
func TestTCPIgnoresAcknowledgementOfUnsentData(t *testing.T) {
	h := newTCPHarness(t)
	before := h.conn.sndUna

	output := h.feed(tcpSegment{Seq: h.peerSeq, Ack: h.conn.sndNxt + 10_000, Flags: tcpFlagACK})
	if output.Reset || h.conn.done() {
		t.Fatal("a bogus acknowledgement reset the flow")
	}
	if h.conn.sndUna != before {
		t.Errorf("send window advanced on a bogus ack: %d -> %d", before, h.conn.sndUna)
	}
}

// A SYN arriving inside an established flow is a stale duplicate or an attack; RFC 793 says answer
// with a reset rather than silently re-handshaking.
func TestTCPResetsOnSynInsideAnEstablishedFlow(t *testing.T) {
	h := newTCPHarness(t)
	output := h.feed(tcpSegment{Seq: h.peerSeq, Ack: 5001, Flags: tcpFlagSYN})
	if !output.Reset {
		t.Fatal("a SYN inside an established flow was not reset")
	}
	segments := h.parse(output)
	if len(segments) == 0 || !segments[0].has(tcpFlagRST) {
		t.Error("expected an RST on the wire")
	}
}

// An idle flow holds a socket and a quota slot on the egress, so it is reclaimed rather than left
// pinned by a forgotten consumer.
func TestTCPReclaimsIdleFlows(t *testing.T) {
	h := newTCPHarness(t)

	h.advance(testIdle / 2)
	if out := h.conn.onTick(h.now); out.Done {
		t.Fatal("flow was reclaimed before the idle timeout")
	}
	h.advance(testIdle)
	out := h.conn.onTick(h.now)
	if !out.Done || !out.Reset {
		t.Errorf("idle flow was not reclaimed: %+v", out)
	}
}

// Revocation and quota breaches abort a live flow, which the consumer must see as a reset.
func TestTCPAbortResetsALiveFlow(t *testing.T) {
	h := newTCPHarness(t)
	output := h.conn.abort()
	if !output.Reset || !output.Done {
		t.Fatalf("abort did not tear the flow down: %+v", output)
	}
	segments := h.parse(output)
	if len(segments) != 1 || !segments[0].has(tcpFlagRST) {
		t.Error("abort should emit exactly one RST")
	}
	if second := h.conn.abort(); len(second.Segments) != 0 {
		t.Error("aborting twice sent a second reset")
	}
}

// We close first: FIN_WAIT_1 to FIN_WAIT_2 to TIME_WAIT, then the flow is reclaimed on its timer.
func TestTCPActiveCloseWalksThroughTimeWait(t *testing.T) {
	h := newTCPHarness(t)

	closing := h.conn.onAppClose(h.now)
	fin := h.expectOne(closing, "FIN")
	if h.conn.state != tcpStateFinWait1 {
		t.Fatalf("state = %s, want FIN_WAIT_1", h.conn.state)
	}

	h.feed(tcpSegment{Seq: h.peerSeq, Ack: fin.Seq + 1, Flags: tcpFlagACK})
	if h.conn.state != tcpStateFinWait2 {
		t.Fatalf("state = %s, want FIN_WAIT_2", h.conn.state)
	}

	h.feed(tcpSegment{Seq: h.peerSeq, Ack: fin.Seq + 1, Flags: tcpFlagACK | tcpFlagFIN})
	if h.conn.state != tcpStateTimeWait {
		t.Fatalf("state = %s, want TIME_WAIT", h.conn.state)
	}

	if out := h.conn.onTick(h.now.Add(tcpTimeWaitDuration / 2)); out.Done {
		t.Fatal("TIME_WAIT expired early")
	}
	h.advance(tcpTimeWaitDuration)
	if out := h.conn.onTick(h.now); !out.Done {
		t.Error("TIME_WAIT never expired")
	}
}

// Application writes are split at the negotiated MSS so the egress never emits a segment the mesh
// path would have to fragment.
func TestTCPSplitsApplicationWritesAtTheNegotiatedMSS(t *testing.T) {
	h := newTCPHarness(t)
	if h.conn.sndMSS > testPathMTU-ipv4MinHeaderLen-tcpMinHeaderLen {
		t.Fatalf("send MSS %d exceeds what the path allows", h.conn.sndMSS)
	}

	payload := bytes.Repeat([]byte("x"), h.conn.sndMSS*2+7)
	output := h.conn.onAppData(payload, h.now)
	segments := h.parse(output)
	if len(segments) != 3 {
		t.Fatalf("expected three segments, got %d", len(segments))
	}
	var reassembled []byte
	for index, segment := range segments {
		if index < 2 && len(segment.Payload) != h.conn.sndMSS {
			t.Errorf("segment %d carried %d bytes, want a full MSS", index, len(segment.Payload))
		}
		reassembled = append(reassembled, segment.Payload...)
	}
	if !bytes.Equal(reassembled, payload) {
		t.Error("splitting lost or reordered payload")
	}
}

// Data arriving after the peer's FIN is a protocol violation; refusing it tells the far end its
// stack is out of step instead of hiding the problem.
func TestTCPResetsOnDataAfterPeerFin(t *testing.T) {
	h := newTCPHarness(t)

	h.feed(tcpSegment{Seq: h.peerSeq, Ack: 5001, Flags: tcpFlagACK | tcpFlagFIN})
	h.peerSeq++

	output := h.feed(tcpSegment{Seq: h.peerSeq, Ack: 5001, Flags: tcpFlagACK, Payload: []byte("late")})
	if !output.Reset {
		t.Error("data after FIN did not reset the flow")
	}
}
