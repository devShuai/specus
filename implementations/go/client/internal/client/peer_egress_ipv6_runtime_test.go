package client

import (
	"bytes"
	"encoding/binary"
	"io"
	"log"
	"net"
	"sync"
	"testing"
	"time"
)

// The egress runtime carrying IPv6 (protocol/spec/peer-egress.md, IPv6 数据面, 出口), mirroring the
// IPv4 suites: real bytes over real sockets, and the refusals that keep a consumer to its own
// address and out of the mesh.

// egressIPv6ConsumerMesh is the session peer's mesh IPv4 in these tests; its derived address is the
// only source the egress accepts from it.
const egressIPv6ConsumerMesh = "100.96.0.1"

func egressIPv6Consumer(t *testing.T) [16]byte {
	t.Helper()
	return egressMeshAddress6(testAddr(t, egressIPv6ConsumerMesh))
}

func egressSyn6(t *testing.T, sourcePort int, destination string, destinationPort int) tcpSegment {
	t.Helper()
	return tcpSegment{
		IPv6: true, SourceIP6: egressIPv6Consumer(t), DestinationIP6: mustEgressAddress6(t, destination),
		SourcePort: uint16(sourcePort), DestinationPort: uint16(destinationPort),
		Seq: 1000, Flags: tcpFlagSYN, Window: 65535, MSS: 1360,
	}
}

// packets6 returns the IPv6 packets the runtime sent back to a consumer, as written.
func (h *egressHarness) packets6() [][]byte {
	h.mu.Lock()
	defer h.mu.Unlock()
	var out [][]byte
	for _, raw := range h.frames {
		frame, code := parsePeerEgressFrameFor(raw, true)
		if code == "" && frame.Type == peerEgressTypeIPPacket && frame.Inner.IPv6 {
			out = append(out, frame.Body)
		}
	}
	return out
}

func (h *egressHarness) segments6() []tcpSegment {
	var out []tcpSegment
	for _, packet := range h.packets6() {
		if segment, ok := parseTCPSegment6(packet); ok {
			out = append(out, segment)
		}
	}
	return out
}

func (h *egressHarness) frameCount() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.frames)
}

// checkReturnHeader holds a returned packet to what the spec fixes: version 6, traffic class and flow
// label zero, hop limit 64, from the target to the consumer's derived address.
func checkReturnHeader(t *testing.T, packet []byte, source [16]byte, destination [16]byte) {
	t.Helper()
	if binary.BigEndian.Uint32(packet[0:4]) != 0x60000000 {
		t.Errorf("version, traffic class and flow label = %08x, want 60000000", binary.BigEndian.Uint32(packet[0:4]))
	}
	if packet[7] != ipv6HopLimit {
		t.Errorf("hop limit = %d, want %d", packet[7], ipv6HopLimit)
	}
	if [16]byte(packet[8:24]) != source || [16]byte(packet[24:40]) != destination {
		t.Errorf("addresses = %s -> %s, want %s -> %s", formatEgressAddress6([16]byte(packet[8:24])),
			formatEgressAddress6([16]byte(packet[24:40])), formatEgressAddress6(source), formatEgressAddress6(destination))
	}
}

// listenIPv6Loopback starts a listener on ::1, or skips: a host without IPv6 loopback cannot run the
// real-socket half of this suite.
func listenIPv6Loopback(t *testing.T, network string) (net.Listener, net.PacketConn) {
	t.Helper()
	if network == "tcp6" {
		listener, err := net.Listen(network, "[::1]:0")
		if err != nil {
			t.Skipf("no IPv6 loopback on this host (%v); the IPv6 real-socket tests need ::1", err)
		}
		t.Cleanup(func() { _ = listener.Close() })
		return listener, nil
	}
	packet, err := net.ListenPacket(network, "[::1]:0")
	if err != nil {
		t.Skipf("no IPv6 loopback on this host (%v); the IPv6 real-socket tests need ::1", err)
	}
	t.Cleanup(func() { _ = packet.Close() })
	return nil, packet
}

// testConsumer6 is the IPv6 counterpart of testConsumer: its own sequence space, and only what it
// reads off the wire.
type testConsumer6 struct {
	t       *testing.T
	runtime *egressRuntime
	local   [16]byte
	remote  [16]byte
	port    uint16
	target  uint16

	mu        sync.Mutex
	seq, ack  uint32
	packets   [][]byte
	inbound   []tcpSegment
	received  []byte
	datagrams []udpDatagram
}

// startEgressAgainst6 builds a runtime whose dialer reaches target on ::1 while the consumer and the
// policy both speak the routable destination, as startEgressAgainst does for IPv4: ::1 is on the
// forced-deny list, so naming it would only ever prove the refusal.
func startEgressAgainst6(t *testing.T, target string, destination string) *testConsumer6 {
	t.Helper()
	consumer := &testConsumer6{
		t: t, local: egressIPv6Consumer(t), remote: mustEgressAddress6(t, destination), port: 40000, target: 443,
		seq: 1000,
	}
	consumer.runtime = newEgressRuntime(log.New(io.Discard, "", 0),
		func(_ int64, frame []byte) error {
			consumer.onFrame(append([]byte(nil), frame...))
			return nil
		},
		func(protocol string, _ string, timeout time.Duration) (net.Conn, error) {
			return net.DialTimeout(protocol, target, timeout)
		})
	consumer.runtime.applyPolicy(testEgressPolicy(destination+"/128"), newEgressContext(), time.Now())
	t.Cleanup(func() { consumer.runtime.shutdown(time.Now()) })
	return consumer
}

func (c *testConsumer6) onFrame(raw []byte) {
	frame, code := parsePeerEgressFrameFor(raw, true)
	if code != "" {
		c.t.Errorf("the egress sent a frame that does not parse: %s", code)
		return
	}
	if frame.Type != peerEgressTypeIPPacket {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.packets = append(c.packets, frame.Body)
	if datagram, ok := parseUDPDatagram6(frame.Body); ok {
		c.datagrams = append(c.datagrams, datagram)
		return
	}
	segment, ok := parseTCPSegment6(frame.Body)
	if !ok {
		c.t.Error("the egress sent an IPv6 packet that is neither TCP nor UDP")
		return
	}
	c.inbound = append(c.inbound, segment)
	if len(segment.Payload) > 0 {
		c.received = append(c.received, segment.Payload...)
		c.ack = segment.Seq + uint32(len(segment.Payload))
	}
}

func (c *testConsumer6) send(flags uint8, payload []byte) {
	c.mu.Lock()
	segment := tcpSegment{
		IPv6: true, SourceIP6: c.local, DestinationIP6: c.remote,
		SourcePort: c.port, DestinationPort: c.target,
		Seq: c.seq, Ack: c.ack, Flags: flags, Window: 65535, Payload: payload,
	}
	if flags&tcpFlagSYN != 0 {
		segment.MSS = 1360
	}
	c.seq += segment.segmentLength()
	c.mu.Unlock()
	c.runtime.handleFrameFrom(7, egressIPv6ConsumerMesh, egressFrameFor(buildTCPSegment(segment)), time.Now())
}

func (c *testConsumer6) waitFor(what string, condition func() bool) {
	c.t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		c.mu.Lock()
		done := condition()
		c.mu.Unlock()
		if done {
			return
		}
		time.Sleep(time.Millisecond)
	}
	c.t.Fatalf("timed out waiting for %s", what)
}

// A handshake, a byte each way and the headers of everything returned, through the user-space stack
// to a real listener on ::1.
func TestEgressIPv6CarriesTCPEndToEnd(t *testing.T) {
	listener, _ := listenIPv6Loopback(t, "tcp6")
	served := make(chan struct{})
	go func() {
		defer close(served)
		socket, err := listener.Accept()
		if err != nil {
			return
		}
		defer socket.Close()
		buffer := make([]byte, 64)
		read, err := socket.Read(buffer)
		if err != nil {
			return
		}
		_, _ = socket.Write(append([]byte("echo:"), buffer[:read]...))
	}()

	consumer := startEgressAgainst6(t, listener.Addr().String(), "2001:db8:1::c8")
	consumer.send(tcpFlagSYN, nil)
	var synAck tcpSegment
	consumer.waitFor("the SYN-ACK", func() bool {
		for _, segment := range consumer.inbound {
			if segment.has(tcpFlagSYN) && segment.has(tcpFlagACK) {
				synAck = segment
				consumer.ack = segment.Seq + 1
				return true
			}
		}
		return false
	})
	// The path MTU the stack starts from is 1280; an IPv6 header and a TCP header come out of it.
	if synAck.MSS != egressDefaultPathMTU-ipv6HeaderLen-tcpMinHeaderLen {
		t.Errorf("SYN-ACK MSS = %d, want %d", synAck.MSS, egressDefaultPathMTU-ipv6HeaderLen-tcpMinHeaderLen)
	}
	consumer.send(tcpFlagACK, nil)
	consumer.send(tcpFlagACK|tcpFlagPSH, []byte("hello"))

	consumer.waitFor("the echoed reply", func() bool { return bytes.Equal(consumer.received, []byte("echo:hello")) })
	<-served

	consumer.mu.Lock()
	packets := append([][]byte(nil), consumer.packets...)
	consumer.mu.Unlock()
	for _, packet := range packets {
		checkReturnHeader(t, packet, consumer.remote, consumer.local)
	}
}

// A datagram out and its answer back, over a real UDP socket on ::1.
func TestEgressIPv6CarriesUDPEndToEnd(t *testing.T) {
	_, listener := listenIPv6Loopback(t, "udp6")
	go func() {
		buffer := make([]byte, 64)
		read, from, err := listener.ReadFrom(buffer)
		if err != nil {
			return
		}
		_, _ = listener.WriteTo(append([]byte("answer:"), buffer[:read]...), from)
	}()

	consumer := startEgressAgainst6(t, listener.LocalAddr().String(), "2001:db8:1::35")
	query := udpDatagram{
		IPv6: true, SourceIP6: consumer.local, DestinationIP6: consumer.remote,
		SourcePort: 51000, DestinationPort: 53, Payload: []byte("query"),
	}
	consumer.runtime.handleFrameFrom(7, egressIPv6ConsumerMesh, egressFrameFor(buildUDPDatagram(query)), time.Now())

	var reply udpDatagram
	consumer.waitFor("the answer", func() bool {
		if len(consumer.datagrams) == 0 {
			return false
		}
		reply = consumer.datagrams[0]
		return true
	})
	if string(reply.Payload) != "answer:query" {
		t.Errorf("reply payload = %q", reply.Payload)
	}
	if reply.SourceIP6 != query.DestinationIP6 || reply.DestinationIP6 != query.SourceIP6 ||
		reply.SourcePort != query.DestinationPort || reply.DestinationPort != query.SourcePort {
		t.Errorf("the reply did not mirror the flow: %+v", reply)
	}
	consumer.mu.Lock()
	packet := consumer.packets[0]
	consumer.mu.Unlock()
	checkReturnHeader(t, packet, consumer.remote, consumer.local)
}

// A consumer speaks only for its own derived address. A packet from any other source -- another
// device's derived address, an address outside the prefix -- is dropped before anything is judged,
// opened or answered, and so is every IPv6 packet from a session whose mesh address is unknown.
func TestEgressIPv6DropsAForgedSource(t *testing.T) {
	for name, send := range map[string]func(*egressHarness, tcpSegment){
		"another device's address": func(h *egressHarness, syn tcpSegment) {
			syn.SourceIP6 = egressMeshAddress6(testAddr(t, "100.96.0.2"))
			h.runtime.handleFrameFrom(7, egressIPv6ConsumerMesh, egressFrameFor(buildTCPSegment(syn)), flowEpoch)
		},
		"an address outside the prefix": func(h *egressHarness, syn tcpSegment) {
			syn.SourceIP6 = mustEgressAddress6(t, "2001:db8:ffff::1")
			h.runtime.handleFrameFrom(7, egressIPv6ConsumerMesh, egressFrameFor(buildTCPSegment(syn)), flowEpoch)
		},
		"a session without a mesh address": func(h *egressHarness, syn tcpSegment) {
			h.runtime.handleFrame(7, egressFrameFor(buildTCPSegment(syn)), flowEpoch)
		},
		"a datagram from another device": func(h *egressHarness, syn tcpSegment) {
			h.runtime.handleFrameFrom(9, "100.96.0.9", egressFrameFor(buildUDPDatagram(udpDatagram{
				IPv6: true, SourceIP6: syn.SourceIP6, DestinationIP6: syn.DestinationIP6,
				SourcePort: 51000, DestinationPort: 53, Payload: []byte("query"),
			})), flowEpoch)
		},
	} {
		t.Run(name, func(t *testing.T) {
			harness := newEgressHarness(t, "::/0")
			send(harness, egressSyn6(t, 40000, "2001:db8:1::c8", 443))
			if harness.dialCount() != 0 || harness.runtime.flows.size() != 0 {
				t.Error("a packet with a forged source opened a flow")
			}
			if harness.frameCount() != 0 {
				t.Errorf("a packet with a forged source was answered with %d frames", harness.frameCount())
			}
		})
	}
	// And the same SYN from the right address opens, so the drop above is the source and nothing else.
	harness := newEgressHarness(t, "::/0")
	harness.runtime.handleFrameFrom(7, egressIPv6ConsumerMesh,
		egressFrameFor(buildTCPSegment(egressSyn6(t, 40000, "2001:db8:1::c8", 443))), flowEpoch)
	if harness.dialCount() != 1 {
		t.Fatalf("the consumer's own address dialled %d times, want 1", harness.dialCount())
	}
}

// The derived prefix is the mesh to IPv6: a destination inside it is refused the way a mesh IPv4
// destination is, however broad the policy, and the consumer gets an IPv6 reset and a flow-reject
// written in IPv6.
func TestEgressIPv6RefusesAMeshDestination(t *testing.T) {
	harness := newEgressHarness(t, "::/0")
	harness.runtime.applyPolicy(func() egressPolicy {
		policy := testEgressPolicy("::/0", "fc00::/7")
		policy.Scope = egressScopeLAN
		return policy
	}(), newEgressContext(), flowEpoch)
	destination := "fd53:7065:6375:7300::6460:2"
	harness.runtime.handleFrameFrom(7, egressIPv6ConsumerMesh,
		egressFrameFor(buildTCPSegment(egressSyn6(t, 40000, destination, 22))), flowEpoch)

	if harness.dialCount() != 0 {
		t.Error("a mesh destination was dialled")
	}
	controls := harness.controls()
	if len(controls) != 1 || controls[0].Code != egressCodeForbiddenDestType {
		t.Fatalf("controls = %+v, want one %s", controls, egressCodeForbiddenDestType)
	}
	if controls[0].SourceIP != "fd53:7065:6375:7300::6460:1" || controls[0].DestinationIP != destination ||
		controls[0].Protocol != "tcp" || controls[0].DestinationPort != 22 {
		t.Errorf("flow-reject = %+v", controls[0])
	}
	segments := harness.segments6()
	if len(segments) != 1 || !segments[0].has(tcpFlagRST) {
		t.Fatalf("segments = %+v, want one reset", segments)
	}
	checkReturnHeader(t, harness.packets6()[0], mustEgressAddress6(t, destination), egressIPv6Consumer(t))
}

// ICMPv6 is refused the way ICMP over IPv4 is, before the source or anything else is looked at.
func TestEgressIPv6RefusesICMPv6(t *testing.T) {
	harness := newEgressHarness(t, "::/0")
	packet := make([]byte, ipv6HeaderLen+8)
	writeIPv6Header(packet, ipv6NextHeaderICMP, 8, egressIPv6Consumer(t), mustEgressAddress6(t, "2001:db8:1::c8"))
	packet[ipv6HeaderLen] = 128 // echo request
	harness.runtime.handleFrameFrom(7, egressIPv6ConsumerMesh, egressFrameFor(packet), flowEpoch)

	if harness.dialCount() != 0 {
		t.Error("ICMPv6 opened a socket")
	}
	if codes := harness.rejectCodes(); len(codes) != 1 || codes[0] != egressCodeProtocolDenied {
		t.Errorf("reject codes = %v, want [%s]", codes, egressCodeProtocolDenied)
	}
}

// A stray segment for an IPv6 flow that was never opened gets an IPv6 reset.
func TestEgressIPv6ResetsSegmentsForUnknownFlows(t *testing.T) {
	harness := newEgressHarness(t, "::/0")
	stray := egressSyn6(t, 40000, "2001:db8:1::c8", 443)
	stray.Flags, stray.Seq, stray.Ack, stray.MSS, stray.Payload = tcpFlagACK, 5000, 9000, 0, []byte("stale")
	harness.runtime.handleFrameFrom(7, egressIPv6ConsumerMesh, egressFrameFor(buildTCPSegment(stray)), flowEpoch)

	if harness.dialCount() != 0 {
		t.Error("a stray segment opened a socket")
	}
	segments := harness.segments6()
	if len(segments) != 1 || !segments[0].has(tcpFlagRST) || segments[0].Seq != 9000 {
		t.Fatalf("segments = %+v, want one reset at the stray's ACK", segments)
	}
}

// flow-purge names IPv6 prefixes as well, and a prefix closes only flows of its own family. A policy
// push that withdraws the IPv6 rule closes the IPv6 flow with a flow-reject written in IPv6.
func TestEgressIPv6FlowsArePurgedAndRevokedByFamily(t *testing.T) {
	harness := newEgressHarness(t, "203.0.113.0/24", "2001:db8:1::/48")
	harness.runtime.handleFrame(7, egressFrameFor(buildTCPSegment(egressSyn(t, "100.96.0.1", 40000, "203.0.113.10", 443))), flowEpoch)
	harness.runtime.handleFrameFrom(7, egressIPv6ConsumerMesh,
		egressFrameFor(buildTCPSegment(egressSyn6(t, 40001, "2001:db8:1::c8", 443))), flowEpoch)
	harness.waitFor("both flows to open", func() bool { return harness.runtime.flows.size() == 2 })

	// ::/0 holds no IPv4 flow, and 0.0.0.0/0 no IPv6 one.
	body, err := encodePeerEgressControl(peerEgressControl{
		Type: peerEgressControlFlowPurge, Destinations: []string{"0.0.0.0/0", "2001:db8:2::/48"},
	})
	if err != nil {
		t.Fatal(err)
	}
	harness.runtime.handleFrame(7, encodePeerEgressFrame(peerEgressTypeControl, false, body), flowEpoch)
	if harness.runtime.flows.size() != 1 || !harness.socket(0).isClosed() || harness.socket(1).isClosed() {
		t.Fatalf("an IPv4 purge reached the IPv6 flow or missed the IPv4 one: %d flows left", harness.runtime.flows.size())
	}

	harness.runtime.applyPolicy(testEgressPolicy("203.0.113.0/24"), newEgressContext(), flowEpoch)
	if harness.runtime.flows.size() != 0 || !harness.socket(1).isClosed() {
		t.Fatal("withdrawing the IPv6 rule left the IPv6 flow open")
	}
	var revoked *peerEgressControl
	for _, control := range harness.controls() {
		if control.Code == egressCodeDestinationDenied {
			revoked = &control
		}
	}
	if revoked == nil || revoked.SourceIP != "fd53:7065:6375:7300::6460:1" || revoked.DestinationIP != "2001:db8:1::c8" ||
		revoked.SourcePort != 40001 {
		t.Errorf("revocation flow-reject = %+v", revoked)
	}

	// An IPv6 purge reaches an IPv6 flow.
	harness.runtime.handleFrameFrom(7, egressIPv6ConsumerMesh,
		egressFrameFor(buildTCPSegment(egressSyn6(t, 40002, "2001:db8:1::c9", 443))), flowEpoch)
	harness.runtime.applyPolicy(testEgressPolicy("2001:db8:1::/48"), newEgressContext(), flowEpoch)
	harness.runtime.handleFrameFrom(7, egressIPv6ConsumerMesh,
		egressFrameFor(buildTCPSegment(egressSyn6(t, 40002, "2001:db8:1::c9", 443))), flowEpoch)
	harness.waitFor("the IPv6 flow to open", func() bool { return harness.runtime.flows.size() == 1 })
	body, err = encodePeerEgressControl(peerEgressControl{
		Type: peerEgressControlFlowPurge, Destinations: []string{"2001:db8:1::c9"},
	})
	if err != nil {
		t.Fatal(err)
	}
	harness.runtime.handleFrame(7, encodePeerEgressFrame(peerEgressTypeControl, false, body), flowEpoch)
	if harness.runtime.flows.size() != 0 {
		t.Error("an IPv6 purge left its flow open")
	}
}
