package client

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"testing"
)

// The segment layer sits under every flow the egress terminates, so a parser that accepts loosely
// here is a bug that only shows up as corrupted traffic much later.

func testAddr(t *testing.T, dotted string) uint32 {
	t.Helper()
	value, ok := parseEgressAddress(dotted)
	if !ok {
		t.Fatalf("%s did not parse", dotted)
	}
	return value
}

func TestTCPSegmentRoundTrips(t *testing.T) {
	original := tcpSegment{
		SourceIP:        testAddr(t, "100.96.0.1"),
		DestinationIP:   testAddr(t, "203.0.113.200"),
		SourcePort:      54321,
		DestinationPort: 443,
		Seq:             0x11223344,
		Ack:             0x55667788,
		Flags:           tcpFlagACK | tcpFlagPSH,
		Window:          65535,
		Payload:         []byte("specus-egress-payload"),
	}
	packet := buildTCPSegment(original)

	parsed, ok := parseTCPSegment(packet)
	if !ok {
		t.Fatal("a segment we built did not parse")
	}
	if parsed.SourceIP != original.SourceIP || parsed.DestinationIP != original.DestinationIP ||
		parsed.SourcePort != original.SourcePort || parsed.DestinationPort != original.DestinationPort ||
		parsed.Seq != original.Seq || parsed.Ack != original.Ack ||
		parsed.Flags != original.Flags || parsed.Window != original.Window {
		t.Errorf("header did not round trip: %+v", parsed)
	}
	if !bytes.Equal(parsed.Payload, original.Payload) {
		t.Errorf("payload = %q", parsed.Payload)
	}
}

func TestTCPSegmentCarriesMSSOnSyn(t *testing.T) {
	packet := buildTCPSegment(tcpSegment{
		SourceIP: testAddr(t, "203.0.113.200"), DestinationIP: testAddr(t, "100.96.0.1"),
		SourcePort: 443, DestinationPort: 54321,
		Flags: tcpFlagSYN | tcpFlagACK, Window: 65535, MSS: 1360,
	})
	parsed, ok := parseTCPSegment(packet)
	if !ok {
		t.Fatal("SYN-ACK did not parse")
	}
	if parsed.MSS != 1360 {
		t.Errorf("MSS = %d, want 1360", parsed.MSS)
	}
	// The header must stay 4-byte aligned once the option is padded.
	if dataOffset := int(packet[ipv4MinHeaderLen+12]>>4) * 4; dataOffset%4 != 0 || dataOffset < 24 {
		t.Errorf("data offset = %d", dataOffset)
	}
}

// A segment we cannot fully trust must not advance any state, so the parser refuses rather than
// returning a best-effort result.
func TestTCPSegmentRejectsUntrustworthyInput(t *testing.T) {
	good := buildTCPSegment(tcpSegment{
		SourceIP: testAddr(t, "100.96.0.1"), DestinationIP: testAddr(t, "203.0.113.200"),
		SourcePort: 54321, DestinationPort: 443, Flags: tcpFlagSYN, Window: 65535,
	})

	corrupted := append([]byte(nil), good...)
	corrupted[ipv4MinHeaderLen+16] ^= 0xff
	if _, ok := parseTCPSegment(corrupted); ok {
		t.Error("a segment with a bad TCP checksum was accepted")
	}

	if _, ok := parseTCPSegment(good[:ipv4MinHeaderLen+10]); ok {
		t.Error("a truncated segment was accepted")
	}

	shortOffset := append([]byte(nil), good...)
	shortOffset[ipv4MinHeaderLen+12] = 0x30 // data offset 12 bytes, below the 20-byte minimum
	if _, ok := parseTCPSegment(shortOffset); ok {
		t.Error("a segment claiming a sub-minimum data offset was accepted")
	}

	udp := append([]byte(nil), good...)
	udp[9] = ipv4ProtocolUDP
	if _, ok := parseTCPSegment(udp); ok {
		t.Error("a non-TCP packet was accepted")
	}
}

// RFC 793: a reset answering a segment that carries ACK takes its sequence from that ACK; otherwise
// it acknowledges the incoming sequence space. Getting this wrong leaves the consumer retrying a
// refused flow until its own timeout instead of failing fast.
func TestTCPResetFollowsTheIncomingSegment(t *testing.T) {
	syn := tcpSegment{
		SourceIP: testAddr(t, "100.96.0.1"), DestinationIP: testAddr(t, "203.0.113.9"),
		SourcePort: 54321, DestinationPort: 22, Seq: 1000, Flags: tcpFlagSYN,
	}
	reset, ok := parseTCPSegment(buildTCPReset(syn))
	if !ok {
		t.Fatal("reset for a SYN did not parse")
	}
	if !reset.has(tcpFlagRST) || !reset.has(tcpFlagACK) {
		t.Errorf("flags = %#x", reset.Flags)
	}
	// SYN occupies one sequence number, so the reset acknowledges 1001.
	if reset.Ack != 1001 {
		t.Errorf("ack = %d, want 1001", reset.Ack)
	}
	if reset.SourcePort != 22 || reset.DestinationPort != 54321 {
		t.Errorf("reset was not mirrored: %d -> %d", reset.SourcePort, reset.DestinationPort)
	}

	acked := tcpSegment{
		SourceIP: syn.SourceIP, DestinationIP: syn.DestinationIP,
		SourcePort: syn.SourcePort, DestinationPort: syn.DestinationPort,
		Seq: 2000, Ack: 9000, Flags: tcpFlagACK,
	}
	reset, ok = parseTCPSegment(buildTCPReset(acked))
	if !ok {
		t.Fatal("reset for an ACK did not parse")
	}
	if reset.Seq != 9000 {
		t.Errorf("seq = %d, want the incoming ack 9000", reset.Seq)
	}
	if reset.has(tcpFlagACK) {
		t.Error("a reset derived from an ACK should not itself carry ACK")
	}
}

func TestSegmentLengthCountsSynAndFin(t *testing.T) {
	if got := (tcpSegment{Flags: tcpFlagSYN}).segmentLength(); got != 1 {
		t.Errorf("SYN length = %d, want 1", got)
	}
	if got := (tcpSegment{Flags: tcpFlagFIN, Payload: make([]byte, 5)}).segmentLength(); got != 6 {
		t.Errorf("FIN with payload = %d, want 6", got)
	}
	if got := (tcpSegment{Flags: tcpFlagACK, Payload: make([]byte, 5)}).segmentLength(); got != 5 {
		t.Errorf("plain ACK = %d, want 5", got)
	}
}

// Sequence numbers wrap, so comparisons have to be modular. A naive < would break every flow that
// runs long enough to cross 2^32.
func TestSequenceComparisonsWrap(t *testing.T) {
	// A var, not a const: the additions below must wrap at runtime the way real sequence
	// numbers do, and a constant expression would overflow at compile time instead.
	nearMax := uint32(0xffffff00)
	if !seqLess(nearMax, nearMax+0x200) {
		t.Error("comparison did not wrap")
	}
	if seqLess(nearMax+0x200, nearMax) {
		t.Error("wrapped comparison is not antisymmetric")
	}
	if !seqLessEqual(nearMax, nearMax) {
		t.Error("seqLessEqual should hold for equal values")
	}
	if !seqInWindow(nearMax+0x100, nearMax, 0x200) {
		t.Error("a sequence inside a wrapping window was rejected")
	}
	if seqInWindow(nearMax+0x300, nearMax, 0x200) {
		t.Error("a sequence past a wrapping window was accepted")
	}
	// A zero window admits exactly the next expected byte, which is how a probe is recognised.
	if !seqInWindow(500, 500, 0) || seqInWindow(501, 500, 0) {
		t.Error("zero-window handling is wrong")
	}
}

// The egress must parse what the consumer's real stack emits, not only what this file builds. The
// SYN from the shared frame vector is a packet produced independently of this code.
func TestParsesTheSynFromTheSharedFrameVector(t *testing.T) {
	var vector egressFrameVector
	readEgressVector(t, "peer-egress-frame-v1.json", &vector)
	var innerHex string
	for _, testCase := range vector.Accept {
		if testCase.Name == "ip-tcp-syn-outbound" {
			innerHex = testCase.InnerPacketHex
		}
	}
	if innerHex == "" {
		t.Fatal("frame vector no longer carries ip-tcp-syn-outbound")
	}
	packet, err := hex.DecodeString(innerHex)
	if err != nil {
		t.Fatal(err)
	}
	segment, ok := parseTCPSegment(packet)
	if !ok {
		t.Fatal("the vector SYN did not parse")
	}
	if !segment.has(tcpFlagSYN) || segment.has(tcpFlagACK) {
		t.Errorf("flags = %#x", segment.Flags)
	}
	if segment.DestinationPort != 443 || segment.SourcePort != 54321 {
		t.Errorf("ports = %d -> %d", segment.SourcePort, segment.DestinationPort)
	}
	if got := binary.BigEndian.Uint32(packet[16:20]); segment.DestinationIP != got {
		t.Errorf("destination = %d", segment.DestinationIP)
	}
}
