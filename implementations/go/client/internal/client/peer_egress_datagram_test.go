package client

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"testing"
)

func TestUDPDatagramRoundTrips(t *testing.T) {
	original := udpDatagram{
		SourceIP:        testAddr(t, "100.96.0.1"),
		DestinationIP:   testAddr(t, "203.0.113.53"),
		SourcePort:      51000,
		DestinationPort: 53,
		Payload:         []byte("specus-egress-datagram"),
	}
	parsed, ok := parseUDPDatagram(buildUDPDatagram(original))
	if !ok {
		t.Fatal("a datagram we built did not parse")
	}
	if parsed.SourceIP != original.SourceIP || parsed.DestinationIP != original.DestinationIP ||
		parsed.SourcePort != original.SourcePort || parsed.DestinationPort != original.DestinationPort {
		t.Errorf("header did not round trip: %+v", parsed)
	}
	if !bytes.Equal(parsed.Payload, original.Payload) {
		t.Errorf("payload = %q", parsed.Payload)
	}
}

// A payload-free datagram is legal UDP and is what several keepalive schemes send, so refusing it
// would silently break the flows that rely on it.
func TestUDPDatagramCarriesAnEmptyPayload(t *testing.T) {
	packet := buildUDPDatagram(udpDatagram{
		SourceIP: testAddr(t, "100.96.0.1"), DestinationIP: testAddr(t, "203.0.113.53"),
		SourcePort: 51000, DestinationPort: 443,
	})
	parsed, ok := parseUDPDatagram(packet)
	if !ok {
		t.Fatal("an empty datagram was refused")
	}
	if len(parsed.Payload) != 0 {
		t.Errorf("payload = %q", parsed.Payload)
	}
	if length := binary.BigEndian.Uint16(packet[ipv4MinHeaderLen+4 : ipv4MinHeaderLen+6]); length != udpHeaderLen {
		t.Errorf("length field = %d, want %d", length, udpHeaderLen)
	}
}

func TestUDPDatagramRejectsUntrustworthyInput(t *testing.T) {
	good := buildUDPDatagram(udpDatagram{
		SourceIP: testAddr(t, "100.96.0.1"), DestinationIP: testAddr(t, "203.0.113.53"),
		SourcePort: 51000, DestinationPort: 53, Payload: []byte("query"),
	})

	corrupted := append([]byte(nil), good...)
	corrupted[ipv4MinHeaderLen+udpHeaderLen] ^= 0xff
	if _, ok := parseUDPDatagram(corrupted); ok {
		t.Error("a datagram with a bad checksum was accepted")
	}

	if _, ok := parseUDPDatagram(good[:ipv4MinHeaderLen+4]); ok {
		t.Error("a truncated datagram was accepted")
	}

	// A UDP length shorter than what IPv4 delivered would leave trailing bytes riding along.
	short := append([]byte(nil), good...)
	binary.BigEndian.PutUint16(short[ipv4MinHeaderLen+4:ipv4MinHeaderLen+6], udpHeaderLen)
	if _, ok := parseUDPDatagram(short); ok {
		t.Error("a datagram whose length field understates its body was accepted")
	}

	long := append([]byte(nil), good...)
	binary.BigEndian.PutUint16(long[ipv4MinHeaderLen+4:ipv4MinHeaderLen+6], 4096)
	if _, ok := parseUDPDatagram(long); ok {
		t.Error("a datagram claiming more body than IPv4 delivered was accepted")
	}

	tcp := append([]byte(nil), good...)
	tcp[9] = ipv4ProtocolTCP
	if _, ok := parseUDPDatagram(tcp); ok {
		t.Error("a non-UDP packet was accepted")
	}
}

// IPv4 lets a sender skip the UDP checksum, and plenty do. Refusing those would drop real traffic.
func TestUDPDatagramAcceptsAnAbsentChecksum(t *testing.T) {
	packet := buildUDPDatagram(udpDatagram{
		SourceIP: testAddr(t, "100.96.0.1"), DestinationIP: testAddr(t, "203.0.113.53"),
		SourcePort: 51000, DestinationPort: 53, Payload: []byte("query"),
	})
	binary.BigEndian.PutUint16(packet[ipv4MinHeaderLen+6:ipv4MinHeaderLen+8], 0)
	if _, ok := parseUDPDatagram(packet); !ok {
		t.Error("a datagram with no checksum was refused")
	}
}

// RFC 768 reserves zero to mean "not computed", so a checksum that works out to zero has to go on
// the wire as its complement instead. A receiver would otherwise stop verifying that flow.
func TestUDPDatagramNeverTransmitsAZeroChecksum(t *testing.T) {
	// Searched rather than hand-derived: the payload that sums to zero depends on the addresses
	// and ports, so pinning one here would be a constant nobody could re-derive later.
	base := udpDatagram{
		SourceIP: testAddr(t, "100.96.0.1"), DestinationIP: testAddr(t, "203.0.113.53"),
		SourcePort: 51000, DestinationPort: 53, Payload: make([]byte, 2),
	}
	found := false
	for candidate := 0; candidate <= 0xffff; candidate++ {
		binary.BigEndian.PutUint16(base.Payload, uint16(candidate))
		packet := buildUDPDatagram(base)
		raw := peerEgressUDPChecksum(packet, ipv4MinHeaderLen, udpHeaderLen+len(base.Payload))
		// raw is computed over a packet that already carries the emitted checksum, so a
		// correctly emitted datagram verifies to zero either way. What we are looking for is
		// the case where the checksum field itself was forced away from zero.
		if binary.BigEndian.Uint16(packet[ipv4MinHeaderLen+6:ipv4MinHeaderLen+8]) == 0xffff && raw == 0 {
			found = true
			if _, ok := parseUDPDatagram(packet); !ok {
				t.Fatal("the 0xffff form did not verify")
			}
			break
		}
	}
	if !found {
		t.Fatal("no payload produced a zero checksum, so the guard went untested")
	}
}

// The strongest check available: this packet came out of the vector generator, not out of this
// file, so agreeing on it is agreement between two implementations.
func TestParsesTheUDPDatagramFromTheSharedFrameVector(t *testing.T) {
	var vector egressFrameVector
	readEgressVector(t, "peer-egress-frame-v1.json", &vector)
	var innerHex string
	var wantSource, wantDestination int
	for _, testCase := range vector.Accept {
		if testCase.Name == "ip-udp-outbound" {
			innerHex = testCase.InnerPacketHex
			wantSource, wantDestination = testCase.InnerSourcePort, testCase.InnerDestinationPort
		}
	}
	if innerHex == "" {
		t.Fatal("frame vector no longer carries ip-udp-outbound")
	}
	packet, err := hex.DecodeString(innerHex)
	if err != nil {
		t.Fatal(err)
	}
	datagram, ok := parseUDPDatagram(packet)
	if !ok {
		t.Fatal("the vector datagram did not parse")
	}
	if int(datagram.SourcePort) != wantSource || int(datagram.DestinationPort) != wantDestination {
		t.Errorf("ports = %d -> %d, want %d -> %d",
			datagram.SourcePort, datagram.DestinationPort, wantSource, wantDestination)
	}
	if got := binary.BigEndian.Uint32(packet[16:20]); datagram.DestinationIP != got {
		t.Errorf("destination = %d", datagram.DestinationIP)
	}
}
