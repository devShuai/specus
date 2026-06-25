package client

import (
	"encoding/binary"
	"net"
	"testing"
)

func TestPeerPacketICMPEchoReplyForMatchesJavaNoopFallback(t *testing.T) {
	request := minimalICMPEchoRequestPacket("100.103.117.15", "100.112.186.105")

	reply := peerPacketICMPEchoReplyFor(request, "100.112.186.105")

	if reply == nil {
		t.Fatalf("ICMP echo reply is nil")
	}
	if got := peerPacketSourceIPv4(reply); got != "100.112.186.105" {
		t.Fatalf("reply source = %q", got)
	}
	if got := peerPacketDestinationIPv4(reply); got != "100.103.117.15" {
		t.Fatalf("reply destination = %q", got)
	}
	if got := reply[20]; got != icmpEchoReply {
		t.Fatalf("ICMP type = %d, want echo reply", got)
	}
	if got := reply[8]; got != 64 {
		t.Fatalf("TTL = %d, want 64", got)
	}
	if checksum := peerPacketChecksum(reply[:20]); checksum != 0 {
		t.Fatalf("IPv4 checksum validation = %#04x, want 0", checksum)
	}
	if checksum := peerPacketChecksum(reply[20:]); checksum != 0 {
		t.Fatalf("ICMP checksum validation = %#04x, want 0", checksum)
	}
}

func TestPeerPacketICMPEchoReplyForRejectsNonLocalTarget(t *testing.T) {
	request := minimalICMPEchoRequestPacket("100.103.117.15", "100.112.186.105")

	if reply := peerPacketICMPEchoReplyFor(request, "100.112.186.106"); reply != nil {
		t.Fatalf("unexpected reply for non-local target: %v", reply)
	}
}

func minimalICMPEchoRequestPacket(source, target string) []byte {
	packet := make([]byte, 32)
	packet[0] = 0x45
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
	packet[8] = 64
	packet[9] = ipv4ProtocolICMP
	copy(packet[12:16], net.ParseIP(source).To4())
	copy(packet[16:20], net.ParseIP(target).To4())
	packet[20] = icmpEchoRequest
	packet[21] = 0
	binary.BigEndian.PutUint16(packet[22:24], 0)
	binary.BigEndian.PutUint16(packet[24:26], 0x1234)
	binary.BigEndian.PutUint16(packet[26:28], 1)
	copy(packet[28:], []byte{1, 2, 3, 4})
	binary.BigEndian.PutUint16(packet[22:24], peerPacketChecksum(packet[20:]))
	binary.BigEndian.PutUint16(packet[10:12], peerPacketChecksum(packet[:20]))
	return packet
}
