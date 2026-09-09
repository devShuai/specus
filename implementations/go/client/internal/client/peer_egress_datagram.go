package client

import "encoding/binary"

// UDP datagram encoding and decoding for the egress user-space stack.
//
// The counterpart of peer_egress_segment.go. The egress terminates UDP in user space for the same
// reason it terminates TCP there: no NAT table, no routing entry and no elevated privileges, which
// is what lets an ordinary desktop act as an egress.
//
// QUIC needs nothing of its own. It rides on UDP, so it is carried by exactly this path as one
// long-lived session per four-tuple, kept alive by its own traffic rather than by anything here.

const (
	udpHeaderLen = 8

	// udpMaxPayload is the largest payload an IPv4 datagram can carry: 65535 less the minimum
	// IPv4 header and the UDP header. Anything claiming more is malformed, not merely large.
	udpMaxPayload = 65535 - ipv4MinHeaderLen - udpHeaderLen
)

// udpDatagram is one parsed UDP datagram together with the IPv4 addresses that carried it.
type udpDatagram struct {
	SourceIP        uint32
	DestinationIP   uint32
	SourcePort      uint16
	DestinationPort uint16
	Payload         []byte
}

// parseUDPDatagram reads an IPv4 packet carrying UDP. Like the TCP parser it returns false for
// anything it cannot fully validate: a datagram we cannot trust must not open a session or reach a
// real socket.
func parseUDPDatagram(packet []byte) (udpDatagram, bool) {
	if len(packet) < ipv4MinHeaderLen || packet[0]>>4 != 4 || peerPacketProtocol(packet) != ipv4ProtocolUDP {
		return udpDatagram{}, false
	}
	ihl := int(packet[0]&0x0f) * 4
	total := int(binary.BigEndian.Uint16(packet[2:4]))
	if ihl < ipv4MinHeaderLen || total < ihl+udpHeaderLen || total > len(packet) {
		return udpDatagram{}, false
	}
	datagram := packet[ihl:total]
	length := int(binary.BigEndian.Uint16(datagram[4:6]))
	// The UDP length must describe exactly the bytes IPv4 delivered. Accepting a shorter one
	// would let a sender smuggle trailing bytes past us, which is why the frame layer refuses
	// trailing bytes too.
	if length != len(datagram) || length > udpHeaderLen+udpMaxPayload {
		return udpDatagram{}, false
	}
	// A zero checksum means the sender did not compute one, which IPv4 permits. Present means it
	// must be right.
	if binary.BigEndian.Uint16(datagram[6:8]) != 0 {
		if peerEgressUDPChecksum(packet[:total], ihl, length) != 0 {
			return udpDatagram{}, false
		}
	}
	return udpDatagram{
		SourceIP:        binary.BigEndian.Uint32(packet[12:16]),
		DestinationIP:   binary.BigEndian.Uint32(packet[16:20]),
		SourcePort:      binary.BigEndian.Uint16(datagram[0:2]),
		DestinationPort: binary.BigEndian.Uint16(datagram[2:4]),
		Payload:         append([]byte(nil), datagram[udpHeaderLen:]...),
	}, true
}

// buildUDPDatagram renders a datagram as a complete IPv4 packet, checksums included.
func buildUDPDatagram(datagram udpDatagram) []byte {
	length := udpHeaderLen + len(datagram.Payload)
	packet := make([]byte, ipv4MinHeaderLen+length)

	packet[0] = 0x45
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
	packet[8] = 64
	packet[9] = ipv4ProtocolUDP
	binary.BigEndian.PutUint32(packet[12:16], datagram.SourceIP)
	binary.BigEndian.PutUint32(packet[16:20], datagram.DestinationIP)

	udp := packet[ipv4MinHeaderLen:]
	binary.BigEndian.PutUint16(udp[0:2], datagram.SourcePort)
	binary.BigEndian.PutUint16(udp[2:4], datagram.DestinationPort)
	binary.BigEndian.PutUint16(udp[4:6], uint16(length))
	copy(udp[udpHeaderLen:], datagram.Payload)

	binary.BigEndian.PutUint16(packet[10:12], peerPacketChecksum(packet[:ipv4MinHeaderLen]))
	checksum := peerEgressUDPChecksum(packet, ipv4MinHeaderLen, length)
	// RFC 768: zero is reserved to mean "no checksum", so a computed zero goes on the wire as
	// its equivalent complement instead.
	if checksum == 0 {
		checksum = 0xffff
	}
	binary.BigEndian.PutUint16(udp[6:8], checksum)
	return packet
}

// peerEgressUDPChecksum is the UDP counterpart of peerPacketTCPChecksum. The pseudo-header differs
// only in the protocol number, but the two cannot share code without making the mesh path's TCP
// checksum take a parameter it never varies.
func peerEgressUDPChecksum(packet []byte, offset, length int) uint16 {
	var sum uint32
	for index := 12; index < 20; index += 2 {
		sum += uint32(binary.BigEndian.Uint16(packet[index : index+2]))
	}
	sum += ipv4ProtocolUDP
	sum += uint32(length)
	datagram := packet[offset : offset+length]
	for index := 0; index+1 < len(datagram); index += 2 {
		sum += uint32(binary.BigEndian.Uint16(datagram[index : index+2]))
	}
	if len(datagram)%2 == 1 {
		sum += uint32(datagram[len(datagram)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}
