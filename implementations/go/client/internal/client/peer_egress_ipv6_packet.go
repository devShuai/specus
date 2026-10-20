package client

import "encoding/binary"

// The egress side of the IPv6 data plane (protocol/spec/peer-egress.md, IPv6 数据面): the address a
// device has in it, and the IPv6 packets the user-space stack reads from consumers and writes back.
//
// The stack is the IPv4 one. A segment or datagram carries the family it arrived in, and everything
// above the codec -- the state machine, the flow table, the judgment layer -- works on it unchanged.

// egressIPv6PacketCapable says this egress accepts IPv6 packets in SPEG1 type=1 frames, and so
// announces ipv6PacketCapable at login. The consumer side is separate: egressConsumerCarriesIPv6 says
// whether this device sends IPv6 to an egress, and stays false until the consumer data plane exists.
const egressIPv6PacketCapable = true

const (
	ipv6HeaderLen = 40

	// ipv6NextHeaderICMP is ICMPv6. Like every next header but TCP and UDP it is refused, and named
	// only so the tests can say what they send.
	ipv6NextHeaderICMP = 58

	// ipv6HopLimit is what the egress writes on every packet it returns to a consumer.
	ipv6HopLimit = 64

	// udpMaxPayload6 is the largest payload an IPv6 datagram without a jumbogram can carry: the
	// payload length field counts the UDP header but not the fixed IPv6 header.
	udpMaxPayload6 = 65535 - udpHeaderLen
)

// egressMeshPrefix6 is the prefix every device's IPv6 address lies in: the device's mesh IPv4 is
// its low 32 bits. It is fixed and does not follow peerMeshCidr. To IPv6 it is what the Peer Mesh
// network is to IPv4, so a destination inside it is refused the way a mesh destination is.
const egressMeshPrefix6 = "fd53:7065:6375:7300::/96"

var egressMeshPrefix6Network = [12]byte{0xfd, 0x53, 0x70, 0x65, 0x63, 0x75, 0x73, 0x00}

// egressMeshAddress6 is the IPv6 address derived from a mesh IPv4 address.
func egressMeshAddress6(meshIPv4 uint32) [16]byte {
	var address [16]byte
	copy(address[:12], egressMeshPrefix6Network[:])
	binary.BigEndian.PutUint32(address[12:], meshIPv4)
	return address
}

// egressMeshIPv4From6 reads the mesh IPv4 address back out of a derived address. Only an address
// inside the prefix is one.
func egressMeshIPv4From6(address [16]byte) (uint32, bool) {
	if [12]byte(address[:12]) != egressMeshPrefix6Network {
		return 0, false
	}
	return binary.BigEndian.Uint32(address[12:]), true
}

// egressDeviceAddress6 derives a device's IPv6 address from its mesh IPv4 as the mesh writes it, or
// reports false when that is not an IPv4 address at all.
func egressDeviceAddress6(meshIPv4 string) ([16]byte, bool) {
	address, ok := parseEgressAddress(meshIPv4)
	if !ok {
		return [16]byte{}, false
	}
	return egressMeshAddress6(address), true
}

// parseTCPSegment6 reads an IPv6 packet whose next header is TCP. Like parseTCPSegment it returns
// false for anything it cannot fully validate, a bad checksum included. A TCP header behind an
// extension header is not read: the frame layer has already sent anything but a bare TCP or UDP
// payload to the protocol refusal.
func parseTCPSegment6(packet []byte) (tcpSegment, bool) {
	payload, ok := ipv6Payload(packet, ipv4ProtocolTCP)
	if !ok || len(payload) < tcpMinHeaderLen {
		return tcpSegment{}, false
	}
	dataOffset := int(payload[12]>>4) * 4
	if dataOffset < tcpMinHeaderLen || dataOffset > len(payload) {
		return tcpSegment{}, false
	}
	source, destination := [16]byte(packet[8:24]), [16]byte(packet[24:40])
	if egressChecksum6(source, destination, ipv4ProtocolTCP, payload) != 0 {
		return tcpSegment{}, false
	}
	segment := tcpSegment{
		IPv6:            true,
		SourceIP6:       source,
		DestinationIP6:  destination,
		SourcePort:      binary.BigEndian.Uint16(payload[0:2]),
		DestinationPort: binary.BigEndian.Uint16(payload[2:4]),
		Seq:             binary.BigEndian.Uint32(payload[4:8]),
		Ack:             binary.BigEndian.Uint32(payload[8:12]),
		Flags:           payload[13],
		Window:          binary.BigEndian.Uint16(payload[14:16]),
		Payload:         append([]byte(nil), payload[dataOffset:]...),
	}
	segment.MSS = parseTCPOptionMSS(payload[tcpMinHeaderLen:dataOffset])
	return segment, true
}

// parseUDPDatagram6 reads an IPv6 packet whose next header is UDP.
//
// A zero checksum is refused rather than read as "none": IPv4 lets a sender leave it out, IPv6 does
// not (RFC 8200 8.1), because there is no header checksum underneath to catch a damaged address.
func parseUDPDatagram6(packet []byte) (udpDatagram, bool) {
	payload, ok := ipv6Payload(packet, ipv4ProtocolUDP)
	if !ok || len(payload) < udpHeaderLen {
		return udpDatagram{}, false
	}
	if int(binary.BigEndian.Uint16(payload[4:6])) != len(payload) {
		return udpDatagram{}, false
	}
	source, destination := [16]byte(packet[8:24]), [16]byte(packet[24:40])
	if binary.BigEndian.Uint16(payload[6:8]) == 0 || egressChecksum6(source, destination, ipv4ProtocolUDP, payload) != 0 {
		return udpDatagram{}, false
	}
	return udpDatagram{
		IPv6:            true,
		SourceIP6:       source,
		DestinationIP6:  destination,
		SourcePort:      binary.BigEndian.Uint16(payload[0:2]),
		DestinationPort: binary.BigEndian.Uint16(payload[2:4]),
		Payload:         append([]byte(nil), payload[udpHeaderLen:]...),
	}, true
}

// ipv6Payload returns what follows the fixed header of an IPv6 packet carrying nextHeader directly,
// with exactly the length the header states.
func ipv6Payload(packet []byte, nextHeader byte) ([]byte, bool) {
	if len(packet) < ipv6HeaderLen || packet[0]>>4 != 6 || packet[6] != nextHeader {
		return nil, false
	}
	length := int(binary.BigEndian.Uint16(packet[4:6]))
	if ipv6HeaderLen+length != len(packet) {
		return nil, false
	}
	return packet[ipv6HeaderLen:], true
}

// writeIPv6Header fills the fixed header of a packet the egress returns: traffic class and flow
// label zero, hop limit 64.
func writeIPv6Header(packet []byte, nextHeader byte, payloadLength int, source, destination [16]byte) {
	packet[0] = 0x60
	packet[1], packet[2], packet[3] = 0, 0, 0
	binary.BigEndian.PutUint16(packet[4:6], uint16(payloadLength))
	packet[6] = nextHeader
	packet[7] = ipv6HopLimit
	copy(packet[8:24], source[:])
	copy(packet[24:40], destination[:])
}

// egressChecksum6 is the TCP and UDP checksum over the RFC 8200 8.1 pseudo-header: both addresses,
// the upper-layer length as 32 bits, three zero bytes and the next header. Over a segment that
// already carries its checksum it comes to zero, the same convention as the IPv4 helpers.
func egressChecksum6(source, destination [16]byte, nextHeader byte, upper []byte) uint16 {
	var sum uint32
	for index := 0; index < 16; index += 2 {
		sum += uint32(binary.BigEndian.Uint16(source[index : index+2]))
		sum += uint32(binary.BigEndian.Uint16(destination[index : index+2]))
	}
	length := uint32(len(upper))
	sum += length >> 16
	sum += length & 0xffff
	sum += uint32(nextHeader)
	for index := 0; index+1 < len(upper); index += 2 {
		sum += uint32(binary.BigEndian.Uint16(upper[index : index+2]))
	}
	if len(upper)%2 == 1 {
		sum += uint32(upper[len(upper)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}
