package client

import "encoding/binary"

// Telling the application that a flow a rule claims cannot go through.
//
// The consumer's rule is that a destination routed through an egress never goes out locally, and
// dropping the packet honours it. But a dropped packet is indistinguishable, to the application,
// from a slow network: a TCP connect retries its SYN for a minute or more, an established
// connection retransmits until its own timeout. The rule is working exactly as configured and the
// user sees a hang.
//
// So a packet that cannot be forwarded because the egress is unavailable is answered, into the
// TUN, the way an unreachable host would answer it: a TCP reset, or an ICMP host-unreachable for a
// datagram. The application fails at once, with a reason its own stack reports, and can retry once
// the egress is back. A flow the consumer closes itself -- the egress went offline, a rule changed
// -- is reset from what the consumer remembered about it, since the application sent nothing to
// answer.
//
// Only unavailability is answered. A failed send is not: the session to the egress may be
// re-establishing, and a flow that would have recovered is worth more than a fast failure. A block
// rule is not: it is a drop. Pinned by protocol/test-vectors/peer-egress-failure-v1.json.

// egressFailurePacket answers a packet the consumer refused to forward, or returns nil when
// there is nothing an application could act on.
func egressFailurePacket(packet []byte, protocol int) []byte {
	switch protocol {
	case ipv4ProtocolTCP:
		segment, ok := parseTCPSegment(packet)
		if !ok {
			return nil
		}
		// A segment the application sent through the TUN has a valid checksum, so a parse
		// failure here is a truncated or non-TCP packet, which gets no answer.
		return buildTCPReset(segment)
	case ipv4ProtocolUDP:
		return peerPacketICMPHostUnreachableFor(packet)
	}
	return nil
}

// egressFailurePacket6 answers an IPv6 packet the consumer refused to forward, the same way: a TCP
// segment with a reset by RFC 793, a UDP datagram with an ICMPv6 address unreachable. Pinned by the
// failure section of protocol/test-vectors/peer-egress-ipv6-v1.json.
func egressFailurePacket6(packet []byte, nextHeader int) []byte {
	switch nextHeader {
	case ipv4ProtocolTCP:
		segment, ok := parseTCPSegment6(packet)
		if !ok {
			return nil
		}
		return buildTCPReset(segment)
	case ipv4ProtocolUDP:
		return egressICMPv6AddressUnreachable(packet)
	}
	return nil
}

const (
	icmpv6DestinationUnreachable = 1
	// icmpv6AddressUnreachable is the counterpart of IPv4's host unreachable: the stack reports
	// EHOSTUNREACH on the socket.
	icmpv6AddressUnreachable = 3
	icmpv6HeaderLen          = 8
)

// egressICMPv6AddressUnreachable builds an ICMPv6 destination unreachable, code 3, for an IPv6
// packet: from the packet's destination back to its source, hop limit 64, quoting as much of the
// packet as fits without the whole error passing the IPv6 minimum MTU (RFC 4443 2.4 c). The
// checksum covers the RFC 8200 pseudo-header, as every ICMPv6 checksum does.
func egressICMPv6AddressUnreachable(packet []byte) []byte {
	if len(packet) < ipv6HeaderLen || packet[0]>>4 != 6 {
		return nil
	}
	original := len(packet)
	if stated := ipv6HeaderLen + int(binary.BigEndian.Uint16(packet[4:6])); stated < original {
		original = stated
	}
	quoted := min(original, egressIPv6MinimumMTU-ipv6HeaderLen-icmpv6HeaderLen)
	source, destination := [16]byte(packet[24:40]), [16]byte(packet[8:24])
	response := make([]byte, ipv6HeaderLen+icmpv6HeaderLen+quoted)
	writeIPv6Header(response, ipv6NextHeaderICMP, icmpv6HeaderLen+quoted, source, destination)
	message := response[ipv6HeaderLen:]
	message[0] = icmpv6DestinationUnreachable
	message[1] = icmpv6AddressUnreachable
	copy(message[icmpv6HeaderLen:], packet[:quoted])
	binary.BigEndian.PutUint16(message[2:4], egressChecksum6(source, destination, ipv6NextHeaderICMP, message))
	return response
}

// egressFlowResetPacket builds the reset for a flow the consumer closed, or returns nil when it
// cannot: a datagram flow, or a TCP flow on which the application has not yet sent an
// acknowledgement, whose retransmitted SYN will be answered when it arrives.
func egressFlowResetPacket(flow *egressConsumerFlow) []byte {
	if flow == nil || flow.Key.protocol != ipv4ProtocolTCP || !flow.AppAckKnown {
		return nil
	}
	// An IPv6 flow is reset by the same rule, only in its own family.
	return buildTCPSegment(tcpSegment{
		SourceIP:        flow.Key.remoteIP,
		DestinationIP:   flow.Key.consumerIP,
		IPv6:            flow.Key.ipv6,
		SourceIP6:       flow.Key.remoteIP6,
		DestinationIP6:  flow.Key.consumerIP6,
		SourcePort:      flow.Key.remotePort,
		DestinationPort: flow.Key.consumerPort,
		Seq:             flow.AppAck,
		Ack:             flow.AppSeqNext,
		Flags:           tcpFlagRST | tcpFlagACK,
	})
}

// noteApplicationProgress records where the application is on a TCP flow from a segment it sent.
//
// Read from the header directly rather than through parseTCPSegment: this runs on every forwarded
// packet, and a checksum over the whole segment for two numbers would be paid on every one.
func (flow *egressConsumerFlow) noteApplicationProgress(packet []byte) {
	ihl := int(packet[0]&0x0f) * 4
	total := peerPacketTotalLength(packet)
	if packet[0]>>4 == 6 {
		// The fixed header, and the payload length it states: the data plane carries TCP only
		// directly behind it.
		ihl = ipv6HeaderLen
		total = len(packet)
		if len(packet) >= ipv6HeaderLen {
			total = ipv6HeaderLen + int(binary.BigEndian.Uint16(packet[4:6]))
		}
	}
	if len(packet) < ihl+tcpMinHeaderLen {
		return
	}
	tcp := packet[ihl:]
	dataOffset := int(tcp[12]>>4) * 4
	if dataOffset < tcpMinHeaderLen {
		return
	}
	if total > len(packet) {
		total = len(packet)
	}
	payload := total - ihl - dataOffset
	if payload < 0 {
		payload = 0
	}
	flags := tcp[13]
	next := binary.BigEndian.Uint32(tcp[4:8]) + uint32(payload)
	if flags&tcpFlagSYN != 0 {
		next++
	}
	if flags&tcpFlagFIN != 0 {
		next++
	}
	flow.AppSeqNext = next
	if flags&tcpFlagACK != 0 {
		flow.AppAck = binary.BigEndian.Uint32(tcp[8:12])
		flow.AppAckKnown = true
	}
}
