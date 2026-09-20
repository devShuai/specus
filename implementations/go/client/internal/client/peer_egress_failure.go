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

// egressFlowResetPacket builds the reset for a flow the consumer closed, or returns nil when it
// cannot: a datagram flow, or a TCP flow on which the application has not yet sent an
// acknowledgement, whose retransmitted SYN will be answered when it arrives.
func egressFlowResetPacket(flow *egressConsumerFlow) []byte {
	if flow == nil || flow.Key.protocol != ipv4ProtocolTCP || !flow.AppAckKnown {
		return nil
	}
	return buildTCPSegment(tcpSegment{
		SourceIP:        flow.Key.remoteIP,
		DestinationIP:   flow.Key.consumerIP,
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
	if len(packet) < ihl+tcpMinHeaderLen {
		return
	}
	tcp := packet[ihl:]
	dataOffset := int(tcp[12]>>4) * 4
	if dataOffset < tcpMinHeaderLen {
		return
	}
	total := peerPacketTotalLength(packet)
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
