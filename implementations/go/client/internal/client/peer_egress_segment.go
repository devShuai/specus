package client

import "encoding/binary"

// TCP segment encoding and decoding for the egress user-space stack.
//
// The egress node terminates TCP in user space rather than handing packets to the kernel, so that
// acting as an egress needs no NAT table, no routing table entry and no elevated privileges. That
// constraint is what makes a Windows machine usable as an egress at all, and it is why this file
// exists instead of a call into the OS.

const (
	tcpFlagFIN = 0x01
	tcpFlagSYN = 0x02
	tcpFlagRST = 0x04
	tcpFlagPSH = 0x08
	tcpFlagACK = 0x10

	tcpMinHeaderLen  = 20
	ipv4MinHeaderLen = 20

	// tcpDefaultMSS is what we advertise when the peer sends no MSS option. 536 is the IPv4
	// minimum every implementation must accept.
	tcpDefaultMSS = 536
)

// tcpSegment is one parsed TCP segment together with the IPv4 addresses that carried it.
type tcpSegment struct {
	SourceIP        uint32
	DestinationIP   uint32
	SourcePort      uint16
	DestinationPort uint16
	Seq             uint32
	Ack             uint32
	Flags           uint8
	Window          uint16
	MSS             int
	Payload         []byte
}

func (s tcpSegment) has(flag uint8) bool { return s.Flags&flag != 0 }

// segmentLength is what the peer's sequence space advances by: payload plus one for each of SYN and
// FIN, which occupy a sequence number of their own.
func (s tcpSegment) segmentLength() uint32 {
	length := uint32(len(s.Payload))
	if s.has(tcpFlagSYN) {
		length++
	}
	if s.has(tcpFlagFIN) {
		length++
	}
	return length
}

// parseTCPSegment reads an IPv4 packet carrying TCP. It returns false for anything it cannot fully
// validate, including a bad checksum: a segment we cannot trust must not advance any state.
func parseTCPSegment(packet []byte) (tcpSegment, bool) {
	if len(packet) < ipv4MinHeaderLen || packet[0]>>4 != 4 || peerPacketProtocol(packet) != ipv4ProtocolTCP {
		return tcpSegment{}, false
	}
	ihl := int(packet[0]&0x0f) * 4
	total := int(binary.BigEndian.Uint16(packet[2:4]))
	if ihl < ipv4MinHeaderLen || total < ihl+tcpMinHeaderLen || total > len(packet) {
		return tcpSegment{}, false
	}
	tcp := packet[ihl:total]
	dataOffset := int(tcp[12]>>4) * 4
	if dataOffset < tcpMinHeaderLen || dataOffset > len(tcp) {
		return tcpSegment{}, false
	}
	if peerPacketTCPChecksum(packet[:total], ihl, total-ihl) != 0 {
		return tcpSegment{}, false
	}
	segment := tcpSegment{
		SourceIP:        binary.BigEndian.Uint32(packet[12:16]),
		DestinationIP:   binary.BigEndian.Uint32(packet[16:20]),
		SourcePort:      binary.BigEndian.Uint16(tcp[0:2]),
		DestinationPort: binary.BigEndian.Uint16(tcp[2:4]),
		Seq:             binary.BigEndian.Uint32(tcp[4:8]),
		Ack:             binary.BigEndian.Uint32(tcp[8:12]),
		Flags:           tcp[13],
		Window:          binary.BigEndian.Uint16(tcp[14:16]),
		Payload:         append([]byte(nil), tcp[dataOffset:]...),
	}
	segment.MSS = parseTCPOptionMSS(tcp[tcpMinHeaderLen:dataOffset])
	return segment, true
}

func parseTCPOptionMSS(options []byte) int {
	for cursor := 0; cursor < len(options); {
		kind := options[cursor]
		if kind == 0 {
			break
		}
		if kind == 1 {
			cursor++
			continue
		}
		if cursor+1 >= len(options) {
			break
		}
		length := int(options[cursor+1])
		if length < 2 || cursor+length > len(options) {
			break
		}
		if kind == 2 && length == 4 {
			return int(binary.BigEndian.Uint16(options[cursor+2 : cursor+4]))
		}
		cursor += length
	}
	return 0
}

// buildTCPSegment renders a segment as a complete IPv4 packet, checksums included.
//
// mss > 0 emits an MSS option, which is only meaningful on a SYN.
func buildTCPSegment(segment tcpSegment) []byte {
	options := []byte(nil)
	if segment.MSS > 0 {
		options = []byte{2, 4, byte(segment.MSS >> 8), byte(segment.MSS)}
	}
	// The TCP header must end on a 4-byte boundary; pad with NOP/EOL.
	for len(options)%4 != 0 {
		options = append(options, 0)
	}
	tcpLen := tcpMinHeaderLen + len(options) + len(segment.Payload)
	packet := make([]byte, ipv4MinHeaderLen+tcpLen)

	packet[0] = 0x45
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
	packet[8] = 64
	packet[9] = ipv4ProtocolTCP
	binary.BigEndian.PutUint32(packet[12:16], segment.SourceIP)
	binary.BigEndian.PutUint32(packet[16:20], segment.DestinationIP)

	tcp := packet[ipv4MinHeaderLen:]
	binary.BigEndian.PutUint16(tcp[0:2], segment.SourcePort)
	binary.BigEndian.PutUint16(tcp[2:4], segment.DestinationPort)
	binary.BigEndian.PutUint32(tcp[4:8], segment.Seq)
	binary.BigEndian.PutUint32(tcp[8:12], segment.Ack)
	tcp[12] = byte((tcpMinHeaderLen + len(options)) / 4 << 4)
	tcp[13] = segment.Flags
	binary.BigEndian.PutUint16(tcp[14:16], segment.Window)
	copy(tcp[tcpMinHeaderLen:], options)
	copy(tcp[tcpMinHeaderLen+len(options):], segment.Payload)

	binary.BigEndian.PutUint16(packet[10:12], peerPacketChecksum(packet[:ipv4MinHeaderLen]))
	binary.BigEndian.PutUint16(tcp[16:18], peerPacketTCPChecksum(packet, ipv4MinHeaderLen, tcpLen))
	return packet
}

// buildTCPReset answers an unwanted segment with an RST the peer's stack will accept.
//
// RFC 793: a reset for a segment carrying ACK takes its sequence from that ACK; otherwise it
// acknowledges the incoming sequence space so the peer cannot dismiss it as out of window. Getting
// this wrong leaves the consumer retrying a refused flow until its own timeout.
func buildTCPReset(segment tcpSegment) []byte {
	reset := tcpSegment{
		SourceIP:        segment.DestinationIP,
		DestinationIP:   segment.SourceIP,
		SourcePort:      segment.DestinationPort,
		DestinationPort: segment.SourcePort,
		Flags:           tcpFlagRST,
	}
	if segment.has(tcpFlagACK) {
		reset.Seq = segment.Ack
	} else {
		reset.Flags |= tcpFlagACK
		reset.Ack = segment.Seq + segment.segmentLength()
	}
	return buildTCPSegment(reset)
}

// seqLess reports a < b in TCP's wrapping sequence space.
func seqLess(a, b uint32) bool { return int32(a-b) < 0 }

func seqLessEqual(a, b uint32) bool { return int32(a-b) <= 0 }

// seqInWindow reports whether seq falls within [start, start+size).
func seqInWindow(seq, start uint32, size uint32) bool {
	if size == 0 {
		return seq == start
	}
	return !seqLess(seq, start) && seqLess(seq, start+size)
}
