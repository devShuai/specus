package client

import (
	"encoding/binary"
	"time"
)

// The DNS responder's TCP endpoint in the TUN (protocol/spec/peer-egress-dns.md, 三, TUN 里的 TCP).
//
// An application whose UDP answer came back truncated asks again over TCP, so port 53 of the listen
// address answers TCP too, in the same read path and without a socket. Only what RFC 7766 needs is
// here, and the spec lists it: a handshake that settles the MSS, in-order reception, queries cut out
// of the byte stream by their two-byte length and answered in the order they arrived, answers cut
// into segments, retransmission on a fixed second, and the two ways a connection ends. No window
// scaling, SACK or timestamps; out-of-order data is dropped and the current ACK repeated, which is
// all a client talking to a server on the same machine ever needs.
//
// The egress's own TCP stack (peer_egress_tcp.go) is not reused. It terminates connections for a
// real socket, with an RTT estimate and backoff tuned for a path across the internet; this one talks
// to an application on the same machine, and its retransmission rule is the spec's, not an RTO's.
//
// Everything here runs under the consumer's lock and returns the packets to write, which the caller
// writes to the TUN with no lock held.

const (
	egressDNSTCPMaxMSS = 1360
	// egressDNSTCPMaxConns bounds the connections held at once; a SYN past it is reset.
	egressDNSTCPMaxConns = 64
	// egressDNSTCPRetransmit is how long a segment waits for its ACK before it is sent again, and
	// egressDNSTCPMaxRetries how many times: a segment still unacknowledged after that resets the
	// connection.
	egressDNSTCPRetransmit = time.Second
	egressDNSTCPMaxRetries = 3
	// egressDNSTCPIdle closes a connection that has had no new query and no unanswered one for
	// this long.
	egressDNSTCPIdle   = 10 * time.Second
	egressDNSTCPWindow = 65535
	// egressDNSTickInterval is how often the timers above are checked while any connection exists.
	egressDNSTickInterval = 250 * time.Millisecond
)

type egressDNSConnKey struct {
	address uint32
	port    uint16
}

// egressDNSSegment is one segment sent and not yet acknowledged.
type egressDNSSegment struct {
	seq     uint32
	flags   uint8
	payload []byte
	sentAt  time.Time
	retries int
}

func (s *egressDNSSegment) length() uint32 {
	length := uint32(len(s.payload))
	if s.flags&(tcpFlagSYN|tcpFlagFIN) != 0 {
		length++
	}
	return length
}

// egressDNSAnswerSlot is one query's place in the answer order. A forwarded query's slot is filled
// when the upstream answers, and every answer behind it waits.
type egressDNSAnswerSlot struct {
	ready  bool
	answer []byte
}

type egressDNSConn struct {
	key   egressDNSConnKey
	local uint32
	mss   int

	irs, rcvNxt         uint32
	iss, sndUna, sndNxt uint32
	established         bool

	// received holds the bytes of a query still arriving; slots the queries in arrival order.
	received []byte
	slots    []*egressDNSAnswerSlot
	unacked  []*egressDNSSegment

	finReceived, finSent, finAcked bool
	finSentAt                      time.Time
	// activeAt is the last new query or answer; the idle close counts from it.
	activeAt time.Time
	// closed marks a connection taken out of the table, so an answer arriving for it late is
	// dropped rather than sent on a connection that no longer exists.
	closed bool
}

// packet renders a segment of this connection, acknowledging everything received so far.
func (conn *egressDNSConn) packet(seq uint32, flags uint8, payload []byte) []byte {
	segment := tcpSegment{
		SourceIP: conn.local, DestinationIP: conn.key.address,
		SourcePort: dnsPort, DestinationPort: conn.key.port,
		Seq: seq, Ack: conn.rcvNxt, Flags: flags, Window: egressDNSTCPWindow, Payload: payload,
	}
	if flags&tcpFlagSYN != 0 {
		segment.MSS = conn.mss
	}
	return buildTCPSegment(segment)
}

// send queues a segment for acknowledgement and renders it.
func (conn *egressDNSConn) send(flags uint8, payload []byte, now time.Time) []byte {
	segment := &egressDNSSegment{seq: conn.sndNxt, flags: flags, payload: payload, sentAt: now}
	conn.sndNxt += segment.length()
	conn.unacked = append(conn.unacked, segment)
	return conn.packet(segment.seq, segment.flags, segment.payload)
}

// acknowledgement is a bare ACK of where reception stands.
func (conn *egressDNSConn) acknowledgement() []byte {
	return conn.packet(conn.sndNxt, tcpFlagACK, nil)
}

// acknowledge takes an ACK from the peer. One that acknowledges nothing new, or more than was
// sent, changes nothing.
func (conn *egressDNSConn) acknowledge(ack uint32) {
	if !seqLess(conn.sndUna, ack) || seqLess(conn.sndNxt, ack) {
		return
	}
	conn.sndUna = ack
	kept := conn.unacked[:0]
	for _, segment := range conn.unacked {
		if !seqLessEqual(segment.seq+segment.length(), ack) {
			kept = append(kept, segment)
			continue
		}
		if segment.flags&tcpFlagSYN != 0 {
			conn.established = true
		}
		if segment.flags&tcpFlagFIN != 0 {
			conn.finAcked = true
		}
	}
	conn.unacked = kept
}

// flush writes the answers that are ready, in arrival order, stopping at the first that is not, and
// the FIN when the peer has finished and nothing is left to answer.
func (conn *egressDNSConn) flush(now time.Time) [][]byte {
	var out [][]byte
	for len(conn.slots) > 0 && conn.slots[0].ready {
		answer := conn.slots[0].answer
		conn.slots = conn.slots[1:]
		if answer == nil || len(answer) > 0xFFFF {
			// A dropped query has no answer to write, and an answer too long for its length
			// prefix cannot be framed.
			continue
		}
		framed := binary.BigEndian.AppendUint16(make([]byte, 0, 2+len(answer)), uint16(len(answer)))
		framed = append(framed, answer...)
		for len(framed) > 0 {
			chunk := framed[:min(conn.mss, len(framed))]
			framed = framed[len(chunk):]
			out = append(out, conn.send(tcpFlagACK|tcpFlagPSH, chunk, now))
		}
		conn.activeAt = now
	}
	if conn.finReceived && len(conn.slots) == 0 && !conn.finSent {
		out = append(out, conn.closeFromHere(now))
	}
	return out
}

func (conn *egressDNSConn) closeFromHere(now time.Time) []byte {
	conn.finSent, conn.finSentAt = true, now
	return conn.send(tcpFlagFIN|tcpFlagACK, nil, now)
}

// dnsTCPSegmentLocked takes one segment addressed to the responder's TCP port and returns what goes
// back. Called with the consumer's lock held.
func (c *egressConsumer) dnsTCPSegmentLocked(segment tcpSegment, now time.Time) [][]byte {
	key := egressDNSConnKey{address: segment.SourceIP, port: segment.SourcePort}
	conn := c.dnsConns[key]
	if segment.has(tcpFlagRST) {
		if conn != nil {
			c.dropDNSConnLocked(conn)
		}
		return nil
	}
	if segment.has(tcpFlagSYN) && !segment.has(tcpFlagACK) {
		if conn != nil {
			if !conn.established && segment.Seq == conn.irs && len(conn.unacked) > 0 {
				// The SYN again: the SYN-ACK was lost, so it goes again.
				return [][]byte{conn.packet(conn.unacked[0].seq, conn.unacked[0].flags, nil)}
			}
			// A new connection on the four-tuple of an old one.
			c.dropDNSConnLocked(conn)
		}
		if len(c.dnsConns) >= egressDNSTCPMaxConns {
			return [][]byte{buildTCPReset(segment)}
		}
		mss := segment.MSS
		if mss <= 0 {
			mss = tcpDefaultMSS
		}
		// Random, like the egress's: a guessable one lets anything that can reach the TUN inject
		// into the connection.
		iss := newEgressISS()
		conn = &egressDNSConn{
			key: key, local: segment.DestinationIP, mss: min(mss, egressDNSTCPMaxMSS),
			irs: segment.Seq, rcvNxt: segment.Seq + 1, iss: iss, sndUna: iss, sndNxt: iss, activeAt: now,
		}
		c.dnsConns[key] = conn
		c.scheduleDNSTickLocked()
		return [][]byte{conn.send(tcpFlagSYN|tcpFlagACK, nil, now)}
	}
	if conn == nil {
		// Nothing of ours: a reset tells the application's stack to stop.
		return [][]byte{buildTCPReset(segment)}
	}
	if segment.has(tcpFlagSYN) {
		return nil
	}
	if segment.has(tcpFlagACK) {
		conn.acknowledge(segment.Ack)
	}
	var out [][]byte
	if length := segment.segmentLength(); length > 0 {
		if segment.Seq != conn.rcvNxt || conn.finReceived {
			// Out of order, a repeat, or past the peer's own FIN: dropped, and the current ACK
			// tells the peer where to resume.
			return [][]byte{conn.acknowledgement()}
		}
		conn.received = append(conn.received, segment.Payload...)
		conn.rcvNxt += uint32(len(segment.Payload))
		if segment.has(tcpFlagFIN) {
			conn.rcvNxt++
			conn.finReceived = true
		}
		c.takeDNSQueriesLocked(conn, now)
		out = conn.flush(now)
		if len(out) == 0 {
			out = [][]byte{conn.acknowledgement()}
		}
	}
	if conn.finSent && conn.finAcked && conn.finReceived {
		c.dropDNSConnLocked(conn)
	}
	return out
}

// takeDNSQueriesLocked cuts the complete queries out of what a connection has received and gives
// each its place in the answer order: answered at once, dropped, or forwarded over TCP and answered
// when the upstream is.
func (c *egressConsumer) takeDNSQueriesLocked(conn *egressDNSConn, now time.Time) {
	for len(conn.received) >= 2 {
		size := int(binary.BigEndian.Uint16(conn.received[0:2]))
		if len(conn.received) < 2+size {
			return
		}
		query := append([]byte(nil), conn.received[2:2+size]...)
		conn.received = conn.received[2+size:]
		conn.activeAt = now
		slot := &egressDNSAnswerSlot{}
		conn.slots = append(conn.slots, slot)
		result := c.respondDNSLocked(query, now)
		c.countDNSAnswerLocked(result)
		switch result.Outcome {
		case egressDNSAnswer:
			slot.ready, slot.answer = true, result.Response
		case egressDNSForward:
			toTun := c.toTun
			c.forwardDNSLocked("tcp", query, func(answer []byte) {
				c.mu.Lock()
				var packets [][]byte
				if !conn.closed {
					slot.ready, slot.answer = true, answer
					packets = conn.flush(c.clock())
				}
				c.mu.Unlock()
				writePackets(toTun, packets)
			})
		default:
			slot.ready = true
		}
	}
}

// dropDNSConnLocked forgets a connection without a word to the peer.
func (c *egressConsumer) dropDNSConnLocked(conn *egressDNSConn) {
	conn.closed = true
	if c.dnsConns[conn.key] == conn {
		delete(c.dnsConns, conn.key)
	}
}

// tickDNSLocked runs the connections' timers: retransmission, and the idle close. Called with the
// consumer's lock held.
func (c *egressConsumer) tickDNSLocked(now time.Time) [][]byte {
	var out [][]byte
	for _, conn := range c.dnsConns {
		expired := false
		for _, segment := range conn.unacked {
			if now.Sub(segment.sentAt) < egressDNSTCPRetransmit {
				continue
			}
			if segment.retries >= egressDNSTCPMaxRetries {
				expired = true
				break
			}
			segment.retries++
			segment.sentAt = now
			out = append(out, conn.packet(segment.seq, segment.flags, segment.payload))
		}
		if expired {
			// The peer stopped acknowledging. The reset is at the first byte it has not
			// acknowledged, which is where its stack expects the next one.
			out = append(out, conn.packet(conn.sndUna, tcpFlagRST|tcpFlagACK, nil))
			c.dropDNSConnLocked(conn)
			continue
		}
		switch {
		case conn.established && !conn.finSent && len(conn.slots) == 0 && now.Sub(conn.activeAt) >= egressDNSTCPIdle:
			out = append(out, conn.closeFromHere(now))
		case conn.finSent && conn.finAcked && !conn.finReceived && now.Sub(conn.finSentAt) >= egressDNSTCPIdle:
			// Our FIN was taken and the peer never sent its own: nothing is left to say.
			c.dropDNSConnLocked(conn)
		}
	}
	return out
}

// tickDNS is tickDNSLocked for a caller without the lock, writing what it produces to the TUN.
func (c *egressConsumer) tickDNS(now time.Time) {
	c.mu.Lock()
	packets := c.tickDNSLocked(now)
	toTun := c.toTun
	c.mu.Unlock()
	writePackets(toTun, packets)
}

// scheduleDNSTickLocked arms the timer that drives tickDNS while there are connections. It runs
// only while it has something to do, so an idle responder costs nothing.
func (c *egressConsumer) scheduleDNSTickLocked() {
	if c.dnsTickInterval <= 0 || c.dnsTickArmed || len(c.dnsConns) == 0 {
		return
	}
	c.dnsTickArmed = true
	time.AfterFunc(c.dnsTickInterval, func() {
		c.mu.Lock()
		c.dnsTickArmed = false
		packets := c.tickDNSLocked(c.clock())
		c.scheduleDNSTickLocked()
		toTun := c.toTun
		c.mu.Unlock()
		writePackets(toTun, packets)
	})
}
