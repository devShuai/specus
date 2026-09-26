package client

import "time"

// User-space TCP termination for the egress side.
//
// This state machine owns no sockets and reads no clock. Segments and time come in as arguments;
// effects come back in tcpOutput, or through an optional nonblocking queue-admission callback.
// The callback must not do network I/O or acquire a mesh lock. Rejection leaves data unsent.
// Two reasons that shape matters. The conformance suite can drive loss, reordering and timers
// deterministically without a network. And P4 has to port this logic to Java and .NET, where the
// I/O and scheduling primitives are different but the protocol decisions must not be.

type tcpState int

const (
	tcpStateSynReceived tcpState = iota
	tcpStateEstablished
	// The application (the real socket) closed first, so we sent FIN and await its acknowledgement.
	tcpStateFinWait1
	tcpStateFinWait2
	// The consumer closed first; we owe a FIN once the real socket drains.
	tcpStateCloseWait
	tcpStateClosing
	tcpStateLastAck
	tcpStateTimeWait
	tcpStateClosed
)

func (s tcpState) String() string {
	switch s {
	case tcpStateSynReceived:
		return "SYN_RECEIVED"
	case tcpStateEstablished:
		return "ESTABLISHED"
	case tcpStateFinWait1:
		return "FIN_WAIT_1"
	case tcpStateFinWait2:
		return "FIN_WAIT_2"
	case tcpStateCloseWait:
		return "CLOSE_WAIT"
	case tcpStateClosing:
		return "CLOSING"
	case tcpStateLastAck:
		return "LAST_ACK"
	case tcpStateTimeWait:
		return "TIME_WAIT"
	default:
		return "CLOSED"
	}
}

const (
	// tcpReceiveWindow is our advertised receive window, not the downstream send credit.
	// Downstream sends obey the peer window and a conservative four-MSS flight limit;
	// this is not an adaptive congestion controller. See protocol/spec/peer-egress.md.
	//
	// 65535 and not 64 KiB: the header field is sixteen bits and there is no window scaling in
	// this version, so a 65536 would go on the wire as a zero window and tell every consumer to
	// stop sending.
	tcpReceiveWindow = 65535
	tcpSendBuffer    = 65536

	tcpInitialRTO = 1 * time.Second
	tcpMinRTO     = 200 * time.Millisecond
	tcpMaxRTO     = 60 * time.Second

	// tcpMaxRetransmits is how many times one segment is resent before the flow is abandoned.
	tcpMaxRetransmits = 6

	// tcpTimeWaitDuration is deliberately short of the classic 2*MSL. Nothing else on this host
	// can bind the four-tuple, since it exists only inside this stack, so the window only has to
	// outlive stragglers on the mesh path.
	tcpTimeWaitDuration = 10 * time.Second

	// Keepalive finds out whether a silent consumer is still there.
	//
	// A peer that vanished without closing holds a socket and a quota slot until the idle
	// timeout collects it; probing learns the truth sooner. It deliberately does not extend the
	// idle budget. That budget is a resource limit rather than a liveness question, so a flow
	// that is genuinely alive but idle is still reclaimed on schedule.
	tcpKeepaliveIdle     = 15 * time.Second
	tcpKeepaliveInterval = 5 * time.Second
	tcpKeepaliveProbes   = 3

	// tcpMaxReassembly bounds out-of-order segments held per flow. A peer that sends a hole and
	// then floods must not be able to grow this without bound.
	tcpMaxReassembly = 32
)

// tcpOutput is everything the state machine wants the caller to do. It never acts itself.
type tcpOutput struct {
	// Segments to send back to the consumer, already rendered as IPv4 packets.
	Segments [][]byte
	// Deliver is payload to write to the real socket, in order.
	Deliver []byte
	// CloseApp reports that the consumer finished sending, so the real socket should be
	// half-closed for writing.
	CloseApp bool
	// Done reports the flow is finished and its resources can be released.
	Done bool
	// Reset reports the flow ended abnormally; the caller should drop the socket rather than
	// closing it gracefully.
	Reset bool
}

func (o *tcpOutput) send(packet []byte) { o.Segments = append(o.Segments, packet) }

type tcpRetransmitEntry struct {
	seq      uint32
	flags    uint8
	payload  []byte
	sentAt   time.Time
	attempts int
	// retransmitted marks a segment that was resent, so its RTT sample is discarded. That is
	// Karn's algorithm: an ambiguous sample would poison the estimator whenever loss happens.
	retransmitted bool
}

type tcpOutOfOrder struct {
	seq     uint32
	payload []byte
	fin     bool
}

// tcpConn is one terminated flow.
type tcpConn struct {
	localIP, remoteIP     uint32
	localPort, remotePort uint16

	state tcpState

	// Send sequence space.
	iss     uint32
	sndUna  uint32
	sndNxt  uint32
	sndWnd  uint32
	sndWL1  uint32
	sndWL2  uint32
	pending []byte
	// Optional nonblocking transport admission. A rejected segment stays in TCP state,
	// rather than being counted as sent and silently dropped by a full local queue.
	tryTransmit func([]byte) bool
	sendBlocked bool
	persistAt   time.Time

	// Receive sequence space.
	irs    uint32
	rcvNxt uint32
	rcvWnd uint32

	sndMSS int

	retransmit []tcpRetransmitEntry
	rto        time.Duration
	srtt       time.Duration
	rttvar     time.Duration

	reassembly []tcpOutOfOrder

	// finSeq is the sequence our FIN occupies once sent, so its acknowledgement is recognisable.
	finSeq    uint32
	finSent   bool
	finRcvd   bool
	appClosed bool

	lastActivity time.Time
	closedAt     time.Time
	idleTimeout  time.Duration

	keepaliveProbes int
	lastProbe       time.Time
}

// acceptTCPSyn opens a flow from the consumer's SYN and produces the SYN-ACK.
//
// iss is supplied rather than generated here so tests are deterministic; production passes a random
// value, which is what keeps an off-path attacker from guessing the sequence space.
func acceptTCPSyn(syn tcpSegment, iss uint32, pathMTU int, idleTimeout time.Duration, now time.Time) (*tcpConn, tcpOutput) {
	conn := &tcpConn{
		localIP:      syn.DestinationIP,
		remoteIP:     syn.SourceIP,
		localPort:    syn.DestinationPort,
		remotePort:   syn.SourcePort,
		state:        tcpStateSynReceived,
		iss:          iss,
		sndUna:       iss,
		sndNxt:       iss,
		sndWnd:       uint32(syn.Window),
		sndWL1:       syn.Seq,
		irs:          syn.Seq,
		rcvNxt:       syn.Seq + 1,
		rcvWnd:       tcpReceiveWindow,
		rto:          tcpInitialRTO,
		lastActivity: now,
		idleTimeout:  idleTimeout,
	}
	// Clamp what we will send to what the path can carry, so the egress never emits a segment the
	// mesh path has to fragment.
	conn.sndMSS = tcpDefaultMSS
	if syn.MSS > 0 {
		conn.sndMSS = syn.MSS
	}
	if limit := pathMTU - ipv4MinHeaderLen - tcpMinHeaderLen; limit > 0 && conn.sndMSS > limit {
		conn.sndMSS = limit
	}
	if conn.sndMSS < tcpDefaultMSS {
		conn.sndMSS = tcpDefaultMSS
	}

	var output tcpOutput
	conn.emit(&output, tcpFlagSYN|tcpFlagACK, nil, now, conn.advertisedMSS(pathMTU))
	return conn, output
}

func (c *tcpConn) advertisedMSS(pathMTU int) int {
	mss := pathMTU - ipv4MinHeaderLen - tcpMinHeaderLen
	if mss < tcpDefaultMSS {
		mss = tcpDefaultMSS
	}
	return mss
}

// tcpAdvertisedWindow renders the receive window into the sixteen bits the header has.
//
// Clamped rather than truncated. A window of 65536 wraps to zero, and a zero window is not a large
// window: it is the signal that tells the peer to stop sending entirely and wait to be probed.
func tcpAdvertisedWindow(window uint32) uint16 {
	if window > 0xffff {
		return 0xffff
	}
	return uint16(window)
}

// emit renders one segment, queues it for retransmission when it occupies sequence space, and
// advances SND.NXT.
func (c *tcpConn) transmit(output *tcpOutput, packet []byte) bool {
	if c.tryTransmit != nil {
		accepted := c.tryTransmit(packet)
		c.sendBlocked = !accepted
		return accepted
	}
	output.send(packet)
	return true
}

func (c *tcpConn) emit(output *tcpOutput, flags uint8, payload []byte, now time.Time, mss int) bool {
	segment := tcpSegment{
		SourceIP:        c.localIP,
		DestinationIP:   c.remoteIP,
		SourcePort:      c.localPort,
		DestinationPort: c.remotePort,
		Seq:             c.sndNxt,
		Ack:             c.rcvNxt,
		Flags:           flags,
		Window:          tcpAdvertisedWindow(c.rcvWnd),
		MSS:             mss,
		Payload:         payload,
	}
	if flags&tcpFlagACK == 0 && flags&tcpFlagRST == 0 {
		segment.Ack = 0
	}
	if !c.transmit(output, buildTCPSegment(segment)) {
		return false
	}

	length := segment.segmentLength()
	if length == 0 {
		// A pure ACK carries no sequence space, so it is never retransmitted; the peer will
		// re-ask by retransmitting whatever it thinks is missing.
		return true
	}
	c.retransmit = append(c.retransmit, tcpRetransmitEntry{
		seq: c.sndNxt, flags: flags, payload: append([]byte(nil), payload...), sentAt: now,
	})
	if flags&tcpFlagFIN != 0 {
		c.finSeq = c.sndNxt + length - 1
		c.finSent = true
	}
	c.sndNxt += length
	return true
}

func (c *tcpConn) ack(output *tcpOutput, now time.Time) {
	c.emit(output, tcpFlagACK, nil, now, 0)
}

// reset tears the flow down and tells the peer, then marks it finished.
func (c *tcpConn) reset(output *tcpOutput) {
	output.send(buildTCPSegment(tcpSegment{
		SourceIP: c.localIP, DestinationIP: c.remoteIP,
		SourcePort: c.localPort, DestinationPort: c.remotePort,
		Seq: c.sndNxt, Flags: tcpFlagRST,
	}))
	c.state = tcpStateClosed
	c.retransmit = nil
	c.pending = nil
	c.reassembly = nil
	output.Done = true
	output.Reset = true
}

// onSegment feeds one inbound segment through the state machine.
func (c *tcpConn) onSegment(segment tcpSegment, now time.Time) tcpOutput {
	var output tcpOutput
	if c.state == tcpStateClosed {
		return output
	}
	// Any segment proves the consumer is still there, so the probe run restarts. The idle clock
	// is different: it measures data, not liveness. Letting a keepalive exchange refresh it would
	// mean two stacks could hold a socket and a quota slot open indefinitely by pinging each
	// other, which is exactly the resource the timeout exists to bound.
	c.keepaliveProbes = 0
	if segment.segmentLength() > 0 {
		c.lastActivity = now
	}

	if segment.has(tcpFlagRST) {
		// An in-window reset ends the flow. Out-of-window resets are ignored, which is what stops
		// a blind off-path attacker from tearing down flows by guessing.
		if seqInWindow(segment.Seq, c.rcvNxt, c.rcvWnd) || segment.Seq == c.rcvNxt {
			c.state = tcpStateClosed
			c.retransmit = nil
			c.pending = nil
			c.reassembly = nil
			output.Done = true
			output.Reset = true
		}
		return output
	}

	if segment.has(tcpFlagSYN) && c.state != tcpStateSynReceived {
		// A SYN inside an established flow is either a stale duplicate or an attack; RFC 793 says
		// answer with a reset rather than silently re-handshaking.
		c.reset(&output)
		return output
	}

	if segment.has(tcpFlagACK) {
		c.processAck(segment, now, &output)
		if c.state == tcpStateClosed {
			output.Done = true
			return output
		}
	}

	if c.state == tcpStateSynReceived {
		if !segment.has(tcpFlagACK) || c.sndUna != c.iss+1 {
			// A duplicate SYN: resend the SYN-ACK rather than opening a second flow.
			return output
		}
		c.state = tcpStateEstablished
	}
	c.flushSend(&output, now)

	// RFC 1122: a keepalive probe re-sends one byte of already acknowledged sequence space to
	// force an acknowledgement. Without answering it, a healthy flow looks dead to the consumer
	// and gets torn down from the far end. A normal bare ACK carries the sequence we already
	// expect, so only one below it is a probe.
	if len(segment.Payload) == 0 && !segment.has(tcpFlagFIN) && !segment.has(tcpFlagSYN) &&
		seqLess(segment.Seq, c.rcvNxt) {
		c.ack(&output, now)
		return output
	}

	c.acceptData(segment, now, &output)
	c.updateStateAfterFin(&output, now)
	return output
}

// processAck advances the send window and retires acknowledged retransmission entries.
func (c *tcpConn) processAck(segment tcpSegment, now time.Time, output *tcpOutput) {
	if seqLess(segment.Ack, c.sndUna) || seqLess(c.sndNxt, segment.Ack) {
		// Acknowledging something we never sent. Ignore rather than reset: a delayed duplicate
		// would otherwise be able to kill a healthy flow.
		return
	}
	if seqLess(c.sndUna, segment.Ack) {
		c.sndUna = segment.Ack
	}
	// RFC 9293 SND.WL1/WL2: an old window advertisement must not reopen the window.
	if seqLess(c.sndWL1, segment.Seq) || (c.sndWL1 == segment.Seq && seqLessEqual(c.sndWL2, segment.Ack)) {
		c.sndWnd = uint32(segment.Window)
		c.sndWL1, c.sndWL2 = segment.Seq, segment.Ack
		if c.sndWnd > 0 {
			c.persistAt = time.Time{}
		}
	}

	kept := c.retransmit[:0]
	for _, entry := range c.retransmit {
		end := entry.seq + tcpEntryLength(entry)
		if seqLessEqual(end, c.sndUna) {
			// Karn: only an unambiguous sample updates the estimator.
			if !entry.retransmitted {
				c.updateRTO(now.Sub(entry.sentAt))
			}
			continue
		}
		if seqLess(entry.seq, c.sndUna) && len(entry.payload) > 0 {
			skip := min(int(c.sndUna-entry.seq), len(entry.payload))
			entry.payload = entry.payload[skip:]
			entry.seq += uint32(skip)
		}
		kept = append(kept, entry)
	}
	c.retransmit = kept

	if c.finSent && seqLess(c.finSeq, c.sndUna) {
		switch c.state {
		case tcpStateFinWait1:
			c.state = tcpStateFinWait2
		case tcpStateClosing:
			c.enterTimeWait(now)
		case tcpStateLastAck:
			c.state = tcpStateClosed
			output.Done = true
		}
	}
}

func tcpEntryLength(entry tcpRetransmitEntry) uint32 {
	length := uint32(len(entry.payload))
	if entry.flags&tcpFlagSYN != 0 {
		length++
	}
	if entry.flags&tcpFlagFIN != 0 {
		length++
	}
	return length
}

// updateRTO is Jacobson/Karels: smooth the round-trip estimate and its variance, then set the
// timeout well clear of normal jitter so a slow path does not look like loss.
func (c *tcpConn) updateRTO(sample time.Duration) {
	if sample <= 0 {
		return
	}
	if c.srtt == 0 {
		c.srtt = sample
		c.rttvar = sample / 2
	} else {
		diff := c.srtt - sample
		if diff < 0 {
			diff = -diff
		}
		c.rttvar = (3*c.rttvar + diff) / 4
		c.srtt = (7*c.srtt + sample) / 8
	}
	c.rto = c.srtt + 4*c.rttvar
	if c.rto < tcpMinRTO {
		c.rto = tcpMinRTO
	}
	if c.rto > tcpMaxRTO {
		c.rto = tcpMaxRTO
	}
}

// acceptData takes in-order payload, buffers out-of-order payload, and acknowledges.
func (c *tcpConn) acceptData(segment tcpSegment, now time.Time, output *tcpOutput) {
	if len(segment.Payload) == 0 && !segment.has(tcpFlagFIN) {
		return
	}
	if c.finRcvd {
		// Data after the peer's FIN is a protocol violation. Reset instead of quietly dropping,
		// so the far end learns its stack is out of step.
		if len(segment.Payload) > 0 {
			c.reset(output)
		}
		return
	}

	if seqLess(segment.Seq, c.rcvNxt) {
		// Wholly or partly retransmitted. Trim what we already have; if nothing new remains this
		// is a duplicate and only needs an ACK to re-synchronise the peer.
		skip := c.rcvNxt - segment.Seq
		if skip >= uint32(len(segment.Payload)) {
			if segment.has(tcpFlagFIN) && segment.Seq+segment.segmentLength()-1 == c.rcvNxt {
				c.finRcvd = true
				c.rcvNxt++
				output.CloseApp = true
			}
			c.ack(output, now)
			return
		}
		segment.Payload = segment.Payload[skip:]
		segment.Seq = c.rcvNxt
	}

	if !seqInWindow(segment.Seq, c.rcvNxt, c.rcvWnd) {
		// Outside the advertised window. Acknowledge so the peer re-syncs, but take nothing.
		c.ack(output, now)
		return
	}

	if segment.Seq != c.rcvNxt {
		c.bufferOutOfOrder(segment)
		c.ack(output, now)
		return
	}

	output.Deliver = append(output.Deliver, segment.Payload...)
	c.rcvNxt += uint32(len(segment.Payload))
	if segment.has(tcpFlagFIN) {
		c.finRcvd = true
		c.rcvNxt++
		output.CloseApp = true
	}
	c.drainReassembly(output)
	c.ack(output, now)
}

func (c *tcpConn) bufferOutOfOrder(segment tcpSegment) {
	if len(c.reassembly) >= tcpMaxReassembly {
		// Dropping is safe: the peer will retransmit. Growing without bound is not.
		return
	}
	for _, held := range c.reassembly {
		if held.seq == segment.Seq {
			return
		}
	}
	c.reassembly = append(c.reassembly, tcpOutOfOrder{
		seq:     segment.Seq,
		payload: append([]byte(nil), segment.Payload...),
		fin:     segment.has(tcpFlagFIN),
	})
}

// drainReassembly delivers whatever the newly arrived segment made contiguous.
func (c *tcpConn) drainReassembly(output *tcpOutput) {
	for progress := true; progress; {
		progress = false
		for index, held := range c.reassembly {
			if held.seq != c.rcvNxt {
				continue
			}
			output.Deliver = append(output.Deliver, held.payload...)
			c.rcvNxt += uint32(len(held.payload))
			if held.fin {
				c.finRcvd = true
				c.rcvNxt++
				output.CloseApp = true
			}
			c.reassembly = append(c.reassembly[:index], c.reassembly[index+1:]...)
			progress = true
			break
		}
	}
}

func (c *tcpConn) updateStateAfterFin(output *tcpOutput, now time.Time) {
	if !c.finRcvd {
		return
	}
	switch c.state {
	case tcpStateEstablished:
		c.state = tcpStateCloseWait
	case tcpStateFinWait1:
		c.state = tcpStateClosing
	case tcpStateFinWait2:
		c.enterTimeWait(now)
	}
	_ = output
}

func (c *tcpConn) enterTimeWait(now time.Time) {
	c.state = tcpStateTimeWait
	c.closedAt = now
	c.retransmit = nil
	c.reassembly = nil
}

// onAppData queues payload read from the real socket, split at the negotiated MSS.
func (c *tcpConn) onAppData(data []byte, now time.Time) tcpOutput {
	var output tcpOutput
	if c.appClosed || (c.state != tcpStateSynReceived && c.state != tcpStateEstablished && c.state != tcpStateCloseWait) {
		return output
	}
	if len(data) > c.appReadCredit() {
		c.reset(&output)
		return output
	}
	c.lastActivity = now
	c.pending = append(c.pending, data...)
	c.flushSend(&output, now)
	return output
}

// Credit includes both unsent and unacknowledged bytes: ACKs, not successful queue writes,
// permit further socket reads. The per-flow flight ceiling is conservative, not full TCP CC.
func (c *tcpConn) appReadCredit() int {
	if c.appClosed || (c.state != tcpStateSynReceived && c.state != tcpStateEstablished && c.state != tcpStateCloseWait) {
		return 0
	}
	return max(0, tcpSendBuffer-len(c.pending)-int(c.sndNxt-c.sndUna))
}

func (c *tcpConn) sendCredit() int {
	return max(0, min(int(c.sndWnd), 4*c.sndMSS)-int(c.sndNxt-c.sndUna))
}

func (c *tcpConn) flushSend(output *tcpOutput, now time.Time) {
	if c.state != tcpStateEstablished && c.state != tcpStateCloseWait {
		return
	}
	for len(c.pending) > 0 && c.sendCredit() > 0 {
		n := min(len(c.pending), c.sndMSS, c.sendCredit())
		if !c.emit(output, tcpFlagACK|tcpFlagPSH, c.pending[:n], now, 0) {
			return
		}
		c.pending = c.pending[n:]
	}
	if c.appClosed && len(c.pending) == 0 && c.sendCredit() > 0 && !c.finSent {
		if !c.emit(output, tcpFlagACK|tcpFlagFIN, nil, now, 0) {
			return
		}
		if c.state == tcpStateCloseWait {
			c.state = tcpStateLastAck
		} else {
			c.state = tcpStateFinWait1
		}
	}
}

// onAppClose reports that the real socket reached EOF, so the consumer gets our FIN.
func (c *tcpConn) onAppClose(now time.Time) tcpOutput {
	var output tcpOutput
	if c.appClosed || c.state == tcpStateClosed {
		return output
	}
	c.appClosed = true
	c.lastActivity = now
	c.flushSend(&output, now)
	return output
}

// abort tears the flow down deliberately, which is what an authorization revocation or a quota
// breach uses.
func (c *tcpConn) abort() tcpOutput {
	var output tcpOutput
	if c.state == tcpStateClosed {
		return output
	}
	c.reset(&output)
	return output
}

// onTick drives retransmission, the TIME_WAIT expiry and the idle timeout.
func (c *tcpConn) onTick(now time.Time) tcpOutput {
	var output tcpOutput
	if c.state == tcpStateClosed {
		return output
	}
	if c.state == tcpStateTimeWait {
		if now.Sub(c.closedAt) >= tcpTimeWaitDuration {
			c.state = tcpStateClosed
			output.Done = true
		}
		return output
	}
	if c.idleTimeout > 0 && now.Sub(c.lastActivity) >= c.idleTimeout {
		// An idle flow holds a socket and a quota slot on the egress; reclaim it rather than
		// letting a forgotten consumer pin resources. This is checked before the keepalive so a
		// probe cannot hold a flow past the limit the policy set.
		c.reset(&output)
		return output
	}
	c.flushSend(&output, now)
	if c.sndWnd == 0 && c.state != tcpStateSynReceived && (len(c.pending) > 0 || len(c.retransmit) > 0 || c.appClosed) {
		// Persist is not a failed transmission. Probe without spending the retry budget; the
		// resource-policy idle timeout still bounds a peer that never reopens its window.
		if c.persistAt.IsZero() {
			c.persistAt = now
			return output
		}
		if now.Sub(c.persistAt) < c.rto {
			return output
		}
		c.persistAt = now
		if len(c.retransmit) == 0 && len(c.pending) > 0 {
			if c.emit(&output, tcpFlagACK|tcpFlagPSH, c.pending[:1], now, 0) {
				c.pending = c.pending[1:]
			}
		} else if len(c.retransmit) > 0 && len(c.retransmit[0].payload) > 0 {
			entry := &c.retransmit[0]
			entry.retransmitted = true
			c.transmit(&output, buildTCPSegment(tcpSegment{SourceIP: c.localIP, DestinationIP: c.remoteIP,
				SourcePort: c.localPort, DestinationPort: c.remotePort, Seq: entry.seq, Ack: c.rcvNxt,
				Flags: tcpFlagACK, Window: tcpAdvertisedWindow(c.rcvWnd), Payload: entry.payload[:1]}))
		} else {
			c.transmit(&output, buildTCPSegment(tcpSegment{SourceIP: c.localIP, DestinationIP: c.remoteIP,
				SourcePort: c.localPort, DestinationPort: c.remotePort, Seq: c.sndNxt - 1, Ack: c.rcvNxt,
				Flags: tcpFlagACK, Window: tcpAdvertisedWindow(c.rcvWnd)}))
		}
		return output
	}
	if len(c.retransmit) == 0 && len(c.pending) == 0 && c.keepalive(now, &output) {
		return output
	}

	// One RTO retransmits the oldest outstanding segment, not a burst of the entire flight.
	for index := 0; index < len(c.retransmit) && index < 1; index++ {
		entry := &c.retransmit[index]
		if now.Sub(entry.sentAt) < c.rto {
			continue
		}
		if entry.attempts >= tcpMaxRetransmits {
			c.reset(&output)
			return output
		}
		payload := entry.payload
		if c.state != tcpStateSynReceived && len(payload) > int(c.sndWnd) {
			payload = payload[:c.sndWnd]
		}
		if !c.transmit(&output, buildTCPSegment(tcpSegment{
			SourceIP: c.localIP, DestinationIP: c.remoteIP,
			SourcePort: c.localPort, DestinationPort: c.remotePort,
			Seq: entry.seq, Ack: c.rcvNxt, Flags: entry.flags,
			Window: tcpAdvertisedWindow(c.rcvWnd), Payload: payload,
		})) {
			return output
		}
		entry.attempts++
		entry.retransmitted = true
		entry.sentAt = now
		// Back off the connection's RTO once per oldest-segment timeout, capped.
		c.rto *= 2
		if c.rto > tcpMaxRTO {
			c.rto = tcpMaxRTO
		}
	}
	return output
}

// keepalive probes a silent flow and reports whether the flow ended because the consumer never
// answered. Established flows only: in any closing state the peer already told us where it stands,
// and the retransmission timer covers whatever is still outstanding.
//
// The probe carries the last byte of already acknowledged sequence space and no payload, which is
// what RFC 1122 says forces an acknowledgement. It is built directly rather than through emit
// because it occupies no new sequence space and must not enter the retransmission queue.
func (c *tcpConn) keepalive(now time.Time, output *tcpOutput) bool {
	if c.state != tcpStateEstablished || now.Sub(c.lastActivity) < tcpKeepaliveIdle {
		return false
	}
	if c.keepaliveProbes >= tcpKeepaliveProbes {
		c.reset(output)
		return true
	}
	if !c.lastProbe.IsZero() && now.Sub(c.lastProbe) < tcpKeepaliveInterval {
		return false
	}
	c.keepaliveProbes++
	c.lastProbe = now
	output.send(buildTCPSegment(tcpSegment{
		SourceIP: c.localIP, DestinationIP: c.remoteIP,
		SourcePort: c.localPort, DestinationPort: c.remotePort,
		Seq: c.sndNxt - 1, Ack: c.rcvNxt, Flags: tcpFlagACK, Window: tcpAdvertisedWindow(c.rcvWnd),
	}))
	return false
}

func (c *tcpConn) done() bool { return c.state == tcpStateClosed }
