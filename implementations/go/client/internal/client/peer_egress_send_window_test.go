package client

import (
	"bytes"
	"testing"
	"time"
)

func TestTCPQueueAdmissionRetainsDataAndFin(t *testing.T) {
	h := newTCPHarness(t)
	h.conn.tryTransmit = func([]byte) bool { return false }
	h.conn.onAppData([]byte("abc"), h.now)
	h.conn.onAppClose(h.now)
	for i := 0; i < 10; i++ {
		h.now = h.now.Add(time.Second)
		if out := h.conn.onTick(h.now); out.Reset {
			t.Fatal("local queue pressure reset the flow")
		}
	}
	if h.conn.sndNxt != 5001 || string(h.conn.pending) != "abc" || h.conn.finSent {
		t.Fatal("rejected data or FIN consumed sequence space")
	}
	var sent []tcpSegment
	h.conn.tryTransmit = func(packet []byte) bool {
		segment, ok := parseTCPSegment(packet)
		if !ok {
			t.Fatal("invalid packet")
		}
		sent = append(sent, segment)
		return true
	}
	h.conn.onTick(h.now)
	if len(sent) != 2 || sent[0].Seq != 5001 || string(sent[0].Payload) != "abc" ||
		!sent[1].has(tcpFlagFIN) || sent[1].Seq != 5004 {
		t.Fatalf("lost/reordered data after queue recovery: %+v", sent)
	}
}

func TestTCPQueueRejectionDoesNotSpendRetransmissionBudget(t *testing.T) {
	h := newTCPHarness(t)
	h.conn.onAppData([]byte("abc"), h.now)
	h.conn.tryTransmit = func([]byte) bool { return false }
	initialRTO := h.conn.rto
	for i := 0; i < 10; i++ {
		h.now = h.now.Add(time.Second)
		if out := h.conn.onTick(h.now); out.Reset {
			t.Fatal("queue rejection consumed retry budget")
		}
	}
	if h.conn.retransmit[0].attempts != 0 || h.conn.rto != initialRTO {
		t.Fatal("unsent retransmission changed retry budget or RTO")
	}
}

func TestTCPSendWindowAndPendingFin(t *testing.T) {
	h := newTCPHarness(t)
	h.peerWnd = 3
	h.feed(tcpSegment{Seq: h.peerSeq, Ack: 5001, Flags: tcpFlagACK})
	out := h.conn.onAppData([]byte("abcdef"), h.now)
	segment := h.expectOne(out, "window-limited data")
	if string(segment.Payload) != "abc" {
		t.Fatalf("sent beyond window: %q", segment.Payload)
	}
	if out = h.conn.onAppClose(h.now); len(out.Segments) != 0 {
		t.Fatal("FIN overtook buffered data")
	}
	out = h.feed(tcpSegment{Seq: h.peerSeq, Ack: 5004, Flags: tcpFlagACK})
	segment = h.expectOne(out, "remaining data")
	if string(segment.Payload) != "def" || segment.Seq != 5004 {
		t.Fatalf("bad remainder: %+v", segment)
	}
	out = h.feed(tcpSegment{Seq: h.peerSeq, Ack: 5007, Flags: tcpFlagACK})
	if fin := h.expectOne(out, "deferred FIN"); !fin.has(tcpFlagFIN) || fin.Seq != 5007 {
		t.Fatal("bad deferred FIN")
	}
}

func TestTCPSendWindowBoundsFlightAndHandlesPartialAck(t *testing.T) {
	h := newTCPHarness(t)
	h.conn.onAppData(bytes.Repeat([]byte{42}, 32000), h.now)
	if h.conn.sndNxt-h.conn.sndUna > uint32(4*h.conn.sndMSS) {
		t.Fatal("unbounded flight")
	}
	h.peerWnd = 1
	h.feed(tcpSegment{Seq: h.peerSeq, Ack: 5002, Flags: tcpFlagACK})
	h.now = h.now.Add(time.Second)
	out := h.conn.onTick(h.now)
	segment := h.expectOne(out, "oldest unacknowledged byte")
	if segment.Seq != 5002 || len(segment.Payload) != 1 {
		t.Fatalf("retransmit exceeded shrunk window: %+v", segment)
	}
}

func TestTCPZeroWindowIsBoundedAndReopens(t *testing.T) {
	h := newTCPHarness(t)
	h.peerWnd = 0
	h.feed(tcpSegment{Seq: h.peerSeq, Ack: 5001, Flags: tcpFlagACK})
	if out := h.conn.onAppData(bytes.Repeat([]byte{42}, tcpSendBuffer), h.now); len(out.Segments) != 0 {
		t.Fatal("data sent into zero window")
	}
	if h.conn.appReadCredit() != 0 {
		t.Fatal("reader was not backpressured")
	}
	h.conn.onTick(h.now)
	for i := 0; i < 10; i++ {
		h.now = h.now.Add(time.Second)
		out := h.conn.onTick(h.now)
		if out.Reset {
			t.Fatal("persist consumed the retransmission budget")
		}
		for _, segment := range h.parse(out) {
			if len(segment.Payload) > 1 {
				t.Fatal("persist sent more than one byte")
			}
		}
	}
	h.peerWnd = 65535
	out := h.feed(tcpSegment{Seq: h.peerSeq, Ack: 5002, Flags: tcpFlagACK})
	if len(out.Segments) == 0 || h.conn.appReadCredit() != 1 {
		t.Fatal("window reopening did not resume data/reader credit")
	}
}

func TestTCPSendWindowIgnoresStaleUpdatesAndFutureHandshakeAck(t *testing.T) {
	h := newTCPHarness(t)
	h.feed(tcpSegment{Seq: h.peerSeq + 10, Ack: 5001, Flags: tcpFlagACK, Window: 1})
	h.feed(tcpSegment{Seq: h.peerSeq, Ack: 5001, Flags: tcpFlagACK, Window: 65535})
	if h.conn.sndWnd != 1 {
		t.Fatal("stale segment reopened the window")
	}
	syn := h.segment(tcpSegment{Seq: 1000, Flags: tcpFlagSYN})
	c, _ := acceptTCPSyn(syn, 5000, testPathMTU, testIdle, h.now)
	c.onAppData([]byte("banner"), h.now)
	out := c.onSegment(h.segment(tcpSegment{Seq: 1001, Ack: 9999, Flags: tcpFlagACK}), h.now)
	if c.state != tcpStateSynReceived || len(out.Segments) != 0 {
		t.Fatal("invalid ACK completed handshake")
	}
	out = c.onSegment(h.segment(tcpSegment{Seq: 1001, Ack: 5001, Flags: tcpFlagACK}), h.now)
	if segment := h.expectOne(out, "buffered banner"); string(segment.Payload) != "banner" {
		t.Fatal("lost pre-handshake data")
	}
}
