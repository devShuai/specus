package client

import (
	"fmt"
	"io"
	"sync"
	"testing"
	"time"
)

func finishEgressForReuse(t *testing.T, h *egressHarness, opening tcpSegment) tcpSegment {
	t.Helper()
	h.runtime.handleFrame(7, egressFrameFor(buildTCPSegment(opening)), flowEpoch)
	h.completeHandshake(7, opening)
	h.reset()
	h.socket(0).readErr <- io.EOF
	h.waitFor("the original flow FIN", h.sawFin)
	var fin tcpSegment
	for _, segment := range h.segments() {
		if segment.has(tcpFlagFIN) {
			fin = segment
		}
	}
	h.runtime.handleFrame(7, egressFrameFor(buildTCPSegment(tcpSegment{
		SourceIP: opening.SourceIP, DestinationIP: opening.DestinationIP,
		SourcePort: opening.SourcePort, DestinationPort: opening.DestinationPort,
		Seq: opening.Seq + 1, Ack: fin.Seq + 1, Flags: tcpFlagACK | tcpFlagFIN, Window: 65535,
	})), flowEpoch.Add(time.Millisecond))
	h.runtime.mu.Lock()
	count := h.runtime.flows.size()
	h.runtime.mu.Unlock()
	if count != 0 || !h.socket(0).isClosed() {
		t.Fatal("original connection did not finish")
	}
	h.reset()
	return fin
}

func TestEgressRuntimeTimeWaitReuse(t *testing.T) {
	for _, offset := range []int64{-1, 0, 65535, 2147483648, 2147483649} {
		t.Run(fmt.Sprintf("ambiguous-sequence-%d", offset), func(t *testing.T) {
			h := newEgressHarness(t)
			t.Cleanup(func() { h.runtime.shutdown(flowEpoch) })
			opening := egressSyn(t, "100.96.0.1", 40000, "203.0.113.10", 443)
			finishEgressForReuse(t, h, opening)
			packet := opening
			packet.Seq = uint32(int64(opening.Seq) + 2 + offset)
			h.runtime.handleFrame(7, egressFrameFor(buildTCPSegment(packet)), flowEpoch)
			h.runtime.mu.Lock()
			_, present := h.runtime.flows.lookup(egressFlowKey{protocol: 6, consumerIP: opening.SourceIP, consumerPort: opening.SourcePort, remoteIP: opening.DestinationIP, remotePort: opening.DestinationPort})
			h.runtime.mu.Unlock()
			if h.dialCount() != 1 || h.sawReset() || !present {
				t.Fatal("ambiguous/window-overlapping SYN recycled the tuple")
			}
		})
	}
	for _, oldSeq := range []uint32{1000, 0xffffff9c} {
		t.Run(map[uint32]string{1000: "fresh", 0xffffff9c: "sequence-wrap"}[oldSeq], func(t *testing.T) {
			h := newEgressHarness(t)
			t.Cleanup(func() { h.runtime.shutdown(flowEpoch) })
			opening := egressSyn(t, "100.96.0.1", 40000, "203.0.113.10", 443)
			opening.Seq = oldSeq
			oldFin := finishEgressForReuse(t, h, opening)
			next := opening
			next.Seq += 1000000
			h.runtime.handleFrame(7, egressFrameFor(buildTCPSegment(next)), flowEpoch.Add(2*time.Millisecond))
			if h.dialCount() != 2 || h.sawReset() {
				t.Fatal("fresh SYN did not open on its first attempt")
			}
			response := h.segments()[0]
			if response.Flags != tcpFlagSYN|tcpFlagACK || response.Ack != next.Seq+1 || !seqLess(oldFin.Seq, response.Seq) {
				t.Fatal("replacement handshake overlaps old sequence space")
			}
			h.completeHandshake(7, next)
			data := next
			data.Seq++
			data.Ack = response.Seq + 1
			data.Flags = tcpFlagACK | tcpFlagPSH
			data.Payload = []byte{42}
			h.runtime.handleFrame(7, egressFrameFor(buildTCPSegment(data)), flowEpoch)
			if writes := h.socket(1).written(); len(writes) != 1 || len(writes[0]) != 1 || writes[0][0] != 42 {
				t.Fatal("new payload missing")
			}
		})
	}
	for _, flags := range []uint8{tcpFlagSYN, tcpFlagRST, tcpFlagACK | tcpFlagFIN} {
		t.Run(map[uint8]string{tcpFlagSYN: "old-syn", tcpFlagRST: "old-reset", tcpFlagACK | tcpFlagFIN: "old-fin"}[flags], func(t *testing.T) {
			h := newEgressHarness(t)
			t.Cleanup(func() { h.runtime.shutdown(flowEpoch) })
			opening := egressSyn(t, "100.96.0.1", 40000, "203.0.113.10", 443)
			fin := finishEgressForReuse(t, h, opening)
			packet := opening
			packet.Flags = flags
			packet.Ack = fin.Seq + 1
			if flags == tcpFlagRST {
				packet.Seq += 2
			} else if flags != tcpFlagSYN {
				packet.Seq++
			}
			h.runtime.handleFrame(7, egressFrameFor(buildTCPSegment(packet)), flowEpoch.Add(2*time.Millisecond))
			h.runtime.mu.Lock()
			_, present := h.runtime.flows.lookup(egressFlowKey{protocol: 6, consumerIP: opening.SourceIP, consumerPort: opening.SourcePort, remoteIP: opening.DestinationIP, remotePort: opening.DestinationPort})
			h.runtime.mu.Unlock()
			if !present || h.sawReset() || h.dialCount() != 1 {
				t.Fatal("old traffic destroyed TIME_WAIT")
			}
			if flags == tcpFlagACK|tcpFlagFIN && len(h.segments()) != 1 {
				t.Fatal("retransmitted FIN was not acknowledged")
			}
		})
	}
	t.Run("old-packets-before-and-after-handshake", func(t *testing.T) {
		h := newEgressHarness(t)
		t.Cleanup(func() { h.runtime.shutdown(flowEpoch) })
		opening := egressSyn(t, "100.96.0.1", 40000, "203.0.113.10", 443)
		oldFin := finishEgressForReuse(t, h, opening)
		next := opening
		next.Seq += 1000000
		h.runtime.handleFrame(7, egressFrameFor(buildTCPSegment(next)), flowEpoch)
		if h.dialCount() != 2 {
			t.Fatal("replacement not opened")
		}
		response := h.segments()[0]
		for _, established := range []bool{false, true} {
			if established {
				h.completeHandshake(7, next)
			}
			for _, flags := range []uint8{tcpFlagACK, tcpFlagRST, tcpFlagACK | tcpFlagFIN, tcpFlagACK | tcpFlagPSH, tcpFlagSYN} {
				packet := opening
				packet.Flags = flags
				packet.Ack = oldFin.Seq + 1
				if flags != tcpFlagSYN {
					packet.Seq++
				}
				if flags == tcpFlagACK|tcpFlagPSH {
					packet.Payload = []byte{99}
				}
				h.runtime.handleFrame(7, egressFrameFor(buildTCPSegment(packet)), flowEpoch)
			}
			if h.socket(1).isClosed() || len(h.socket(1).written()) != 0 {
				t.Fatal("old packet closed or wrote to replacement")
			}
			h.socket(1).mu.Lock()
			halfClosed := h.socket(1).wroteClose
			h.socket(1).mu.Unlock()
			if halfClosed {
				t.Fatal("old FIN half-closed replacement")
			}
		}
		data := next
		data.Seq++
		data.Ack = response.Seq + 1
		data.Flags = tcpFlagACK | tcpFlagPSH
		data.Payload = []byte{42}
		h.runtime.handleFrame(7, egressFrameFor(buildTCPSegment(data)), flowEpoch)
		if len(h.socket(1).written()) != 1 {
			t.Fatal("old packets poisoned new handshake")
		}
	})
	for _, mode := range []string{"current-permission", "current-cap", "new-rate-token"} {
		t.Run(mode, func(t *testing.T) {
			h := newEgressHarness(t)
			t.Cleanup(func() { h.runtime.shutdown(flowEpoch) })
			h.runtime.flowRate.clock = func() int64 { return 0 }
			opening := egressSyn(t, "100.96.0.1", 40000, "203.0.113.10", 443)
			finishEgressForReuse(t, h, opening)
			expectedDials := 1
			expectedCode := egressCodeLimitExceeded
			switch mode {
			case "current-permission":
				h.runtime.peerACLAllows = func(int64) bool { return false }
				expectedCode = egressCodePeerACLDenied
			case "current-cap":
				p := testEgressPolicy("203.0.113.0/24")
				p.Limits = egressLimits{MaxFlowsPerConsumer: 1}
				h.runtime.applyPolicy(p, newEgressContext(), flowEpoch)
				other := opening
				other.SourcePort++
				h.runtime.handleFrame(7, egressFrameFor(buildTCPSegment(other)), flowEpoch)
				expectedDials = 2
				h.reset()
			case "new-rate-token":
				for i := 1; i < egressFlowRateCapacity; i++ {
					if !h.runtime.flowRate.take(7) {
						t.Fatal("unexpected early bucket exhaustion")
					}
				}
			}
			next := opening
			next.Seq += 1000000
			h.runtime.handleFrame(7, egressFrameFor(buildTCPSegment(next)), flowEpoch)
			codes := h.rejectCodes()
			if h.dialCount() != expectedDials || len(codes) != 1 || codes[0] != expectedCode {
				t.Fatalf("reuse bypassed %s: dials=%d codes=%v", mode, h.dialCount(), codes)
			}
		})
	}
	t.Run("racing-syn-at-cap-one", func(t *testing.T) {
		h := newEgressHarness(t)
		opening := egressSyn(t, "100.96.0.1", 40000, "203.0.113.10", 443)
		finishEgressForReuse(t, h, opening)
		p := testEgressPolicy("203.0.113.0/24")
		p.Limits = egressLimits{MaxFlowsPerConsumer: 1}
		h.runtime.applyPolicy(p, newEgressContext(), flowEpoch)
		next := opening
		next.Seq += 1000000
		h.gate = make(chan struct{})
		var once sync.Once
		release := func() { once.Do(func() { close(h.gate) }) }
		done := make(chan struct{})
		t.Cleanup(func() {
			release()
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Error("connect worker did not stop")
			}
			h.runtime.shutdown(flowEpoch)
		})
		go func() { defer close(done); h.runtime.handleFrame(7, egressFrameFor(buildTCPSegment(next)), flowEpoch) }()
		h.waitFor("replacement reservation", func() bool { return h.dialCount() == 2 })
		h.runtime.openTCPFlow(7, egressFlowKey{protocol: 6, consumerIP: next.SourceIP, consumerPort: next.SourcePort, remoteIP: next.DestinationIP, remotePort: next.DestinationPort}, next, flowEpoch)
		if h.sawReset() || len(h.rejectCodes()) != 0 || h.dialCount() != 2 {
			t.Fatal("duplicate SYN reset the authorized reserved slot")
		}
		release()
		<-done
	})
	// A live flow is never replaced even if the SYN sequence is much newer.
	t.Run("live-flow-control", func(t *testing.T) {
		h := newEgressHarness(t)
		t.Cleanup(func() { h.runtime.shutdown(flowEpoch) })
		opening := egressSyn(t, "100.96.0.1", 40000, "203.0.113.10", 443)
		h.runtime.handleFrame(7, egressFrameFor(buildTCPSegment(opening)), flowEpoch)
		h.completeHandshake(7, opening)
		next := opening
		next.Seq += 1000000
		h.runtime.handleFrame(7, egressFrameFor(buildTCPSegment(next)), flowEpoch)
		if h.dialCount() != 1 {
			t.Fatal("live flow replaced")
		}
	})
}
