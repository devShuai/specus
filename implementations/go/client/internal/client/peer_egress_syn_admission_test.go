package client

import (
	"testing"
	"time"
)

func TestEgressSynAckAdmissionPreservesSequenceMSSAndHandshake(t *testing.T) {
	syn := egressSyn(t, "100.96.0.1", 40000, "203.0.113.10", 443)
	iss := ^uint32(0)
	admit := false
	var sent []tcpSegment
	conn, output := acceptTCPSynWithTransmit(syn, iss, 1280, time.Minute, flowEpoch, func(packet []byte) bool {
		if !admit {
			return false
		}
		segment, ok := parseTCPSegment(packet)
		if !ok {
			t.Fatal("invalid admitted segment")
		}
		sent = append(sent, segment)
		return true
	})
	if len(output.Segments) != 0 || !conn.sendBlocked || conn.sndNxt != iss || len(conn.retransmit) != 0 {
		t.Fatal("rejected SYN-ACK advanced sequence space or bypassed admission")
	}
	// A target may speak first, but no data can precede the admitted handshake.
	conn.onAppData([]byte("hello"), flowEpoch)
	ack := syn
	ack.Flags, ack.Seq, ack.Ack = tcpFlagACK, syn.Seq+1, iss
	conn.onSegment(ack, flowEpoch)
	for i := 1; i <= 10; i++ {
		conn.onTick(flowEpoch.Add(time.Duration(i) * time.Millisecond))
	}
	if conn.state != tcpStateSynReceived || len(conn.retransmit) != 0 || conn.sndNxt != iss || len(sent) != 0 {
		t.Fatal("rejection or forged ACK spent sequence space, retries, or opened handshake")
	}
	admit = true
	admittedAt := flowEpoch.Add(2 * time.Second)
	conn.onTick(admittedAt)
	if len(sent) != 1 || sent[0].Flags != tcpFlagSYN|tcpFlagACK || sent[0].Seq != iss || sent[0].MSS != 1240 {
		t.Fatalf("initial admission changed SYN-ACK identity or MSS: %+v", sent)
	}
	if len(conn.retransmit) != 1 || conn.retransmit[0].attempts != 0 || !conn.retransmit[0].sentAt.Equal(admittedAt) {
		t.Fatal("local backpressure consumed network retransmission budget")
	}
	conn.onTick(admittedAt.Add(tcpInitialRTO - time.Millisecond))
	if len(sent) != 1 {
		t.Fatal("RTO started before actual admission")
	}
	ack.Ack = iss + uint32(1) // wrap to zero is valid TCP sequence arithmetic
	conn.onSegment(ack, admittedAt.Add(tcpInitialRTO))
	if conn.state != tcpStateEstablished || len(sent) != 2 || sent[1].Seq != 0 || string(sent[1].Payload) != "hello" {
		t.Fatal("valid handshake did not release buffered data after admitted SYN-ACK")
	}
}

func TestEgressPendingSynAckDoesNotSurviveRevocation(t *testing.T) {
	h := newEgressHarness(t)
	t.Cleanup(func() { h.runtime.shutdown(flowEpoch) })
	h.runtime.send = func(_ int64, _ []byte) error { return errEgressQueueFull }
	syn := egressSyn(t, "100.96.0.1", 40000, "203.0.113.10", 443)
	h.runtime.handleFrame(7, egressFrameFor(buildTCPSegment(syn)), flowEpoch)
	h.runtime.revokeConsumer(7, flowEpoch)
	if !h.socket(0).isClosed() {
		t.Fatal("revocation retained the pending socket")
	}
	var admitted int
	h.runtime.send = func(_ int64, _ []byte) error { admitted++; return nil }
	h.runtime.sendReady(flowEpoch.Add(time.Millisecond))
	h.runtime.onTick(flowEpoch.Add(2 * time.Second))
	if admitted != 0 || h.dialCount() != 1 {
		t.Fatal("revoked pending handshake resumed or redialed")
	}
}
