package client

import "testing"

// Binds the per-consumer new-flow bucket to protocol/test-vectors/peer-egress-rate-v1.json, then
// checks that the runtime spends a token only where the spec says: on a flow every other check
// admitted and that does not exist yet.

type egressFlowRateVector struct {
	Capacity        int    `json:"capacity"`
	RefillPerSecond int    `json:"refillPerSecond"`
	RefusalCode     string `json:"refusalCode"`
	Events          []struct {
		AtMs     int64 `json:"atMs"`
		Consumer int64 `json:"consumer"`
		Flows    int   `json:"flows"`
		Admitted int   `json:"admitted"`
		Refused  int   `json:"refused"`
	} `json:"events"`
}

func TestEgressFlowRateMatchesSharedVector(t *testing.T) {
	var vector egressFlowRateVector
	readRepositoryJSON(t, "protocol/test-vectors/peer-egress-rate-v1.json", &vector)
	if vector.Capacity != egressFlowRateCapacity || vector.RefillPerSecond != egressFlowRateRefillPerSecond {
		t.Fatalf("vector bucket %d refilling %d/s, implementation %d refilling %d/s",
			vector.Capacity, vector.RefillPerSecond, egressFlowRateCapacity, egressFlowRateRefillPerSecond)
	}
	if vector.RefusalCode != egressCodeLimitExceeded {
		t.Fatalf("vector refuses with %s, implementation with %s", vector.RefusalCode, egressCodeLimitExceeded)
	}
	if len(vector.Events) == 0 {
		t.Fatal("the vector has no events")
	}
	rate := newEgressFlowRate()
	for index, event := range vector.Events {
		admitted := 0
		for range event.Flows {
			if rate.admit(event.Consumer, event.AtMs) {
				admitted++
			}
		}
		if admitted != event.Admitted || event.Flows-admitted != event.Refused {
			t.Errorf("event %d (consumer %d at %d ms): admitted %d refused %d, want %d and %d",
				index, event.Consumer, event.AtMs, admitted, event.Flows-admitted, event.Admitted, event.Refused)
		}
	}
}

// Forgetting a bucket is safe only once it is full again, because a forgotten consumer starts over
// with a full one.
func TestEgressFlowRateForgetsOnlyRefilledBuckets(t *testing.T) {
	rate := newEgressFlowRate()
	for range egressFlowRateCapacity {
		rate.admit(7, 0)
	}
	rate.admit(9, 1000)
	if !rate.admit(7, 1000) {
		t.Fatal("a second of refill gave consumer 7 nothing")
	}

	// Both last took a token at 1000 ms, consumer 7 leaving 63 and consumer 9 leaving 127. A second
	// later, when the first sweep is due, 9 is full and 7 one token short.
	rate.admit(11, egressFlowRateFullAfterMs)
	if _, kept := rate.buckets[9]; kept {
		t.Error("a bucket that had refilled was kept")
	}
	if _, kept := rate.buckets[7]; !kept {
		t.Fatal("a bucket still refilling was forgotten, which would hand its consumer a full one")
	}
	if got := len(rate.buckets); got != 2 {
		t.Errorf("%d buckets held, want consumers 7 and 11", got)
	}
}

func TestEgressRuntimeRateLimitsNewFlowsPerConsumer(t *testing.T) {
	harness := newEgressHarness(t, "203.0.113.0/24")
	t.Cleanup(func() { harness.runtime.shutdown(flowEpoch) })
	var nowMs int64
	harness.runtime.flowRate.clock = func() int64 { return nowMs }

	// Attempts any other check refuses spend nothing.
	for port := 40000; port < 40000+2*egressFlowRateCapacity; port++ {
		harness.runtime.handleFrame(9, egressFrameFor(buildTCPSegment(
			egressSyn(t, "100.96.0.2", port, "198.51.100.10", 443))), flowEpoch)
	}
	if _, charged := harness.runtime.flowRate.buckets[9]; charged {
		t.Error("flows refused by the destination rules took tokens")
	}

	syns := make([]tcpSegment, 0, egressFlowRateCapacity)
	for port := 40000; port < 40000+egressFlowRateCapacity; port++ {
		syn := egressSyn(t, "100.96.0.1", port, "203.0.113.10", 443)
		syns = append(syns, syn)
		harness.runtime.handleFrame(7, egressFrameFor(buildTCPSegment(syn)), flowEpoch)
	}
	if harness.dialCount() != egressFlowRateCapacity {
		t.Fatalf("dialled %d of the first %d flows at one instant", harness.dialCount(), egressFlowRateCapacity)
	}
	harness.reset()

	over := egressSyn(t, "100.96.0.1", 40000+egressFlowRateCapacity, "203.0.113.10", 443)
	harness.runtime.handleFrame(7, egressFrameFor(buildTCPSegment(over)), flowEpoch)
	harness.runtime.handleFrame(7, egressFrameFor(buildUDPDatagram(udpDatagram{
		SourceIP: testAddr(t, "100.96.0.1"), DestinationIP: testAddr(t, "203.0.113.53"),
		SourcePort: 51000, DestinationPort: 53, Payload: []byte("query"),
	})), flowEpoch)
	if harness.dialCount() != egressFlowRateCapacity {
		t.Error("a flow past the bucket reached a socket")
	}
	if codes := harness.rejectCodes(); len(codes) != 2 || codes[0] != egressCodeLimitExceeded || codes[1] != egressCodeLimitExceeded {
		t.Errorf("reject codes past the bucket = %v", codes)
	}
	if !harness.sawReset() {
		t.Error("the refused SYN got no reset, so its application waits on a flow that will never open")
	}
	if counts := harness.runtime.rejections.cumulativeCounts(); counts[egressCodeLimitExceeded] != 2 {
		t.Errorf("refusal aggregate = %v, want two %s", counts, egressCodeLimitExceeded)
	}

	// Another consumer has a bucket of its own.
	harness.reset()
	harness.runtime.handleFrame(9, egressFrameFor(buildTCPSegment(
		egressSyn(t, "100.96.0.2", 41000, "203.0.113.10", 443))), flowEpoch)
	if harness.dialCount() != egressFlowRateCapacity+1 || len(harness.rejectCodes()) != 0 {
		t.Errorf("consumer 9 was held to consumer 7's bucket: dialled %d, rejects %v",
			harness.dialCount(), harness.rejectCodes())
	}

	// A retransmitted SYN of a flow that exists is not a new flow, whether it reaches the flow's own
	// state machine or races into the opening path.
	harness.reset()
	harness.runtime.handleFrame(7, egressFrameFor(buildTCPSegment(syns[0])), flowEpoch)
	key := egressFlowKey{protocol: ipv4ProtocolTCP, consumerIP: syns[1].SourceIP,
		consumerPort: syns[1].SourcePort, remoteIP: syns[1].DestinationIP, remotePort: syns[1].DestinationPort}
	harness.runtime.openTCPFlow(7, key, syns[1], flowEpoch)
	if codes := harness.rejectCodes(); len(codes) != 0 {
		t.Errorf("a retransmitted SYN was refused as a new flow: %v", codes)
	}
	if harness.dialCount() != egressFlowRateCapacity+1 {
		t.Error("a retransmitted SYN dialled again")
	}
	if harness.sawReset() {
		t.Error("a retransmitted SYN was reset")
	}
	harness.runtime.mu.Lock()
	forConsumer, _ := harness.runtime.flows.counts(7)
	harness.runtime.mu.Unlock()
	if forConsumer != egressFlowRateCapacity {
		t.Errorf("consumer 7 holds %d flows after the retransmissions, want %d", forConsumer, egressFlowRateCapacity)
	}

	// A token takes 15.625 ms to come back.
	harness.reset()
	nowMs = 15
	harness.runtime.handleFrame(7, egressFrameFor(buildTCPSegment(over)), flowEpoch)
	if codes := harness.rejectCodes(); len(codes) != 1 || codes[0] != egressCodeLimitExceeded {
		t.Errorf("reject codes 15 ms on = %v", codes)
	}
	harness.reset()
	nowMs = 16
	harness.runtime.handleFrame(7, egressFrameFor(buildTCPSegment(over)), flowEpoch)
	if codes := harness.rejectCodes(); len(codes) != 0 || harness.dialCount() != egressFlowRateCapacity+2 {
		t.Errorf("16 ms on: dialled %d, reject codes %v", harness.dialCount(), codes)
	}
}
