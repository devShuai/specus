package client

import (
	"errors"
	"io"
	"log"
	"testing"
	"time"
)

// The consumer data plane, tested from the leak side.
//
// Almost every case here asks the same question in a different way: can a destination the user
// routed through an egress end up going out locally instead? A connection that fails is a bad
// afternoon; a connection that silently uses the wrong source address is the thing the user
// installed this to prevent.

type consumerHarness struct {
	t        *testing.T
	consumer *egressConsumer
	sent     []struct {
		egress int64
		frame  []byte
	}
	toTun   [][]byte
	sendErr error
}

func newConsumerHarness(t *testing.T, rules []egressRule, online map[int64]bool) *consumerHarness {
	t.Helper()
	harness := &consumerHarness{t: t}
	harness.consumer = newEgressConsumer(log.New(io.Discard, "", 0),
		func(egress int64, frame []byte) error {
			if harness.sendErr != nil {
				return harness.sendErr
			}
			harness.sent = append(harness.sent, struct {
				egress int64
				frame  []byte
			}{egress, append([]byte(nil), frame...)})
			return nil
		},
		func(packet []byte) error {
			harness.toTun = append(harness.toTun, append([]byte(nil), packet...))
			return nil
		})
	harness.consumer.configure(rules, egressDefaultMeshCIDR, "100.96.0.1", flowEpoch)
	for egress, up := range online {
		harness.consumer.setEgressOnline(egress, up, flowEpoch)
	}
	return harness
}

func consumerRules() []egressRule {
	return []egressRule{
		{Match: "203.0.113.0/24", Action: egressActionEgress, EgressClientID: 2},
		{Match: "192.0.2.0/24", Action: egressActionBlock},
		{Match: "198.51.100.0/24", Action: egressActionDirect},
	}
}

func consumerPacket(t *testing.T, destination string, port int) []byte {
	t.Helper()
	return buildTCPSegment(tcpSegment{
		SourceIP: testAddr(t, "100.96.0.1"), DestinationIP: testAddr(t, destination),
		SourcePort: 40000, DestinationPort: uint16(port),
		Seq: 1000, Flags: tcpFlagSYN, Window: 65535,
	})
}

func TestConsumerForwardsAMatchedDestination(t *testing.T) {
	harness := newConsumerHarness(t, consumerRules(), map[int64]bool{2: true})

	outcome := harness.consumer.handleOutbound(consumerPacket(t, "203.0.113.10", 443), flowEpoch)
	if outcome != egressOutcomeForwarded {
		t.Fatalf("outcome = %s", outcome)
	}
	if len(harness.sent) != 1 || harness.sent[0].egress != 2 {
		t.Fatalf("sent %d frames", len(harness.sent))
	}
	frame, code := parsePeerEgressFrame(harness.sent[0].frame)
	if code != "" {
		t.Fatalf("the frame we built does not parse: %s", code)
	}
	// hop stays clear: this node is a consumer, not an egress forwarding for another one.
	if frame.Hop {
		t.Error("the hop flag was set, which an egress refuses")
	}
	if frame.Inner.DestinationIP != "203.0.113.10" {
		t.Errorf("inner destination = %s", frame.Inner.DestinationIP)
	}
}

// Traffic no rule claims is not this layer's business. Claiming it would swallow the mesh's own
// packets, which share the device.
func TestConsumerLeavesUnclaimedTrafficAlone(t *testing.T) {
	harness := newConsumerHarness(t, consumerRules(), map[int64]bool{2: true})

	for _, destination := range []string{"8.8.8.8", "198.51.100.10", "100.96.0.5"} {
		if outcome := harness.consumer.handleOutbound(consumerPacket(t, destination, 443), flowEpoch); outcome != egressOutcomeNotMine {
			t.Errorf("%s: outcome = %s, want not-mine", destination, outcome)
		}
	}
	if len(harness.sent) != 0 {
		t.Errorf("%d frames were sent for traffic no rule claims", len(harness.sent))
	}
}

// The whole point. An egress that cannot take the flow means the packet is dropped, never handed
// back to the local stack.
func TestConsumerBlocksWhenTheEgressIsUnavailable(t *testing.T) {
	cases := []struct {
		name  string
		setup func(*consumerHarness)
	}{
		{"never online", func(*consumerHarness) {}},
		{"went offline", func(h *consumerHarness) {
			h.consumer.setEgressOnline(2, true, flowEpoch)
			h.consumer.setEgressOnline(2, false, flowEpoch)
		}},
		{"the send fails", func(h *consumerHarness) {
			h.consumer.setEgressOnline(2, true, flowEpoch)
			h.sendErr = errors.New("no path to peer")
		}},
	}
	for _, testCase := range cases {
		harness := newConsumerHarness(t, consumerRules(), nil)
		testCase.setup(harness)

		outcome := harness.consumer.handleOutbound(consumerPacket(t, "203.0.113.10", 443), flowEpoch)
		if outcome != egressOutcomeBlockedNoEgress {
			t.Errorf("%s: outcome = %s, want blocked", testCase.name, outcome)
		}
		if outcome == egressOutcomeNotMine {
			t.Errorf("%s: the packet was handed back to the local stack", testCase.name)
		}
	}
}

func TestConsumerBlocksWhatABlockRuleClaims(t *testing.T) {
	harness := newConsumerHarness(t, consumerRules(), map[int64]bool{2: true})

	if outcome := harness.consumer.handleOutbound(consumerPacket(t, "192.0.2.10", 443), flowEpoch); outcome != egressOutcomeBlockedByRule {
		t.Errorf("outcome = %s", outcome)
	}
	if len(harness.sent) != 0 {
		t.Error("a blocked destination was forwarded to an egress")
	}
}

// ICMP has no egress in this version. The rule still says this destination must not go out locally,
// so it is dropped rather than handed back.
func TestConsumerDropsProtocolsItCannotCarry(t *testing.T) {
	harness := newConsumerHarness(t, consumerRules(), map[int64]bool{2: true})

	packet := make([]byte, 28)
	packet[0] = 0x45
	packet[2], packet[3] = 0, 28
	packet[9] = ipv4ProtocolICMP
	copy(packet[12:16], []byte{100, 96, 0, 1})
	copy(packet[16:20], []byte{203, 0, 113, 10})

	if outcome := harness.consumer.handleOutbound(packet, flowEpoch); outcome != egressOutcomeUnsupported {
		t.Errorf("outcome = %s, want unsupported", outcome)
	}
	if len(harness.sent) != 0 {
		t.Error("an unsupported protocol was forwarded")
	}
}

// Three ways the return path could be abused, each closed by its own check.
func TestConsumerRefusesReturnTrafficItDidNotAskFor(t *testing.T) {
	harness := newConsumerHarness(t, consumerRules(), map[int64]bool{2: true})
	harness.consumer.handleOutbound(consumerPacket(t, "203.0.113.10", 443), flowEpoch)

	reply := func(source, destination string, sourcePort, destinationPort int) []byte {
		return encodePeerEgressFrame(peerEgressTypeIPPacket, false, buildTCPSegment(tcpSegment{
			SourceIP: testAddr(t, source), DestinationIP: testAddr(t, destination),
			SourcePort: uint16(sourcePort), DestinationPort: uint16(destinationPort),
			Seq: 1, Ack: 1001, Flags: tcpFlagSYN | tcpFlagACK, Window: 65535,
		}))
	}

	// Addressed to somebody else's virtual IP.
	harness.consumer.handleInbound(reply("203.0.113.10", "100.96.0.9", 443, 40000), 2, flowEpoch)
	// Claiming a mesh address, which would let an egress speak as another peer.
	harness.consumer.handleInbound(reply("100.96.0.5", "100.96.0.1", 443, 40000), 2, flowEpoch)
	// From an address no flow of ours is talking to.
	harness.consumer.handleInbound(reply("198.51.100.10", "100.96.0.1", 443, 40000), 2, flowEpoch)
	// From the right address but the wrong egress.
	harness.consumer.handleInbound(reply("203.0.113.10", "100.96.0.1", 443, 40000), 3, flowEpoch)

	if len(harness.toTun) != 0 {
		t.Errorf("%d forged replies reached the local stack", len(harness.toTun))
	}

	// The genuine reply does get through, so the checks above are not simply refusing everything.
	harness.consumer.handleInbound(reply("203.0.113.10", "100.96.0.1", 443, 40000), 2, flowEpoch)
	if len(harness.toTun) != 1 {
		t.Errorf("the genuine reply did not reach the local stack: %d writes", len(harness.toTun))
	}
}

// An established flow survives a rule change that still sends it to the same egress, and does not
// survive one that stops.
func TestConsumerPurgesFlowsARuleChangeInvalidates(t *testing.T) {
	harness := newConsumerHarness(t, consumerRules(), map[int64]bool{2: true})
	harness.consumer.handleOutbound(consumerPacket(t, "203.0.113.10", 443), flowEpoch)
	if harness.consumer.flowCount() != 1 {
		t.Fatalf("%d flows after one packet", harness.consumer.flowCount())
	}

	// A change that leaves the rule saying the same thing keeps the flow.
	unchanged := harness.consumer.configure(append(consumerRules(),
		egressRule{Match: "10.1.0.0/16", Action: egressActionBlock}),
		egressDefaultMeshCIDR, "100.96.0.1", flowEpoch)
	if len(unchanged) != 0 || harness.consumer.flowCount() != 1 {
		t.Errorf("an unrelated rule addition purged %d egresses", len(unchanged))
	}

	// Turning the rule into a block closes the flow and tells the egress to drop its side.
	purge := harness.consumer.configure([]egressRule{
		{Match: "203.0.113.0/24", Action: egressActionBlock},
	}, egressDefaultMeshCIDR, "100.96.0.1", flowEpoch)

	if harness.consumer.flowCount() != 0 {
		t.Errorf("%d flows survived the rule change", harness.consumer.flowCount())
	}
	if len(purge[2]) != 1 || purge[2][0] != "203.0.113.10/32" {
		t.Errorf("purge for egress 2 = %v", purge[2])
	}
}

// Without the purge the egress holds the socket until its own idle timer, and the user sees a
// connection that is dead at one end and open at the other.
func TestConsumerPurgesFlowsWhenTheEgressGoesOffline(t *testing.T) {
	harness := newConsumerHarness(t, consumerRules(), map[int64]bool{2: true})
	harness.consumer.handleOutbound(consumerPacket(t, "203.0.113.10", 443), flowEpoch)
	harness.consumer.handleOutbound(consumerPacket(t, "203.0.113.11", 443), flowEpoch)

	purge := harness.consumer.setEgressOnline(2, false, flowEpoch)
	if harness.consumer.flowCount() != 0 {
		t.Errorf("%d flows survived the egress going offline", harness.consumer.flowCount())
	}
	if len(purge[2]) != 2 {
		t.Errorf("purge for egress 2 = %v, want both destinations", purge[2])
	}
}

// A flow-reject is diagnostic, but it does tell the consumer this flow is over, so the entry goes
// rather than lingering until something else clears it.
func TestConsumerDropsAFlowTheEgressRejected(t *testing.T) {
	harness := newConsumerHarness(t, consumerRules(), map[int64]bool{2: true})
	harness.consumer.handleOutbound(consumerPacket(t, "203.0.113.10", 443), flowEpoch)

	body, err := encodePeerEgressControl(peerEgressControl{
		Type: peerEgressControlFlowReject, Protocol: "tcp",
		SourceIP: "100.96.0.1", SourcePort: 40000,
		DestinationIP: "203.0.113.10", DestinationPort: 443,
		Code: egressCodePortDenied,
	})
	if err != nil {
		t.Fatal(err)
	}
	harness.consumer.handleInbound(encodePeerEgressFrame(peerEgressTypeControl, false, body), 2, flowEpoch)

	if harness.consumer.flowCount() != 0 {
		t.Errorf("%d flows survived a flow-reject", harness.consumer.flowCount())
	}
	if counts := harness.consumer.blockedCounts(); counts["rejected-egress_port_denied"] != 1 {
		t.Errorf("blocked counts = %v", counts)
	}
}

// Counted by reason and never by destination. A per-destination record would be the user's own
// browsing history, which is the same reason the egress report aggregates by code.
func TestConsumerCountsBlocksByReasonOnly(t *testing.T) {
	harness := newConsumerHarness(t, consumerRules(), nil)
	harness.consumer.handleOutbound(consumerPacket(t, "192.0.2.10", 443), flowEpoch)
	harness.consumer.handleOutbound(consumerPacket(t, "192.0.2.11", 443), flowEpoch)
	harness.consumer.handleOutbound(consumerPacket(t, "203.0.113.10", 443), flowEpoch)

	counts := harness.consumer.blockedCounts()
	if counts["rule"] != 2 {
		t.Errorf("rule blocks = %d, want 2", counts["rule"])
	}
	if counts["egress-unavailable"] != 1 {
		t.Errorf("unavailable blocks = %d, want 1", counts["egress-unavailable"])
	}
	for reason := range counts {
		for _, destination := range []string{"192.0.2", "203.0.113"} {
			if len(reason) >= len(destination) && reason[:len(destination)] == destination {
				t.Errorf("a destination leaked into the counters as %q", reason)
			}
		}
	}
}

func TestConsumerIgnoresNonEgressFrames(t *testing.T) {
	harness := newConsumerHarness(t, consumerRules(), map[int64]bool{2: true})
	bare := buildTCPSegment(tcpSegment{
		SourceIP: testAddr(t, "203.0.113.10"), DestinationIP: testAddr(t, "100.96.0.1"),
		SourcePort: 443, DestinationPort: 40000, Flags: tcpFlagACK, Window: 65535,
	})
	if harness.consumer.handleInbound(bare, 2, time.Now()) {
		t.Error("a bare IPv4 packet was claimed by the egress return path")
	}
}
