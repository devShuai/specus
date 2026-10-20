package client

import (
	"bytes"
	"encoding/hex"
	"io"
	"log"
	"testing"
)

// The consumer side of the IPv6 data plane against protocol/test-vectors/peer-egress-ipv6-v1.json:
// ruleValidation, consumerOutbound, returnPath and failure. The data plane is switched on in the
// consumer directly, so these run on every platform the suite runs on whatever this build carries.

type egressIPv6ConsumerVector struct {
	RuleValidation struct {
		Cases []struct {
			Name                    string  `json:"name"`
			EgressOnline            bool    `json:"egressOnline"`
			EgressIPv6PacketCapable bool    `json:"egressIpv6PacketCapable"`
			Code                    *string `json:"code"`
			Rule                    struct {
				Match          string `json:"match"`
				Action         string `json:"action"`
				EgressClientID int64  `json:"egressClientId"`
			} `json:"rule"`
		} `json:"cases"`
	} `json:"ruleValidation"`
	ConsumerOutbound struct {
		ConsumerMeshIPv4 string `json:"consumerMeshIpv4"`
		Cases            []struct {
			Name         string `json:"name"`
			PacketHex    string `json:"packetHex"`
			EffectiveMTU int    `json:"effectiveMtu"`
			Expect       string `json:"expect"`
		} `json:"cases"`
	} `json:"consumerOutbound"`
	ReturnPath struct {
		ConsumerMeshIPv4 string `json:"consumerMeshIpv4"`
		Cases            []struct {
			Name      string `json:"name"`
			PacketHex string `json:"packetHex"`
			LiveFlow  bool   `json:"liveFlow"`
			Expect    string `json:"expect"`
		} `json:"cases"`
	} `json:"returnPath"`
	Failure struct {
		ResetOnPacket         egressIPv6FailureCases `json:"resetOnPacket"`
		UnreachableOnDatagram egressIPv6FailureCases `json:"unreachableOnDatagram"`
	} `json:"failure"`
}

type egressIPv6FailureCases struct {
	Cases []struct {
		Name      string `json:"name"`
		PacketHex string `json:"packetHex"`
		Expect    struct {
			PacketHex string `json:"packetHex"`
		} `json:"expect"`
	} `json:"cases"`
}

func readEgressIPv6ConsumerVector(t *testing.T) egressIPv6ConsumerVector {
	t.Helper()
	var vector egressIPv6ConsumerVector
	readEgressVector(t, "peer-egress-ipv6-v1.json", &vector)
	if len(vector.RuleValidation.Cases) == 0 || len(vector.ConsumerOutbound.Cases) == 0 ||
		len(vector.ReturnPath.Cases) == 0 || len(vector.Failure.ResetOnPacket.Cases) == 0 ||
		len(vector.Failure.UnreachableOnDatagram.Cases) == 0 {
		t.Fatal("the IPv6 vector carried no consumer cases")
	}
	return vector
}

// egressIPv6TestRule is the rule every packet in the vector's consumer sections falls under.
var egressIPv6TestRule = egressRule{Match: "2001:db8:1::/48", Action: egressActionEgress, EgressClientID: 2}

// newConsumerHarness6 is a consumer with the IPv6 data plane, the given mesh address, the rules, and
// egress 2 online and listed by the catalogue as taking IPv6 packets unless said otherwise.
func newConsumerHarness6(t *testing.T, meshIPv4 string, rules []egressRule, online, capable bool) *consumerHarness {
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
	harness.consumer.carriesIPv6 = true
	harness.consumer.configure(rules, egressDefaultMeshCIDR, meshIPv4, flowEpoch)
	harness.consumer.applyCatalog(egressCatalogView{Received: true, Listed: map[int64]egressCatalogListing{
		2: {IPv6PacketCapable: capable, Version: 1, VersionKnown: true},
	}}, flowEpoch)
	harness.consumer.setEgressOnline(2, online, flowEpoch)
	return harness
}

func TestEgressIPv6RuleValidationMatchesSharedVector(t *testing.T) {
	vector := readEgressIPv6ConsumerVector(t)
	toARule := decodeEgressHex(t, "to-a-rule", vector.ConsumerOutbound.Cases[0].PacketHex)
	for _, testCase := range vector.RuleValidation.Cases {
		rule := egressRule{Match: testCase.Rule.Match, Action: testCase.Rule.Action, EgressClientID: testCase.Rule.EgressClientID}
		want := ""
		if testCase.Code != nil {
			want = *testCase.Code
		}
		online := map[int64]bool{rule.EgressClientID: testCase.EgressOnline}
		capable6 := map[int64]bool{rule.EgressClientID: testCase.EgressIPv6PacketCapable}
		if code := egressRuleStatusCodeFor(rule, egressDefaultMeshCIDR, "", true, online, nil, capable6); code != want {
			t.Errorf("%s: code = %q, want %q", testCase.Name, code, want)
		}

		// The same answer from the status a running consumer publishes.
		harness := newConsumerHarness6(t, "100.96.0.1", []egressRule{rule}, testCase.EgressOnline, testCase.EgressIPv6PacketCapable)
		snapshot := harness.consumer.statusSnapshot()
		code := egressRuleStatusCodeFor(rule, snapshot.MeshCIDR, snapshot.FakeIPCIDR, snapshot.CarriesIPv6,
			snapshot.Online, snapshot.Capable, snapshot.Capable6)
		if code != want {
			t.Errorf("%s: status code = %q, want %q", testCase.Name, code, want)
		}

		// And what the traffic does: a rule out of force for its egress still claims its destination,
		// and blocks it under the egress's reason rather than letting it out.
		if want == egressCodeRuleMeshOverlap || !egressCIDR6Covers(t, rule.Match, toARule) {
			continue
		}
		harness.consumer.handleOutbound(toARule, flowEpoch)
		counts := harness.consumer.blockedCounts()
		switch {
		case !testCase.EgressOnline:
			if counts["egress-unavailable"] != 1 {
				t.Errorf("%s: blocked = %v, want egress-unavailable", testCase.Name, counts)
			}
		case want == egressCodeRuleEgressNoIPv6:
			if counts["egress-no-ipv6"] != 1 || len(harness.sent) != 0 {
				t.Errorf("%s: blocked = %v sent = %d, want egress-no-ipv6 and nothing sent", testCase.Name, counts, len(harness.sent))
			}
		default:
			if len(harness.sent) != 1 || len(counts) != 0 {
				t.Errorf("%s: sent = %d blocked = %v, want it forwarded", testCase.Name, len(harness.sent), counts)
			}
		}
	}
}

// egressCIDR6Covers reports whether a rule's match covers a packet's destination.
func egressCIDR6Covers(t *testing.T, match string, packet []byte) bool {
	t.Helper()
	cidr, _, ok := parseEgressCIDR6(match)
	return ok && cidr.contains([16]byte(packet[24:40]))
}

func TestEgressIPv6ConsumerOutboundMatchesSharedVector(t *testing.T) {
	vector := readEgressIPv6ConsumerVector(t)
	for _, testCase := range vector.ConsumerOutbound.Cases {
		harness := newConsumerHarness6(t, vector.ConsumerOutbound.ConsumerMeshIPv4, []egressRule{egressIPv6TestRule}, true, true)
		mtu := testCase.EffectiveMTU
		harness.consumer.pathMTU = func(egress int64) int {
			if egress != 2 {
				t.Errorf("%s: path MTU asked of egress %d", testCase.Name, egress)
			}
			return mtu
		}
		packet := decodeEgressHex(t, testCase.Name, testCase.PacketHex)
		outcome := harness.consumer.handleOutbound(packet, flowEpoch)
		counts := harness.consumer.blockedCounts()
		if len(harness.toTun) != 0 {
			t.Errorf("%s: answered into the TUN: %x", testCase.Name, harness.toTun)
		}
		switch testCase.Expect {
		case "forward":
			if outcome != egressOutcomeForwarded || len(harness.sent) != 1 || harness.sent[0].egress != 2 {
				t.Fatalf("%s: outcome %s, sent %d", testCase.Name, outcome, len(harness.sent))
			}
			frame, code := parsePeerEgressFrameFor(harness.sent[0].frame, true)
			if code != "" || frame.Type != peerEgressTypeIPPacket || frame.Hop || !bytes.Equal(frame.Body, packet) {
				t.Errorf("%s: the packet did not go as it was (code %q)", testCase.Name, code)
			}
			if len(counts) != 0 {
				t.Errorf("%s: blocked = %v", testCase.Name, counts)
			}
		case "drop-silently":
			if outcome != egressOutcomeIgnored || len(harness.sent) != 0 || len(counts) != 0 {
				t.Errorf("%s: outcome %s, sent %d, blocked %v; want it dropped and not counted",
					testCase.Name, outcome, len(harness.sent), counts)
			}
		default:
			if len(harness.sent) != 0 || counts[testCase.Expect] != 1 || len(counts) != 1 {
				t.Errorf("%s: outcome %s, sent %d, blocked %v; want %s", testCase.Name, outcome,
					len(harness.sent), counts, testCase.Expect)
			}
		}
	}
}

func TestEgressIPv6ReturnPathMatchesSharedVector(t *testing.T) {
	vector := readEgressIPv6ConsumerVector(t)
	// The flow the replies belong to is the vector's own outbound packet: the same five-tuple,
	// mirrored.
	opening := decodeEgressHex(t, "to-a-rule", vector.ConsumerOutbound.Cases[0].PacketHex)
	for _, testCase := range vector.ReturnPath.Cases {
		harness := newConsumerHarness6(t, vector.ReturnPath.ConsumerMeshIPv4, []egressRule{egressIPv6TestRule}, true, true)
		if testCase.LiveFlow {
			if outcome := harness.consumer.handleOutbound(opening, flowEpoch); outcome != egressOutcomeForwarded {
				t.Fatalf("%s: the flow did not open: %s", testCase.Name, outcome)
			}
		}
		packet := decodeEgressHex(t, testCase.Name, testCase.PacketHex)
		claimed := harness.consumer.handleInbound(encodePeerEgressFrame(peerEgressTypeIPPacket, false, packet), 2, flowEpoch)
		counts := harness.consumer.blockedCounts()
		switch testCase.Expect {
		case "deliver":
			if !claimed || len(harness.toTun) != 1 || !bytes.Equal(harness.toTun[0], packet) || len(counts) != 0 {
				t.Errorf("%s: claimed %v, written %d, blocked %v; want it delivered", testCase.Name, claimed, len(harness.toTun), counts)
			}
		case "not-for-consumer":
			if claimed || len(harness.toTun) != 0 || len(counts) != 0 {
				t.Errorf("%s: claimed %v, written %d, blocked %v; want it left for the egress role",
					testCase.Name, claimed, len(harness.toTun), counts)
			}
		default:
			if !claimed || len(harness.toTun) != 0 || counts[testCase.Expect] != 1 || len(counts) != 1 {
				t.Errorf("%s: claimed %v, written %d, blocked %v; want %s", testCase.Name, claimed,
					len(harness.toTun), counts, testCase.Expect)
			}
		}
	}

	// From the right five-tuple but another egress, a reply is not one this device asked for.
	harness := newConsumerHarness6(t, vector.ReturnPath.ConsumerMeshIPv4, []egressRule{egressIPv6TestRule}, true, true)
	harness.consumer.handleOutbound(opening, flowEpoch)
	reply := decodeEgressHex(t, "reply", vector.ReturnPath.Cases[0].PacketHex)
	harness.consumer.handleInbound(encodePeerEgressFrame(peerEgressTypeIPPacket, false, reply), 3, flowEpoch)
	if counts := harness.consumer.blockedCounts(); counts["return-no-flow"] != 1 || len(harness.toTun) != 0 {
		t.Errorf("a reply from another egress: blocked %v, written %d", counts, len(harness.toTun))
	}
}

// Without the data plane the consumer leaves IPv6 alone in both directions, as before it existed.
func TestEgressIPv6IsNotClaimedWithoutTheDataPlane(t *testing.T) {
	vector := readEgressIPv6ConsumerVector(t)
	harness := newConsumerHarness6(t, "100.96.0.1", []egressRule{egressIPv6TestRule}, true, true)
	harness.consumer.carriesIPv6 = false
	for _, testCase := range vector.ConsumerOutbound.Cases {
		if outcome := harness.consumer.handleOutbound(decodeEgressHex(t, testCase.Name, testCase.PacketHex), flowEpoch); outcome != egressOutcomeNotMine {
			t.Errorf("%s: outcome %s without the data plane", testCase.Name, outcome)
		}
	}
	reply := decodeEgressHex(t, "reply", vector.ReturnPath.Cases[0].PacketHex)
	if harness.consumer.handleInbound(encodePeerEgressFrame(peerEgressTypeIPPacket, false, reply), 2, flowEpoch) {
		t.Error("an IPv6 reply was claimed without the data plane")
	}
	if counts := harness.consumer.blockedCounts(); len(counts) != 0 || len(harness.sent) != 0 {
		t.Errorf("blocked %v, sent %d", counts, len(harness.sent))
	}
}

// Byte for byte: what goes back into the TUN when the egress a rule names is unavailable.
func TestEgressIPv6FailureMatchesSharedVector(t *testing.T) {
	vector := readEgressIPv6ConsumerVector(t)
	all := append(append([]struct {
		Name      string `json:"name"`
		PacketHex string `json:"packetHex"`
		Expect    struct {
			PacketHex string `json:"packetHex"`
		} `json:"expect"`
	}(nil), vector.Failure.ResetOnPacket.Cases...), vector.Failure.UnreachableOnDatagram.Cases...)
	for _, testCase := range all {
		packet := decodeEgressHex(t, testCase.Name, testCase.PacketHex)
		want := decodeEgressHex(t, testCase.Name, testCase.Expect.PacketHex)
		if got := egressFailurePacket6(packet, int(packet[6])); !bytes.Equal(got, want) {
			t.Errorf("%s: answer\n got %s\nwant %s", testCase.Name, hex.EncodeToString(got), testCase.Expect.PacketHex)
		}

		// Through the data plane: the rule's egress is offline.
		harness := newConsumerHarness6(t, "100.96.0.1", []egressRule{egressIPv6TestRule}, false, true)
		if outcome := harness.consumer.handleOutbound(packet, flowEpoch); outcome != egressOutcomeBlockedNoEgress {
			t.Errorf("%s: outcome %s", testCase.Name, outcome)
		}
		if len(harness.toTun) != 1 || !bytes.Equal(harness.toTun[0], want) {
			t.Errorf("%s: the TUN was written %d packets, not the vector's answer", testCase.Name, len(harness.toTun))
		}
		if len(want) > egressIPv6MinimumMTU {
			t.Errorf("%s: the answer is %d bytes, past the IPv6 minimum MTU", testCase.Name, len(want))
		}
	}
}

// resetOnPurge in IPv6: a flow the consumer closes itself is reset from what it remembered, by the
// same rule as IPv4, and the purge names the destination as a /128.
func TestEgressIPv6PurgeResetsTheFlow(t *testing.T) {
	harness := newConsumerHarness6(t, "100.96.0.1", []egressRule{egressIPv6TestRule}, true, true)
	local, _ := egressDeviceAddress6("100.96.0.1")
	remote, _ := parseEgressAddress6("2001:db8:1::c8")
	segment := tcpSegment{IPv6: true, SourceIP6: local, DestinationIP6: remote, SourcePort: 40000, DestinationPort: 443,
		Seq: 5000, Ack: 9000, Flags: tcpFlagACK | tcpFlagPSH, Window: 65535, Payload: []byte("GET /")}
	if outcome := harness.consumer.handleOutbound(buildTCPSegment(segment), flowEpoch); outcome != egressOutcomeForwarded {
		t.Fatalf("outcome %s", outcome)
	}
	purge := harness.consumer.setEgressOnline(2, false, flowEpoch)
	if destinations := purge[2]; len(destinations) != 1 || destinations[0] != "2001:db8:1::c8/128" {
		t.Errorf("purge = %v", purge)
	}
	if len(harness.toTun) != 1 {
		t.Fatalf("resets written: %d", len(harness.toTun))
	}
	reset, ok := parseTCPSegment6(harness.toTun[0])
	if !ok {
		t.Fatalf("the reset does not read as IPv6 TCP: %x", harness.toTun[0])
	}
	if reset.SourceIP6 != remote || reset.DestinationIP6 != local || reset.SourcePort != 443 || reset.DestinationPort != 40000 ||
		reset.Flags != tcpFlagRST|tcpFlagACK || reset.Seq != 9000 || reset.Ack != 5005 || reset.Window != 0 {
		t.Errorf("reset = %+v", reset)
	}
	if harness.toTun[0][7] != ipv6HopLimit || harness.toTun[0][1] != 0 {
		t.Errorf("reset header %x", harness.toTun[0][:8])
	}

	// The catalogue no longer saying the egress takes IPv6 packets closes the flow as well.
	harness = newConsumerHarness6(t, "100.96.0.1", []egressRule{egressIPv6TestRule}, true, true)
	harness.consumer.handleOutbound(buildTCPSegment(segment), flowEpoch)
	purge = harness.consumer.applyCatalog(egressCatalogView{Received: true, Listed: map[int64]egressCatalogListing{
		2: {Version: 1, VersionKnown: true},
	}}, flowEpoch)
	if len(purge[2]) != 1 || harness.consumer.flowCount() != 0 {
		t.Errorf("the catalogue withdrew the capability and the flow stayed: purge %v, flows %d", purge, harness.consumer.flowCount())
	}
}

// A flow-reject for an IPv6 flow names it in IPv6, and resets and forgets it.
func TestEgressIPv6FlowRejectClosesTheFlow(t *testing.T) {
	harness := newConsumerHarness6(t, "100.96.0.1", []egressRule{egressIPv6TestRule}, true, true)
	local, _ := egressDeviceAddress6("100.96.0.1")
	remote, _ := parseEgressAddress6("2001:db8:1::c8")
	harness.consumer.handleOutbound(buildTCPSegment(tcpSegment{IPv6: true, SourceIP6: local, DestinationIP6: remote,
		SourcePort: 40000, DestinationPort: 443, Seq: 5000, Ack: 9000, Flags: tcpFlagACK, Window: 65535}), flowEpoch)
	body, err := encodePeerEgressControl(peerEgressControl{Type: peerEgressControlFlowReject, Code: egressCodeDestinationDenied,
		Protocol: "tcp", SourceIP: formatEgressAddress6(local), SourcePort: 40000,
		DestinationIP: formatEgressAddress6(remote), DestinationPort: 443})
	if err != nil {
		t.Fatal(err)
	}
	if !harness.consumer.handleInbound(encodePeerEgressFrame(peerEgressTypeControl, false, body), 2, flowEpoch) {
		t.Fatal("the flow-reject was not claimed")
	}
	if harness.consumer.flowCount() != 0 || len(harness.toTun) != 1 {
		t.Errorf("flows %d, resets %d", harness.consumer.flowCount(), len(harness.toTun))
	}
	if counts := harness.consumer.blockedCounts(); counts["rejected-egress_dest_denied"] != 1 {
		t.Errorf("blocked = %v", counts)
	}
}

// The rule set of the rules vector's ipv6 section, run through the consumer's own steering with the
// data plane: what each IPv6 destination's packet does is what the vector says the rules decide.
func TestEgressIPv6ConsumerSteersByTheRulesVector(t *testing.T) {
	vector, rules := loadEgressIPv6Vector(t)
	harness := newConsumerHarness6(t, "100.96.0.1", rules, true, true)
	for _, testCase := range vector.IPv6.Cases {
		destination, ok := parseEgressAddress6(testCase.Destination)
		if !ok {
			continue
		}
		harness.consumer.mu.Lock()
		steering := harness.consumer.steer6Locked(destination)
		harness.consumer.mu.Unlock()
		switch testCase.Expect.Action {
		case egressActionEgress:
			if !steering.claimed || steering.blocked != "" || steering.egress != testCase.Expect.EgressClientID {
				t.Errorf("%s: steering %+v", testCase.Name, steering)
			}
		case egressActionBlock:
			if !steering.claimed || steering.blocked != "rule" {
				t.Errorf("%s: steering %+v", testCase.Name, steering)
			}
		default:
			if steering.claimed {
				t.Errorf("%s: a direct destination was claimed: %+v", testCase.Name, steering)
			}
		}
	}
}

// Whether a device carries IPv6 is its platform's support and an MTU of at least 1280; unset reads as
// the default, which is 1280.
func TestEgressConsumerCarriesIPv6NeedsThePlatformAndTheMinimumMTU(t *testing.T) {
	if egressConsumerCarriesIPv6(MinPeerMeshMTU) || egressConsumerCarriesIPv6(1279) {
		t.Error("a Peer Mesh MTU below 1280 carries IPv6")
	}
	if got := egressConsumerCarriesIPv6(1280); got != egressPlatformCarriesIPv6 {
		t.Errorf("at 1280: %v, platform says %v", got, egressPlatformCarriesIPv6)
	}
	if got := egressConsumerCarriesIPv6(0); got != egressPlatformCarriesIPv6 {
		t.Errorf("unset: %v, platform says %v", got, egressPlatformCarriesIPv6)
	}
}
