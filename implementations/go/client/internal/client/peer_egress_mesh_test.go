package client

import (
	"io"
	"log"
	"testing"
	"time"
)

// The wiring between Peer Mesh and the egress plane. The plane itself is covered by its own
// fault-injection suite; what these cases hold down is the join: the pushed policy, the revision
// guard that keeps a replayed push from walking it backwards, and the framing budget a returning
// segment has to fit.

func newEgressMeshHarness(t *testing.T) *peerMeshClient {
	t.Helper()
	return newPeerMeshClient(
		Config{PeerMeshDevice: "noop", PeerMeshTunName: "specus0", PeerMeshMTU: 1280,
			ServerBaseURL: "https://198.51.100.7:8443"},
		log.New(io.Discard, "", 0))
}

func TestEgressControlAppliesAPushedPolicy(t *testing.T) {
	mesh := newEgressMeshHarness(t)
	defer mesh.shutdownEgress()

	mesh.applyEgressControl(`{"type":"egress-config","enabled":true,"revision":7,"scope":"PUBLIC",
		"allowedConsumerClientIds":[5],
		"destinationRules":[{"cidr":"203.0.113.0/24","protocols":["tcp"],"portRanges":[[443,443]]}],
		"limits":{"maxConcurrentFlows":256,"maxFlowsPerConsumer":64,"idleTimeoutSeconds":60}}`)

	runtime := mesh.ensureEgress()
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	if !runtime.enabled {
		t.Error("the pushed policy did not enable the egress")
	}
	if runtime.policy.Scope != egressScopePublic {
		t.Errorf("scope = %q", runtime.policy.Scope)
	}
	if len(runtime.policy.DestinationRules) != 1 {
		t.Fatalf("%d destination rules", len(runtime.policy.DestinationRules))
	}
	if runtime.flows.idleTimeout != 60*time.Second {
		t.Errorf("idle timeout = %s", runtime.flows.idleTimeout)
	}
}

// A snapshot at or below the last accepted revision is ignored, so a reordered or replayed push
// cannot walk the policy backwards into permissions the operator has already withdrawn.
func TestEgressControlIgnoresAStaleRevision(t *testing.T) {
	mesh := newEgressMeshHarness(t)
	defer mesh.shutdownEgress()

	mesh.applyEgressControl(`{"type":"egress-config","enabled":true,"revision":7,"scope":"PUBLIC",
		"allowedConsumerClientIds":[5],
		"destinationRules":[{"cidr":"203.0.113.0/24","protocols":["tcp"],"portRanges":[[443,443]]}]}`)
	// A replay of an older, broader snapshot.
	mesh.applyEgressControl(`{"type":"egress-config","enabled":true,"revision":6,"scope":"PUBLIC",
		"allowedConsumerClientIds":[5,9],
		"destinationRules":[{"cidr":"0.0.0.0/0","protocols":["tcp","udp"],"portRanges":[[1,65535]]}]}`)

	runtime := mesh.ensureEgress()
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	if len(runtime.policy.AllowedConsumerClientIDs) != 1 {
		t.Errorf("the stale snapshot was applied: consumers = %v", runtime.policy.AllowedConsumerClientIDs)
	}
	if runtime.policy.DestinationRules[0].CIDR != "203.0.113.0/24" {
		t.Errorf("rules came from the stale snapshot: %v", runtime.policy.DestinationRules)
	}
}

// Disabling has to stop the egress, so a push that turns the switch off must not be mistaken for a
// stale one and skipped.
func TestEgressControlAppliesADisablingPush(t *testing.T) {
	mesh := newEgressMeshHarness(t)
	defer mesh.shutdownEgress()

	mesh.applyEgressControl(`{"type":"egress-config","enabled":true,"revision":7,
		"destinationRules":[{"cidr":"203.0.113.0/24","protocols":["tcp"],"portRanges":[[443,443]]}]}`)
	mesh.applyEgressControl(`{"type":"egress-config","enabled":false,"revision":8}`)

	runtime := mesh.ensureEgress()
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	if runtime.enabled {
		t.Error("the egress stayed enabled after a disabling push")
	}
}

func TestEgressControlIgnoresMalformedPushes(t *testing.T) {
	mesh := newEgressMeshHarness(t)
	defer mesh.shutdownEgress()

	mesh.applyEgressControl(`{"type":"egress-config","enabled":true,"revision":7,
		"destinationRules":[{"cidr":"203.0.113.0/24","protocols":["tcp"],"portRanges":[[443,443]]}]}`)
	mesh.applyEgressControl(`not json at all`)

	runtime := mesh.ensureEgress()
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	if !runtime.enabled || len(runtime.policy.DestinationRules) != 1 {
		t.Error("a malformed push disturbed the policy already in force")
	}
}

// A returning segment travels inside an SPEG1 frame, so the frame header comes out of the budget
// the stack sizes segments against. sendEncryptedPayload cannot do this for us: its clamp only
// recognises a bare IPv4 packet, and an egress frame is not one.
func TestEgressPathMTULeavesRoomForTheFrameHeader(t *testing.T) {
	runtime := newEgressRuntime(log.New(io.Discard, "", 0), nil, nil)
	runtime.setPathMTU(1400 - peerEgressFrameHeaderLen)

	runtime.mu.Lock()
	budget := runtime.pathMTU
	runtime.mu.Unlock()
	if budget != 1400-peerEgressFrameHeaderLen {
		t.Fatalf("path MTU = %d", budget)
	}

	syn := tcpSegment{
		SourceIP: testAddr(t, "100.96.0.1"), DestinationIP: testAddr(t, "203.0.113.10"),
		SourcePort: 40000, DestinationPort: 443, Seq: 1000, Flags: tcpFlagSYN, Window: 65535,
	}
	conn, output := acceptTCPSyn(syn, 5000, budget, time.Minute, flowEpoch)
	synAck, ok := parseTCPSegment(output.Segments[0])
	if !ok {
		t.Fatal("the SYN-ACK did not parse")
	}
	if framed := len(output.Segments[0]) + peerEgressFrameHeaderLen; framed > 1400 {
		t.Errorf("a framed SYN-ACK is %d bytes, over the path MTU", framed)
	}
	if synAck.MSS+ipv4MinHeaderLen+tcpMinHeaderLen+peerEgressFrameHeaderLen > 1400 {
		t.Errorf("advertised MSS %d does not leave room for the frame header", synAck.MSS)
	}
	_ = conn
}

// A measurement below the IPv4 minimum would shrink every segment to nothing, so it is ignored
// rather than applied.
func TestEgressPathMTURejectsAnUnusableMeasurement(t *testing.T) {
	runtime := newEgressRuntime(log.New(io.Discard, "", 0), nil, nil)
	runtime.setPathMTU(64)
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	if runtime.pathMTU != egressDefaultPathMTU {
		t.Errorf("path MTU = %d, want the default kept", runtime.pathMTU)
	}
}

// The deployment's own control, STUN and TURN endpoints must be unreachable through the egress, or
// a peer could use it to reach the infrastructure it is only supposed to reach the internet through.
func TestEgressDenyListCoversTheDeploymentEndpoints(t *testing.T) {
	mesh := newEgressMeshHarness(t)
	defer mesh.shutdownEgress()
	mesh.runtime.PeerMesh.StunHost = "192.0.2.10"
	mesh.runtime.PeerMesh.TurnHost = "192.0.2.11"

	denied := mesh.deploymentDenyCIDRs()
	want := map[string]bool{"198.51.100.7/32": false, "192.0.2.10/32": false, "192.0.2.11/32": false}
	for _, cidr := range denied {
		if _, expected := want[cidr]; expected {
			want[cidr] = true
		}
	}
	for cidr, found := range want {
		if !found {
			t.Errorf("%s is not in the deny list: %v", cidr, denied)
		}
	}
}

// A hostname would have to be resolved here, and a resolution taken at policy time can differ from
// the one the connect uses. Listing it would make the block look enforced when it is not.
func TestEgressDenyListSkipsHostnames(t *testing.T) {
	mesh := newPeerMeshClient(Config{ServerBaseURL: "https://control.example.com:8443"},
		log.New(io.Discard, "", 0))
	defer mesh.shutdownEgress()
	mesh.runtime.PeerMesh.StunHost = "stun.example.com"

	if denied := mesh.deploymentDenyCIDRs(); len(denied) != 0 {
		t.Errorf("hostnames entered the deny list: %v", denied)
	}
}

// Forwarding into a network this host owns would loop back into its own capture path, so whatever
// the enumeration returns has to be something the judgment layer can actually match against.
func TestLocalInterfaceCIDRsAreParseable(t *testing.T) {
	for _, cidr := range localInterfaceCIDRs() {
		parsed, ok := parseEgressCIDR(cidr)
		if !ok {
			t.Errorf("%q is not a CIDR the judgment layer accepts", cidr)
			continue
		}
		// Host bits must already be cleared, since the parser refuses a prefix that carries them.
		if parsed.network&^egressMaskFor(parsed.prefixLen) != 0 {
			t.Errorf("%q carries host bits", cidr)
		}
	}
}

// A node nothing has configured as an egress must not answer for the role. Building a plane on
// first contact would let any peer turn an unconfigured device into an egress by sending it a frame.
func TestEgressFrameIsRefusedOnAnUnconfiguredNode(t *testing.T) {
	mesh := newEgressMeshHarness(t)
	defer mesh.shutdownEgress()

	syn := buildTCPSegment(tcpSegment{
		SourceIP: testAddr(t, "100.96.0.1"), DestinationIP: testAddr(t, "203.0.113.10"),
		SourcePort: 40000, DestinationPort: 443, Seq: 1000, Flags: tcpFlagSYN, Window: 65535,
	})
	frame := &peerDataFrame{Payload: encodePeerEgressFrame(peerEgressTypeIPPacket, false, syn)}

	if !mesh.handlePeerEgressFrame(frame, &peerMeshSession{PeerID: 7}) {
		t.Error("an SPEG1 frame fell through to the bare-IPv4 path")
	}
	mesh.mu.Lock()
	built := mesh.egress != nil
	mesh.mu.Unlock()
	if built {
		t.Error("an incoming frame built an egress plane on a node that was never configured as one")
	}
}

// A payload that is not an egress frame has to fall through, or the mesh's own packet path would
// stop working the moment the egress is configured.
func TestNonEgressPayloadsFallThrough(t *testing.T) {
	mesh := newEgressMeshHarness(t)
	defer mesh.shutdownEgress()
	mesh.applyEgressControl(`{"type":"egress-config","enabled":true,"revision":1,
		"destinationRules":[{"cidr":"203.0.113.0/24","protocols":["tcp"],"portRanges":[[443,443]]}]}`)

	bare := buildTCPSegment(tcpSegment{
		SourceIP: testAddr(t, "100.96.0.1"), DestinationIP: testAddr(t, "100.96.0.2"),
		SourcePort: 40000, DestinationPort: 443, Seq: 1000, Flags: tcpFlagSYN, Window: 65535,
	})
	if mesh.handlePeerEgressFrame(&peerDataFrame{Payload: bare}, &peerMeshSession{PeerID: 7}) {
		t.Error("a bare IPv4 packet was claimed by the egress path")
	}
}
