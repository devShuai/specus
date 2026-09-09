package client

import (
	"io"
	"log"
	"path/filepath"
	"testing"
)

// The join between the consumer layers and Peer Mesh: the TUN hook, the rule application path, and
// the split that decides whether an incoming frame belongs to this node's consumer role or its
// egress role.

func newConsumerMeshHarness(t *testing.T) *peerMeshClient {
	t.Helper()
	mesh := newPeerMeshClient(
		Config{PeerMeshDevice: "noop", PeerMeshTunName: "specus0", PeerMeshMTU: 1280},
		log.New(io.Discard, "", 0))
	// Never the real journal: a test that clobbered a user's own would take back routes it never
	// installed.
	mesh.egressJournalPath = filepath.Join(t.TempDir(), "egress-routes.json")
	return mesh
}

func consumerRuntimeConfig() RuntimeConfig {
	var runtime RuntimeConfig
	runtime.PeerMesh.VirtualIP = "100.96.0.1"
	runtime.PeerMesh.CIDR = egressDefaultMeshCIDR
	return runtime
}

// A node with no rules configured must not claim anything from the TUN, or the mesh's own traffic
// would stop moving the moment this file was linked in.
func TestMeshLeavesTheTunAloneWithoutConsumerRules(t *testing.T) {
	mesh := newConsumerMeshHarness(t)
	packet := buildTCPSegment(tcpSegment{
		SourceIP: testAddr(t, "100.96.0.1"), DestinationIP: testAddr(t, "203.0.113.10"),
		SourcePort: 40000, DestinationPort: 443, Flags: tcpFlagSYN, Window: 65535,
	})
	if mesh.handleEgressOutbound(packet) {
		t.Error("a node with no consumer rules claimed a packet from the TUN")
	}
}

// A rule set is rarely wrong all at once. Refusing to apply any of it would leave a user with one
// typo sending everything out locally, which is the failure this feature exists to prevent.
func TestMeshAppliesGoodRulesAlongsideRefusedOnes(t *testing.T) {
	mesh := newConsumerMeshHarness(t)
	defer mesh.withdrawEgressRoutes()

	mesh.applyEgressRules([]egressRule{
		{Match: "203.0.113.0/24", Action: egressActionEgress, EgressClientID: 2},
		{Match: "*.example.com", Action: egressActionEgress, EgressClientID: 2},
	}, consumerRuntimeConfig())

	mesh.mu.Lock()
	consumer := mesh.egressConsumer
	mesh.mu.Unlock()
	if consumer == nil {
		t.Fatal("applying rules built no consumer")
	}

	// The good rule claims its destination even though the other was refused.
	packet := buildTCPSegment(tcpSegment{
		SourceIP: testAddr(t, "100.96.0.1"), DestinationIP: testAddr(t, "203.0.113.10"),
		SourcePort: 40000, DestinationPort: 443, Flags: tcpFlagSYN, Window: 65535,
	})
	if !mesh.handleEgressOutbound(packet) {
		t.Error("the surviving rule did not claim its destination")
	}
	// With no egress online it is blocked rather than handed back, which is the whole point.
	if counts := consumer.blockedCounts(); counts["egress-unavailable"] != 1 {
		t.Errorf("blocked counts = %v", counts)
	}
}

// A node can be a consumer and an egress at once, and both roles receive type=1 frames. The
// consumer claims only what is addressed to its own virtual IP.
func TestMeshRoutesReturnTrafficToTheConsumerRole(t *testing.T) {
	mesh := newConsumerMeshHarness(t)
	defer mesh.withdrawEgressRoutes()
	mesh.applyEgressRules([]egressRule{
		{Match: "203.0.113.0/24", Action: egressActionEgress, EgressClientID: 2},
	}, consumerRuntimeConfig())

	mesh.mu.Lock()
	consumer := mesh.egressConsumer
	mesh.mu.Unlock()
	consumer.setEgressOnline(2, true, flowEpoch)
	consumer.handleOutbound(buildTCPSegment(tcpSegment{
		SourceIP: testAddr(t, "100.96.0.1"), DestinationIP: testAddr(t, "203.0.113.10"),
		SourcePort: 40000, DestinationPort: 443, Flags: tcpFlagSYN, Window: 65535,
	}), flowEpoch)

	reply := encodePeerEgressFrame(peerEgressTypeIPPacket, false, buildTCPSegment(tcpSegment{
		SourceIP: testAddr(t, "203.0.113.10"), DestinationIP: testAddr(t, "100.96.0.1"),
		SourcePort: 443, DestinationPort: 40000, Flags: tcpFlagSYN | tcpFlagACK, Window: 65535,
	}))
	if !mesh.handlePeerEgressFrame(&peerDataFrame{Payload: reply}, &peerMeshSession{PeerID: 2}) {
		t.Error("a reply addressed to this node was not claimed")
	}

	// A frame addressed at the wider network belongs to the egress role, not this one. There is
	// no egress plane here, so what matters is that the consumer did not swallow it and report
	// the return path as abused.
	outbound := encodePeerEgressFrame(peerEgressTypeIPPacket, false, buildTCPSegment(tcpSegment{
		SourceIP: testAddr(t, "100.96.0.9"), DestinationIP: testAddr(t, "198.51.100.10"),
		SourcePort: 40000, DestinationPort: 443, Flags: tcpFlagSYN, Window: 65535,
	}))
	mesh.handlePeerEgressFrame(&peerDataFrame{Payload: outbound}, &peerMeshSession{PeerID: 2})
	if counts := consumer.blockedCounts(); counts["return-wrong-destination"] != 0 {
		t.Errorf("an egress-bound frame was counted as an abused return path: %v", counts)
	}
}

// The journal lives beside the machine identity, so a route left by a killed process is found again
// by the next run rather than by the user.
func TestEgressRouteJournalPathIsUnderTheClientDirectory(t *testing.T) {
	path := egressRouteJournalPath()
	if path == "" {
		t.Skip("no home directory on this machine")
	}
	if filepath.Base(path) != "egress-routes.json" {
		t.Errorf("journal file = %s", filepath.Base(path))
	}
	if filepath.Base(filepath.Dir(path)) != ".specus" {
		t.Errorf("journal directory = %s", filepath.Dir(path))
	}
}

// Withdrawal has to be safe to call when nothing was ever installed, since it runs on every stop.
func TestMeshWithdrawEgressRoutesIsSafeWhenNothingWasInstalled(t *testing.T) {
	mesh := newConsumerMeshHarness(t)
	mesh.withdrawEgressRoutes()
	mesh.withdrawEgressRoutes()
}
