package client

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"
)

// What the consumer makes of an egress its rules name, from the roster and egress-catalog
// (protocol/spec/peer-egress.md, 能力不支持; protocol/test-vectors/peer-egress-standing-v1.json).
//
// The failure these hold down: an online egress whose client cannot take a flow, or which the server
// no longer offers to this device, was sent flows it dropped without a word, so the application
// waited for its own timeout and the status showed nothing wrong. Every case is played with real
// packets through the real consumer, by address and by name, so what is checked is what the
// application would see: a frame to the egress, or a reset or an unreachable straight back.

type egressStandingVector struct {
	CatalogWaitSeconds int `json:"catalogWaitSeconds"`
	Cases              []struct {
		Name            string  `json:"name"`
		Online          bool    `json:"online"`
		CatalogReceived bool    `json:"catalogReceived"`
		Listed          bool    `json:"listed"`
		EgressVersion   *int64  `json:"egressVersion"`
		Standing        string  `json:"standing"`
		Blocked         *string `json:"blocked"`
	} `json:"cases"`
}

func loadEgressStandingVector(t *testing.T) egressStandingVector {
	t.Helper()
	var vector egressStandingVector
	readEgressVector(t, "peer-egress-standing-v1.json", &vector)
	if len(vector.Cases) == 0 {
		t.Fatal("the standing vector has no cases")
	}
	return vector
}

// standingRules send a name and an address range to egress 2.
func standingRules() []egressRule {
	return []egressRule{
		{Match: "*.example.com", Action: egressActionEgress, EgressClientID: 2},
		{Match: "203.0.113.0/24", Action: egressActionEgress, EgressClientID: 2},
	}
}

// standingCatalogue is an egress-catalog that lists egress 9 and, when listed, egress 2 with the
// egressVersion given (none when nil) and the capability given. Egress 9 is always there, so "not
// listed" is a catalogue that names somebody else rather than an empty one.
func standingCatalogue(revision int, listed bool, version *int64, capable bool) string {
	entries := []string{`{"clientId":9,"online":true,"domainTargetCapable":true,"egressVersion":1}`}
	if listed {
		entry := fmt.Sprintf(`{"clientId":2,"clientName":"office-gateway","online":true,"scope":"PUBLIC",`+
			`"protocols":["tcp","udp"],"domainTargetCapable":%v,"ipv6TargetCapable":false`, capable)
		if version != nil {
			entry += fmt.Sprintf(`,"egressVersion":%d`, *version)
		}
		entries = append(entries, entry+"}")
	}
	return fmt.Sprintf(`{"type":"egress-catalog","revision":%d,"egresses":[%s]}`, revision, strings.Join(entries, ","))
}

// newStandingHarness is a consumer with phase two's pool, the standing rules, egress 2 online or not,
// and the catalogue view given.
func newStandingHarness(t *testing.T, online bool, view egressCatalogView) *consumerHarness {
	t.Helper()
	harness := newConsumerHarness(t, nil, nil)
	harness.consumer.configureIn(standingRules(), egressDefaultMeshCIDR, "100.96.0.1", egressDefaultFakeIPCIDR, flowEpoch)
	harness.consumer.setEgressOnline(2, online, flowEpoch)
	harness.consumer.applyCatalog(view, flowEpoch)
	return harness
}

// standingPackets are what an application sends under the standing rules: TCP and UDP, to an address
// a rule names and to the fake address handed out for a name a rule names.
func standingPackets(t *testing.T, harness *consumerHarness) map[string][]byte {
	t.Helper()
	assignment, running := harness.consumer.assignFakeIP("www.example.com", flowEpoch)
	if !running {
		t.Fatal("phase two is not running in the consumer")
	}
	address := testAddr(t, "203.0.113.10")
	local := testAddr(t, "100.96.0.1")
	tcp := func(destination uint32, port uint16) []byte {
		return buildTCPSegment(tcpSegment{SourceIP: local, DestinationIP: destination, SourcePort: port,
			DestinationPort: 443, Seq: 1000, Flags: tcpFlagSYN, Window: 65535})
	}
	udp := func(destination uint32, port uint16) []byte {
		return buildUDPDatagram(udpDatagram{SourceIP: local, DestinationIP: destination, SourcePort: port,
			DestinationPort: 443, Payload: []byte("hello")})
	}
	return map[string][]byte{
		"tcp to an address": tcp(address, 40000),
		"udp to an address": udp(address, 40001),
		"tcp to a name":     tcp(assignment.Address, 40002),
		"udp to a name":     udp(assignment.Address, 40003),
	}
}

// expectStandingDecision sends one packet and checks it went out to egress 2, or was blocked for
// the reason given and answered with the failure packet for it.
func expectStandingDecision(t *testing.T, label string, harness *consumerHarness, packet []byte, blocked *string) {
	t.Helper()
	consumer := harness.consumer
	sentBefore, tunBefore := len(harness.sent), len(harness.toTun)
	counted := consumer.blockedCounts()
	outcome := consumer.handleOutbound(packet, flowEpoch)
	sent, written := harness.sent[sentBefore:], harness.toTun[tunBefore:]
	delta := map[string]int64{}
	for reason, count := range consumer.blockedCounts() {
		if count != counted[reason] {
			delta[reason] = count - counted[reason]
		}
	}
	if blocked == nil {
		if outcome != egressOutcomeForwarded || len(sent) == 0 || len(written) != 0 || len(delta) != 0 {
			t.Errorf("%s: outcome %s, %d frames, %d answers, counted %v; want it sent to egress 2",
				label, outcome, len(sent), len(written), delta)
			return
		}
		last, code := parsePeerEgressFrame(sent[len(sent)-1].frame)
		if sent[len(sent)-1].egress != 2 || code != "" || last.Type != peerEgressTypeIPPacket || string(last.Body) != string(packet) {
			t.Errorf("%s: the last frame is not the packet, to egress 2 (%s)", label, code)
		}
		return
	}
	if outcome != egressOutcomeBlockedNoEgress || len(sent) != 0 {
		t.Errorf("%s: outcome %s with %d frames sent, want blocked %s", label, outcome, len(sent), *blocked)
	}
	if !reflect.DeepEqual(delta, map[string]int64{*blocked: 1}) {
		t.Errorf("%s: counted %v, want one %s", label, delta, *blocked)
	}
	// Answered like an egress that is not there: a reset for TCP, a host-unreachable for UDP.
	want := egressFailurePacket(packet, peerPacketProtocol(packet))
	if len(written) != 1 || string(written[0]) != string(want) {
		t.Errorf("%s: wrote %d packets to the TUN, want the failure packet for it", label, len(written))
	}
}

// Every case of the shared vector, played through the real consumer with real packets. The
// catalogue goes through the real decoder: received means one was accepted in this session; not
// received is an earlier session's catalogue followed by a new session, which must count for nothing.
//
// Egress 2 is held to resolve names throughout, so that what decides a packet to a name is the
// standing alone; how the standing and the capability combine is the next test's.
func TestConsumerStandingMatchesTheSharedVector(t *testing.T) {
	vector := loadEgressStandingVector(t)
	if vector.CatalogWaitSeconds != int(egressCatalogWait/time.Second) {
		t.Errorf("catalogWaitSeconds = %d, the client waits %s", vector.CatalogWaitSeconds, egressCatalogWait)
	}
	for _, c := range vector.Cases {
		reader := newEgressCatalogReader()
		if !reader.read([]byte(standingCatalogue(4, c.Listed, c.EgressVersion, true))) {
			t.Fatalf("%s: the catalogue was refused", c.Name)
		}
		if !c.CatalogReceived {
			reader.newSession()
		}
		harness := newStandingHarness(t, c.Online, reader.view())
		harness.consumer.setDomainCapable(map[int64]bool{2: true}, flowEpoch)
		if got := harness.consumer.statusSnapshot().Standing[2]; got != c.Standing {
			t.Errorf("%s: standing %q, want %q", c.Name, got, c.Standing)
		}
		if got := egressCatalogStanding(c.CatalogReceived, c.Listed,
			egressCatalogListing{Version: derefInt64(c.EgressVersion), VersionKnown: c.EgressVersion != nil}); got != c.Standing {
			t.Errorf("%s: egressCatalogStanding = %q, want %q", c.Name, got, c.Standing)
		}
		for label, packet := range standingPackets(t, harness) {
			expectStandingDecision(t, c.Name+", "+label, harness, packet, c.Blocked)
		}
	}
}

func derefInt64(value *int64) int64 {
	if value == nil {
		return 0
	}
	return *value
}

// The domain capability is looked at only for an egress the standing lets through: a name rule to an
// egress the catalogue does not offer, or whose client has no peer egress, is counted for that, and
// egress-no-domain is kept for an offered egress that does not resolve names.
func TestConsumerChecksTheDomainCapabilityAfterTheStanding(t *testing.T) {
	cases := []struct {
		name      string
		catalogue string
		want      string
	}{
		{"not offered", standingCatalogue(1, false, nil, false), "egress-not-offered"},
		{"unsupported", standingCatalogue(1, true, int64Pointer(0), false), "egress-unsupported"},
		{"offered without names", standingCatalogue(1, true, int64Pointer(1), false), "egress-no-domain"},
	}
	for _, c := range cases {
		reader := newEgressCatalogReader()
		reader.read([]byte(c.catalogue))
		harness := newStandingHarness(t, true, reader.view())
		packets := standingPackets(t, harness)
		want := c.want
		expectStandingDecision(t, c.name+", tcp to a name", harness, packets["tcp to a name"], &want)
		// By address the capability does not matter.
		if c.want == "egress-no-domain" {
			expectStandingDecision(t, c.name+", tcp to an address", harness, packets["tcp to an address"], nil)
		} else {
			expectStandingDecision(t, c.name+", tcp to an address", harness, packets["tcp to an address"], &want)
		}
	}
}

// A standing that turns to one that blocks closes the egress's flows as its going offline does: each
// flow is purged at the egress by its destination, a TCP flow the application has spoken on is reset,
// and the next packet is blocked and answered. A standing that stays usable, and a new control
// session (unknown blocks nothing), close nothing.
func TestConsumerPurgesTheFlowsOfAnEgressWhoseStandingTurns(t *testing.T) {
	for _, turn := range []struct {
		name      string
		catalogue string
		reason    string
	}{
		{"no longer offered", standingCatalogue(2, false, nil, true), "egress-not-offered"},
		{"client without peer egress", standingCatalogue(2, true, int64Pointer(0), true), "egress-unsupported"},
	} {
		reader := newEgressCatalogReader()
		reader.read([]byte(standingCatalogue(1, true, int64Pointer(1), true)))
		harness := newStandingHarness(t, true, reader.view())
		consumer := harness.consumer
		packets := standingPackets(t, harness)
		for _, label := range []string{"tcp to an address", "udp to a name"} {
			expectStandingDecision(t, turn.name+", before, "+label, harness, packets[label], nil)
		}
		// The application has answered the SYN-ACK, so its flow can be reset where its stack accepts it.
		consumer.handleOutbound(buildTCPSegment(tcpSegment{SourceIP: testAddr(t, "100.96.0.1"),
			DestinationIP: testAddr(t, "203.0.113.10"), SourcePort: 40000, DestinationPort: 443,
			Seq: 1001, Ack: 700001, Flags: tcpFlagACK, Window: 65535}), flowEpoch)
		if consumer.flowCount() != 2 {
			t.Fatalf("%s: %d flows open, want 2", turn.name, consumer.flowCount())
		}
		name, _ := consumer.fakeIPName(peerPacketDestination(t, packets["udp to a name"]), flowEpoch)
		if name != "www.example.com" {
			t.Fatalf("%s: the fake address stands for %q", turn.name, name)
		}

		// Still offered: a newer catalogue and a new control session leave the flows alone.
		reader.read([]byte(standingCatalogue(5, true, nil, true)))
		if purge := consumer.applyCatalog(reader.view(), flowEpoch); len(purge) != 0 || consumer.flowCount() != 2 {
			t.Fatalf("%s: a catalogue still offering the egress purged %v", turn.name, purge)
		}
		reader.newSession()
		if purge := consumer.applyCatalog(reader.view(), flowEpoch); len(purge) != 0 || consumer.flowCount() != 2 {
			t.Fatalf("%s: a new control session purged %v", turn.name, purge)
		}
		tunBefore := len(harness.toTun)

		if !reader.read([]byte(turn.catalogue)) {
			t.Fatalf("%s: the turning catalogue was refused", turn.name)
		}
		purge := consumer.applyCatalog(reader.view(), flowEpoch)
		fake := formatEgressAddress(peerPacketDestination(t, packets["udp to a name"]))
		want := map[int64][]string{2: sortedUniqueStrings([]string{"203.0.113.10/32", fake + "/32"})}
		if !reflect.DeepEqual(purge, want) {
			t.Errorf("%s: purge %v, want %v", turn.name, purge, want)
		}
		if consumer.flowCount() != 0 {
			t.Errorf("%s: %d flows outlived the standing turning", turn.name, consumer.flowCount())
		}
		resets := harness.toTun[tunBefore:]
		if len(resets) != 1 {
			t.Fatalf("%s: %d packets written to the TUN, want the reset of the TCP flow", turn.name, len(resets))
		}
		if reset, ok := parseTCPSegment(resets[0]); !ok || reset.Flags&tcpFlagRST == 0 || reset.Seq != 700001 ||
			formatEgressAddress(reset.SourceIP) != "203.0.113.10" {
			t.Errorf("%s: the reset is %+v", turn.name, reset)
		}
		// What the mesh sends the egress for it: one flow-purge naming both destinations.
		frames := egressFlowPurgeFrames(purge)
		frame, code := parsePeerEgressFrame(frames[2])
		control, ok := decodePeerEgressControl(frame.Body)
		if code != "" || !ok || control.Type != peerEgressControlFlowPurge || !reflect.DeepEqual(control.Destinations, want[2]) {
			t.Errorf("%s: the flow-purge to egress 2 is %+v (%s)", turn.name, control, code)
		}
		for _, label := range []string{"tcp to an address", "udp to a name"} {
			reason := turn.reason
			expectStandingDecision(t, turn.name+", after, "+label, harness, packets[label], &reason)
		}
	}
}

func peerPacketDestination(t *testing.T, packet []byte) uint32 {
	t.Helper()
	address, ok := parseEgressAddress(peerPacketDestinationIPv4(packet))
	if !ok {
		t.Fatal("the packet has no IPv4 destination")
	}
	return address
}

// Through the mesh: a catalogue from the control channel sets the standing, a control connection
// ending and the next one authenticating each make it unknown until that session's first catalogue,
// and a consumer built after a catalogue still gets it.
func TestMeshCatalogueStandingFollowsTheControlSession(t *testing.T) {
	mesh := newEgressMeshHarness(t)
	defer mesh.shutdownEgress()
	mesh.egressRoutes = newEgressRouteInstaller(newFakeRouteCommander(), journalPath(t))
	mesh.noteControlAuthenticated()
	// Before the consumer exists.
	mesh.handleControl(nil, `{"type":"egress-catalog","revision":3,"egresses":[{"clientId":43,"egressVersion":0}]}`,
		RuntimeConfig{}, nil)
	applyEgressRulesForTest(t, mesh, []egressRule{
		{Match: "203.0.113.0/24", Action: egressActionEgress, EgressClientID: 42},
		{Match: "198.51.100.0/24", Action: egressActionEgress, EgressClientID: 43},
	}, statusRuntimeConfig())
	mesh.syncEgressAvailability(map[int64]bool{42: true, 43: true})

	standings := func() map[int64]string {
		out := map[int64]string{}
		peers, _ := mapSection(t, mesh.egressStatusJSON(), "consumer")["peers"].([]map[string]any)
		for _, peer := range peers {
			id, _ := peer["clientId"].(int64)
			out[id], _ = peer["standing"].(string)
		}
		return out
	}
	if got := standings(); !reflect.DeepEqual(got, map[int64]string{42: "not-offered", 43: "unsupported"}) {
		t.Errorf("after a catalogue that came before the consumer: %v", got)
	}

	mesh.suspend()
	if got := standings(); !reflect.DeepEqual(got, map[int64]string{42: "unknown", 43: "unknown"}) {
		t.Errorf("after the control connection ended: %v", got)
	}
	mesh.noteControlAuthenticated()
	// The new session numbers afresh: revision 1 is accepted.
	mesh.handleControl(nil, `{"type":"egress-catalog","revision":1,"egresses":[{"clientId":42,"egressVersion":1},{"clientId":43}]}`,
		RuntimeConfig{}, nil)
	if got := standings(); !reflect.DeepEqual(got, map[int64]string{42: "offered", 43: "offered"}) {
		t.Errorf("after the new session's catalogue: %v", got)
	}
	// Authenticating again, even with no connection ending noticed in between, starts over.
	mesh.noteControlAuthenticated()
	if got := standings(); !reflect.DeepEqual(got, map[int64]string{42: "unknown", 43: "unknown"}) {
		t.Errorf("after a new control session authenticated: %v", got)
	}
}

// consumer.catalog says whether this control session has heard the catalogue: waiting until 30 s
// after control authentication, none after that, received once one was accepted. A control
// connection that ends goes back to waiting rather than blaming the server.
func TestEgressStatusSaysWhetherTheServerSentACatalogue(t *testing.T) {
	mesh := newEgressMeshHarness(t)
	defer mesh.shutdownEgress()
	now := time.Date(2026, 10, 6, 9, 0, 0, 0, time.UTC)
	mesh.egressClock = func() time.Time { return now }
	catalog := func() string {
		value, _ := mapSection(t, mesh.egressStatusJSON(), "consumer")["catalog"].(string)
		return value
	}
	wait := time.Duration(loadEgressStandingVector(t).CatalogWaitSeconds) * time.Second

	if got := catalog(); got != "waiting" {
		t.Errorf("before any control session: %q", got)
	}
	now = now.Add(time.Hour)
	if got := catalog(); got != "waiting" {
		t.Errorf("an hour with no control session: %q", got)
	}
	mesh.noteControlAuthenticated()
	now = now.Add(wait - time.Millisecond)
	if got := catalog(); got != "waiting" {
		t.Errorf("just short of the wait: %q", got)
	}
	now = now.Add(time.Millisecond)
	if got := catalog(); got != "none" {
		t.Errorf("at the wait with no catalogue: %q", got)
	}
	// A catalogue that is refused is not one received.
	mesh.handleControl(nil, `{"type":"egress-catalog","revision":"1"}`, RuntimeConfig{}, nil)
	if got := catalog(); got != "none" {
		t.Errorf("after a refused catalogue: %q", got)
	}
	mesh.handleControl(nil, `{"type":"egress-catalog","revision":1,"egresses":[]}`, RuntimeConfig{}, nil)
	if got := catalog(); got != "received" {
		t.Errorf("after an accepted catalogue: %q", got)
	}
	mesh.suspend()
	now = now.Add(time.Hour)
	if got := catalog(); got != "waiting" {
		t.Errorf("with the control connection gone: %q", got)
	}
	mesh.noteControlAuthenticated()
	if got := catalog(); got != "waiting" {
		t.Errorf("a new session: %q", got)
	}
	now = now.Add(wait)
	if got := catalog(); got != "none" {
		t.Errorf("a new session that heard nothing: %q, the last session's catalogue counted", got)
	}
}

// The status carries the standing of each egress peer and counts the two new blocks by their own
// reasons.
func TestEgressStatusReportsStandingsAndTheirBlocks(t *testing.T) {
	mesh := newEgressMeshHarness(t)
	defer mesh.shutdownEgress()
	mesh.egressRoutes = newEgressRouteInstaller(newFakeRouteCommander(), journalPath(t))
	applyEgressRulesForTest(t, mesh, []egressRule{
		{Match: "203.0.113.0/24", Action: egressActionEgress, EgressClientID: 42},
		{Match: "198.51.100.0/24", Action: egressActionEgress, EgressClientID: 43},
		{Match: "192.0.2.0/24", Action: egressActionEgress, EgressClientID: 44},
	}, statusRuntimeConfig())
	mesh.syncEgressAvailability(map[int64]bool{42: true, 43: true, 44: false})
	mesh.noteControlAuthenticated()
	mesh.handleControl(nil, `{"type":"egress-catalog","revision":1,"egresses":[{"clientId":43,"egressVersion":0},{"clientId":44,"egressVersion":2}]}`,
		RuntimeConfig{}, nil)
	consumer := mesh.egressConsumer
	for _, destination := range []string{"203.0.113.9", "198.51.100.9", "198.51.100.10", "192.0.2.9"} {
		consumer.handleOutbound(buildTCPSegment(tcpSegment{SourceIP: testAddr(t, "10.42.0.7"),
			DestinationIP: testAddr(t, destination), SourcePort: 40000, DestinationPort: 443,
			Seq: 1000, Flags: tcpFlagSYN, Window: 65535}), time.Now())
	}

	section := mapSection(t, mesh.egressStatusJSON(), "consumer")
	if section["catalog"] != "received" {
		t.Errorf("catalog = %v", section["catalog"])
	}
	peers, _ := section["peers"].([]map[string]any)
	want := []map[string]any{
		{"clientId": int64(42), "online": true, "standing": "not-offered", "path": "none", "flows": 0},
		{"clientId": int64(43), "online": true, "standing": "unsupported", "path": "none", "flows": 0},
		{"clientId": int64(44), "online": false, "standing": "offered", "path": "none", "flows": 0},
	}
	if !reflect.DeepEqual(peers, want) {
		t.Errorf("peers = %v, want %v", peers, want)
	}
	blocked, _ := section["blocked"].(map[string]int64)
	if !reflect.DeepEqual(blocked, map[string]int64{"egress-not-offered": 1, "egress-unsupported": 2, "egress-unavailable": 1}) {
		t.Errorf("blocked = %v", blocked)
	}
}
