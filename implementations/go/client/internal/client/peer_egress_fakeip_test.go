package client

import (
	"errors"
	"strings"
	"testing"
	"time"
)

// Phase two's joins, which the shared cases do not reach: the pool's route, the status, the
// egress-catalog wiring, the configuration, and an egress closing a flow that is still connecting.

func phaseTwoRules() []egressRule {
	return []egressRule{
		{Match: "*.example.com", Action: egressActionEgress, EgressClientID: 2},
		{Match: "203.0.113.0/24", Action: egressActionEgress, EgressClientID: 2},
	}
}

// newPhaseTwoHarness is a reconcile harness with phase two asked for, on a device whose own
// networks are the ones given rather than the test machine's.
func newPhaseTwoHarness(t *testing.T, localNetworks []string, rules ...egressRule) *reconcileHarness {
	t.Helper()
	harness := newReconcileHarness(t, rules...)
	harness.mesh.config.PeerEgressDNSTakeover = true
	harness.mesh.egressLocalNetworks = func() []string { return localNetworks }
	return harness
}

func (h *reconcileHarness) consumer() *egressConsumer {
	h.mesh.mu.Lock()
	defer h.mesh.mu.Unlock()
	return h.mesh.egressConsumer
}

// While phase two runs the pool is one more tunnel route, from the pool itself; a domain rule adds
// none of its own. A bypass address inside the pool keeps its /32 like one inside a rule's prefix.
func TestEgressRoutePlanAddsThePoolWhilePhaseTwoRuns(t *testing.T) {
	routes, refused := planEgressRoutesIn(phaseTwoRules(), []string{"198.18.3.4", "192.0.2.9"},
		egressDefaultMeshCIDR, egressDefaultFakeIPCIDR)
	if len(refused) != 0 {
		t.Fatalf("refused %v while phase two runs", refused)
	}
	want := []egressRoute{
		{CIDR: "198.18.3.4/32", Kind: egressRouteBypass, Origin: "bypass"},
		{CIDR: "198.18.0.0/15", Kind: egressRouteToTun, Origin: egressRouteOriginFakeIPPool},
		{CIDR: "203.0.113.0/24", Kind: egressRouteToTun, Origin: "rule:203.0.113.0/24"},
	}
	if !sameEgressRouteSet(routes, want) {
		t.Errorf("routes = %+v, want %+v", routes, want)
	}

	// Without phase two the pool is nobody's, and the domain rule is refused as in phase one.
	routes, refused = planEgressRoutes(phaseTwoRules(), []string{"198.18.3.4"}, egressDefaultMeshCIDR)
	if len(refused) != 1 || refused[0].Code != egressCodeRuleDomainUnsupported {
		t.Errorf("refused = %v, want the domain rule as unsupported", refused)
	}
	for _, route := range routes {
		if route.Origin == egressRouteOriginFakeIPPool || route.CIDR == "198.18.3.4/32" {
			t.Errorf("phase one planned %+v", route)
		}
	}
}

// The pool's route is installed, journalled and taken back with the rest.
func TestMeshInstallsThePoolRouteAndTakesItBack(t *testing.T) {
	harness := newPhaseTwoHarness(t, []string{"192.168.1.0/24"}, phaseTwoRules()...)
	harness.tick(0)

	if !contains(harness.commander.installLog, "198.18.0.0/15") {
		t.Fatalf("the pool's route was not installed: %v", harness.commander.installLog)
	}
	harness.mesh.mu.Lock()
	installed := harness.mesh.egressRoutes.installedRoutes()
	harness.mesh.mu.Unlock()
	journalled := false
	for _, route := range installed {
		if route.CIDR == "198.18.0.0/15" && route.Origin == egressRouteOriginFakeIPPool && route.Kind == egressRouteToTun {
			journalled = true
		}
	}
	if !journalled {
		t.Errorf("the journal does not hold the pool's route: %+v", installed)
	}
	consumer := harness.consumer()
	if consumer == nil || consumer.fakeIPCIDR != "198.18.0.0/15" {
		t.Fatal("the consumer was not given the pool")
	}

	harness.mesh.withdrawEgressRoutes()
	if !contains(harness.commander.removeLog, "198.18.0.0/15") {
		t.Errorf("the pool's route was not taken back: %v", harness.commander.removeLog)
	}
}

// Phase two stopping with no rules configured still reaches the consumer: it drops its pool and
// its responder, and the pool's route comes out of the table.
func TestMeshStopsPhaseTwoWithoutRules(t *testing.T) {
	harness := newPhaseTwoHarness(t, nil)
	harness.tick(0)
	consumer := harness.consumer()
	if consumer == nil || consumer.fakeIPCIDR == "" || !contains(harness.commander.installLog, "198.18.0.0/15") {
		t.Fatal("phase two did not start without rules")
	}

	// The mesh network moves over the pool, which stops phase two.
	harness.mesh.mu.Lock()
	harness.mesh.runtime.PeerMesh.CIDR = "198.18.0.0/16"
	harness.mesh.mu.Unlock()
	harness.tick(time.Second)

	consumer.mu.Lock()
	pool, responder := consumer.fakeIPCIDR, consumer.fakeIP
	consumer.mu.Unlock()
	if pool != "" || responder != nil {
		t.Errorf("the consumer kept pool %q after phase two stopped", pool)
	}
	if !contains(harness.commander.removeLog, "198.18.0.0/15") {
		t.Errorf("the pool's route was not taken out: removed %v", harness.commander.removeLog)
	}
	query := buildUDPDatagram(udpDatagram{SourceIP: testAddr(t, "100.96.0.1"), DestinationIP: testAddr(t, "198.18.0.1"),
		SourcePort: 53000, DestinationPort: 53, Payload: []byte{0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0}})
	if outcome := consumer.handleOutbound(query, flowEpoch); outcome != egressOutcomeNotMine {
		t.Errorf("a query to the old listen address: %s, want not-mine", outcome)
	}
}

// A pool somebody else already routes is refused the way a rule's prefix is, and the status lists it
// as not installed; a failed install is rolled back with the rest of that apply.
func TestMeshTreatsThePoolRouteLikeARuleRoute(t *testing.T) {
	harness := newPhaseTwoHarness(t, nil, phaseTwoRules()...)
	harness.commander.foreign["198.18.0.0/15"] = "198.18.0.0/15 via 192.0.2.1 dev eth0"
	harness.tick(0)
	routes, _ := mapSection(t, harness.mesh.egressStatusJSON(), "consumer")["routes"].([]map[string]any)
	found := false
	for _, route := range routes {
		if route["cidr"] == "198.18.0.0/15" {
			found = true
			if route["installed"] != false || route["origin"] != egressRouteOriginFakeIPPool || route["conflict"] == "" {
				t.Errorf("the contested pool reads %v", route)
			}
		}
	}
	if !found {
		t.Fatalf("the contested pool is missing from the status: %v", routes)
	}

	failing := newPhaseTwoHarness(t, nil, phaseTwoRules()...)
	failing.commander.installErr["198.18.0.0/15"] = errors.New("permission denied")
	failing.tick(0)
	failing.mesh.mu.Lock()
	outcome, installed := failing.mesh.egressApplied, failing.mesh.egressRoutes.installedRoutes()
	failing.mesh.mu.Unlock()
	if !outcome.RolledBack || len(installed) != 0 {
		t.Errorf("a failed pool install left rolledBack=%v and %+v installed", outcome.RolledBack, installed)
	}
}

// A pool over one of this device's own networks stops phase two alone: no pool route, domain rules
// refused as in phase one, and the status saying why.
func TestMeshKeepsPhaseTwoOffWhenThePoolOverlapsThisDevice(t *testing.T) {
	harness := newPhaseTwoHarness(t, []string{"198.18.4.0/24"}, phaseTwoRules()...)
	harness.tick(0)

	if contains(harness.commander.installLog, "198.18.0.0/15") {
		t.Error("the pool was routed over this device's own network")
	}
	if !contains(harness.commander.installLog, "203.0.113.0/24") {
		t.Error("phase one stopped with phase two")
	}
	section := mapSection(t, harness.mesh.egressStatusJSON(), "consumer")
	dns, _ := section["dns"].(map[string]any)
	if dns["takeover"] != false || dns["code"] != egressCodeFakeIPPoolInvalid || dns["pool"] != "198.18.0.0/15" {
		t.Errorf("dns = %v", dns)
	}
	rules, _ := section["rules"].([]map[string]any)
	if len(rules) != 2 || rules[0]["code"] != egressCodeRuleDomainUnsupported || rules[0]["kind"] != "domain" {
		t.Errorf("rules = %v, want the domain rule refused as in phase one", rules)
	}
}

// consumer.dns appears only when phase two was asked for, and says what the pool holds; rules carry
// their kind; a domain rule to an online egress that cannot resolve names reads out of force and
// names no peer; the new blocks are counted with the rest.
func TestEgressStatusReportsPhaseTwo(t *testing.T) {
	plain := newReconcileHarness(t, phaseTwoRules()[1])
	plain.tick(0)
	section := mapSection(t, plain.mesh.egressStatusJSON(), "consumer")
	if _, present := section["dns"]; present {
		t.Error("consumer.dns appears without peerEgressDnsTakeover")
	}
	if rules, _ := section["rules"].([]map[string]any); len(rules) != 1 || rules[0]["kind"] != "cidr" {
		t.Errorf("rules = %v, want kind cidr", rules)
	}

	harness := newPhaseTwoHarness(t, nil, phaseTwoRules()...)
	harness.tick(0)
	consumer := harness.consumer()
	consumer.clock = func() time.Time { return flowEpoch }
	if _, running := consumer.assignFakeIP("www.example.com", flowEpoch); !running {
		t.Fatal("phase two is not running in the consumer")
	}
	consumer.setEgressOnline(2, true, flowEpoch)
	consumer.handleOutbound(buildTCPSegment(tcpSegment{SourceIP: testAddr(t, "100.96.0.1"),
		DestinationIP: testAddr(t, "198.18.0.9"), SourcePort: 40000, DestinationPort: 443,
		Seq: 1000, Flags: tcpFlagSYN, Window: 65535}), flowEpoch)
	consumer.handleOutbound(buildTCPSegment(tcpSegment{SourceIP: testAddr(t, "100.96.0.1"),
		DestinationIP: testAddr(t, "198.18.0.2"), SourcePort: 40001, DestinationPort: 443,
		Seq: 1000, Flags: tcpFlagSYN, Window: 65535}), flowEpoch)

	section = mapSection(t, harness.mesh.egressStatusJSON(), "consumer")
	dns, _ := section["dns"].(map[string]any)
	if dns["active"] != true || dns["pool"] != "198.18.0.0/15" || dns["mappings"] != 1 || dns["quarantined"] != 0 {
		t.Errorf("dns = %v", dns)
	}
	// This harness's machine refuses every command, so the system DNS takeover fails; whatever
	// code there is belongs to the takeover, not to the pool.
	if code, _ := dns["code"].(string); code == egressCodeFakeIPPoolInvalid {
		t.Errorf("a running phase two carries the pool's code: %v", dns)
	}
	rules, _ := section["rules"].([]map[string]any)
	if len(rules) != 2 || rules[0]["kind"] != "domain" || rules[0]["code"] != egressCodeRuleEgressNoDomain || rules[0]["inForce"] != false {
		t.Errorf("rules = %v, want the domain rule out of force for its egress", rules)
	}
	blocked, _ := section["blocked"].(map[string]int64)
	if blocked["fake-ip-unmapped"] != 1 || blocked["egress-no-domain"] != 1 {
		t.Errorf("blocked = %v", blocked)
	}

	// Once the catalogue says the egress resolves names, the rule is in force.
	harness.mesh.handleControl(nil, `{"type":"egress-catalog","revision":1,"egresses":[{"clientId":2,"domainTargetCapable":true}]}`,
		RuntimeConfig{}, nil)
	rules, _ = mapSection(t, harness.mesh.egressStatusJSON(), "consumer")["rules"].([]map[string]any)
	if rules[0]["inForce"] != true {
		t.Errorf("the domain rule is still out of force with a capable egress: %v", rules[0])
	}
}

// egress-catalog reaches the consumer from the control channel: before the consumer exists it is
// kept for it, after it a change can close flows, a new control session resets only the revision
// floor, and a key the mesh's own decoding would choke on does not stop it.
func TestMeshAppliesEgressCatalogToTheConsumer(t *testing.T) {
	harness := newPhaseTwoHarness(t, nil, phaseTwoRules()...)
	harness.mesh.handleControl(nil, `{"type":"egress-catalog","revision":5,"peers":7,"egresses":[{"clientId":2,"domainTargetCapable":true}]}`,
		RuntimeConfig{}, nil)
	harness.tick(0)
	consumer := harness.consumer()
	consumer.setEgressOnline(2, true, flowEpoch)
	assignment, _ := consumer.assignFakeIP("www.example.com", flowEpoch)
	consumer.handleOutbound(buildTCPSegment(tcpSegment{SourceIP: testAddr(t, "100.96.0.1"),
		DestinationIP: assignment.Address, SourcePort: 40000, DestinationPort: 443,
		Seq: 1000, Flags: tcpFlagSYN, Window: 65535}), flowEpoch)
	// This mesh has no session to the egress, so the send itself fails; what matters is that the
	// packet got that far rather than being stopped for the capability.
	if blocked := consumer.blockedCounts(); blocked["egress-no-domain"] != 0 || blocked["send-failed"] != 1 {
		t.Fatalf("blocked = %v: the catalogue that came before the consumer was not kept for it", blocked)
	}
	if consumer.flowCount() != 1 {
		t.Fatalf("%d flows after the first packet", consumer.flowCount())
	}

	// An older revision in the same session changes nothing.
	harness.mesh.handleControl(nil, `{"type":"egress-catalog","revision":4,"egresses":[]}`, RuntimeConfig{}, nil)
	if consumer.flowCount() != 1 {
		t.Fatal("a stale catalogue closed a flow")
	}
	// A new session numbers afresh: revision 1 is accepted and closes the flow to the name.
	harness.mesh.suspend()
	harness.mesh.handleControl(nil, `{"type":"egress-catalog","revision":1,"egresses":[{"clientId":2,"domainTargetCapable":false}]}`,
		RuntimeConfig{}, nil)
	if consumer.flowCount() != 0 {
		t.Error("the flow to a name outlived its egress losing the capability")
	}
}

// The name goes first or the packet does not go: an egress given the packet alone would open a flow
// to the fake address itself.
func TestConsumerSendsNoPacketWhoseNameCouldNotBeSent(t *testing.T) {
	harness := newConsumerHarness(t, nil, map[int64]bool{2: true})
	harness.consumer.configureIn(phaseTwoRules(), egressDefaultMeshCIDR, "100.96.0.1", egressDefaultFakeIPCIDR, flowEpoch)
	harness.consumer.setDomainCapable(map[int64]bool{2: true}, flowEpoch)
	assignment, _ := harness.consumer.assignFakeIP("www.example.com", flowEpoch)
	harness.sendErr = errors.New("no path to peer")

	outcome := harness.consumer.handleOutbound(buildUDPDatagram(udpDatagram{SourceIP: testAddr(t, "100.96.0.1"),
		DestinationIP: assignment.Address, SourcePort: 50000, DestinationPort: 443, Payload: []byte("q")}), flowEpoch)
	if outcome != egressOutcomeBlockedNoEgress || harness.consumer.blockedCounts()["send-failed"] != 1 {
		t.Errorf("outcome = %s, blocked = %v", outcome, harness.consumer.blockedCounts())
	}
	if len(harness.sent) != 0 || len(harness.toTun) != 0 {
		t.Errorf("sent %d frames and wrote %d packets for a failed send", len(harness.sent), len(harness.toTun))
	}
}

// Without phase two the pool means nothing: an address in it is not the consumer's to claim.
func TestConsumerLeavesThePoolAloneWithoutPhaseTwo(t *testing.T) {
	harness := newConsumerHarness(t, phaseTwoRules(), map[int64]bool{2: true})
	outcome := harness.consumer.handleOutbound(buildTCPSegment(tcpSegment{SourceIP: testAddr(t, "100.96.0.1"),
		DestinationIP: testAddr(t, "198.18.0.2"), SourcePort: 40000, DestinationPort: 443,
		Seq: 1000, Flags: tcpFlagSYN, Window: 65535}), flowEpoch)
	if outcome != egressOutcomeNotMine {
		t.Errorf("outcome = %s, want not-mine", outcome)
	}
	if _, running := harness.consumer.assignFakeIP("www.example.com", flowEpoch); running {
		t.Error("a consumer without phase two handed out a fake address")
	}
}

// A SYN that reached the egress before its name did opens a flow to the fake address itself, and
// the connect hangs. The name-bind that follows closes it, without a flow-reject, and the
// application's retransmitted SYN is dialled to what the name resolves to.
func TestEgressNameBindClosesAFlowStillConnecting(t *testing.T) {
	harness := newEgressHarness(t, "198.18.0.0/15", "203.0.113.0/24")
	harness.runtime.resolve = resolvingTo("203.0.113.10")
	gate := make(chan struct{})
	harness.mu.Lock()
	harness.gate = gate
	harness.mu.Unlock()

	syn := egressSyn(t, "100.96.0.1", 40000, "198.18.0.5", 443)
	done := make(chan struct{})
	go func() {
		harness.runtime.handleFrame(7, egressFrameFor(buildTCPSegment(syn)), flowEpoch)
		close(done)
	}()
	harness.waitFor("the connect to the fake address", func() bool { return harness.dialCount() == 1 })

	bindName(t, harness, 7, "198.18.0.5", "example.com")
	harness.runtime.mu.Lock()
	remaining := harness.runtime.flows.size()
	harness.runtime.mu.Unlock()
	if remaining != 0 {
		t.Fatalf("%d flows after the name-bind, want the early flow closed", remaining)
	}

	harness.mu.Lock()
	harness.gate = nil
	harness.mu.Unlock()
	close(gate)
	<-done
	if !harness.socket(0).isClosed() {
		t.Error("the socket to the fake address outlived its flow")
	}

	harness.runtime.handleFrame(7, egressFrameFor(buildTCPSegment(syn)), flowEpoch)
	harness.mu.Lock()
	dialed := append([]string(nil), harness.dialed...)
	harness.mu.Unlock()
	if len(dialed) != 2 || dialed[1] != "203.0.113.10:443" {
		t.Fatalf("dialled %v, want the retransmission dialled to the resolved address", dialed)
	}
	harness.runtime.mu.Lock()
	flow, open := harness.runtime.flows.lookup(egressFlowKey{protocol: ipv4ProtocolTCP,
		consumerIP: testAddr(t, "100.96.0.1"), consumerPort: 40000, remoteIP: testAddr(t, "198.18.0.5"), remotePort: 443})
	harness.runtime.mu.Unlock()
	if !open || flow.Name != "example.com" {
		t.Errorf("the reopened flow is not the named one: open=%v", open)
	}
	if codes := harness.rejectCodes(); len(codes) != 0 {
		t.Errorf("the close sent flow-reject %v", codes)
	}
}

// A node running phase two keeps its own pool out of what its egress role dials, whatever the policy
// allows: a flow dialled there would be routed into this node's own tunnel.
func TestEgressRoleRefusesThisNodesOwnPool(t *testing.T) {
	for _, takeover := range []bool{false, true} {
		mesh := newEgressMeshHarness(t)
		mesh.config.PeerEgressEnabled, mesh.config.PeerEgressDNSTakeover = true, takeover
		mesh.applyEgressControl(`{"type":"egress-config","enabled":true,"revision":1,"scope":"PUBLIC",
			"allowedConsumerClientIds":[5],
			"destinationRules":[{"cidr":"198.18.0.0/15","protocols":["tcp"],"portRanges":[[443,443]]}]}`)
		runtime := mesh.ensureEgress()
		runtime.mu.Lock()
		code := runtime.authorizeTo(5, egressFlowKey{protocol: ipv4ProtocolTCP, remotePort: 443}, testAddr(t, "198.18.0.5"))
		runtime.mu.Unlock()
		mesh.shutdownEgress()
		want := egressCodeAllowed
		if takeover {
			want = egressCodeForbiddenDestType
		}
		if code != want {
			t.Errorf("takeover=%v: %s, want %s", takeover, code, want)
		}
	}
}

// Both switches are known configuration keys; the pool defaults; and a domain rule is warned about
// exactly when phase two would refuse it.
func TestConfigKnowsThePhaseTwoKeys(t *testing.T) {
	base := `"serverBaseUrl":"http://127.0.0.1:1","apiKey":"k","secret":"s","peerEgressEnabled":true,
		"peerEgressRules":[{"match":"*.example.com","action":"egress","egressClientId":2}]`
	cases := []struct {
		name, extra string
		pool        string
		warned      bool
	}{
		{"takeover off", ``, egressDefaultFakeIPCIDR, true},
		{"takeover on", `,"peerEgressDnsTakeover":true`, egressDefaultFakeIPCIDR, false},
		{"another pool", `,"peerEgressDnsTakeover":true,"peerEgressFakeIpCidr":"10.200.0.0/16"`, "10.200.0.0/16", false},
		{"unusable pool", `,"peerEgressDnsTakeover":true,"peerEgressFakeIpCidr":"198.18.0.0/25"`, "198.18.0.0/25", true},
	}
	for _, c := range cases {
		var warnings []string
		config, err := ParseConfigWithDiagnostics([]byte("{"+base+c.extra+"}"), func(w string) { warnings = append(warnings, w) })
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		joined := strings.Join(warnings, " | ")
		if strings.Contains(joined, "Unknown configuration field") {
			t.Errorf("%s: %q", c.name, joined)
		}
		if config.PeerEgressFakeIPCIDR != c.pool {
			t.Errorf("%s: pool %q, want %q", c.name, config.PeerEgressFakeIPCIDR, c.pool)
		}
		warned := strings.Contains(joined, "peerEgressRules[0] is not in force: "+egressCodeRuleDomainUnsupported)
		if warned != c.warned {
			t.Errorf("%s: warned=%v (%q), want %v", c.name, warned, joined, c.warned)
		}
		if code := EgressRuleCode(config, config.PeerEgressRules[0]); (code != "") != c.warned {
			t.Errorf("%s: EgressRuleCode = %q", c.name, code)
		}
	}
}

// An unusable pool is said in so many words, the same in all three clients, whenever phase two is
// asked for: judged with the master switch on and against the default mesh network, like the rules.
func TestConfigWarnsOfAnUnusablePool(t *testing.T) {
	const warning = "peerEgressFakeIpCidr is not usable: EGRESS_FAKE_IP_POOL_INVALID; domain rules are not in force"
	cases := []struct {
		name, fields string
		warned       bool
	}{
		{"too narrow", `"peerEgressDnsTakeover":true,"peerEgressFakeIpCidr":"198.18.0.0/25"`, true},
		{"over the default mesh", `"peerEgressDnsTakeover":true,"peerEgressFakeIpCidr":"100.96.0.0/16"`, true},
		{"not a prefix", `"peerEgressDnsTakeover":true,"peerEgressFakeIpCidr":"fake-ip"`, true},
		{"with the master switch off", `"peerEgressEnabled":false,"peerEgressDnsTakeover":true,"peerEgressFakeIpCidr":"198.18.0.0/25"`, true},
		{"usable", `"peerEgressDnsTakeover":true,"peerEgressFakeIpCidr":"10.200.0.0/16"`, false},
		{"default", `"peerEgressDnsTakeover":true`, false},
		{"takeover off", `"peerEgressFakeIpCidr":"198.18.0.0/25"`, false},
	}
	for _, c := range cases {
		data := []byte(`{"serverBaseUrl":"http://127.0.0.1:1","apiKey":"k","secret":"s",` + c.fields + `}`)
		var warnings []string
		if _, err := ParseConfigWithDiagnostics(data, func(w string) { warnings = append(warnings, w) }); err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		count := 0
		for _, got := range warnings {
			if got == warning {
				count++
			}
		}
		if want := map[bool]int{true: 1, false: 0}[c.warned]; count != want {
			t.Errorf("%s: warnings %q, want the pool warning %d time(s)", c.name, warnings, want)
		}
	}
}

// A name-bind closes both kinds of flow it makes stale, and resets only the one that was a real
// connection. The flow opened before any name was dialled to the fake address; the application's
// retransmitted SYN is right behind the name-bind, and a reset would refuse it. The flow opened for
// another name did reach somewhere, and is told it is over.
func TestEgressNameBindResetsOnlyAFlowOpenedForAnotherName(t *testing.T) {
	harness := newEgressHarness(t, "198.18.0.0/15", "203.0.113.0/24")
	harness.runtime.resolve = resolvingTo("203.0.113.10")
	consumerIP := testAddr(t, "100.96.0.1")
	key := func(port uint16) egressFlowKey {
		return egressFlowKey{protocol: ipv4ProtocolTCP, consumerIP: consumerIP, consumerPort: port,
			remoteIP: testAddr(t, "198.18.0.5"), remotePort: 443}
	}
	resetTo := func(port uint16, from int) bool {
		for _, segment := range harness.segments()[from:] {
			if segment.has(tcpFlagRST) && segment.DestinationIP == consumerIP && segment.DestinationPort == port {
				return true
			}
		}
		return false
	}
	gone := func(port uint16) bool {
		harness.runtime.mu.Lock()
		defer harness.runtime.mu.Unlock()
		_, present := harness.runtime.flows.lookup(key(port))
		return !present
	}

	// Opened with no name: established with the fake address itself, then closed silently.
	openEstablishedEgressFlow(t, harness, 7, key(40000))
	before := len(harness.segments())
	bindName(t, harness, 7, "198.18.0.5", "example.com")
	if !gone(40000) || !harness.socket(0).isClosed() {
		t.Fatal("the flow opened before its name survived the name-bind")
	}
	if resetTo(40000, before) {
		t.Error("the flow opened before its name was reset, refusing the SYN the name-bind came to rescue")
	}

	// Opened for example.com, then the address is bound to another name: reset.
	openEstablishedEgressFlow(t, harness, 7, key(40001))
	before = len(harness.segments())
	bindName(t, harness, 7, "198.18.0.5", "www.example.com")
	if !gone(40001) || !harness.socket(1).isClosed() {
		t.Fatal("the flow opened for the old name survived the rebinding")
	}
	if !resetTo(40001, before) {
		t.Error("the flow opened for the old name was closed without a reset")
	}
	if codes := harness.rejectCodes(); len(codes) != 0 {
		t.Errorf("the name-binds sent flow-reject %v", codes)
	}
}
