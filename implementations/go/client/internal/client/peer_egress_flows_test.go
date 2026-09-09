package client

import (
	"testing"
	"time"
)

// The flow table is what makes a socket legitimate: it holds the quota a policy grants and the
// record that lets a returning packet be matched to a flow this node actually opened. Every test
// here drives it with an injected clock, so idle expiry is exact rather than approximately timed.

var flowEpoch = time.Date(2026, 9, 9, 12, 0, 0, 0, time.UTC)

func flowKey(t *testing.T, protocol int, consumerIP string, consumerPort int, remoteIP string, remotePort int) egressFlowKey {
	t.Helper()
	return egressFlowKey{
		protocol:     protocol,
		consumerIP:   testAddr(t, consumerIP),
		consumerPort: uint16(consumerPort),
		remoteIP:     testAddr(t, remoteIP),
		remotePort:   uint16(remotePort),
	}
}

func testEgressPolicy(destinations ...string) egressPolicy {
	rules := make([]egressDestinationRule, 0, len(destinations))
	for _, cidr := range destinations {
		// An empty portRanges denies every port, so a rule meant to allow traffic has to say so.
		rules = append(rules, egressDestinationRule{CIDR: cidr, Protocols: []string{"tcp", "udp"},
			PortRanges: [][]int{{1, 65535}}})
	}
	return egressPolicy{
		Enabled:                  true,
		Scope:                    egressScopePublic,
		AllowedConsumerClientIDs: []int64{7, 9},
		DestinationRules:         rules,
	}
}

func TestFlowTableCountsFeedTheLimitChecks(t *testing.T) {
	table := newEgressFlowTable(time.Minute)
	table.open(flowKey(t, ipv4ProtocolTCP, "100.96.0.1", 40000, "203.0.113.10", 443), 7, flowEpoch)
	table.open(flowKey(t, ipv4ProtocolTCP, "100.96.0.1", 40001, "203.0.113.10", 443), 7, flowEpoch)
	table.open(flowKey(t, ipv4ProtocolUDP, "100.96.0.2", 51000, "203.0.113.53", 53), 9, flowEpoch)

	forConsumer, total := table.counts(7)
	if forConsumer != 2 || total != 3 {
		t.Errorf("consumer 7: %d of %d, want 2 of 3", forConsumer, total)
	}
	// A consumer with nothing open must read zero rather than inheriting anyone else's count.
	if forConsumer, _ = table.counts(11); forConsumer != 0 {
		t.Errorf("unknown consumer counted %d", forConsumer)
	}
}

// A quota that counted TCP and UDP separately would let a consumer double its allowance by
// splitting traffic across protocols.
func TestFlowTableCountsBothProtocolsAgainstOneQuota(t *testing.T) {
	table := newEgressFlowTable(time.Minute)
	table.open(flowKey(t, ipv4ProtocolTCP, "100.96.0.1", 40000, "203.0.113.10", 443), 7, flowEpoch)
	table.open(flowKey(t, ipv4ProtocolUDP, "100.96.0.1", 40000, "203.0.113.10", 443), 7, flowEpoch)
	if forConsumer, _ := table.counts(7); forConsumer != 2 {
		t.Errorf("count = %d, want both protocols counted", forConsumer)
	}
}

// Two datagrams leaving one consumer port for different destinations are separate sessions. Keying
// on the source port alone would put the second destination's replies on the first one's socket.
func TestFlowTableSeparatesDestinationsSharingASourcePort(t *testing.T) {
	table := newEgressFlowTable(time.Minute)
	first := flowKey(t, ipv4ProtocolUDP, "100.96.0.1", 51000, "203.0.113.53", 53)
	second := flowKey(t, ipv4ProtocolUDP, "100.96.0.1", 51000, "198.51.100.53", 53)

	if _, opened := table.open(first, 7, flowEpoch); !opened {
		t.Fatal("the first session did not open")
	}
	if _, opened := table.open(second, 7, flowEpoch); !opened {
		t.Fatal("a second destination on the same source port was folded into the first session")
	}
	if table.size() != 2 {
		t.Errorf("size = %d, want 2", table.size())
	}
}

// A retransmitted SYN or a second datagram arriving mid-open is ordinary traffic. Reporting it as a
// new flow would charge the consumer twice for one session.
func TestFlowTableReopenReturnsTheExistingFlow(t *testing.T) {
	table := newEgressFlowTable(time.Minute)
	key := flowKey(t, ipv4ProtocolTCP, "100.96.0.1", 40000, "203.0.113.10", 443)
	first, opened := table.open(key, 7, flowEpoch)
	if !opened {
		t.Fatal("the flow did not open")
	}
	again, opened := table.open(key, 7, flowEpoch.Add(time.Second))
	if opened {
		t.Error("a repeated open was reported as a new flow")
	}
	if again != first {
		t.Error("the repeated open returned a different flow")
	}
	if forConsumer, _ := table.counts(7); forConsumer != 1 {
		t.Errorf("count = %d, want the quota charged once", forConsumer)
	}
	if !again.LastSeen.Equal(flowEpoch.Add(time.Second)) {
		t.Error("the repeated open did not refresh activity")
	}
}

// Nothing in UDP says a session ended, so the idle timer is the only thing that ends one.
func TestFlowTableExpiresIdleSessions(t *testing.T) {
	table := newEgressFlowTable(30 * time.Second)
	idle := flowKey(t, ipv4ProtocolUDP, "100.96.0.1", 51000, "203.0.113.53", 53)
	busy := flowKey(t, ipv4ProtocolUDP, "100.96.0.1", 51001, "203.0.113.53", 53)
	table.open(idle, 7, flowEpoch)
	table.open(busy, 7, flowEpoch)

	if reaped := table.expire(flowEpoch.Add(20 * time.Second)); len(reaped) != 0 {
		t.Fatalf("reaped %d flows before the timeout elapsed", len(reaped))
	}

	table.touch(busy, flowEpoch.Add(25*time.Second))
	reaped := table.expire(flowEpoch.Add(40 * time.Second))
	if len(reaped) != 1 || reaped[0].Key != idle {
		t.Fatalf("expiry reaped %d flows, want only the idle one", len(reaped))
	}
	if table.size() != 1 {
		t.Errorf("size = %d, want the touched flow kept", table.size())
	}
	if forConsumer, _ := table.counts(7); forConsumer != 1 {
		t.Errorf("count = %d, want the expired flow to have released its quota slot", forConsumer)
	}
}

// Withdrawing a consumer's authorization has to stop its traffic now, not when it next happens to
// open something.
func TestFlowTableRevokesOneConsumerImmediately(t *testing.T) {
	table := newEgressFlowTable(time.Minute)
	table.open(flowKey(t, ipv4ProtocolTCP, "100.96.0.1", 40000, "203.0.113.10", 443), 7, flowEpoch)
	table.open(flowKey(t, ipv4ProtocolTCP, "100.96.0.1", 40001, "203.0.113.11", 443), 7, flowEpoch)
	survivor := flowKey(t, ipv4ProtocolTCP, "100.96.0.2", 40000, "203.0.113.12", 443)
	table.open(survivor, 9, flowEpoch)

	reaped := table.revokeConsumer(7)
	if len(reaped) != 2 {
		t.Fatalf("revoked %d flows, want 2", len(reaped))
	}
	if table.size() != 1 {
		t.Errorf("size = %d, want the other consumer untouched", table.size())
	}
	if _, ok := table.lookup(survivor); !ok {
		t.Error("revoking one consumer closed another consumer's flow")
	}
}

func TestFlowTablePurgesByDestination(t *testing.T) {
	table := newEgressFlowTable(time.Minute)
	inRange := flowKey(t, ipv4ProtocolTCP, "100.96.0.1", 40000, "203.0.113.10", 443)
	exact := flowKey(t, ipv4ProtocolUDP, "100.96.0.1", 51000, "198.51.100.50", 53)
	unrelated := flowKey(t, ipv4ProtocolTCP, "100.96.0.1", 40002, "192.0.2.10", 443)
	table.open(inRange, 7, flowEpoch)
	table.open(exact, 7, flowEpoch)
	table.open(unrelated, 7, flowEpoch)

	reaped := table.purgeDestinations([]string{"203.0.113.0/24", "198.51.100.50/32"})
	if len(reaped) != 2 {
		t.Fatalf("purged %d flows, want 2", len(reaped))
	}
	if _, ok := table.lookup(unrelated); !ok {
		t.Error("a flow outside every purged prefix was closed")
	}
}

// A purge nobody can parse must close nothing. Treating an unreadable prefix as matching everything
// would turn one malformed control message into a total outage.
func TestFlowTablePurgeIgnoresUnparseablePrefixes(t *testing.T) {
	table := newEgressFlowTable(time.Minute)
	table.open(flowKey(t, ipv4ProtocolTCP, "100.96.0.1", 40000, "203.0.113.10", 443), 7, flowEpoch)

	if reaped := table.purgeDestinations([]string{"not-a-cidr", "203.0.113.1/24"}); len(reaped) != 0 {
		t.Fatalf("purged %d flows on a malformed message", len(reaped))
	}
	if table.size() != 1 {
		t.Error("a malformed purge closed a flow")
	}
}

// An operator who deletes a destination rule expects that traffic to stop. A change that only
// governed new flows would read as the rule having failed to apply.
func TestFlowTableReauthorizeClosesFlowsThePolicyNoLongerAllows(t *testing.T) {
	table := newEgressFlowTable(time.Minute)
	kept := flowKey(t, ipv4ProtocolTCP, "100.96.0.1", 40000, "203.0.113.10", 443)
	dropped := flowKey(t, ipv4ProtocolTCP, "100.96.0.1", 40001, "198.51.100.10", 443)
	table.open(kept, 7, flowEpoch)
	table.open(dropped, 7, flowEpoch)

	narrowed := testEgressPolicy("203.0.113.0/24")
	reaped := table.reauthorize(narrowed, func(int64) bool { return true }, newEgressContext(), nil)
	if len(reaped) != 1 || reaped[0].Flow.Key != dropped {
		t.Fatalf("reauthorize reaped %d flows, want only the one outside the new rule", len(reaped))
	}
	if _, ok := table.lookup(kept); !ok {
		t.Error("a flow the policy still allows was closed")
	}
}

func TestFlowTableReauthorizeHonoursTheConsumerACL(t *testing.T) {
	table := newEgressFlowTable(time.Minute)
	table.open(flowKey(t, ipv4ProtocolTCP, "100.96.0.1", 40000, "203.0.113.10", 443), 7, flowEpoch)
	table.open(flowKey(t, ipv4ProtocolTCP, "100.96.0.2", 40000, "203.0.113.10", 443), 9, flowEpoch)

	policy := testEgressPolicy("203.0.113.0/24")
	reaped := table.reauthorize(policy, func(consumer int64) bool { return consumer != 9 },
		newEgressContext(), nil)
	if len(reaped) != 1 || reaped[0].Flow.Consumer != 9 {
		t.Fatalf("reauthorize reaped %d flows, want only the peer whose ACL was withdrawn", len(reaped))
	}
}

// One policy push can close flows for different reasons at once. A single code for the batch would
// tell a consumer its flow died of something that did not happen to it.
func TestFlowTableReauthorizeReportsEachFlowsOwnReason(t *testing.T) {
	table := newEgressFlowTable(time.Minute)
	outsideRule := flowKey(t, ipv4ProtocolTCP, "100.96.0.1", 40000, "198.51.100.10", 443)
	deniedConsumer := flowKey(t, ipv4ProtocolTCP, "100.96.0.2", 40000, "203.0.113.10", 443)
	table.open(outsideRule, 7, flowEpoch)
	table.open(deniedConsumer, 9, flowEpoch)

	policy := testEgressPolicy("203.0.113.0/24")
	policy.AllowedConsumerClientIDs = []int64{7}

	reasons := make(map[egressFlowKey]string)
	for _, entry := range table.reauthorize(policy, func(int64) bool { return true }, newEgressContext(), nil) {
		reasons[entry.Flow.Key] = entry.Code
	}
	if reasons[outsideRule] != egressCodeDestinationDenied {
		t.Errorf("flow outside the rule reported %q", reasons[outsideRule])
	}
	if reasons[deniedConsumer] != egressCodeConsumerDenied {
		t.Errorf("flow of a removed consumer reported %q", reasons[deniedConsumer])
	}
}

// Lowering a quota should stop the next flow, not pick live ones to kill. A limit breach is not a
// permission a running flow lost.
func TestFlowTableReauthorizeDoesNotEnforceLoweredLimits(t *testing.T) {
	table := newEgressFlowTable(time.Minute)
	table.open(flowKey(t, ipv4ProtocolTCP, "100.96.0.1", 40000, "203.0.113.10", 443), 7, flowEpoch)
	table.open(flowKey(t, ipv4ProtocolTCP, "100.96.0.1", 40001, "203.0.113.10", 443), 7, flowEpoch)

	policy := testEgressPolicy("203.0.113.0/24")
	policy.Limits = egressLimits{MaxConcurrentFlows: 1, MaxFlowsPerConsumer: 1}
	if reaped := table.reauthorize(policy, func(int64) bool { return true }, newEgressContext(), nil); len(reaped) != 0 {
		t.Fatalf("a lowered quota killed %d running flows", len(reaped))
	}
}

// The forced-deny list has to hold on re-evaluation too, not only at open. A local interface added
// after a flow started would otherwise leave that flow looping back into this node.
func TestFlowTableReauthorizeAppliesForcedDeny(t *testing.T) {
	table := newEgressFlowTable(time.Minute)
	table.open(flowKey(t, ipv4ProtocolTCP, "100.96.0.1", 40000, "203.0.113.10", 443), 7, flowEpoch)

	policy := testEgressPolicy("0.0.0.0/0")
	reaped := table.reauthorize(policy, func(int64) bool { return true }, newEgressContext(),
		[]string{"203.0.113.0/24"})
	if len(reaped) != 1 {
		t.Fatalf("reaped %d flows, want the one now pointing at a local interface", len(reaped))
	}
}

// Without this a peer could hand the egress a packet carrying any source address it liked and have
// it relayed into the mesh as though the egress had fetched it.
func TestFlowTableReturnPathRequiresAnOpenFlow(t *testing.T) {
	table := newEgressFlowTable(time.Minute)
	key := flowKey(t, ipv4ProtocolTCP, "100.96.0.1", 40000, "203.0.113.10", 443)
	table.open(key, 7, flowEpoch)

	if !table.hasReturnPath(key) {
		t.Error("a live flow was not recognised on the return path")
	}
	forged := key
	forged.remoteIP = testAddr(t, "198.51.100.10")
	if table.hasReturnPath(forged) {
		t.Error("a packet from an address this node never contacted was accepted")
	}
	table.close(key)
	if table.hasReturnPath(key) {
		t.Error("a closed flow still admitted return traffic")
	}
}

func TestFlowTableDrainReleasesEverything(t *testing.T) {
	table := newEgressFlowTable(time.Minute)
	table.open(flowKey(t, ipv4ProtocolTCP, "100.96.0.1", 40000, "203.0.113.10", 443), 7, flowEpoch)
	table.open(flowKey(t, ipv4ProtocolUDP, "100.96.0.2", 51000, "203.0.113.53", 53), 9, flowEpoch)

	if reaped := table.drain(); len(reaped) != 2 {
		t.Fatalf("drain returned %d flows, want 2", len(reaped))
	}
	if table.size() != 0 {
		t.Errorf("size = %d after drain", table.size())
	}
	if forConsumer, total := table.counts(7); forConsumer != 0 || total != 0 {
		t.Errorf("counts after drain: %d of %d", forConsumer, total)
	}
	if len(table.perConsumer) != 0 {
		t.Errorf("perConsumer kept %d entries for consumers with nothing open", len(table.perConsumer))
	}
}

// Every reap emits one record per closed flow. Map order would make those records, and this suite,
// differ run to run.
func TestFlowTableReapsInAStableOrder(t *testing.T) {
	var first []egressFlowKey
	for attempt := 0; attempt < 8; attempt++ {
		table := newEgressFlowTable(time.Minute)
		for port := 40000; port < 40010; port++ {
			table.open(flowKey(t, ipv4ProtocolTCP, "100.96.0.1", port, "203.0.113.10", 443), 7, flowEpoch)
		}
		table.open(flowKey(t, ipv4ProtocolUDP, "100.96.0.1", 40000, "203.0.113.10", 443), 7, flowEpoch)

		var order []egressFlowKey
		for _, flow := range table.drain() {
			order = append(order, flow.Key)
		}
		if attempt == 0 {
			first = order
			continue
		}
		for index := range order {
			if order[index] != first[index] {
				t.Fatalf("attempt %d differed at position %d", attempt, index)
			}
		}
	}
	if len(first) != 11 {
		t.Fatalf("drained %d flows, want 11", len(first))
	}
	// TCP sorts before UDP by protocol number, so the single UDP flow lands last.
	if first[len(first)-1].protocol != ipv4ProtocolUDP {
		t.Error("the ordering is not by protocol first")
	}
}

// The spec puts ICMP out of scope with an instruction to refuse rather than degrade silently.
// Forwarding it would need a raw socket, and the whole point of the user-space stack is that acting
// as an egress needs no privilege at all.
func TestEgressRefusesProtocolsOutsideThisVersion(t *testing.T) {
	if name := egressProtocolName(ipv4ProtocolICMP); name != "" {
		t.Errorf("ICMP mapped to %q, so a rule could match it", name)
	}
	policy := testEgressPolicy("203.0.113.0/24")
	decision := authorizeEgressFlow(egressRequest{
		ConsumerClientID: 7,
		DestinationIP:    "203.0.113.10",
		DestinationPort:  0,
		Protocol:         egressProtocolName(ipv4ProtocolICMP),
	}, policy, true, newEgressContext())
	if decision.Allowed || decision.Code != egressCodeProtocolDenied {
		t.Errorf("ICMP got %s/%v, want %s/false", decision.Code, decision.Allowed, egressCodeProtocolDenied)
	}
}

func TestFlowTableFallsBackToADefaultIdleTimeout(t *testing.T) {
	table := newEgressFlowTable(0)
	key := flowKey(t, ipv4ProtocolUDP, "100.96.0.1", 51000, "203.0.113.53", 53)
	table.open(key, 7, flowEpoch)
	if reaped := table.expire(flowEpoch.Add(egressDefaultIdleTimeout - time.Second)); len(reaped) != 0 {
		t.Error("a session expired before the default timeout")
	}
	if reaped := table.expire(flowEpoch.Add(egressDefaultIdleTimeout)); len(reaped) != 1 {
		t.Error("a session outlived the default timeout")
	}
}
