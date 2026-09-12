package client

import (
	"testing"
	"time"
)

// What the status surface has to be able to say.
//
// The three things it exists for are a rule that is configured and not in force, a route this
// feature wanted and did not get, and an egress peer a rule names that is offline. Each of those is
// a way for the feature to be doing nothing while every other surface looks healthy, so each one
// gets a case here.

func statusRuntimeConfig() RuntimeConfig {
	return RuntimeConfig{PeerMesh: PeerMeshConfig{CIDR: "10.42.0.0/16", VirtualIP: "10.42.0.7"}}
}

// A refused rule is reported as refused, with the code, rather than being left out.
//
// Left out is the failure that matters: an operator who wrote a rule and reads a status listing
// only the rules that worked has no way to see that the one they care about is text in a file.
func TestEgressStatusReportsARuleThatIsNotInForce(t *testing.T) {
	mesh := newEgressMeshHarness(t)
	defer mesh.shutdownEgress()
	commander := newFakeRouteCommander()
	mesh.egressRoutes = newEgressRouteInstaller(commander, journalPath(t))

	mesh.applyEgressRules([]egressRule{
		{Match: "203.0.113.0/24", Action: egressActionEgress, EgressClientID: 42},
		// Refused: phase one does not take over the default route.
		{Match: "0.0.0.0/0", Action: egressActionEgress, EgressClientID: 42},
	}, statusRuntimeConfig())

	consumer := mapSection(t, mesh.egressStatusJSON(), "consumer")
	if active, _ := consumer["active"].(bool); !active {
		t.Fatal("the consumer reports itself inactive after applying rules")
	}
	rules, ok := consumer["rules"].([]map[string]any)
	if !ok || len(rules) != 2 {
		t.Fatalf("rules = %#v", consumer["rules"])
	}
	if inForce, _ := rules[0]["inForce"].(bool); !inForce {
		t.Errorf("the usable rule is reported as not in force: %#v", rules[0])
	}
	if code, present := rules[0]["code"]; present {
		t.Errorf("the usable rule carries a refusal code %v", code)
	}
	if inForce, _ := rules[1]["inForce"].(bool); inForce {
		t.Error("the default-route rule is reported as in force")
	}
	if code, _ := rules[1]["code"].(string); code != egressCodeRuleDefaultRoute {
		t.Errorf("the refused rule's code = %q, want %q", code, egressCodeRuleDefaultRoute)
	}
}

// A refused rule does not contribute an egress peer.
//
// Reporting one would advertise a peer this node will never send to, which reads as a healthy
// destination for a rule that steers nothing.
func TestEgressStatusOmitsPeersNamedOnlyByRefusedRules(t *testing.T) {
	mesh := newEgressMeshHarness(t)
	defer mesh.shutdownEgress()
	mesh.egressRoutes = newEgressRouteInstaller(newFakeRouteCommander(), journalPath(t))

	mesh.applyEgressRules([]egressRule{
		{Match: "0.0.0.0/0", Action: egressActionEgress, EgressClientID: 77},
	}, statusRuntimeConfig())

	consumer := mapSection(t, mesh.egressStatusJSON(), "consumer")
	peers, _ := consumer["peers"].([]map[string]any)
	if len(peers) != 0 {
		t.Errorf("a refused rule contributed an egress peer: %#v", peers)
	}
}

// A route that was refused because something already owned the prefix is listed, not dropped.
func TestEgressStatusReportsARouteThatWasNotInstalled(t *testing.T) {
	mesh := newEgressMeshHarness(t)
	defer mesh.shutdownEgress()
	commander := newFakeRouteCommander()
	const existing = "203.0.113.0/24 via 192.0.2.1 dev eth0"
	commander.foreign["203.0.113.0/24"] = existing
	mesh.egressRoutes = newEgressRouteInstaller(commander, journalPath(t))

	mesh.applyEgressRules([]egressRule{
		{Match: "203.0.113.0/24", Action: egressActionEgress, EgressClientID: 42},
	}, statusRuntimeConfig())

	consumer := mapSection(t, mesh.egressStatusJSON(), "consumer")
	routes, _ := consumer["routes"].([]map[string]any)
	var found map[string]any
	for _, route := range routes {
		if route["cidr"] == "203.0.113.0/24" {
			found = route
		}
	}
	if found == nil {
		t.Fatalf("the contested route is missing from %#v", routes)
	}
	if installed, _ := found["installed"].(bool); installed {
		t.Error("the contested route is reported as installed")
	}
	if found["conflict"] != existing {
		t.Errorf("conflict = %v, want %q", found["conflict"], existing)
	}
	// And the apply is dated, so a reader can tell a stale answer from a current one.
	if at, _ := found["cidr"].(string); at == "" {
		t.Error("the route carries no prefix")
	}
	if _, present := consumer["appliedAtUnixMs"]; !present {
		t.Error("the consumer section does not say when the routes were applied")
	}
}

// Routes this feature does own are reported as installed, and come from the journal.
func TestEgressStatusReportsTheRoutesItOwns(t *testing.T) {
	mesh := newEgressMeshHarness(t)
	defer mesh.shutdownEgress()
	mesh.egressRoutes = newEgressRouteInstaller(newFakeRouteCommander(), journalPath(t))

	mesh.applyEgressRules([]egressRule{
		{Match: "203.0.113.0/24", Action: egressActionEgress, EgressClientID: 42},
	}, statusRuntimeConfig())

	consumer := mapSection(t, mesh.egressStatusJSON(), "consumer")
	routes, _ := consumer["routes"].([]map[string]any)
	if len(routes) == 0 {
		t.Fatal("no routes reported after a successful apply")
	}
	for _, route := range routes {
		if installed, _ := route["installed"].(bool); !installed {
			t.Errorf("route %v is reported as not installed", route["cidr"])
		}
		if route["origin"] == "" {
			t.Errorf("route %v does not say what asked for it", route["cidr"])
		}
	}
}

// Before anything has been applied the section says so rather than reporting an empty rule set,
// which would read as "configured and nothing matched".
func TestEgressStatusSeparatesNeverAppliedFromNothingConfigured(t *testing.T) {
	mesh := newEgressMeshHarness(t)
	defer mesh.shutdownEgress()

	consumer := mapSection(t, mesh.egressStatusJSON(), "consumer")
	if active, _ := consumer["active"].(bool); active {
		t.Error("the consumer reports itself active before any rules were applied")
	}
	if _, present := consumer["appliedAtUnixMs"]; present {
		t.Error("an apply time is reported before any apply happened")
	}
}

// The egress role's own half: not serving until a policy enables it, then serving with its counts.
func TestEgressStatusReportsWhetherThisNodeIsServing(t *testing.T) {
	mesh := newEgressMeshHarness(t)
	defer mesh.shutdownEgress()

	egress := mapSection(t, mesh.egressStatusJSON(), "egress")
	if active, _ := egress["active"].(bool); active {
		t.Error("the egress reports itself serving before any policy arrived")
	}

	mesh.applyEgressControl(`{"type":"egress-config","enabled":true,"revision":3,"scope":"PUBLIC",
		"allowedConsumerClientIds":[5],
		"destinationRules":[{"cidr":"203.0.113.0/24","protocols":["tcp"],"portRanges":[[443,443]]}],
		"limits":{"maxConcurrentFlows":256,"maxFlowsPerConsumer":64,"idleTimeoutSeconds":60}}`)

	egress = mapSection(t, mesh.egressStatusJSON(), "egress")
	if active, _ := egress["active"].(bool); !active {
		t.Error("the egress does not report itself serving after a policy enabled it")
	}
	if revision, _ := egress["revision"].(int64); revision != 3 {
		t.Errorf("revision = %v, want 3", egress["revision"])
	}
	if _, present := egress["refused"]; !present {
		t.Error("the egress section carries no refusal counts")
	}
}

// Refusals handed back to consumers are counted by code, because each code is a different problem.
func TestEgressStatusCountsRefusalsByCode(t *testing.T) {
	mesh := newEgressMeshHarness(t)
	defer mesh.shutdownEgress()
	runtime := mesh.ensureEgress()
	runtime.mu.Lock()
	runtime.rejections.record(5, egressCodeDestinationDenied, time.Now())
	runtime.rejections.record(5, egressCodeDestinationDenied, time.Now())
	runtime.mu.Unlock()

	egress := mapSection(t, mesh.egressStatusJSON(), "egress")
	refused, _ := egress["refused"].(map[string]int64)
	if refused[egressCodeDestinationDenied] != 2 {
		t.Errorf("refused = %#v, want two %s", refused, egressCodeDestinationDenied)
	}
}

func mapSection(t *testing.T, status map[string]any, key string) map[string]any {
	t.Helper()
	section, ok := status[key].(map[string]any)
	if !ok {
		t.Fatalf("status carries no %q section: %#v", key, status)
	}
	return section
}
