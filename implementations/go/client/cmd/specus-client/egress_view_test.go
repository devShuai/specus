package main

import (
	"encoding/json"
	"strings"
	"testing"
)

// What a person sees when they run the egress command.
//
// The rule this holds down is that problems are printed and healthy items are counted. A status
// that listed every rule would push the one line that matters off the screen on any node with a
// real rule set, and a status that printed only the summary would make an operator go and read the
// JSON to find out which rule is the broken one.

func egressSection(t *testing.T, document string) map[string]any {
	t.Helper()
	var section map[string]any
	if err := json.Unmarshal([]byte(document), &section); err != nil {
		t.Fatalf("fixture is not JSON: %v", err)
	}
	return section
}

const healthyEgressState = `{
  "consumer": {
    "active": true,
    "appliedAtUnixMs": 1757000000000,
    "rules": [
      {"index": 0, "match": "203.0.113.0/24", "action": "egress", "egressClientId": 42,
       "inForce": true},
      {"index": 1, "match": "198.51.100.0/24", "action": "egress", "egressClientId": 42,
       "inForce": true}
    ],
    "routes": [
      {"cidr": "203.0.113.0/24", "kind": "tun", "origin": "rule:203.0.113.0/24",
       "installed": true},
      {"cidr": "198.51.100.0/24", "kind": "tun", "origin": "rule:198.51.100.0/24",
       "installed": true}
    ],
    "peers": [{"clientId": 42, "online": true}],
    "flows": 3,
    "blocked": {},
    "rolledBack": false
  },
  "egress": {"active": true, "flows": 5, "totalFlows": 11, "bytesIn": 900, "bytesOut": 1200,
             "refused": {}}
}`

const brokenEgressState = `{
  "consumer": {
    "active": true,
    "appliedAtUnixMs": 1757000000000,
    "rules": [
      {"index": 0, "match": "203.0.113.0/24", "action": "egress", "egressClientId": 42,
       "inForce": true},
      {"index": 1, "match": "0.0.0.0/0", "action": "egress", "egressClientId": 42,
       "inForce": false, "code": "EGRESS_RULE_DEFAULT_ROUTE"}
    ],
    "routes": [
      {"cidr": "203.0.113.0/24", "kind": "tun", "origin": "rule:203.0.113.0/24",
       "installed": false, "conflict": "203.0.113.0/24 via 192.0.2.1 dev eth0"}
    ],
    "peers": [{"clientId": 42, "online": false}],
    "flows": 0,
    "blocked": {"no-egress-online": 7, "never-fired": 0},
    "routeError": "install 203.0.113.0/24: permission denied",
    "rolledBack": true
  },
  "egress": {"active": true, "flows": 0, "totalFlows": 0, "bytesIn": 0, "bytesOut": 0,
             "refused": {"EGRESS_DEST_DENIED": 4}}
}`

// A working node says so briefly and names nothing, because there is nothing to act on.
func TestEgressViewCountsAHealthyNodeWithoutListingIt(t *testing.T) {
	lines := egressLines(egressSection(t, healthyEgressState))
	output := strings.Join(lines, "\n")
	if len(lines) != 2 {
		t.Errorf("a healthy node printed %d lines:\n%s", len(lines), output)
	}
	for _, want := range []string{"2 rules (0 not in force)", "2 routes (0 not installed)",
		"3 flows", "egress: serving"} {
		if !strings.Contains(output, want) {
			t.Errorf("output does not mention %q:\n%s", want, output)
		}
	}
	// The healthy rules are counted, not listed.
	if strings.Contains(output, "203.0.113.0/24") {
		t.Errorf("a healthy node listed an individual rule:\n%s", output)
	}
}

// A broken node names every problem, and says which rule and which route.
func TestEgressViewNamesEveryProblem(t *testing.T) {
	output := strings.Join(egressLines(egressSection(t, brokenEgressState)), "\n")
	for _, want := range []string{
		// The rule that is text in a file rather than a rule.
		`rule 1 "0.0.0.0/0": NOT IN FORCE (EGRESS_RULE_DEFAULT_ROUTE)`,
		// The route whose traffic is leaving by the physical interface right now.
		"route 203.0.113.0/24 (rule:203.0.113.0/24): NOT INSTALLED, already present: " +
			"203.0.113.0/24 via 192.0.2.1 dev eth0",
		// The peer a rule in force is pointing at.
		"egress peer 42: offline",
		"route install failed: install 203.0.113.0/24: permission denied (rolledBack=true)",
		"blocked: no-egress-online=7",
		"refused: EGRESS_DEST_DENIED=4",
	} {
		if !strings.Contains(output, want) {
			t.Errorf("output does not mention %q:\n%s", want, output)
		}
	}
	// A counter that never fired is not printed: a row of zeros would bury the one that did.
	if strings.Contains(output, "never-fired") {
		t.Errorf("a zero counter was printed:\n%s", output)
	}
}

// The two states this section has that are neither healthy nor broken, and which have to read
// differently: nothing configured, and nothing serving.
func TestEgressViewSeparatesNotConfiguredFromNoProblems(t *testing.T) {
	output := strings.Join(egressLines(egressSection(t,
		`{"consumer": {"active": false}, "egress": {"active": false}}`)), "\n")
	if !strings.Contains(output, "consumer: not configured") {
		t.Errorf("an unconfigured consumer is not reported as such:\n%s", output)
	}
	if !strings.Contains(output, "egress: not serving") {
		t.Errorf("a node that is not serving is not reported as such:\n%s", output)
	}
}

// The state file may have been written by another runtime, so a missing or wrongly typed field has
// to produce a line rather than a panic. A status command that crashed on a field somebody spelled
// differently would be worse than one that prints a zero.
func TestEgressViewToleratesStateItDidNotWrite(t *testing.T) {
	for _, document := range []string{
		`{}`,
		`{"consumer": null, "egress": null}`,
		`{"consumer": {"active": true, "rules": "not a list", "routes": 7, "peers": {},
		  "flows": "three", "blocked": [1,2]}, "egress": {"active": "yes"}}`,
		`{"consumer": {"active": true, "rules": [null, 5, {"inForce": "maybe"}],
		  "routes": [{"installed": null}]}, "egress": {"active": true, "flows": null}}`,
	} {
		lines := egressLines(egressSection(t, document))
		if len(lines) == 0 {
			t.Errorf("%s produced no output", document)
		}
	}
	// And a section that is absent entirely says so instead of printing an empty summary.
	if lines := egressLines(nil); len(lines) != 1 || !strings.Contains(lines[0], "No egress state") {
		t.Errorf("a missing section rendered as %v", lines)
	}
}

// A rule that is not in force must never be counted as one that is. Asserted on the summary
// numbers, because those are what an operator reads first and what a dashboard would chart.
func TestEgressViewDoesNotCountRefusedRulesAsInForce(t *testing.T) {
	output := strings.Join(egressLines(egressSection(t, brokenEgressState)), "\n")
	if !strings.Contains(output, "2 rules (1 not in force)") {
		t.Errorf("the summary miscounts the refused rule:\n%s", output)
	}
	if !strings.Contains(output, "1 routes (1 not installed)") {
		t.Errorf("the summary miscounts the uninstalled route:\n%s", output)
	}
	if !strings.Contains(output, "1 egress peers (1 offline)") {
		t.Errorf("the summary miscounts the offline peer:\n%s", output)
	}
}
