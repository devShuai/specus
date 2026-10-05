package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
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
	if !strings.Contains(output, "1 egress peers (1 offline, 0 via relay)") {
		t.Errorf("the summary miscounts the offline peer:\n%s", output)
	}
}

// Rules saved with the switch off read as a state of their own, never as "not configured": the
// person who wrote the rules and did not turn them on needs to be told that nothing is in force.
func TestEgressViewSaysRulesAreSavedButNotTakingOver(t *testing.T) {
	lines := egressLines(egressSection(t, `{
  "consumer": {
    "enabled": false, "active": false,
    "rules": [
      {"index": 0, "match": "203.0.113.0/24", "action": "egress", "egressClientId": 42,
       "inForce": false, "code": "EGRESS_CONSUMER_DISABLED"},
      {"index": 1, "match": "198.51.100.0/24", "action": "block",
       "inForce": false, "code": "EGRESS_RULE_DISABLED"}
    ],
    "routes": [], "peers": [], "flows": 0, "blocked": {}
  },
  "egress": {"active": false}
}`))
	want := "  consumer: takeover off | 2 rules saved, none in force (peerEgressEnabled is false)"
	if len(lines) == 0 || lines[0] != want {
		t.Fatalf("first line = %q, want %q", strings.Join(lines, "\n"), want)
	}
	// Off with nothing saved is simply not configured.
	lines = egressLines(egressSection(t, `{"consumer": {"enabled": false, "active": false, "rules": []}}`))
	if lines[0] != "  consumer: not configured (no rules have been applied)" {
		t.Fatalf("empty switched-off consumer = %q", lines[0])
	}
}

// Every problem is followed by what to do about it, and the path to each egress is counted: an
// egress on the relay is slower but working, one online with no path is in force with nowhere to send.
func TestEgressViewSaysWhatToDoAboutEachProblem(t *testing.T) {
	section := egressSection(t, `{"consumer": {"active": true, "flows": 2,
		"rules": [{"index": 0, "match": "203.0.113.0/24", "action": "egress", "egressClientId": 42, "inForce": true},
		          {"index": 1, "match": "198.51.100.0/24", "action": "egress", "egressClientId": 43, "inForce": true},
		          {"index": 2, "match": "192.0.2.0/24", "action": "egress", "egressClientId": 44, "inForce": true}],
		"routes": [{"cidr": "203.0.113.0/24", "kind": "tun", "origin": "rule:203.0.113.0/24", "installed": false,
		            "conflict": "203.0.113.0/24 via 192.0.2.1 dev eth0"}],
		"peers": [{"clientId": 42, "online": true, "path": "relay", "flows": 2},
		          {"clientId": 43, "online": true, "path": "none", "flows": 0},
		          {"clientId": 44, "online": false, "path": "none", "flows": 0}],
		"routeError": "ip route replace 192.0.2.0/24 dev specus0: Operation not permitted", "rolledBack": true},
		"egress": {"active": false}}`)
	output := strings.Join(egressLines(section), "\n")
	for _, want := range []string{
		"3 egress peers (1 offline, 1 via relay)",
		"      fix: remove or narrow that route, or change the rule; the client retries every 60 s",
		"    egress peer 43: online but no path to it yet",
		"      fix: wait for a direct or relay path; if it lasts, check that both devices reach the server over UDP",
		"      fix: start egress device 44 or restore its connection; until then its destinations are blocked, not sent locally",
		"      fix: run the client as administrator or root, with peerMeshDevice set to auto",
	} {
		if !strings.Contains(output, want) {
			t.Errorf("missing %q in:\n%s", want, output)
		}
	}
	if strings.Contains(output, "egress peer 42") {
		t.Errorf("an egress on the relay is working and is counted, not listed:\n%s", output)
	}
}

// egressProblemLines renders a consumer with the peers and catalog given ("" leaves the field out)
// and keeps only what comes after the summary line: the problems and their fixes.
func egressProblemLines(t *testing.T, peers string, catalog string) []string {
	t.Helper()
	field := ""
	if catalog != "" {
		field = `"catalog": "` + catalog + `", `
	}
	lines := egressLines(egressSection(t, `{"consumer": {"active": true, "flows": 0, "rules": [], "routes": [],
		"peers": `+peers+`, `+field+`"blocked": {}}, "egress": {"active": false}}`))
	// The summary, then the problems, then the egress role's own line.
	if len(lines) < 2 {
		t.Fatalf("rendered %v", lines)
	}
	return lines[1 : len(lines)-1]
}

// Why an online egress cannot take a flow is said, with what to do about it. The peers keep their
// client-id order and each is reported once, by the first of: offline, not offered by the
// catalogue, a client without peer egress, no path.
func TestEgressViewSaysWhyAnOnlineEgressCannotTakeAFlow(t *testing.T) {
	got := egressProblemLines(t, `[
		{"clientId": 40, "online": true, "standing": "unknown", "path": "none", "flows": 0},
		{"clientId": 41, "online": false, "standing": "not-offered", "path": "none", "flows": 0},
		{"clientId": 42, "online": true, "standing": "not-offered", "path": "direct", "flows": 0},
		{"clientId": 43, "online": true, "standing": "unsupported", "path": "none", "flows": 0},
		{"clientId": 44, "online": true, "standing": "offered", "path": "relay", "flows": 2},
		{"clientId": 45, "online": true, "standing": "offered", "path": "direct", "flows": 1}]`, "received")
	want := []string{
		"    egress peer 40: online but no path to it yet",
		"      fix: wait for a direct or relay path; if it lasts, check that both devices reach the server over UDP",
		"    egress peer 41: offline, so its rules have nowhere to send",
		"      fix: start egress device 41 or restore its connection; until then its destinations are blocked, not sent locally",
		"    egress peer 42: not offered to this device by the server's egress catalog",
		"      fix: ask an administrator to enable its egress policy and allow this device, and check the mesh ACL and the tenant switch; until then its destinations are blocked, not sent locally",
		"    egress peer 43: online, but its client does not support peer egress",
		"      fix: upgrade the client on egress device 43; until then its destinations are blocked, not sent locally",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("problems:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

// A server that sent no catalogue is said once, after every egress peer's lines and before the
// route error and the blocked counts; while the wait is still on, or once one came, nothing.
func TestEgressViewSaysOnceThatTheServerSentNoCatalogue(t *testing.T) {
	peers := `[{"clientId": 41, "online": true, "standing": "unknown", "path": "none", "flows": 0},
		{"clientId": 42, "online": false, "standing": "unknown", "path": "none", "flows": 0},
		{"clientId": 43, "online": true, "standing": "unknown", "path": "direct", "flows": 0}]`
	got := egressProblemLines(t, peers, "none")
	want := []string{
		"    egress peer 41: online but no path to it yet",
		"      fix: wait for a direct or relay path; if it lasts, check that both devices reach the server over UDP",
		"    egress peer 42: offline, so its rules have nowhere to send",
		"      fix: start egress device 42 or restore its connection; until then its destinations are blocked, not sent locally",
		"    server: sent no egress catalog; it may be too old for peer egress",
		"      fix: upgrade the server; until then whether an egress takes a flow is up to the egress itself",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("problems:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	whole := egressLines(egressSection(t, `{"consumer": {"active": true, "flows": 0, "rules": [], "routes": [],
		"peers": `+peers+`, "catalog": "none", "blocked": {"egress-unavailable": 3},
		"routeError": "install 203.0.113.0/24: permission denied", "rolledBack": true}, "egress": {"active": false}}`))
	server, routeError, blocked := -1, -1, -1
	for index, line := range whole {
		switch {
		case strings.HasPrefix(line, "    server: "):
			server = index
		case strings.HasPrefix(line, "    route install failed: "):
			routeError = index
		case strings.HasPrefix(line, "    blocked: "):
			blocked = index
		}
	}
	if server < 0 || !(server < routeError && routeError < blocked) {
		t.Errorf("the server line is not between the peers and the route error:\n%s", strings.Join(whole, "\n"))
	}
	// Said even with no egress peer: the server's silence is not about any one of them.
	if got := egressProblemLines(t, `[]`, "none"); len(got) != 2 || !strings.HasPrefix(got[0], "    server: ") {
		t.Errorf("no peers, catalog none: %v", got)
	}
	for _, catalog := range []string{"waiting", "received", ""} {
		for _, line := range egressProblemLines(t, peers, catalog) {
			if strings.Contains(line, "server:") {
				t.Errorf("catalog %q printed %q", catalog, line)
			}
		}
	}
}

// The three pinned problems read exactly as protocol/spec/peer-egress.md writes them, byte for
// byte, so the three runtimes and the local page say the same thing.
func TestEgressViewUsesTheSpecsWordsForWhatTheCatalogueSays(t *testing.T) {
	pinned := pinnedEgressCatalogueLines(t)
	if len(pinned) != 6 {
		t.Fatalf("the spec pins %d lines, want 6:\n%s", len(pinned), strings.Join(pinned, "\n"))
	}
	for _, id := range []string{"42", "7"} {
		expected := make([]string, len(pinned))
		for index, line := range pinned {
			expected[index] = strings.NewReplacer("peer N:", "peer "+id+":", "device N;", "device "+id+";").Replace(line)
		}
		got := egressProblemLines(t, `[{"clientId": `+id+`, "online": true, "standing": "not-offered", "path": "direct"}]`, "received")
		if !reflect.DeepEqual(got, expected[0:2]) {
			t.Errorf("not offered:\n%q\nwant\n%q", got, expected[0:2])
		}
		got = egressProblemLines(t, `[{"clientId": `+id+`, "online": true, "standing": "unsupported", "path": "direct"}]`, "received")
		if !reflect.DeepEqual(got, expected[2:4]) {
			t.Errorf("unsupported:\n%q\nwant\n%q", got, expected[2:4])
		}
		got = egressProblemLines(t, `[]`, "none")
		if !reflect.DeepEqual(got, expected[4:6]) {
			t.Errorf("no catalogue:\n%q\nwant\n%q", got, expected[4:6])
		}
	}
}

// pinnedEgressCatalogueLines reads the text block under 能力不支持 in protocol/spec/peer-egress.md.
func pinnedEgressCatalogueLines(t *testing.T) []string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	var spec []byte
	for depth := 0; depth < 8 && spec == nil; depth++ {
		spec, _ = os.ReadFile(filepath.Join(dir, "protocol", "spec", "peer-egress.md"))
		dir = filepath.Dir(dir)
	}
	if spec == nil {
		t.Fatal("cannot locate protocol/spec/peer-egress.md")
	}
	text := strings.ReplaceAll(string(spec), "\r\n", "\n")
	_, section, found := strings.Cut(text, "\n### 能力不支持\n")
	if !found {
		t.Fatal("the spec has no 能力不支持 section")
	}
	_, block, found := strings.Cut(section, "```text\n")
	if !found {
		t.Fatal("the 能力不支持 section has no text block")
	}
	block, _, _ = strings.Cut(block, "```")
	return strings.Split(strings.TrimRight(block, "\n"), "\n")
}

// A state file from a build without standings or catalog prints as it always did.
func TestEgressViewReadsAStateWithoutStandings(t *testing.T) {
	got := egressProblemLines(t, `[{"clientId": 42, "online": true, "path": "direct", "flows": 1},
		{"clientId": 43, "online": true, "path": "none", "flows": 0}]`, "")
	want := []string{
		"    egress peer 43: online but no path to it yet",
		"      fix: wait for a direct or relay path; if it lasts, check that both devices reach the server over UDP",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("problems = %q", got)
	}
}
