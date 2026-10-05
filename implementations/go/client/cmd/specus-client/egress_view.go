package main

import (
	"fmt"
	"sort"
	"strings"
)

// Rendering the egress section of a live instance's state for a person.
//
// The JSON form carries everything; this decides what a person is shown. The rule it follows is to
// print the problems and count the rest: a rule that is configured but not in force, a route this
// feature wanted and did not get, an egress peer a rule names that cannot take a flow -- offline,
// not offered by the server's catalogue, or running a client without peer egress. Those are the
// ways this feature can be doing nothing while every other surface looks healthy, and they are the
// reason the section exists.
//
// So a working node prints four lines and a broken one prints the four lines plus exactly what is
// wrong. Listing the healthy rules too would push the one line that matters off the screen on any
// node with a real rule set.

func egressLines(section map[string]any) []string {
	if section == nil {
		return []string{"  No egress state. This build reported none."}
	}
	lines := consumerLines(mapAt(section, "consumer"))
	return append(lines, egressRoleLines(mapAt(section, "egress"))...)
}

func consumerLines(consumer map[string]any) []string {
	// Rules saved with the master switch off are a state of their own, and the one where nothing is
	// in force by design; said as such rather than folded into "not configured". A state file from
	// a build without the switch has no such field and reads as before.
	if enabled, present := consumer["enabled"].(bool); present && !enabled {
		if rules := listAt(consumer, "rules"); len(rules) > 0 {
			return []string{fmt.Sprintf(
				"  consumer: takeover off | %d rules saved, none in force (peerEgressEnabled is false)", len(rules))}
		}
	}
	if consumer == nil || !boolAt(consumer, "active") {
		return []string{"  consumer: not configured (no rules have been applied)"}
	}
	rules := listAt(consumer, "rules")
	routes := listAt(consumer, "routes")
	peers := listAt(consumer, "peers")

	refused, notInstalled, offline, relayed := 0, 0, 0, 0
	for _, rule := range rules {
		if !boolAt(rule, "inForce") {
			refused++
		}
	}
	for _, route := range routes {
		if !boolAt(route, "installed") {
			notInstalled++
		}
	}
	for _, peer := range peers {
		if !boolAt(peer, "online") {
			offline++
		}
		if stringAt(peer, "path") == "relay" {
			relayed++
		}
	}

	lines := []string{fmt.Sprintf(
		"  consumer: %d rules (%d not in force) | %d routes (%d not installed) | %d flows | %d egress peers (%d offline, %d via relay)",
		len(rules), refused, len(routes), notInstalled, intAt(consumer, "flows"), len(peers), offline, relayed)}

	// Then the problems, one line each, in the order an operator would act on them: a rule that
	// is not in force steers nothing at all, a route that is not installed means the traffic
	// leaves locally, and an egress peer that cannot take a flow means the rule is in force with
	// nowhere to send.
	for _, rule := range rules {
		if boolAt(rule, "inForce") {
			continue
		}
		lines = append(lines, fmt.Sprintf("    rule %d %q: NOT IN FORCE (%s)",
			intAt(rule, "index"), stringAt(rule, "match"), stringAt(rule, "code")))
	}
	for _, route := range routes {
		if boolAt(route, "installed") {
			continue
		}
		lines = append(lines, fmt.Sprintf("    route %s (%s): NOT INSTALLED, already present: %s",
			stringAt(route, "cidr"), stringAt(route, "origin"), stringAt(route, "conflict")),
			"      fix: remove or narrow that route, or change the rule; the client retries every 60 s")
	}
	lines = append(lines, egressPeerProblemLines(peers, stringAt(consumer, "catalog"))...)
	if message := stringAt(consumer, "routeError"); message != "" {
		lines = append(lines, fmt.Sprintf("    route install failed: %s (rolledBack=%v)",
			message, boolAt(consumer, "rolledBack")), "      fix: "+routeErrorFix(message))
	}
	if blocked := countsAt(consumer, "blocked"); len(blocked) > 0 {
		lines = append(lines, "    blocked: "+joinCounts(blocked))
	}
	return lines
}

// egressPeerProblemLines says what keeps each egress peer from taking a flow, and what to do about
// it, in the same words in every runtime (protocol/spec/peer-egress.md, 能力不支持).
//
// An egress is reported once, by the first of these that holds, and the kinds come in this order
// whatever order the peers are in: offline; online but not offered to this device by the
// catalogue; online but running a client without peer egress; and online with no path yet. The
// server sending no catalogue at all is said once, after the egresses that cannot take a flow and
// before the ones that only have no path. An egress with no path is a problem too: its rules are in
// force and have nowhere to send.
func egressPeerProblemLines(peers []map[string]any, catalog string) []string {
	var offline, notOffered, unsupported, noPath []string
	for _, peer := range peers {
		id := intAt(peer, "clientId")
		switch {
		case !boolAt(peer, "online"):
			offline = append(offline, fmt.Sprintf("    egress peer %d: offline, so its rules have nowhere to send", id),
				fmt.Sprintf("      fix: start egress device %d or restore its connection; until then its destinations are blocked, not sent locally", id))
		case stringAt(peer, "standing") == "not-offered":
			notOffered = append(notOffered, fmt.Sprintf("    egress peer %d: not offered to this device by the server's egress catalog", id),
				"      fix: ask an administrator to enable its egress policy and allow this device, and check the mesh ACL and the tenant switch; until then its destinations are blocked, not sent locally")
		case stringAt(peer, "standing") == "unsupported":
			unsupported = append(unsupported, fmt.Sprintf("    egress peer %d: online, but its client does not support peer egress", id),
				fmt.Sprintf("      fix: upgrade the client on egress device %d; until then its destinations are blocked, not sent locally", id))
		case stringAt(peer, "path") == "none":
			noPath = append(noPath, fmt.Sprintf("    egress peer %d: online but no path to it yet", id),
				"      fix: wait for a direct or relay path; if it lasts, check that both devices reach the server over UDP")
		}
	}
	lines := append(append(offline, notOffered...), unsupported...)
	if catalog == "none" {
		lines = append(lines, "    server: sent no egress catalog; it may be too old for peer egress",
			"      fix: upgrade the server; until then whether an egress takes a flow is up to the egress itself")
	}
	return append(lines, noPath...)
}

// routeErrorFix names what to do about a failed route install. A refused permission is the common
// case and has one answer; anything else is in the log line of the command that failed.
func routeErrorFix(message string) string {
	lower := strings.ToLower(message)
	for _, hint := range []string{"permission", "denied", "not permitted", "elevat", "access"} {
		if strings.Contains(lower, hint) {
			return "run the client as administrator or root, with peerMeshDevice set to auto"
		}
	}
	return "the client log names the route command that failed; fix what it reports and restart the client"
}

func egressRoleLines(egress map[string]any) []string {
	if egress == nil || !boolAt(egress, "active") {
		// Not a problem and not hidden either. A node that is only a consumer says so, which
		// is what tells an operator who expected it to serve that no policy has arrived.
		return []string{"  egress: not serving (no policy has enabled it)"}
	}
	lines := []string{fmt.Sprintf("  egress: serving | %d flows | %d total | in %d B | out %d B",
		intAt(egress, "flows"), intAt(egress, "totalFlows"),
		intAt(egress, "bytesIn"), intAt(egress, "bytesOut"))}
	if refused := countsAt(egress, "refused"); len(refused) > 0 {
		// By code, because these are the refusals this node handed back to consumers and each
		// code is a different conversation to have with whoever owns the other end.
		lines = append(lines, "    refused: "+joinCounts(refused))
	}
	return lines
}

// The state file is JSON somebody else's runtime may have written, so every read here tolerates a
// missing or wrongly typed field instead of asserting one. A status command that panicked on a
// field a Java client spelled differently would be worse than one that prints a zero.

func mapAt(parent map[string]any, key string) map[string]any {
	value, _ := parent[key].(map[string]any)
	return value
}

func listAt(parent map[string]any, key string) []map[string]any {
	raw, _ := parent[key].([]any)
	entries := make([]map[string]any, 0, len(raw))
	for _, item := range raw {
		if entry, ok := item.(map[string]any); ok {
			entries = append(entries, entry)
		}
	}
	return entries
}

func boolAt(parent map[string]any, key string) bool {
	value, _ := parent[key].(bool)
	return value
}

func intAt(parent map[string]any, key string) int64 {
	switch value := parent[key].(type) {
	case float64:
		return int64(value)
	case int64:
		return value
	case int:
		return int64(value)
	}
	return 0
}

func stringAt(parent map[string]any, key string) string {
	value, _ := parent[key].(string)
	return value
}

func countsAt(parent map[string]any, key string) map[string]int64 {
	raw, _ := parent[key].(map[string]any)
	counts := make(map[string]int64, len(raw))
	for name := range raw {
		// Zeros are dropped rather than printed. A counter that has never fired says nothing,
		// and a line of them would bury the one that has.
		if count := intAt(raw, name); count != 0 {
			counts[name] = count
		}
	}
	return counts
}

func joinCounts(counts map[string]int64) string {
	names := make([]string, 0, len(counts))
	for name := range counts {
		names = append(names, name)
	}
	sort.Strings(names)
	out := ""
	for index, name := range names {
		if index > 0 {
			out += ", "
		}
		out += fmt.Sprintf("%s=%d", name, counts[name])
	}
	return out
}
