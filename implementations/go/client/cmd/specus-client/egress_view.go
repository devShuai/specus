package main

import (
	"fmt"
	"sort"
)

// Rendering the egress section of a live instance's state for a person.
//
// The JSON form carries everything; this decides what a person is shown. The rule it follows is to
// print the problems and count the rest: a rule that is configured but not in force, a route this
// feature wanted and did not get, an egress peer a rule names that is offline. Those are the three
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
	if consumer == nil || !boolAt(consumer, "active") {
		return []string{"  consumer: not configured (no rules have been applied)"}
	}
	rules := listAt(consumer, "rules")
	routes := listAt(consumer, "routes")
	peers := listAt(consumer, "peers")

	refused, notInstalled, offline := 0, 0, 0
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
	}

	lines := []string{fmt.Sprintf(
		"  consumer: %d rules (%d not in force) | %d routes (%d not installed) | %d flows | %d egress peers (%d offline)",
		len(rules), refused, len(routes), notInstalled, intAt(consumer, "flows"), len(peers), offline)}

	// Then the problems, one line each, in the order an operator would act on them: a rule that
	// is not in force steers nothing at all, a route that is not installed means the traffic
	// leaves locally, and an offline peer means the rule is in force with nowhere to send.
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
			stringAt(route, "cidr"), stringAt(route, "origin"), stringAt(route, "conflict")))
	}
	for _, peer := range peers {
		if boolAt(peer, "online") {
			continue
		}
		lines = append(lines, fmt.Sprintf("    egress peer %d: offline, so its rules have nowhere to send",
			intAt(peer, "clientId")))
	}
	if message := stringAt(consumer, "routeError"); message != "" {
		lines = append(lines, fmt.Sprintf("    route install failed: %s (rolledBack=%v)",
			message, boolAt(consumer, "rolledBack")))
	}
	if blocked := countsAt(consumer, "blocked"); len(blocked) > 0 {
		lines = append(lines, "    blocked: "+joinCounts(blocked))
	}
	return lines
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
