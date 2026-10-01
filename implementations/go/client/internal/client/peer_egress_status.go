package client

import (
	"sort"
	"strings"
	"time"
)

// What an operator can read about this node's egress roles.
//
// Until this existed the feature could not say what it was doing. A rule an operator wrote and this
// feature refused was written to the log once, at the moment it was refused, and then nowhere: the
// planner's own comment calls that "a leak they have no way to notice", and closing that gap is
// what this file is for. Same for a route that was not installed because something else already
// owned the prefix -- the traffic goes out locally and every surface looks healthy.
//
// Two of the fields here are derived rather than remembered, and that is deliberate. Whether a rule
// is in force is recomputed from the rule itself, the same way matchEgressRules recomputes it
// before every decision, so the status cannot drift from what steering actually does. Whether a
// route is installed cannot be derived -- the answer came from the platform's routing table at
// apply time -- so that one is remembered.
//
// Nothing secret travels here. Rule matches and prefixes are the operator's own configuration and
// client IDs already appear in the peer list; tokens, keys and addresses learned from other peers
// do not, and DiagnosticSnapshot's allowlist is the reason to keep it that way.

// egressApplyOutcome is what the last route apply left behind that cannot be recomputed.
//
// Only the conflicts, because only they came from outside: the installed set is in the journal, and
// which rules are in force is recomputed from the rules.
type egressApplyOutcome struct {
	At         time.Time
	Conflicts  []egressRouteConflict
	Err        string
	RolledBack bool
	// Applied says an apply has happened at all, so "no routes" is told apart from "never ran".
	Applied bool
}

// consumerStatusSnapshot is the consumer's own view, taken under its lock.
type consumerStatusSnapshot struct {
	Rules    []egressRule
	MeshCIDR string
	Online   map[int64]bool
	Flows    int
	// FlowsByEgress counts the live flows each egress carries, so an operator can see which one the
	// traffic is on.
	FlowsByEgress map[int64]int
	Blocked       map[string]int64
	// Phase two: the pool while it runs ("" otherwise), which egresses resolve names, and the
	// pool's live mappings and quarantined addresses as of the snapshot.
	FakeIPCIDR  string
	Capable     map[int64]bool
	Mappings    int
	Quarantined int
	// The responder: where it listens ("" while phase two does not run), what it forwards to, and
	// its counters.
	Listen     string
	Upstreams  []string
	DNSQueries egressDNSQueries
}

func (c *egressConsumer) statusSnapshot() consumerStatusSnapshot {
	c.mu.Lock()
	defer c.mu.Unlock()
	// Only flows still remembered as of the newest packet count as active.
	c.sweepLocked(c.latest)
	online := make(map[int64]bool, len(c.online))
	for id, up := range c.online {
		online[id] = up
	}
	capable := make(map[int64]bool, len(c.capable))
	for id, able := range c.capable {
		capable[id] = able
	}
	blocked := make(map[string]int64, len(c.blocked))
	for reason, count := range c.blocked {
		blocked[reason] = count
	}
	byEgress := map[int64]int{}
	for _, flow := range c.flows {
		byEgress[flow.Egress]++
	}
	snapshot := consumerStatusSnapshot{
		Rules:         append([]egressRule(nil), c.rules...),
		MeshCIDR:      c.meshCIDR,
		Online:        online,
		Flows:         len(c.flows),
		FlowsByEgress: byEgress,
		Blocked:       blocked,
		FakeIPCIDR:    c.fakeIPCIDR,
		Capable:       capable,
		Upstreams:     append([]string{}, c.dnsUpstreams...),
		DNSQueries:    c.dnsQueries,
	}
	if c.fakeIP != nil {
		// Counted at the moment of asking: a quarantine that ended an hour ago is not one.
		snapshot.Mappings, snapshot.Quarantined = c.fakeIP.counts(c.clock())
		snapshot.Listen = formatEgressAddress(c.fakeIP.listen)
	}
	return snapshot
}

// runtimeStatusSnapshot is the egress role's own view, taken under its lock.
type runtimeStatusSnapshot struct {
	Enabled  bool
	Revision int64
	Flows    int
	Stats    egressStats
	Refused  map[string]int64
}

func (r *egressRuntime) statusSnapshot() runtimeStatusSnapshot {
	r.mu.Lock()
	defer r.mu.Unlock()
	return runtimeStatusSnapshot{
		Enabled:  r.enabled && !r.closed,
		Revision: r.revision,
		Flows:    r.flows.size(),
		Stats:    r.stats,
		Refused:  r.rejections.cumulativeCounts(),
	}
}

// egressStatusJSON is the "egress" section of the diagnostic snapshot.
//
// Built as map[string]any rather than as a struct with tags, matching the rest of that snapshot:
// its shape is a wire contract the Java and .NET clients write too, and the CLI reads whichever
// wrote it.
func (mesh *peerMeshClient) egressStatusJSON() map[string]any {
	mesh.mu.Lock()
	consumer, runtime, installer := mesh.egressConsumer, mesh.egress, mesh.egressRoutes
	outcome := mesh.egressApplied
	mesh.mu.Unlock()

	// The path each egress peer's traffic takes now, read the way sendEncryptedPayload chooses it:
	// a nominated relay first, then the direct endpoint, and "none" when there is neither.
	paths := map[int64]string{}
	mesh.mu.Lock()
	for id, session := range mesh.sessions {
		switch {
		case session == nil || time.Now().After(session.ExpiresAt):
		case session.RelayTargetAllocationID != "":
			paths[id] = egressPathRelay
		case session.RemoteEndpoint != nil:
			paths[id] = egressPathDirect
		}
	}
	mesh.mu.Unlock()

	status := map[string]any{}
	section := consumerStatusJSON(consumer, installer, outcome, paths)
	section["enabled"] = mesh.config.PeerEgressEnabled
	if !mesh.config.PeerEgressEnabled && len(mesh.config.PeerEgressRules) > 0 {
		// The switch off builds no consumer, so the rules come from the configuration. They are
		// listed all the same: "kept but not taking anything over" is a state to show, not to hide.
		section["rules"] = switchedOffRulesJSON(mesh.config.PeerEgressRules)
	}
	if mesh.config.PeerEgressDNSTakeover {
		section["dns"] = mesh.egressDNSStatusJSON(consumer)
	}
	status["consumer"] = section
	status["egress"] = egressRoleStatusJSON(runtime)
	return status
}

// egressDNSStatusJSON is consumer.dns: whether phase two is running, what its pool holds, and what
// the responder is doing. Only written when peerEgressDnsTakeover is on, so a node that never asked
// for phase two reads exactly as before. listen is there only while the responder answers on it;
// journal belongs to the system DNS takeover, a later step, and a field not delivered yet is left
// out rather than faked.
func (mesh *peerMeshClient) egressDNSStatusJSON(consumer *egressConsumer) map[string]any {
	phase := mesh.currentEgressPhaseTwo()
	mesh.mu.Lock()
	upstreams := append([]string{}, mesh.egressDNSUpstreams...)
	takeover := mesh.egressDNSTakeoverStatusLocked()
	mesh.mu.Unlock()
	var queries egressDNSQueries
	// active is phase two running -- pool, route, responder -- and takeover the system's DNS
	// pointing at it, with the journal committed. A pool that is not usable stops both and is the
	// code given; otherwise a refused or failed takeover says why.
	dns := map[string]any{
		"active":      phase.Active,
		"takeover":    phase.Active && takeover.Takeover,
		"pool":        phase.CIDR,
		"mappings":    0,
		"quarantined": 0,
		"journal":     takeover.Journal,
	}
	switch {
	case phase.Code != "":
		dns["code"] = phase.Code
	case phase.Active && takeover.Code == egressCodeDNSTakeoverRefused:
		dns["code"], dns["reason"] = takeover.Code, takeover.Reason
	case takeover.Code == egressCodeDNSTakeoverFailed:
		dns["code"], dns["error"] = takeover.Code, takeover.Error
	}
	if consumer != nil {
		snapshot := consumer.statusSnapshot()
		upstreams, queries = snapshot.Upstreams, snapshot.DNSQueries
		if phase.Active {
			dns["mappings"], dns["quarantined"] = snapshot.Mappings, snapshot.Quarantined
			if snapshot.Listen != "" {
				dns["listen"] = snapshot.Listen
			}
		}
	}
	dns["upstreams"] = upstreams
	// Totals since start, split the way they are read: built here, relayed from an upstream,
	// and failed.
	dns["queries"] = map[string]int64{
		"answered": queries.Answered, "forwarded": queries.Forwarded, "failed": queries.Failed,
	}
	return dns
}

// switchedOffRulesJSON lists configured rules while the master switch is off. None is in force; a
// rule the user switched off says so itself, the rest name the master switch.
func switchedOffRulesJSON(configured []egressRule) []map[string]any {
	rules := make([]map[string]any, 0, len(configured))
	for index, rule := range configured {
		code := egressCodeConsumerDisabled
		if rule.switchedOff() {
			code = egressCodeRuleDisabled
		}
		entry := map[string]any{
			"index":   index,
			"match":   strings.TrimSpace(rule.Match),
			"kind":    egressRuleKind(rule.Match),
			"action":  strings.TrimSpace(rule.Action),
			"inForce": false,
			"code":    code,
		}
		if rule.EgressClientID != 0 {
			entry["egressClientId"] = rule.EgressClientID
		}
		if rule.Port != 0 {
			entry["port"] = rule.Port
		}
		rules = append(rules, entry)
	}
	return rules
}

// The values of a peer entry's path: what carries frames to that egress now.
const (
	egressPathDirect = "direct"
	egressPathRelay  = "relay"
	egressPathNone   = "none"
)

func consumerStatusJSON(consumer *egressConsumer, installer *egressRouteInstaller,
	outcome egressApplyOutcome, paths map[int64]string) map[string]any {
	section := map[string]any{
		"active": consumer != nil,
		"rules":  []map[string]any{},
		"routes": []map[string]any{},
		"peers":  []map[string]any{},
		"flows":  0,
		// Counted by reason rather than totalled: "no egress online" and "denied by the egress"
		// are the same number and completely different problems.
		"blocked": map[string]int64{},
	}
	if consumer == nil {
		return section
	}

	snapshot := consumer.statusSnapshot()
	rules := make([]map[string]any, 0, len(snapshot.Rules))
	peers := map[int64]bool{}
	for index, rule := range snapshot.Rules {
		// With phase two's pool and the catalogue's capabilities, so a domain rule reads as in
		// force exactly when steering would act on it.
		code := egressRuleStatusCode(rule, snapshot.MeshCIDR, snapshot.FakeIPCIDR, snapshot.Online, snapshot.Capable)
		// inForce is the field worth having. A rule that is configured but refused reads
		// false and carries its code, which is the difference between "this rule is
		// protecting me" and "this rule is text in a file".
		entry := map[string]any{
			"index":   index,
			"match":   strings.TrimSpace(rule.Match),
			"kind":    egressRuleKind(rule.Match),
			"action":  strings.TrimSpace(rule.Action),
			"inForce": code == "",
		}
		if code != "" {
			entry["code"] = code
		}
		if rule.EgressClientID != 0 {
			entry["egressClientId"] = rule.EgressClientID
			if code == "" {
				// Only rules that steer contribute a peer. A refused rule naming a peer
				// would otherwise report an egress this node will never send to; so would
				// a domain rule to an egress that cannot resolve names.
				peers[rule.EgressClientID] = snapshot.Online[rule.EgressClientID]
			}
		}
		if rule.Port != 0 {
			entry["port"] = rule.Port
		}
		rules = append(rules, entry)
	}
	section["rules"] = rules
	section["peers"] = egressPeersJSON(peers, snapshot.FlowsByEgress, paths)
	section["flows"] = snapshot.Flows
	section["blocked"] = snapshot.Blocked
	section["routes"] = routesStatusJSON(installer, outcome)
	if outcome.Applied {
		section["appliedAtUnixMs"] = outcome.At.UnixMilli()
		section["rolledBack"] = outcome.RolledBack
		if outcome.Err != "" {
			section["routeError"] = outcome.Err
		}
	}
	return section
}

// routesStatusJSON lists the routes this feature owns and the ones it wanted and did not get.
//
// The installed set comes from the journal rather than from the last apply, because the journal is
// what a restart adopts: after a crash the routes are still in the table and the apply that put
// them there belongs to a process that is gone.
func routesStatusJSON(installer *egressRouteInstaller, outcome egressApplyOutcome) []map[string]any {
	routes := make([]map[string]any, 0)
	if installer != nil {
		for _, route := range installer.installedRoutes() {
			routes = append(routes, map[string]any{
				"cidr":      route.CIDR,
				"kind":      route.Kind.String(),
				"origin":    route.Origin,
				"installed": true,
			})
		}
	}
	// A route refused because the prefix already had an owner is still listed, with installed
	// false and what owns it. Dropping it would make the status look clean while the traffic it
	// was meant to capture leaves by the physical interface.
	for _, conflict := range outcome.Conflicts {
		routes = append(routes, map[string]any{
			"cidr":      conflict.Route.CIDR,
			"kind":      conflict.Route.Kind.String(),
			"origin":    conflict.Route.Origin,
			"installed": false,
			"conflict":  conflict.Existing,
		})
	}
	sort.Slice(routes, func(i, j int) bool {
		left, right := routes[i]["cidr"].(string), routes[j]["cidr"].(string)
		if left != right {
			return left < right
		}
		return routes[i]["origin"].(string) < routes[j]["origin"].(string)
	})
	return routes
}

func egressPeersJSON(peers map[int64]bool, flows map[int64]int, paths map[int64]string) []map[string]any {
	ids := make([]int64, 0, len(peers))
	for id := range peers {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	entries := make([]map[string]any, 0, len(ids))
	for _, id := range ids {
		path := paths[id]
		if path == "" {
			path = egressPathNone
		}
		entries = append(entries, map[string]any{"clientId": id, "online": peers[id], "path": path, "flows": flows[id]})
	}
	return entries
}

func egressRoleStatusJSON(runtime *egressRuntime) map[string]any {
	section := map[string]any{
		"active":  false,
		"flows":   0,
		"refused": map[string]int64{},
	}
	if runtime == nil {
		return section
	}
	snapshot := runtime.statusSnapshot()
	section["active"] = snapshot.Enabled
	section["flows"] = snapshot.Flows
	section["refused"] = snapshot.Refused
	section["totalFlows"] = snapshot.Stats.TotalFlows
	section["bytesIn"] = snapshot.Stats.BytesIn
	section["bytesOut"] = snapshot.Stats.BytesOut
	if snapshot.Revision != 0 {
		section["revision"] = snapshot.Revision
	}
	return section
}
