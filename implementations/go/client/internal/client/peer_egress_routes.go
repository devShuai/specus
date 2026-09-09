package client

import (
	"sort"
	"strconv"
	"strings"
)

// Turning consumer rules into routes.
//
// Only exact prefixes are installed. The default route is never taken, and neither is the
// `0.0.0.0/1` plus `128.0.0.0/1` pair that covers it while pretending not to. A tool that captures
// everything cannot be reasoned about by the person running it, and "unmatched traffic stays local"
// stops being true the moment something covers all of it.
//
// The planner is pure. It says which routes should exist; the installer performs the difference and
// can undo it. Splitting them is what lets rollback, conflict refusal and ownership be tested
// without touching a real routing table.

type egressRouteKind int

const (
	// egressRouteToTun sends a prefix into the TUN for the data plane to handle.
	egressRouteToTun egressRouteKind = iota
	// egressRouteBypass pins one address to the physical path.
	//
	// The control connection, STUN and TURN, peer UDP endpoints and the egress peer's own address
	// have to keep working over the real network. If a rule's prefix happened to contain one of
	// them, its traffic would be routed into the tunnel that carries it, and the tunnel would be
	// carrying its own transport.
	egressRouteBypass
)

func (k egressRouteKind) String() string {
	if k == egressRouteBypass {
		return "bypass"
	}
	return "tun"
}

// egressRoute is one entry this feature wants to own.
type egressRoute struct {
	// CIDR is normalised, so the same route is never described two ways.
	CIDR string
	Kind egressRouteKind
	// Origin says what asked for this route, for the conflict message an operator reads.
	Origin string
}

func (r egressRoute) key() string { return r.CIDR }

// planEgressRoutes works out the routes a rule set and a bypass set need.
//
// Refused rules are returned rather than skipped silently: a rule an operator wrote and this
// feature ignored is a leak they have no way to notice.
func planEgressRoutes(rules []egressRule, bypass []string, meshCIDR string) ([]egressRoute, []egressRuleSetError) {
	refused := validateEgressRuleSet(rules, meshCIDR)
	skip := make(map[int]struct{}, len(refused))
	for _, entry := range refused {
		skip[entry.Index] = struct{}{}
	}

	seen := make(map[string]struct{})
	routes := make([]egressRoute, 0, len(rules)+len(bypass))

	// Bypass first: these are the addresses that must not be captured under any rule, and adding
	// them first means a rule naming the same prefix cannot displace one.
	for _, endpoint := range bypass {
		address, ok := parseEgressAddress(strings.TrimSpace(endpoint))
		if !ok {
			continue
		}
		cidr := formatEgressAddress(address) + "/32"
		if _, duplicate := seen[cidr]; duplicate {
			continue
		}
		seen[cidr] = struct{}{}
		routes = append(routes, egressRoute{CIDR: cidr, Kind: egressRouteBypass, Origin: "bypass"})
	}

	for index, rule := range rules {
		if _, refusedRule := skip[index]; refusedRule {
			continue
		}
		// A direct rule installs nothing. Traffic stays local by not having a route, which is
		// the same mechanism that makes unmatched traffic local, so there is one behaviour
		// rather than two that have to agree.
		//
		// A block rule does install one: the packet has to be captured before it can be
		// dropped, and the data plane is what drops it.
		if rule.Action != egressActionEgress && rule.Action != egressActionBlock {
			continue
		}
		cidr, ok := parseEgressRuleMatch(strings.TrimSpace(rule.Match))
		if !ok {
			continue
		}
		normalised := formatEgressCIDR(cidr)
		if _, duplicate := seen[normalised]; duplicate {
			// Two rules over the same prefix need one route; the engine decides between them
			// per packet, and installing the prefix twice would make removal ambiguous.
			continue
		}
		seen[normalised] = struct{}{}
		routes = append(routes, egressRoute{
			CIDR: normalised, Kind: egressRouteToTun, Origin: "rule:" + rule.Match,
		})
	}

	sortEgressRoutes(routes)
	return routes, refused
}

// formatEgressCIDR renders a prefix the one way this feature writes it, so a route installed in one
// run is recognised as the same route in the next.
func formatEgressCIDR(cidr egressCIDR) string {
	return formatEgressAddress(cidr.network) + "/" + strconv.Itoa(cidr.prefixLen)
}

// sortEgressRoutes orders bypass entries first, then by prefix.
//
// Bypass first because installation happens in this order: the addresses that keep the tunnel's own
// transport working are in place before anything is pointed into the tunnel. Deterministic order
// also means the journal and every log line read the same way run to run.
func sortEgressRoutes(routes []egressRoute) {
	sort.Slice(routes, func(i, j int) bool {
		if routes[i].Kind != routes[j].Kind {
			return routes[i].Kind == egressRouteBypass
		}
		left, leftOK := parseEgressCIDR(routes[i].CIDR)
		right, rightOK := parseEgressCIDR(routes[j].CIDR)
		if !leftOK || !rightOK {
			return routes[i].CIDR < routes[j].CIDR
		}
		if left.network != right.network {
			return left.network < right.network
		}
		return left.prefixLen < right.prefixLen
	})
}

// diffEgressRoutes reports what to add and what to withdraw to get from one set to another.
//
// Withdrawals come back first so a caller applies them first. A prefix that moved from one kind to
// the other has to lose its old entry before the new one goes in, or the platform would either
// refuse the duplicate or silently keep whichever it saw first.
func diffEgressRoutes(current, desired []egressRoute) (remove, add []egressRoute) {
	desiredByKey := make(map[string]egressRoute, len(desired))
	for _, route := range desired {
		desiredByKey[route.key()] = route
	}
	currentByKey := make(map[string]egressRoute, len(current))
	for _, route := range current {
		currentByKey[route.key()] = route
	}

	for _, route := range current {
		want, still := desiredByKey[route.key()]
		if !still || want.Kind != route.Kind {
			remove = append(remove, route)
		}
	}
	for _, route := range desired {
		have, present := currentByKey[route.key()]
		if !present || have.Kind != route.Kind {
			add = append(add, route)
		}
	}
	sortEgressRoutes(remove)
	sortEgressRoutes(add)
	return remove, add
}
