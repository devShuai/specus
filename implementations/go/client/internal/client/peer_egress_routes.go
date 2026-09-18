package client

import (
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Turning consumer rules into routes.
//
// Only exact prefixes are installed, and the planner invents none of its own: no default route,
// and no `0.0.0.0/1` plus `128.0.0.0/1` pair standing in for one. A tool that captures everything
// cannot be reasoned about by the person running it, and "unmatched traffic stays local" stops
// being true the moment something covers all of it.
//
// Validation refuses only `/0`, though. An operator who writes those two halves by hand still gets
// near-total capture, and the lower one is refused today only because it happens to contain the
// mesh. Closing that means picking a minimum prefix length, which is a policy decision rather than
// something to settle while porting.
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

// The kind travels as a name rather than as this package's integer.
//
// The journal is a file an operator may end up reading on a machine whose routing is in a state
// they did not expect, and it has to mean the same thing to the Java and .NET consumers, which do
// not share this enum. A number would make both of those worse for nothing.
func (k egressRouteKind) MarshalJSON() ([]byte, error) {
	return json.Marshal(k.String())
}

// An unrecognised name is an error rather than a default. Guessing would mean withdrawing a prefix
// the previous run may have installed as the other kind, and the whole point of the journal is not
// to act on routes by guess.
func (k *egressRouteKind) UnmarshalJSON(raw []byte) error {
	var name string
	if err := json.Unmarshal(raw, &name); err != nil {
		return err
	}
	switch name {
	case "bypass":
		*k = egressRouteBypass
	case "tun":
		*k = egressRouteToTun
	default:
		return fmt.Errorf("unknown egress route kind %q", name)
	}
	return nil
}

// egressRoute is one entry this feature wants to own.
//
// The field names are the journal's on-disk names, shared with the Java and .NET consumers: a user
// who switches implementations on one machine has to have their routes adopted and withdrawn
// rather than left behind by a reader that did not recognise the file.
type egressRoute struct {
	// CIDR is normalised, so the same route is never described two ways.
	CIDR string          `json:"cidr"`
	Kind egressRouteKind `json:"kind"`
	// Origin says what asked for this route, for the conflict message an operator reads.
	Origin string `json:"origin"`
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

	// The prefixes the rules want captured come first, because they decide which bypass
	// addresses need a route at all.
	//
	// A direct rule installs nothing. Traffic stays local by not having a route, which is the
	// same mechanism that makes unmatched traffic local, so there is one behaviour rather than
	// two that have to agree. A block rule does install one: the packet has to be captured
	// before it can be dropped, and the data plane is what drops it.
	type captured struct {
		cidr  egressCIDR
		match string
	}
	seen := make(map[string]struct{})
	capturing := make([]captured, 0, len(rules))
	for index, rule := range rules {
		if _, refusedRule := skip[index]; refusedRule {
			continue
		}
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
		capturing = append(capturing, captured{cidr: cidr, match: rule.Match})
	}

	routes := make([]egressRoute, 0, len(capturing)+len(bypass))
	seen = make(map[string]struct{})

	// A bypass address gets a /32 only when one of those prefixes covers it. Uncovered, the
	// platform's own routing already carries it, and a route of ours would be one more thing to
	// keep true as peers come and go. Covered, the /32 is what keeps the tunnel's transport out
	// of the tunnel, and it goes in first so a rule naming the same prefix cannot displace it.
	for _, endpoint := range bypass {
		address, ok := parseEgressAddress(strings.TrimSpace(endpoint))
		if !ok {
			continue
		}
		covered := false
		for _, entry := range capturing {
			if entry.cidr.contains(address) {
				covered = true
				break
			}
		}
		if !covered {
			continue
		}
		cidr := formatEgressAddress(address) + "/32"
		if _, duplicate := seen[cidr]; duplicate {
			continue
		}
		seen[cidr] = struct{}{}
		routes = append(routes, egressRoute{CIDR: cidr, Kind: egressRouteBypass, Origin: "bypass"})
	}

	for _, entry := range capturing {
		normalised := formatEgressCIDR(entry.cidr)
		if _, duplicate := seen[normalised]; duplicate {
			continue
		}
		seen[normalised] = struct{}{}
		routes = append(routes, egressRoute{
			CIDR: normalised, Kind: egressRouteToTun, Origin: "rule:" + entry.match,
		})
	}

	sortEgressRoutes(routes)
	return routes, refused
}

// egressRouteRetryInterval is how long an apply that left something undone -- a conflict or a
// failure -- waits before the same plan is tried again. Long enough that an operator's route sitting
// on one of our prefixes is not queried every tick, short enough that its removal is noticed.
//
// Shared vector: protocol/test-vectors/peer-egress-routes-v1.json, reconcile.retryAfterMs.
const egressRouteRetryInterval = 60 * time.Second

// egressRoutePlanAttempt is what the last apply was asked to install, and how it went.
type egressRoutePlanAttempt struct {
	At      time.Time
	Desired []egressRoute
	// Troubled says the apply left something undone: a prefix refused because somebody else
	// owned it, or an install that failed and was rolled back.
	Troubled bool
}

// egressRouteReconcileDue says whether a plan computed on the periodic tick should be applied.
//
// The plan is recomputed every few seconds because its inputs move: peers come and go, the relay
// changes, a hostname resolves differently. Applying every time would rewrite the journal on every
// tick for nothing. So a plan is applied when it differs from the one last applied, and otherwise
// only to retry an apply that left something undone, and then no more often than the interval.
//
// Compared as sets: the planner sorts, but nothing here should depend on that.
func egressRouteReconcileDue(last *egressRoutePlanAttempt, desired []egressRoute, now time.Time) bool {
	if last == nil {
		return true
	}
	if !sameEgressRouteSet(last.Desired, desired) {
		return true
	}
	return last.Troubled && now.Sub(last.At) >= egressRouteRetryInterval
}

func sameEgressRouteSet(left, right []egressRoute) bool {
	if len(left) != len(right) {
		return false
	}
	counts := make(map[egressRoute]int, len(left))
	for _, route := range left {
		counts[route]++
	}
	for _, route := range right {
		counts[route]--
		if counts[route] < 0 {
			return false
		}
	}
	return true
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
