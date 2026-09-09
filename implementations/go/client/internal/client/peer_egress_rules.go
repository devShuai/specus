package client

import "strings"

// The consumer-side rule engine: which destinations leave through an egress, which stay local, and
// which are blocked.
//
// Rules match on destination address and nothing else. That is not a simplification, it is what a
// routing table can express: a route selects on destination, so a port-scoped rule could neither be
// installed as a route nor cleanly handed back to the local stack after capture. Port and protocol
// limits live on the egress policy and are enforced when the flow opens.
//
// Pure, like the egress side: no I/O, no clock, no routing calls. The engine says what should
// happen and the installer performs it, which is what lets the shared vector drive both.

const (
	egressActionEgress = "egress"
	egressActionDirect = "direct"
	egressActionBlock  = "block"
)

const (
	// egressReasonMatched means a rule selected this destination.
	egressReasonMatched = "matched"
	// egressReasonDefault means no rule matched.
	//
	// The engine reports "direct" here because that is what the user sees, but nothing in the
	// data plane acts on it. Unmatched traffic stays local because no route was installed for
	// it, so it never enters the TUN at all. There is deliberately no fallback branch: one would
	// be a second place for the default to be decided, and the two would drift.
	egressReasonDefault = "default"
)

// egressRule is one consumer rule as configured.
//
// Port has no supported meaning and exists so a configuration carrying one is refused with its own
// code rather than silently accepted with the port ignored. Silently ignoring it would send traffic
// the user meant to scope by port through the egress on every port.
type egressRule struct {
	Match          string `json:"match"`
	Action         string `json:"action"`
	EgressClientID int64  `json:"egressClientId,omitempty"`
	Port           int    `json:"port,omitempty"`
}

type egressRuleDecision struct {
	Action string
	// MatchedRuleIndex is the index in the configured order, or -1 when nothing matched.
	MatchedRuleIndex int
	Reason           string
	EgressClientID   int64
}

// validateEgressRule reports the code a rule is refused with, or the empty string if it is usable.
//
// The checks run in the fixed order protocol/spec/peer-egress.md now pins, so implementations agree
// on which code a bad rule fails with and not merely that it fails. A rule can break several at
// once, and no vector case exercises two together, so the spec had to state the order rather than
// leave the vector to imply it.
func validateEgressRule(rule egressRule, meshCIDR string) string {
	match := strings.TrimSpace(rule.Match)
	if match == "" {
		return egressCodeRuleMalformed
	}
	if looksLikeEgressDomainRule(match) {
		return egressCodeRuleDomainUnsupported
	}
	if strings.Contains(match, ":") {
		return egressCodeRuleIPv6Unsupported
	}

	cidr, ok := parseEgressRuleMatch(match)
	if !ok {
		return egressCodeRuleMalformed
	}
	// An undefined action is malformed for the same reason a bad prefix is: the rule cannot be
	// read at all, so it is reported before the refusals that presume it could be.
	switch rule.Action {
	case egressActionEgress, egressActionDirect, egressActionBlock:
	default:
		return egressCodeRuleMalformed
	}
	if cidr.prefixLen == 0 {
		// Taking the default route would override whatever the user configured elsewhere and
		// contradicts "unmatched means local", which is the whole shape of this feature.
		return egressCodeRuleDefaultRoute
	}
	if overlapsEgressMesh(cidr, meshCIDR) {
		// A rule covering the mesh would drag the overlay's own traffic into the egress.
		return egressCodeRuleMeshOverlap
	}
	if rule.Port != 0 {
		return egressCodeRulePortUnsupported
	}

	if rule.Action == egressActionEgress && rule.EgressClientID <= 0 {
		return egressCodeRuleMissingTarget
	}
	return ""
}

// looksLikeEgressDomainRule reports whether a match is a name rather than an address.
//
// Anything that is not an IPv4 or IPv6 literal but does contain a letter or a wildcard is a name.
// Refusing it is the point: resolving a name at configuration time and installing the answer as a
// static route would silently bind the rule to whatever the DNS said that minute, and phase two is
// where domain routing gets a real answer.
func looksLikeEgressDomainRule(match string) bool {
	if strings.HasPrefix(match, "*") {
		return true
	}
	for index := 0; index < len(match); index++ {
		character := match[index]
		if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') {
			// A hex digit here would belong to an IPv6 literal, which has its own code.
			return !strings.Contains(match, ":")
		}
	}
	return false
}

// parseEgressRuleMatch reads a single IPv4 address or a CIDR. A bare address is its own /32.
//
// Host bits must already be clear. No implicit normalisation: runtimes disagree about what to do
// with them, and a rule that means different things in different implementations is worse than one
// that is refused.
func parseEgressRuleMatch(match string) (egressCIDR, bool) {
	if !strings.Contains(match, "/") {
		address, ok := parseEgressAddress(match)
		if !ok {
			return egressCIDR{}, false
		}
		return egressCIDR{network: address, prefixLen: egressMaxPrefix}, true
	}
	return parseEgressCIDR(match)
}

func overlapsEgressMesh(cidr egressCIDR, meshCIDR string) bool {
	mesh, ok := parseEgressCIDR(strings.TrimSpace(meshCIDR))
	if !ok {
		mesh, ok = parseEgressCIDR(egressDefaultMeshCIDR)
		if !ok {
			return false
		}
	}
	// Either direction counts. A rule inside the mesh captures overlay traffic, and a rule
	// containing the mesh captures all of it.
	return mesh.contains(cidr.network) || cidr.contains(mesh.network)
}

// matchEgressRules selects the rule that governs a destination.
//
// Longest prefix wins; among equal prefixes the earlier rule wins. Longest-prefix first rather than
// order first because that is how a routing table behaves, and these rules become routes: an engine
// that disagreed with the table it installs would send traffic somewhere the user could not predict
// from either.
//
// Rules that fail validation are skipped rather than treated as matching nothing in particular. A
// caller is expected to have refused them at configuration time; skipping here means a single bad
// rule cannot change what a good one does.
func matchEgressRules(rules []egressRule, destination string, meshCIDR string) egressRuleDecision {
	address, ok := parseEgressAddress(strings.TrimSpace(destination))
	if !ok {
		return egressRuleDecision{Action: egressActionDirect, MatchedRuleIndex: -1, Reason: egressReasonDefault}
	}

	best := -1
	bestPrefix := -1
	for index, rule := range rules {
		if validateEgressRule(rule, meshCIDR) != "" {
			continue
		}
		cidr, parsed := parseEgressRuleMatch(strings.TrimSpace(rule.Match))
		if !parsed || !cidr.contains(address) {
			continue
		}
		if cidr.prefixLen > bestPrefix {
			best, bestPrefix = index, cidr.prefixLen
		}
	}

	if best < 0 {
		return egressRuleDecision{Action: egressActionDirect, MatchedRuleIndex: -1, Reason: egressReasonDefault}
	}
	return egressRuleDecision{
		Action:           rules[best].Action,
		MatchedRuleIndex: best,
		Reason:           egressReasonMatched,
		EgressClientID:   rules[best].EgressClientID,
	}
}

// egressRuleSetError pairs a refused rule with its code, so a caller can report every problem in a
// configuration at once rather than the first one.
type egressRuleSetError struct {
	Index int
	Match string
	Code  string
}

// validateEgressRuleSet checks a whole configuration.
//
// Every rule is reported, not just the first failure. An operator fixing a rule list one refusal at
// a time learns about the second problem only after redeploying for the first.
func validateEgressRuleSet(rules []egressRule, meshCIDR string) []egressRuleSetError {
	var refused []egressRuleSetError
	for index, rule := range rules {
		if code := validateEgressRule(rule, meshCIDR); code != "" {
			refused = append(refused, egressRuleSetError{Index: index, Match: rule.Match, Code: code})
		}
	}
	return refused
}
