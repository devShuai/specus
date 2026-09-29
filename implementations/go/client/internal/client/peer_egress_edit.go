package client

import "strings"

// What the egress commands and the local page need from the rule engine to edit rules and preview a
// destination. Kept narrow on purpose: they read and write the configuration file, and the engine
// stays the one place that decides what a rule means.

// EgressRule is a consumer rule as configured and as the editors write it back.
type EgressRule = egressRule

// DefaultEgressMeshCIDR is the Peer Mesh network offline checks assume; the real one arrives at login.
const DefaultEgressMeshCIDR = egressDefaultMeshCIDR

// EgressRuleCode reports why a rule is not in force as configured, or "" when it would be. The
// master switch is not part of it; see EgressRuleStatusCode.
func EgressRuleCode(rule EgressRule) string {
	return validateEgressRule(rule, egressDefaultMeshCIDR)
}

// EgressRuleStatusCode is the code a rule reports in status: the master switch off names itself
// unless the rule was switched off on its own, which is the more specific statement.
func EgressRuleStatusCode(enabled bool, rule EgressRule) string {
	if !enabled && !rule.switchedOff() {
		return egressCodeConsumerDisabled
	}
	return EgressRuleCode(rule)
}

// EgressRuleSwitchedOff reports whether the user has taken a rule out of force.
func EgressRuleSwitchedOff(rule EgressRule) bool {
	return rule.switchedOff()
}

// EgressPreview is what the configured rules decide for one destination.
type EgressPreview struct {
	Action           string
	MatchedRuleIndex int
	EgressClientID   int64
}

// PreviewEgressDestination runs the rules as configured against one destination, ignoring the
// master switch: the caller says what the switch changes.
func PreviewEgressDestination(rules []EgressRule, destination string) EgressPreview {
	decision := matchEgressRules(rules, destination, egressDefaultMeshCIDR)
	return EgressPreview{
		Action:           decision.Action,
		MatchedRuleIndex: decision.MatchedRuleIndex,
		EgressClientID:   decision.EgressClientID,
	}
}

// EgressCodeExplanation is one line a person can act on for a rule's code, in the words the Java
// and .NET clients use too. Empty for a code it has nothing to add to.
func EgressCodeExplanation(code string) string {
	switch code {
	case egressCodeRuleDomainUnsupported:
		return "domain rules are not supported yet; use an IPv4 address or CIDR range"
	case egressCodeRuleIPv6Unsupported:
		return "IPv6 rules are not supported; use an IPv4 address or CIDR range"
	case egressCodeRuleMalformed:
		return "not an IPv4 address or CIDR range with zero host bits, or an unknown action"
	case egressCodeRuleDefaultRoute:
		return "0.0.0.0/0 would take over the default route, which is not allowed"
	case egressCodeRuleMeshOverlap:
		return "overlaps the Peer Mesh network"
	case egressCodeRulePortUnsupported:
		return "a rule cannot be limited to a port; port limits belong on the egress policy"
	case egressCodeRuleMissingTarget:
		return "an egress rule needs a positive egress device id"
	case egressCodeRuleDisabled:
		return "switched off"
	case egressCodeConsumerDisabled:
		return "takeover is off (peerEgressEnabled is false)"
	}
	return ""
}

// ValidEgressAddress reports whether a destination is one the rule engine can decide: a plain IPv4
// address. A domain name is told apart so the answer can say why.
func ValidEgressAddress(destination string) (ok bool, domain bool) {
	value := strings.TrimSpace(destination)
	if _, parsed := parseEgressRuleMatch(value); parsed && !strings.Contains(value, "/") {
		return true, false
	}
	return false, looksLikeEgressDomainRule(value) && !strings.Contains(value, ":")
}
