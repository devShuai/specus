package client

import "strings"

// What the egress commands and the local page need from the rule engine to edit rules and preview a
// destination. Kept narrow on purpose: they read and write the configuration file, and the engine
// stays the one place that decides what a rule means.

// EgressRule is a consumer rule as configured and as the editors write it back.
type EgressRule = egressRule

// DefaultEgressMeshCIDR is the Peer Mesh network offline checks assume; the real one arrives at login.
const DefaultEgressMeshCIDR = egressDefaultMeshCIDR

// EgressRuleCode reports why a rule is not in force under a configuration, or "" when it would be.
// The master switch is not part of it; see EgressRuleStatusCode. The configuration decides whether
// a domain rule is judged as a name (peerEgressDnsTakeover on with a usable pool) or refused.
func EgressRuleCode(config Config, rule EgressRule) string {
	return validateEgressRuleIn(rule, egressDefaultMeshCIDR, offlineEgressFakeIPPool(config))
}

// EgressRuleStatusCode is the code a rule reports in status: the master switch off names itself
// unless the rule was switched off on its own, which is the more specific statement.
func EgressRuleStatusCode(config Config, rule EgressRule) string {
	if !config.PeerEgressEnabled && !rule.switchedOff() {
		return egressCodeConsumerDisabled
	}
	return EgressRuleCode(config, rule)
}

// offlineEgressFakeIPPool is the pool phase two would run with under a configuration if the master
// switch were on, judged without a connection: against the default mesh network, and without the
// device's own networks, which are checked when it starts. "" when it would not run.
func offlineEgressFakeIPPool(config Config) string {
	phase := egressPhaseTwo{CIDR: effectiveEgressFakeIPCIDR(config.PeerEgressFakeIPCIDR)}
	phase.Active, phase.Code = evaluateEgressPhaseTwo(true, config.PeerEgressDNSTakeover, phase.CIDR, egressDefaultMeshCIDR)
	return phase.pool()
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

// EgressNamePreview is what the configured domain rules decide for one name, judged without a
// connection.
type EgressNamePreview struct {
	// PhaseTwo reports whether phase two would run with the master switch on, judged the way
	// config validate judges it: peerEgressDnsTakeover on and the pool usable against the default
	// mesh network. The master switch itself is the caller's to state.
	PhaseTwo bool
	// Pool is the fake-IP pool as configured, or the default.
	Pool             string
	Action           string
	MatchedRuleIndex int
	EgressClientID   int64
}

// PreviewEgressName picks the domain rule that claims a name, with the selection the DNS responder
// uses. The rule is picked even while phase two would not run, so the caller can say what turning it
// on would change. Whether the egress can resolve names is only known once connected and is not
// judged here.
func PreviewEgressName(config Config, name string) EgressNamePreview {
	pool := effectiveEgressFakeIPCIDR(config.PeerEgressFakeIPCIDR)
	// Any pool has domain rules judged as names, and which one it is means nothing to them, so the
	// configured pool is given whether it is usable or not: an unusable pool hides no rule.
	index := selectEgressDomainRule(config.PeerEgressRules, name, egressDefaultMeshCIDR, pool)
	preview := EgressNamePreview{PhaseTwo: offlineEgressFakeIPPool(config) != "", Pool: pool, MatchedRuleIndex: index}
	if index >= 0 {
		preview.Action = config.PeerEgressRules[index].Action
		preview.EgressClientID = config.PeerEgressRules[index].EgressClientID
	}
	return preview
}

// EgressPreviewName reads a destination as a name a domain rule could match: normalized the way
// rules compare names (no trailing dots, lower case), and false when it is not written the way a
// domain rule's match must be (ASCII labels of a-z, 0-9 and '-', IDN as punycode). A wildcard
// belongs to a rule, not to a name.
func EgressPreviewName(destination string) (string, bool) {
	value := strings.TrimSpace(destination)
	if strings.Contains(value, "*") || !validEgressDomainMatch(value) {
		return "", false
	}
	return normalizeEgressName(value), true
}

// EgressCodeExplanation is one line a person can act on for a rule's code, in the words the Java
// and .NET clients use too. Empty for a code it has nothing to add to.
func EgressCodeExplanation(code string) string {
	switch code {
	case egressCodeRuleDomainUnsupported:
		return "domain rules are not supported yet; use an IPv4 address or CIDR range"
	case egressCodeRuleIPv6Unsupported:
		return "IPv6 rules are not in force yet: this client cannot carry IPv6 traffic"
	case egressCodeRuleMalformed:
		return "not an IPv4 or IPv6 address or CIDR range with zero host bits (IPv4-mapped IPv6 is written as IPv4), or an unknown action"
	case egressCodeRuleDefaultRoute:
		return "0.0.0.0/0 would take over the default route, which is not allowed"
	case egressCodeRuleMeshOverlap:
		return "overlaps the Peer Mesh network"
	case egressCodeRulePortUnsupported:
		return "a rule cannot be limited to a port; port limits belong on the egress policy"
	case egressCodeRuleMissingTarget:
		return "an egress rule needs a positive egress device id"
	case egressCodeRuleFakeIPOverlap:
		return "overlaps the fake-IP pool (peerEgressFakeIpCidr), whose addresses only domain rules hand out"
	case egressCodeRuleDisabled:
		return "switched off"
	case egressCodeConsumerDisabled:
		return "takeover is off (peerEgressEnabled is false)"
	}
	return ""
}

// ValidEgressAddress reports whether a destination is one the address rules can decide: a plain IPv4
// address. Something that reads as a name is told apart, for EgressPreviewName to judge.
func ValidEgressAddress(destination string) (ok bool, domain bool) {
	value := strings.TrimSpace(destination)
	if _, parsed := parseEgressRuleMatch(value); parsed && !strings.Contains(value, "/") {
		return true, false
	}
	return false, looksLikeEgressDomainRule(value) && !strings.Contains(value, ":")
}
