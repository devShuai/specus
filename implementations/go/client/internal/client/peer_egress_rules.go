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
	// Enabled is nil for a rule as written and false for one the user switched off. Only an
	// explicit false takes a rule out of force.
	Enabled *bool `json:"enabled,omitempty"`
}

// switchedOff reports whether the user has taken this rule out of force.
func (rule egressRule) switchedOff() bool {
	return rule.Enabled != nil && !*rule.Enabled
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
// The checks run in the fixed order protocol/spec/peer-egress.md pins, so implementations agree on
// which code a bad rule fails with and not merely that it fails. A rule can break several at once
// and no vector case exercises two together, so the order had to be stated rather than left for the
// vector to imply. The match is the rule's subject: what it is, whether it is legal, whether it is
// refused as a prefix, and only then the action and the fields it needs.
func validateEgressRule(rule egressRule, meshCIDR string) string {
	return validateEgressRuleIn(rule, meshCIDR, "")
}

// validateEgressRuleIn is validateEgressRule with phase two (protocol/spec/peer-egress-dns.md).
// fakeIPPool is the fake-IP pool while phase two runs and "" while it does not.
//
// Running, a domain rule is checked as a name instead of being refused, and an address rule must
// stay out of the pool: addresses there are handed out to names, so an address rule over them would
// compete with the domain rule that handed each one out. Not running, a domain rule is refused
// exactly as in phase one, and the pool means nothing to an address rule.
func validateEgressRuleIn(rule egressRule, meshCIDR, fakeIPPool string) string {
	return validateEgressRuleFor(rule, meshCIDR, fakeIPPool, egressConsumerCarriesIPv6)
}

// egressConsumerCarriesIPv6 says whether this consumer has an IPv6 data plane: IPv6 packets read
// from the TUN, IPv6 routes installed into it, and IPv6 carried to the egress. It does not yet, so a
// well-formed IPv6 rule is refused with EGRESS_RULE_IPV6_UNSUPPORTED: installing nothing for it and
// reporting it in force would send its destinations straight out of the local interface.
//
// The rule is still read and checked in full first, so a mistake in it is reported as one, and how
// IPv6 rules match is pinned by the vector's ipv6 section, which the tests run with this set.
const egressConsumerCarriesIPv6 = false

// validateEgressRuleFor is validateEgressRuleIn with the consumer's IPv6 data plane stated.
func validateEgressRuleFor(rule egressRule, meshCIDR, fakeIPPool string, carriesIPv6 bool) string {
	// First, ahead of anything about the rule's content: switching a rule off is the user's choice,
	// and a rule should not have to be fixed before it is allowed to sit in the list switched off.
	if rule.switchedOff() {
		return egressCodeRuleDisabled
	}
	match := strings.TrimSpace(rule.Match)
	if match == "" {
		return egressCodeRuleMalformed
	}
	// A colon is unambiguous, so IPv6 is settled before anything else is guessed at: the match is
	// an IPv6 address or prefix, or it is malformed. The mesh and the fake-IP pool are IPv4, so an
	// IPv6 rule has neither to stay clear of.
	if strings.Contains(match, ":") {
		cidr, _, ok := parseEgressCIDR6(match)
		if !ok || cidr.mapped() {
			// An IPv4-mapped prefix reads, but no packet is ever addressed to one: the rule would
			// sit there matching nothing while its writer believed the IPv4 addresses covered.
			return egressCodeRuleMalformed
		}
		if cidr.prefixLen == 0 {
			return egressCodeRuleDefaultRoute
		}
		if code := validateEgressRuleTarget(rule); code != "" {
			return code
		}
		// Last: everything about the rule is right, and what is missing is this device's ability
		// to carry IPv6 at all.
		if !carriesIPv6 {
			return egressCodeRuleIPv6Unsupported
		}
		return ""
	}
	if looksLikeEgressDomainRule(match) {
		if fakeIPPool == "" {
			return egressCodeRuleDomainUnsupported
		}
		if !validEgressDomainMatch(match) {
			return egressCodeRuleMalformed
		}
	} else {
		cidr, ok := parseEgressRuleMatch(match)
		if !ok {
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
		if pool, running := parseEgressCIDR(fakeIPPool); running && egressCIDRsOverlap(cidr, pool) {
			return egressCodeRuleFakeIPOverlap
		}
	}
	return validateEgressRuleTarget(rule)
}

// validateEgressRuleTarget is the part of the order after the match: the port the rule must not
// carry, the action, and the egress an egress rule needs.
func validateEgressRuleTarget(rule egressRule) string {
	if rule.Port != 0 {
		return egressCodeRulePortUnsupported
	}

	switch rule.Action {
	case egressActionEgress, egressActionDirect, egressActionBlock:
	default:
		return egressCodeRuleMalformed
	}
	if rule.Action == egressActionEgress && rule.EgressClientID <= 0 {
		return egressCodeRuleMissingTarget
	}
	return ""
}

// looksLikeEgressDomainRule reports whether a match is a name rather than an address.
//
// Anything that is not an IPv4 or IPv6 literal but does contain a letter or a wildcard is a name.
// Resolving a name at configuration time and installing the answer as a static route would silently
// bind the rule to whatever the DNS said that minute, so a name is either refused (phase one) or
// steered through the fake-IP pool (phase two), never turned into an address here.
//
// Any non-ASCII byte counts as well, so a Unicode name is refused as a malformed name rather than
// read as a broken address: IDN has to be written as punycode.
func looksLikeEgressDomainRule(match string) bool {
	if strings.HasPrefix(match, "*") {
		return true
	}
	for index := 0; index < len(match); index++ {
		character := match[index]
		if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') || character >= 0x80 {
			return true
		}
	}
	return false
}

// validEgressDomainMatch reports whether a domain rule's match is `name` or `*.name`, with the name
// written the way validEgressName accepts it. The wildcard stands for one or more whole labels and
// only on the left, so `*.example.com` covers `a.example.com` and `a.b.example.com`, not the apex.
func validEgressDomainMatch(match string) bool {
	for index := 0; index < len(match); index++ {
		// Checked on the bytes before any case folding: a few Unicode letters fold to ASCII ones.
		if match[index] >= 0x80 {
			return false
		}
	}
	text := strings.ToLower(strings.TrimRight(match, "."))
	text = strings.TrimPrefix(text, "*.")
	// validEgressName trims before it looks, which is right for a name and wrong here: the match has
	// been trimmed already, so space left at either end of the name sits inside it, as in
	// `*. example.com` or `example.com .`, and makes it malformed.
	if strings.Contains(text, "*") || text != normalizeEgressName(text) {
		return false
	}
	return validEgressName(text)
}

// egressDomainRank says whether a domain rule's match covers a normalized name, and how closely:
// an exact match beats any suffix, and a suffix with more labels beats one with fewer.
func egressDomainRank(match, name string) (suffix bool, labels int, covers bool) {
	base := normalizeEgressName(match)
	if strings.HasPrefix(base, "*.") {
		base = base[2:]
		if strings.HasSuffix(name, "."+base) {
			return true, strings.Count(base, ".") + 1, true
		}
		return false, 0, false
	}
	return false, 0, name == base
}

// selectEgressDomainRule picks the domain rule that claims a name, or -1 when none does.
//
// Exact before suffix, then the suffix with more labels, then the earlier rule. Rules out of force
// take no part, as for addresses. A rule pointed at an egress that cannot resolve names still
// claims its names: that is the egress's state at this moment, not a mistake in the rule, and
// letting the name fall through to local resolution would send it somewhere no rule said.
func selectEgressDomainRule(rules []egressRule, name, meshCIDR, fakeIPPool string) int {
	name = normalizeEgressName(name)
	best, bestSuffix, bestLabels := -1, false, 0
	for index, rule := range rules {
		match := strings.TrimSpace(rule.Match)
		if egressRuleKind(match) != "domain" || validateEgressRuleIn(rule, meshCIDR, fakeIPPool) != "" {
			continue
		}
		suffix, labels, covers := egressDomainRank(match, name)
		if !covers {
			continue
		}
		better := best < 0 ||
			(!suffix && bestSuffix) ||
			(suffix && bestSuffix && labels > bestLabels)
		if better {
			best, bestSuffix, bestLabels = index, suffix, labels
		}
	}
	return best
}

// egressRuleStatusCode is the code the status gives a rule, or "" when it is in force: the
// validation, then the capability of the egress a domain rule sends to.
//
// The capability only counts for an egress that is online. The catalogue says false for one that
// is not, and a rule to an offline egress is right and waiting, as any rule to an offline egress is;
// reporting it as pointed at a device that can never take it would send the operator after the rule
// rather than the device.
func egressRuleStatusCode(rule egressRule, meshCIDR, fakeIPPool string, online, capable map[int64]bool) string {
	if code := validateEgressRuleIn(rule, meshCIDR, fakeIPPool); code != "" {
		return code
	}
	if rule.Action == egressActionEgress && egressRuleKind(rule.Match) == "domain" &&
		online[rule.EgressClientID] && !capable[rule.EgressClientID] {
		return egressCodeRuleEgressNoDomain
	}
	return ""
}

// egressRuleKind names what a rule matches on, for the status: an address or prefix, or a name.
func egressRuleKind(match string) string {
	match = strings.TrimSpace(match)
	if !strings.Contains(match, ":") && looksLikeEgressDomainRule(match) {
		return "domain"
	}
	return "cidr"
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
	return egressCIDRsOverlap(cidr, mesh)
}

// egressCIDRsOverlap reports whether two prefixes share an address. For prefixes that is the same
// as one containing the other's network address.
func egressCIDRsOverlap(left, right egressCIDR) bool {
	return left.contains(right.network) || right.contains(left.network)
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
	return matchEgressRulesIn(rules, destination, meshCIDR, "")
}

// matchEgressRulesIn is matchEgressRules with phase two's pool, which only changes which address
// rules are in force. Domain rules never match an address: a destination in the pool is steered by
// the name it was handed out for, and one outside it by address rules alone.
func matchEgressRulesIn(rules []egressRule, destination, meshCIDR, fakeIPPool string) egressRuleDecision {
	return matchEgressRulesFor(rules, destination, meshCIDR, fakeIPPool, egressConsumerCarriesIPv6)
}

// matchEgressRulesFor is matchEgressRulesIn with the consumer's IPv6 data plane stated.
//
// The families never compete: an IPv4 destination is decided by IPv4 rules alone and an IPv6 one by
// IPv6 rules alone, longest prefix within the family. Both are compared by value, so how a rule or a
// destination is spelled (case, leading zeros, where "::" falls) does not change the result.
func matchEgressRulesFor(rules []egressRule, destination, meshCIDR, fakeIPPool string, carriesIPv6 bool) egressRuleDecision {
	destination = strings.TrimSpace(destination)
	ipv6 := strings.Contains(destination, ":")
	address, ok := parseEgressAddress(destination)
	var address6 [16]byte
	if ipv6 {
		address6, ok = parseEgressAddress6(destination)
	}
	if !ok {
		return egressRuleDecision{Action: egressActionDirect, MatchedRuleIndex: -1, Reason: egressReasonDefault}
	}

	best := -1
	bestPrefix := -1
	for index, rule := range rules {
		if validateEgressRuleFor(rule, meshCIDR, fakeIPPool, carriesIPv6) != "" {
			continue
		}
		match := strings.TrimSpace(rule.Match)
		prefixLen := -1
		if strings.Contains(match, ":") {
			if cidr, _, parsed := parseEgressCIDR6(match); parsed && ipv6 && cidr.contains(address6) {
				prefixLen = cidr.prefixLen
			}
		} else if cidr, parsed := parseEgressRuleMatch(match); parsed && !ipv6 && cidr.contains(address) {
			prefixLen = cidr.prefixLen
		}
		if prefixLen > bestPrefix {
			best, bestPrefix = index, prefixLen
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
	return validateEgressRuleSetIn(rules, meshCIDR, "")
}

func validateEgressRuleSetIn(rules []egressRule, meshCIDR, fakeIPPool string) []egressRuleSetError {
	var refused []egressRuleSetError
	for index, rule := range rules {
		if code := validateEgressRuleIn(rule, meshCIDR, fakeIPPool); code != "" {
			refused = append(refused, egressRuleSetError{Index: index, Match: rule.Match, Code: code})
		}
	}
	return refused
}
