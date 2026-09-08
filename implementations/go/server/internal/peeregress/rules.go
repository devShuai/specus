package peeregress

import "strings"

// DefaultMeshCIDR is the Peer Mesh virtual network unless the deployment overrides it.
const DefaultMeshCIDR = "100.96.0.0/11"

// Rule actions.
const (
	ActionEgress = "egress"
	ActionDirect = "direct"
	ActionBlock  = "block"
)

// Rule is one consumer-side split-routing rule.
//
// Rules match on destination address only. The consumer steers traffic by installing routes and a
// route selects on destination address alone, so a port-scoped rule could neither be expressed as a
// route nor cleanly returned to the local stack once the packet had been captured. Port and
// protocol limits live on the egress policy and are enforced when the flow is opened.
type Rule struct {
	Index          int    `json:"index"`
	Match          string `json:"match"`
	Action         string `json:"action"`
	EgressClientID *int64 `json:"egressClientId,omitempty"`
	// Port exists only so a configuration carrying it can be rejected with a specific code rather
	// than having the field silently ignored.
	Port *int `json:"port,omitempty"`
}

// Match is the outcome of evaluating a destination against an ordered rule list.
type Match struct {
	Action           string
	MatchedRuleIndex int // -1 when nothing matched
	EgressClientID   *int64
}

// Matched reports whether any rule applied.
func (m Match) Matched() bool { return m.MatchedRuleIndex >= 0 }

// Unmatched is the default outcome: traffic stays local.
func Unmatched() Match {
	return Match{Action: ActionDirect, MatchedRuleIndex: -1}
}

// ValidateRule returns the failing code, or "" when the rule is acceptable.
//
// The checks run in a fixed order so every implementation reports the same code for a rule that
// violates more than one constraint.
func ValidateRule(rule Rule, meshCIDR string) string {
	match := strings.TrimSpace(rule.Match)
	if match == "" {
		return CodeRuleMalformed
	}
	if strings.ContainsRune(match, ':') {
		return CodeRuleIPv6Unsupported
	}
	if looksLikeDomain(match) {
		return CodeRuleDomainUnsupported
	}
	cidr, ok := ParseCIDR(match)
	if !ok {
		return CodeRuleMalformed
	}
	if cidr.PrefixLen == 0 {
		// This version never takes over the default route: doing so would override the operator's
		// existing configuration and contradict "unmatched traffic stays local".
		return CodeRuleDefaultRoute
	}
	if meshCIDR == "" {
		meshCIDR = DefaultMeshCIDR
	}
	if mesh, ok := ParseCIDR(meshCIDR); ok && cidr.Overlaps(mesh) {
		return CodeRuleMeshOverlap
	}
	if rule.Port != nil {
		return CodeRulePortUnsupported
	}
	action := strings.TrimSpace(rule.Action)
	if action != ActionEgress && action != ActionDirect && action != ActionBlock {
		return CodeRuleMalformed
	}
	if action == ActionEgress && rule.EgressClientID == nil {
		return CodeRuleMissingTarget
	}
	return ""
}

// MatchRules resolves a destination against an ordered rule list.
//
// Longest prefix wins; when two rules share a prefix length the earlier one wins. An unmatched
// destination resolves to direct. That is the routing table's own behaviour rather than a fallback
// branch: a destination with no installed route never reaches the tunnel device in the first place.
func MatchRules(rules []Rule, destination string) Match {
	address, ok := ParseAddress(destination)
	if !ok || len(rules) == 0 {
		return Unmatched()
	}
	best := Unmatched()
	bestPrefix := -1
	for index, rule := range rules {
		cidr, ok := ParseCIDR(rule.Match)
		if !ok || !cidr.Contains(address) {
			continue
		}
		if cidr.PrefixLen > bestPrefix {
			bestPrefix = cidr.PrefixLen
			best = Match{Action: rule.Action, MatchedRuleIndex: index}
			if rule.Action == ActionEgress {
				best.EgressClientID = rule.EgressClientID
			}
		}
	}
	return best
}

func looksLikeDomain(match string) bool {
	for i := 0; i < len(match); i++ {
		c := match[i]
		if (c >= '0' && c <= '9') || c == '.' || c == '/' {
			continue
		}
		return true
	}
	return false
}
