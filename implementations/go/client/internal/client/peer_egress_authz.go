package client

import (
	"strconv"
	"strings"
)

// Egress-side authorization, as defined by protocol/spec/peer-egress.md.
//
// The server takes the same intersection before pushing a policy, but the egress node runs the whole
// decision again before any connect(). The two are not redundant: the pushed policy can be stale by
// the time a flow opens, and the forced-deny list has to hold even if a policy arrives that
// contradicts it. Directory invisibility and data-plane unreachability must both hold.

const egressMaxPrefix = 32

// egressCIDR is an IPv4 prefix.
//
// Parsing is strict on purpose: a prefix whose host bits are set is rejected rather than masked, and
// a leading-zero octet is rejected rather than tolerated. Runtimes disagree about 010 -- decimal ten
// or octal eight -- and an access rule that means different things in different implementations is
// worse than one the operator has to rewrite.
type egressCIDR struct {
	network   uint32
	prefixLen int
}

func parseEgressAddress(text string) (uint32, bool) {
	var value uint32
	octets, start := 0, 0
	for i := 0; i <= len(text); i++ {
		if i != len(text) && text[i] != '.' {
			continue
		}
		digits := i - start
		if digits < 1 || digits > 3 || octets > 3 {
			return 0, false
		}
		if digits > 1 && text[start] == '0' {
			return 0, false
		}
		part := 0
		for j := start; j < i; j++ {
			c := text[j]
			if c < '0' || c > '9' {
				return 0, false
			}
			part = part*10 + int(c-'0')
		}
		if part > 255 {
			return 0, false
		}
		value = value<<8 | uint32(part)
		octets++
		start = i + 1
	}
	if octets != 4 {
		return 0, false
	}
	return value, true
}

// formatEgressAddress is the inverse of parseEgressAddress. Rendering an address back to text is
// what lets a live flow be handed to the judgment layer again after a policy change, since that
// layer speaks the same dotted form the policy is written in.
func formatEgressAddress(value uint32) string {
	var out []byte
	for shift := 24; shift >= 0; shift -= 8 {
		if shift != 24 {
			out = append(out, '.')
		}
		out = strconv.AppendUint(out, uint64(value>>uint(shift)&0xff), 10)
	}
	return string(out)
}

func parseEgressCIDR(text string) (egressCIDR, bool) {
	trimmed := strings.TrimSpace(text)
	if trimmed == "" {
		return egressCIDR{}, false
	}
	addressPart, prefixPart, hasPrefix := strings.Cut(trimmed, "/")
	address, ok := parseEgressAddress(addressPart)
	if !ok {
		return egressCIDR{}, false
	}
	if !hasPrefix {
		return egressCIDR{network: address, prefixLen: egressMaxPrefix}, true
	}
	if prefixPart == "" || len(prefixPart) > 2 {
		return egressCIDR{}, false
	}
	if len(prefixPart) > 1 && prefixPart[0] == '0' {
		return egressCIDR{}, false
	}
	prefix := 0
	for i := 0; i < len(prefixPart); i++ {
		c := prefixPart[i]
		if c < '0' || c > '9' {
			return egressCIDR{}, false
		}
		prefix = prefix*10 + int(c-'0')
	}
	if prefix > egressMaxPrefix {
		return egressCIDR{}, false
	}
	if address&^egressMaskFor(prefix) != 0 {
		return egressCIDR{}, false
	}
	return egressCIDR{network: address, prefixLen: prefix}, true
}

func egressMaskFor(prefixLen int) uint32 {
	if prefixLen <= 0 {
		return 0
	}
	if prefixLen >= egressMaxPrefix {
		return ^uint32(0)
	}
	return ^uint32(0) << uint(egressMaxPrefix-prefixLen)
}

func (c egressCIDR) contains(address uint32) bool {
	mask := egressMaskFor(c.prefixLen)
	return address&mask == c.network&mask
}

func egressContainedIn(address uint32, cidrs []string) bool {
	for _, text := range cidrs {
		if cidr, ok := parseEgressCIDR(text); ok && cidr.contains(address) {
			return true
		}
	}
	return false
}

// egressDestinationRule is one entry of the allowlist pushed in egress-config.
type egressDestinationRule struct {
	CIDR       string   `json:"cidr"`
	Protocols  []string `json:"protocols"`
	PortRanges [][]int  `json:"portRanges"`
}

// egressLimits keep this node from acting as an open proxy.
type egressLimits struct {
	MaxConcurrentFlows  int `json:"maxConcurrentFlows"`
	MaxFlowsPerConsumer int `json:"maxFlowsPerConsumer"`
	IdleTimeoutSeconds  int `json:"idleTimeoutSeconds"`
}

// egressPolicy is the configuration this node received in egress-config.
type egressPolicy struct {
	Enabled                  bool                    `json:"enabled"`
	Scope                    string                  `json:"scope"`
	AllowedConsumerClientIDs []int64                 `json:"allowedConsumerClientIds"`
	DestinationRules         []egressDestinationRule `json:"destinationRules"`
	Limits                   egressLimits            `json:"limits"`
}

// egressRequest is one flow-open attempt, evaluated before any socket is created.
type egressRequest struct {
	ConsumerClientID       int64
	DestinationIP          string
	DestinationPort        int
	Protocol               string
	Hop                    bool
	ActiveFlowsForConsumer int
	ActiveFlowsTotal       int
	// LocalInterfaceCIDRs are networks owned by this node's own tunnel or virtual interfaces.
	// Forwarding into one of them would loop back into this node's own capture path.
	LocalInterfaceCIDRs []string
}

type egressDecision struct {
	Allowed bool
	Code    string
}

// egressContext carries deployment-wide additions to the forced-deny list.
type egressContext struct {
	MeshCIDR string
	// DeploymentDenyCIDRs are the control, STUN and TURN endpoint addresses for this deployment.
	DeploymentDenyCIDRs []string
}

func newEgressContext() egressContext {
	return egressContext{MeshCIDR: egressDefaultMeshCIDR}
}

func egressDeny(code string) egressDecision { return egressDecision{Code: code} }

// authorizeEgressFlow evaluates one flow-open attempt.
//
// The checks run in the fixed order given by protocol/spec/peer-egress.md so implementations agree
// on which code a request fails with, not merely on allow versus deny.
func authorizeEgressFlow(request egressRequest, policy egressPolicy, peerACLAllows bool, context egressContext) egressDecision {
	if request.Hop {
		return egressDeny(egressCodeHopNotAllowed)
	}
	if !policy.Enabled {
		return egressDeny(egressCodeDisabled)
	}
	if !peerACLAllows {
		return egressDeny(egressCodePeerACLDenied)
	}
	allowedConsumer := false
	for _, id := range policy.AllowedConsumerClientIDs {
		if id == request.ConsumerClientID {
			allowedConsumer = true
			break
		}
	}
	if !allowedConsumer {
		return egressDeny(egressCodeConsumerDenied)
	}

	destination, ok := parseEgressAddress(request.DestinationIP)
	if !ok {
		return egressDeny(egressCodeDestinationDenied)
	}
	if egressContainedIn(destination, egressForcedDenyFor(context, request)) {
		return egressDeny(egressCodeForbiddenDestType)
	}

	scope := egressScopePublic
	if egressContainedIn(destination, egressLANCIDRs) {
		scope = egressScopeLAN
	}
	if scope != policy.Scope {
		return egressDeny(egressCodeScopeDenied)
	}

	addressMatched, protocolMatched, portMatched := false, false, false
	for _, rule := range policy.DestinationRules {
		cidr, ok := parseEgressCIDR(rule.CIDR)
		if !ok || !cidr.contains(destination) {
			continue
		}
		addressMatched = true
		if !egressRuleAllowsProtocol(rule, request.Protocol) {
			continue
		}
		protocolMatched = true
		if egressRuleAllowsPort(rule, request.DestinationPort) {
			portMatched = true
			break
		}
	}
	if !addressMatched {
		return egressDeny(egressCodeDestinationDenied)
	}
	if !protocolMatched {
		return egressDeny(egressCodeProtocolDenied)
	}
	if !portMatched {
		return egressDeny(egressCodePortDenied)
	}

	if policy.Limits.MaxFlowsPerConsumer > 0 &&
		request.ActiveFlowsForConsumer >= policy.Limits.MaxFlowsPerConsumer {
		return egressDeny(egressCodeLimitExceeded)
	}
	if policy.Limits.MaxConcurrentFlows > 0 &&
		request.ActiveFlowsTotal >= policy.Limits.MaxConcurrentFlows {
		return egressDeny(egressCodeLimitExceeded)
	}
	return egressDecision{Allowed: true, Code: egressCodeAllowed}
}

func egressForcedDenyFor(context egressContext, request egressRequest) []string {
	denied := make([]string, 0, len(egressForcedDenyCIDRs)+len(egressCloudMetadataCIDRs)+
		len(context.DeploymentDenyCIDRs)+len(request.LocalInterfaceCIDRs)+1)
	denied = append(denied, egressForcedDenyCIDRs...)
	denied = append(denied, egressCloudMetadataCIDRs...)
	mesh := context.MeshCIDR
	if mesh == "" {
		mesh = egressDefaultMeshCIDR
	}
	denied = append(denied, mesh)
	denied = append(denied, context.DeploymentDenyCIDRs...)
	denied = append(denied, request.LocalInterfaceCIDRs...)
	return denied
}

func egressRuleAllowsProtocol(rule egressDestinationRule, protocol string) bool {
	for _, candidate := range rule.Protocols {
		if candidate == protocol {
			return true
		}
	}
	return false
}

// egressProtocolName maps an IPv4 protocol number to the name policies are written in.
//
// Anything else returns the empty string, which no destination rule can match, so an unsupported
// protocol is refused with EGRESS_PROTOCOL_DENIED rather than defaulting to a name some rule might
// allow. ICMP lands here deliberately: forwarding it needs a raw socket, which contradicts the
// zero-privilege premise that lets an ordinary desktop act as an egress at all. Refusing beats
// passing it through silently, for the same reason an unsupported rule is refused rather than
// ignored.
func egressProtocolName(protocol int) string {
	switch protocol {
	case ipv4ProtocolTCP:
		return "tcp"
	case ipv4ProtocolUDP:
		return "udp"
	default:
		return ""
	}
}

func egressRuleAllowsPort(rule egressDestinationRule, port int) bool {
	for _, span := range rule.PortRanges {
		if len(span) == 2 && port >= span[0] && port <= span[1] {
			return true
		}
	}
	return false
}
