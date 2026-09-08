package peeregress

// Policy scopes. Public and LAN access are authorised separately; neither implies the other.
const (
	ScopePublic = "PUBLIC"
	ScopeLAN    = "LAN"
)

// ForcedDenyCIDRs stay denied no matter what the policy says. A rule as broad as 0.0.0.0/0 must not
// reach loopback, link-local, cloud metadata, multicast, broadcast or the mesh itself, so this list
// is consulted before any destination rule.
var ForcedDenyCIDRs = []string{
	"0.0.0.0/8",
	"127.0.0.0/8",
	"169.254.0.0/16",
	"224.0.0.0/4",
	"240.0.0.0/4",
	// Covered by 240.0.0.0/4, listed so the broadcast address is explicit to a reader.
	"255.255.255.255/32",
}

// CloudMetadataCIDRs are well-known instance metadata endpoints, denied independently of the
// link-local block so that the intent survives a future change to that block.
var CloudMetadataCIDRs = []string{
	"169.254.169.254/32",
	"100.100.100.200/32",
}

// LANCIDRs is RFC 1918 private use plus RFC 6598 shared address space.
var LANCIDRs = []string{
	"10.0.0.0/8",
	"172.16.0.0/12",
	"192.168.0.0/16",
	"100.64.0.0/10",
}

// DestinationRule is one entry of an egress policy allowlist.
type DestinationRule struct {
	CIDR       string   `json:"cidr"`
	Protocols  []string `json:"protocols"`
	PortRanges [][]int  `json:"portRanges"`
}

// Limits keep an egress node from acting as an open proxy.
type Limits struct {
	MaxConcurrentFlows  int `json:"maxConcurrentFlows"`
	MaxFlowsPerConsumer int `json:"maxFlowsPerConsumer"`
	IdleTimeoutSeconds  int `json:"idleTimeoutSeconds"`
}

// Policy is the egress-side authorization policy owned by the server.
type Policy struct {
	EgressClientID           int64             `json:"egressClientId"`
	Enabled                  bool              `json:"enabled"`
	AllowedConsumerClientIDs []int64           `json:"allowedConsumerClientIds"`
	Scope                    string            `json:"scope"`
	DestinationRules         []DestinationRule `json:"destinationRules"`
	Limits                   Limits            `json:"limits"`
}

// Request is one flow-open attempt, evaluated before any socket is created.
type Request struct {
	ConsumerClientID       int64  `json:"consumerClientId"`
	DestinationIP          string `json:"destinationIp"`
	DestinationPort        int    `json:"destinationPort"`
	Protocol               string `json:"protocol"`
	Hop                    bool   `json:"hop"`
	ActiveFlowsForConsumer int    `json:"activeFlowsForConsumer"`
	ActiveFlowsTotal       int    `json:"activeFlowsTotal"`
	// LocalInterfaceCIDRs are networks owned by this node's own tunnel or virtual interfaces.
	// Forwarding into one of them would loop back into this node's own capture path.
	LocalInterfaceCIDRs []string `json:"localInterfaceCidrs"`
}

// Decision is the outcome of an authorization evaluation.
type Decision struct {
	Allowed bool
	Code    string
}

// Context carries deployment-wide additions to the forced-deny list.
type Context struct {
	MeshCIDR string
	// DeploymentDenyCIDRs are the control, STUN and TURN endpoint addresses for this deployment.
	DeploymentDenyCIDRs []string
}

// DefaultContext returns the context for a deployment on the default mesh network.
func DefaultContext() Context {
	return Context{MeshCIDR: DefaultMeshCIDR}
}

func deny(code string) Decision { return Decision{Code: code} }

// Authorize evaluates one flow-open attempt.
//
// The checks run in the fixed order given by protocol/spec/peer-egress.md so implementations agree
// on which code a request fails with, not merely on allow versus deny.
func Authorize(request Request, policy Policy, peerACLAllows bool, context Context) Decision {
	if request.Hop {
		return deny(CodeHopNotAllowed)
	}
	if !policy.Enabled {
		return deny(CodeDisabled)
	}
	if !peerACLAllows {
		return deny(CodePeerACLDenied)
	}
	if !containsID(policy.AllowedConsumerClientIDs, request.ConsumerClientID) {
		return deny(CodeConsumerDenied)
	}

	destination, ok := ParseAddress(request.DestinationIP)
	if !ok {
		return deny(CodeDestinationDenied)
	}
	if containedIn(destination, forcedDenyFor(context, request)) {
		return deny(CodeForbiddenDestType)
	}

	scope := ScopePublic
	if containedIn(destination, LANCIDRs) {
		scope = ScopeLAN
	}
	if scope != policy.Scope {
		return deny(CodeScopeDenied)
	}

	addressMatches := make([]DestinationRule, 0, len(policy.DestinationRules))
	for _, rule := range policy.DestinationRules {
		if cidr, ok := ParseCIDR(rule.CIDR); ok && cidr.Contains(destination) {
			addressMatches = append(addressMatches, rule)
		}
	}
	if len(addressMatches) == 0 {
		return deny(CodeDestinationDenied)
	}

	protocolMatches := make([]DestinationRule, 0, len(addressMatches))
	for _, rule := range addressMatches {
		for _, protocol := range rule.Protocols {
			if protocol == request.Protocol {
				protocolMatches = append(protocolMatches, rule)
				break
			}
		}
	}
	if len(protocolMatches) == 0 {
		return deny(CodeProtocolDenied)
	}

	if !portAllowed(protocolMatches, request.DestinationPort) {
		return deny(CodePortDenied)
	}

	if policy.Limits.MaxFlowsPerConsumer > 0 &&
		request.ActiveFlowsForConsumer >= policy.Limits.MaxFlowsPerConsumer {
		return deny(CodeLimitExceeded)
	}
	if policy.Limits.MaxConcurrentFlows > 0 &&
		request.ActiveFlowsTotal >= policy.Limits.MaxConcurrentFlows {
		return deny(CodeLimitExceeded)
	}
	return Decision{Allowed: true, Code: CodeAllowed}
}

func forcedDenyFor(context Context, request Request) []string {
	denied := make([]string, 0, len(ForcedDenyCIDRs)+len(CloudMetadataCIDRs)+
		len(context.DeploymentDenyCIDRs)+len(request.LocalInterfaceCIDRs)+1)
	denied = append(denied, ForcedDenyCIDRs...)
	denied = append(denied, CloudMetadataCIDRs...)
	mesh := context.MeshCIDR
	if mesh == "" {
		mesh = DefaultMeshCIDR
	}
	denied = append(denied, mesh)
	denied = append(denied, context.DeploymentDenyCIDRs...)
	denied = append(denied, request.LocalInterfaceCIDRs...)
	return denied
}

func containsID(ids []int64, want int64) bool {
	for _, id := range ids {
		if id == want {
			return true
		}
	}
	return false
}

func portAllowed(rules []DestinationRule, port int) bool {
	for _, rule := range rules {
		for _, span := range rule.PortRanges {
			if len(span) == 2 && port >= span[0] && port <= span[1] {
				return true
			}
		}
	}
	return false
}
