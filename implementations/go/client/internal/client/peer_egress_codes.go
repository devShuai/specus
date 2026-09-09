package client

// Result codes defined by protocol/spec/peer-egress.md.
//
// The client carries its own copy because the Go client and server are separate modules and the
// client keeps no third-party dependencies. The shared vectors under protocol/test-vectors are what
// keep the two in step, the same way they do for the Java, .NET and C implementations.
const (
	egressCodeAllowed = "EGRESS_ALLOWED"

	// Authorization, evaluated in this order.
	egressCodeHopNotAllowed     = "EGRESS_HOP_NOT_ALLOWED"
	egressCodeDisabled          = "EGRESS_DISABLED"
	egressCodePeerACLDenied     = "EGRESS_PEER_ACL_DENIED"
	egressCodeConsumerDenied    = "EGRESS_CONSUMER_DENIED"
	egressCodeForbiddenDestType = "EGRESS_FORBIDDEN_DESTINATION"
	egressCodeScopeDenied       = "EGRESS_SCOPE_DENIED"
	egressCodeDestinationDenied = "EGRESS_DEST_DENIED"
	egressCodeProtocolDenied    = "EGRESS_PROTOCOL_DENIED"
	egressCodePortDenied        = "EGRESS_PORT_DENIED"
	egressCodeLimitExceeded     = "EGRESS_LIMIT_EXCEEDED"

	// Consumer rule configuration validation.
	egressCodeRuleDomainUnsupported = "EGRESS_RULE_DOMAIN_UNSUPPORTED"
	egressCodeRuleIPv6Unsupported   = "EGRESS_RULE_IPV6_UNSUPPORTED"
	egressCodeRuleMalformed         = "EGRESS_RULE_MALFORMED"
	egressCodeRuleMissingTarget     = "EGRESS_RULE_MISSING_TARGET"
	egressCodeRuleMeshOverlap       = "EGRESS_RULE_MESH_OVERLAP"
	egressCodeRuleDefaultRoute      = "EGRESS_RULE_DEFAULT_ROUTE"
	egressCodeRulePortUnsupported   = "EGRESS_RULE_PORT_UNSUPPORTED"

	// SPEG1 frame decoding.
	egressCodeFrameBadMagic         = "EGRESS_FRAME_BAD_MAGIC"
	egressCodeFrameUnknownType      = "EGRESS_FRAME_UNKNOWN_TYPE"
	egressCodeFrameReservedSet      = "EGRESS_FRAME_RESERVED_SET"
	egressCodeFrameTruncated        = "EGRESS_FRAME_TRUNCATED"
	egressCodeFrameTrailingBytes    = "EGRESS_FRAME_TRAILING_BYTES"
	egressCodeIPv6Unsupported       = "EGRESS_IPV6_UNSUPPORTED"
	egressCodeFrameMalformedControl = "EGRESS_FRAME_MALFORMED_CONTROL"
	egressCodeControlUnsupported    = "EGRESS_CONTROL_UNSUPPORTED"
)

// Policy scopes. Public and LAN access are authorised separately; neither implies the other.
const (
	egressScopePublic = "PUBLIC"
	egressScopeLAN    = "LAN"
)

// egressDefaultMeshCIDR is the Peer Mesh virtual network unless the deployment overrides it.
const egressDefaultMeshCIDR = "100.96.0.0/11"

// Destinations that stay denied no matter what the policy says. A rule as broad as 0.0.0.0/0 must
// not reach loopback, link-local, cloud metadata, multicast, broadcast or the mesh itself, so this
// list is consulted before any destination rule.
var egressForcedDenyCIDRs = []string{
	"0.0.0.0/8",
	"127.0.0.0/8",
	"169.254.0.0/16",
	"224.0.0.0/4",
	"240.0.0.0/4",
	// Covered by 240.0.0.0/4, listed so the broadcast address is explicit to a reader.
	"255.255.255.255/32",
}

// Well-known instance metadata endpoints, denied independently of the link-local block so that the
// intent survives a future change to that block.
var egressCloudMetadataCIDRs = []string{
	"169.254.169.254/32",
	"100.100.100.200/32",
}

// RFC 1918 private use plus RFC 6598 shared address space.
var egressLANCIDRs = []string{
	"10.0.0.0/8",
	"172.16.0.0/12",
	"192.168.0.0/16",
	"100.64.0.0/10",
}
