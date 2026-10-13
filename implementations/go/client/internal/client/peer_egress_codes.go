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
	// A rule the user switched off. Not a configuration error: it stays in the list, out of force.
	egressCodeRuleDisabled = "EGRESS_RULE_DISABLED"
	// The consumer's master switch is off, so rules are kept but nothing is taken over.
	egressCodeConsumerDisabled = "EGRESS_CONSUMER_DISABLED"

	// SPEG1 frame decoding.
	egressCodeFrameBadMagic         = "EGRESS_FRAME_BAD_MAGIC"
	egressCodeFrameUnknownType      = "EGRESS_FRAME_UNKNOWN_TYPE"
	egressCodeFrameReservedSet      = "EGRESS_FRAME_RESERVED_SET"
	egressCodeFrameTruncated        = "EGRESS_FRAME_TRUNCATED"
	egressCodeFrameTrailingBytes    = "EGRESS_FRAME_TRAILING_BYTES"
	egressCodeIPv6Unsupported       = "EGRESS_IPV6_UNSUPPORTED"
	egressCodeFrameMalformedControl = "EGRESS_FRAME_MALFORMED_CONTROL"
	egressCodeControlUnsupported    = "EGRESS_CONTROL_UNSUPPORTED"

	// Phase two, domain rules (protocol/spec/peer-egress-dns.md).
	egressCodeNameUnresolved     = "EGRESS_NAME_UNRESOLVED"
	egressCodeNameUnsupported    = "EGRESS_NAME_UNSUPPORTED"
	egressCodeRuleFakeIPOverlap  = "EGRESS_RULE_FAKE_IP_OVERLAP"
	egressCodeFakeIPPoolInvalid  = "EGRESS_FAKE_IP_POOL_INVALID"
	egressCodeRuleEgressNoDomain = "EGRESS_RULE_EGRESS_NO_DOMAIN"
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

// The IPv6 counterparts of the forced-deny list (protocol/spec/peer-egress.md, 强制拒绝清单), held
// apart from the IPv4 one only so each list reads as one family; a destination is checked against
// both and only a prefix of its own family can contain it.
var egressForcedDenyCIDRs6 = []string{
	"::/128",
	"::1/128",
	// A socket connected to an IPv4-mapped address reaches the IPv4 address, past every IPv4 entry.
	"::ffff:0:0/96",
	// Prefixes that embed an IPv4 address a NAT64 gateway or a 6to4 relay forwards to, metadata
	// and private ranges included.
	"64:ff9b::/96",
	"64:ff9b:1::/48",
	"2002::/16",
	"fe80::/10",
	"fec0::/10",
	"ff00::/8",
}

// The IPv6 instance metadata endpoint, in the unique local range a LAN-scoped policy can grant.
var egressCloudMetadataCIDRs6 = []string{
	"fd00:ec2::254/128",
}

// Unique local addresses, the IPv6 counterpart of the private ranges.
var egressLANCIDRs6 = []string{
	"fc00::/7",
}
