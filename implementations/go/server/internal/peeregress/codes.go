// Package peeregress implements the peer egress rule and authorization semantics defined by
// protocol/spec/peer-egress.md. It is deliberately free of storage and transport concerns so the
// shared vectors under protocol/test-vectors can drive it directly.
package peeregress

// Result codes. Every one is exercised by a shared vector; implementations must agree on which
// code a request fails with, not merely on allow versus deny.
const (
	CodeAllowed = "EGRESS_ALLOWED"

	// Authorization, evaluated in this order.
	CodeHopNotAllowed     = "EGRESS_HOP_NOT_ALLOWED"
	CodeDisabled          = "EGRESS_DISABLED"
	CodePeerACLDenied     = "EGRESS_PEER_ACL_DENIED"
	CodeConsumerDenied    = "EGRESS_CONSUMER_DENIED"
	CodeForbiddenDestType = "EGRESS_FORBIDDEN_DESTINATION"
	CodeScopeDenied       = "EGRESS_SCOPE_DENIED"
	CodeDestinationDenied = "EGRESS_DEST_DENIED"
	CodeProtocolDenied    = "EGRESS_PROTOCOL_DENIED"
	CodePortDenied        = "EGRESS_PORT_DENIED"
	CodeLimitExceeded     = "EGRESS_LIMIT_EXCEEDED"

	// Consumer rule configuration validation.
	CodeRuleDomainUnsupported = "EGRESS_RULE_DOMAIN_UNSUPPORTED"
	CodeRuleIPv6Unsupported   = "EGRESS_RULE_IPV6_UNSUPPORTED"
	CodeRuleMalformed         = "EGRESS_RULE_MALFORMED"
	CodeRuleMissingTarget     = "EGRESS_RULE_MISSING_TARGET"
	CodeRuleMeshOverlap       = "EGRESS_RULE_MESH_OVERLAP"
	CodeRuleDefaultRoute      = "EGRESS_RULE_DEFAULT_ROUTE"
	CodeRulePortUnsupported   = "EGRESS_RULE_PORT_UNSUPPORTED"

	// SPEG1 frame decoding.
	CodeFrameBadMagic      = "EGRESS_FRAME_BAD_MAGIC"
	CodeFrameUnknownType   = "EGRESS_FRAME_UNKNOWN_TYPE"
	CodeFrameReservedSet   = "EGRESS_FRAME_RESERVED_SET"
	CodeFrameTruncated     = "EGRESS_FRAME_TRUNCATED"
	CodeFrameTrailingBytes = "EGRESS_FRAME_TRAILING_BYTES"
	CodeIPv6Unsupported    = "EGRESS_IPV6_UNSUPPORTED"
	CodeFrameMalformedCtrl = "EGRESS_FRAME_MALFORMED_CONTROL"
	CodeControlUnsupported = "EGRESS_CONTROL_UNSUPPORTED"
)
