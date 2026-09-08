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

// knownCodes is every code this build defines, built from the constants above rather than repeated
// as literals so a code cannot be listed under a spelling implementations never return.
var knownCodes = map[string]struct{}{
	CodeAllowed: {},

	CodeHopNotAllowed: {}, CodeDisabled: {}, CodePeerACLDenied: {}, CodeConsumerDenied: {},
	CodeForbiddenDestType: {}, CodeScopeDenied: {}, CodeDestinationDenied: {},
	CodeProtocolDenied: {}, CodePortDenied: {}, CodeLimitExceeded: {},

	CodeRuleDomainUnsupported: {}, CodeRuleIPv6Unsupported: {}, CodeRuleMalformed: {},
	CodeRuleMissingTarget: {}, CodeRuleMeshOverlap: {}, CodeRuleDefaultRoute: {},
	CodeRulePortUnsupported: {},

	CodeFrameBadMagic: {}, CodeFrameUnknownType: {}, CodeFrameReservedSet: {},
	CodeFrameTruncated: {}, CodeFrameTrailingBytes: {}, CodeIPv6Unsupported: {},
	CodeFrameMalformedCtrl: {}, CodeControlUnsupported: {},
}

// IsKnownCode reports whether a code is one this build defines.
//
// Used to filter client-reported refusal counters: without it a client could grow the stored map
// with keys of its own invention.
func IsKnownCode(code string) bool {
	_, ok := knownCodes[code]
	return ok
}
