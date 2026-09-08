namespace Specus.Protocol.PeerEgress;

/// <summary>
/// Result codes defined by protocol/spec/peer-egress.md.
/// </summary>
/// <remarks>
/// Every code is exercised by a shared vector. Implementations must agree on which code a request
/// fails with, not merely on allow versus deny: an operator who only sees "denied" cannot tell a
/// revoked ACL from a closed port.
/// </remarks>
public static class PeerEgressCodes
{
    public const string Allowed = "EGRESS_ALLOWED";

    // Authorization, evaluated in this order.
    public const string HopNotAllowed = "EGRESS_HOP_NOT_ALLOWED";
    public const string Disabled = "EGRESS_DISABLED";
    public const string PeerAclDenied = "EGRESS_PEER_ACL_DENIED";
    public const string ConsumerDenied = "EGRESS_CONSUMER_DENIED";
    public const string ForbiddenDestination = "EGRESS_FORBIDDEN_DESTINATION";
    public const string ScopeDenied = "EGRESS_SCOPE_DENIED";
    public const string DestinationDenied = "EGRESS_DEST_DENIED";
    public const string ProtocolDenied = "EGRESS_PROTOCOL_DENIED";
    public const string PortDenied = "EGRESS_PORT_DENIED";
    public const string LimitExceeded = "EGRESS_LIMIT_EXCEEDED";

    // Consumer rule configuration validation.
    public const string RuleDomainUnsupported = "EGRESS_RULE_DOMAIN_UNSUPPORTED";
    public const string RuleIpv6Unsupported = "EGRESS_RULE_IPV6_UNSUPPORTED";
    public const string RuleMalformed = "EGRESS_RULE_MALFORMED";
    public const string RuleMissingTarget = "EGRESS_RULE_MISSING_TARGET";
    public const string RuleMeshOverlap = "EGRESS_RULE_MESH_OVERLAP";
    public const string RuleDefaultRoute = "EGRESS_RULE_DEFAULT_ROUTE";
    public const string RulePortUnsupported = "EGRESS_RULE_PORT_UNSUPPORTED";

    // SPEG1 frame decoding.
    public const string FrameBadMagic = "EGRESS_FRAME_BAD_MAGIC";
    public const string FrameUnknownType = "EGRESS_FRAME_UNKNOWN_TYPE";
    public const string FrameReservedSet = "EGRESS_FRAME_RESERVED_SET";
    public const string FrameTruncated = "EGRESS_FRAME_TRUNCATED";
    public const string FrameTrailingBytes = "EGRESS_FRAME_TRAILING_BYTES";
    public const string Ipv6Unsupported = "EGRESS_IPV6_UNSUPPORTED";
    public const string FrameMalformedControl = "EGRESS_FRAME_MALFORMED_CONTROL";
    public const string ControlUnsupported = "EGRESS_CONTROL_UNSUPPORTED";
}
