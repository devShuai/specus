namespace Specus.Protocol.PeerEgress;

/// <summary>
/// Egress flow-open authorization, as defined by protocol/spec/peer-egress.md.
/// </summary>
public static class PeerEgressAuthorization
{
    // Policy scopes. Public and LAN access are authorised separately; neither implies the other.
    public const string ScopePublic = "PUBLIC";
    public const string ScopeLan = "LAN";

    /// <summary>
    /// Destinations that stay denied no matter what the policy says.
    /// </summary>
    /// <remarks>
    /// A rule as broad as 0.0.0.0/0 must not reach loopback, link-local, cloud metadata, multicast,
    /// broadcast or the mesh itself, so this list is consulted before any destination rule.
    /// </remarks>
    public static IReadOnlyList<string> ForcedDenyCidrs { get; } =
    [
        "0.0.0.0/8",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "224.0.0.0/4",
        "240.0.0.0/4",
        // Covered by 240.0.0.0/4, listed so the broadcast address is explicit to a reader.
        "255.255.255.255/32",
    ];

    /// <summary>
    /// Well-known instance metadata endpoints, denied independently of the link-local block so that
    /// the intent survives a future change to that block.
    /// </summary>
    public static IReadOnlyList<string> CloudMetadataCidrs { get; } =
    [
        "169.254.169.254/32",
        "100.100.100.200/32",
    ];

    /// <summary>RFC 1918 private use plus RFC 6598 shared address space.</summary>
    public static IReadOnlyList<string> LanCidrs { get; } =
    [
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "100.64.0.0/10",
    ];

    /// <summary>
    /// Evaluates one flow-open attempt.
    /// </summary>
    /// <remarks>
    /// The checks run in the fixed order given by protocol/spec/peer-egress.md so implementations
    /// agree on which code a request fails with, not merely on allow versus deny.
    /// </remarks>
    public static PeerEgressDecision Authorize(PeerEgressRequest request, PeerEgressPolicy policy,
        bool peerAclAllows, PeerEgressContext context)
    {
        if (request.Hop)
        {
            return Deny(PeerEgressCodes.HopNotAllowed);
        }
        if (!policy.Enabled)
        {
            return Deny(PeerEgressCodes.Disabled);
        }
        if (!peerAclAllows)
        {
            return Deny(PeerEgressCodes.PeerAclDenied);
        }
        if (!policy.AllowedConsumerClientIds.Contains(request.ConsumerClientId))
        {
            return Deny(PeerEgressCodes.ConsumerDenied);
        }

        if (!Ipv4Cidr.TryParseAddress(request.DestinationIp, out var destination))
        {
            return Deny(PeerEgressCodes.DestinationDenied);
        }
        if (Ipv4Cidr.ContainedIn(destination, ForcedDenyFor(context, request)))
        {
            return Deny(PeerEgressCodes.ForbiddenDestination);
        }

        var scope = Ipv4Cidr.ContainedIn(destination, LanCidrs) ? ScopeLan : ScopePublic;
        if (!string.Equals(scope, policy.Scope, StringComparison.Ordinal))
        {
            return Deny(PeerEgressCodes.ScopeDenied);
        }

        var addressMatches = policy.DestinationRules
            .Where(rule => Ipv4Cidr.TryParse(rule.Cidr, out var cidr) && cidr.Contains(destination))
            .ToArray();
        if (addressMatches.Length == 0)
        {
            return Deny(PeerEgressCodes.DestinationDenied);
        }

        var protocolMatches = addressMatches
            .Where(rule => rule.Protocols.Contains(request.Protocol, StringComparer.Ordinal))
            .ToArray();
        if (protocolMatches.Length == 0)
        {
            return Deny(PeerEgressCodes.ProtocolDenied);
        }

        if (!PortAllowed(protocolMatches, request.DestinationPort))
        {
            return Deny(PeerEgressCodes.PortDenied);
        }

        var limits = policy.Limits;
        if (limits.MaxFlowsPerConsumer > 0 && request.ActiveFlowsForConsumer >= limits.MaxFlowsPerConsumer)
        {
            return Deny(PeerEgressCodes.LimitExceeded);
        }
        if (limits.MaxConcurrentFlows > 0 && request.ActiveFlowsTotal >= limits.MaxConcurrentFlows)
        {
            return Deny(PeerEgressCodes.LimitExceeded);
        }
        return new PeerEgressDecision(true, PeerEgressCodes.Allowed);
    }

    private static PeerEgressDecision Deny(string code) => new(false, code);

    private static List<string> ForcedDenyFor(PeerEgressContext context, PeerEgressRequest request)
    {
        var denied = new List<string>(ForcedDenyCidrs.Count + CloudMetadataCidrs.Count
            + context.DeploymentDenyCidrs.Count + request.LocalInterfaceCidrs.Count + 1);
        denied.AddRange(ForcedDenyCidrs);
        denied.AddRange(CloudMetadataCidrs);
        denied.Add(string.IsNullOrWhiteSpace(context.MeshCidr)
            ? PeerEgressRules.DefaultMeshCidr
            : context.MeshCidr);
        denied.AddRange(context.DeploymentDenyCidrs);
        denied.AddRange(request.LocalInterfaceCidrs);
        return denied;
    }

    private static bool PortAllowed(IEnumerable<PeerEgressDestinationRule> rules, int port) =>
        rules.Any(rule => rule.PortRanges.Any(span =>
            span.Length == 2 && port >= span[0] && port <= span[1]));
}
