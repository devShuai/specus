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

        // The destination, protocol and port steps look at one set of grants: the destination rules
        // that contain the address and, for a flow that carries a name, the domain rules that cover
        // it (protocol/spec/peer-egress.md, 按域名授权). The steps above stay on the address, so a
        // name that resolves to loopback or the mesh is refused there whatever a domain rule says.
        // A flow without a name is never granted by a domain rule, even one whose address happens
        // to be what an allowed name resolves to: that would turn a grant of a name into a grant of
        // an address.
        var matches = new List<Grant>();
        foreach (var rule in policy.DestinationRules)
        {
            if (Ipv4Cidr.TryParse(rule.Cidr, out var cidr) && cidr.Contains(destination))
            {
                matches.Add(new Grant(rule.Protocols, rule.PortRanges));
            }
        }
        if (request.Name is not null)
        {
            foreach (var rule in policy.DomainRules)
            {
                if (PeerEgressNames.Covers(rule.Match, request.Name))
                {
                    matches.Add(new Grant(rule.Protocols, rule.PortRanges));
                }
            }
        }
        if (matches.Count == 0)
        {
            return Deny(PeerEgressCodes.DestinationDenied);
        }

        var protocolMatches = matches
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

    private static bool PortAllowed(IEnumerable<Grant> rules, int port) =>
        rules.Any(rule => rule.PortRanges.Any(span =>
            span.Length == 2 && port >= span[0] && port <= span[1]));

    /// <summary>What a matching rule of either kind contributes to the protocol and port steps.</summary>
    private readonly record struct Grant(IReadOnlyList<string> Protocols, IReadOnlyList<int[]> PortRanges);
}
