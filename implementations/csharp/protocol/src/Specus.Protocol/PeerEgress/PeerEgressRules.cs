using System.Text.Json.Serialization;

namespace Specus.Protocol.PeerEgress;

/// <summary>
/// One consumer-side split-routing rule.
/// </summary>
/// <remarks>
/// Rules match on destination address only. The consumer steers traffic by installing routes and a
/// route selects on destination address alone, so a port-scoped rule could neither be expressed as
/// a route nor cleanly returned to the local stack once the packet had been captured. Port and
/// protocol limits live on the egress policy and are enforced when the flow is opened.
/// </remarks>
public sealed record PeerEgressRule
{
    [JsonPropertyName("index")]
    public int Index { get; init; }

    [JsonPropertyName("match")]
    public string Match { get; init; } = string.Empty;

    [JsonPropertyName("action")]
    public string Action { get; init; } = string.Empty;

    [JsonPropertyName("egressClientId")]
    public long? EgressClientId { get; init; }

    /// <summary>
    /// Present only so a configuration carrying it can be rejected with a specific code rather than
    /// having the field silently ignored.
    /// </summary>
    [JsonPropertyName("port")]
    public int? Port { get; init; }
}

/// <summary>
/// The outcome of evaluating a destination against an ordered rule list.
/// </summary>
/// <param name="Action">The winning rule's action, or <c>direct</c> when nothing matched.</param>
/// <param name="MatchedRuleIndex">The winning rule's position, or -1 when nothing matched.</param>
/// <param name="EgressClientId">The egress device, set only for an <c>egress</c> action.</param>
public readonly record struct PeerEgressRuleMatch(string Action, int MatchedRuleIndex, long? EgressClientId)
{
    /// <summary>Reports whether any rule applied.</summary>
    public bool Matched => MatchedRuleIndex >= 0;
}

/// <summary>
/// Consumer-side rule validation and matching, as defined by protocol/spec/peer-egress.md.
/// </summary>
public static class PeerEgressRules
{
    /// <summary>The Peer Mesh virtual network unless the deployment overrides it.</summary>
    public const string DefaultMeshCidr = "100.96.0.0/11";

    public const string ActionEgress = "egress";
    public const string ActionDirect = "direct";
    public const string ActionBlock = "block";

    /// <summary>The default outcome: traffic stays local.</summary>
    public static PeerEgressRuleMatch Unmatched { get; } = new(ActionDirect, -1, null);

    /// <summary>
    /// Returns the failing code, or <c>null</c> when the rule is acceptable.
    /// </summary>
    /// <remarks>
    /// The checks run in a fixed order so every implementation reports the same code for a rule
    /// that violates more than one constraint.
    /// </remarks>
    public static string? Validate(PeerEgressRule rule, string? meshCidr)
    {
        var match = rule.Match?.Trim() ?? string.Empty;
        if (match.Length == 0)
        {
            return PeerEgressCodes.RuleMalformed;
        }
        if (match.Contains(':', StringComparison.Ordinal))
        {
            return PeerEgressCodes.RuleIpv6Unsupported;
        }
        if (LooksLikeDomain(match))
        {
            return PeerEgressCodes.RuleDomainUnsupported;
        }
        if (!Ipv4Cidr.TryParse(match, out var cidr))
        {
            return PeerEgressCodes.RuleMalformed;
        }
        if (cidr.PrefixLength == 0)
        {
            // This version never takes over the default route: doing so would override the
            // operator's existing configuration and contradict "unmatched traffic stays local".
            return PeerEgressCodes.RuleDefaultRoute;
        }
        var mesh = string.IsNullOrWhiteSpace(meshCidr) ? DefaultMeshCidr : meshCidr;
        if (Ipv4Cidr.TryParse(mesh, out var meshPrefix) && cidr.Overlaps(meshPrefix))
        {
            return PeerEgressCodes.RuleMeshOverlap;
        }
        if (rule.Port is not null)
        {
            return PeerEgressCodes.RulePortUnsupported;
        }
        var action = rule.Action?.Trim() ?? string.Empty;
        if (action is not (ActionEgress or ActionDirect or ActionBlock))
        {
            return PeerEgressCodes.RuleMalformed;
        }
        if (action == ActionEgress && rule.EgressClientId is null or <= 0)
        {
            // The field being present is not the same as it being usable. Zero is this project's
            // sentinel for "no consumer", so accepting it would let the rule pass validation,
            // install its route, and then fail to find a peer for every packet: a configuration
            // error deferred into a runtime blackhole.
            return PeerEgressCodes.RuleMissingTarget;
        }
        return null;
    }

    /// <summary>
    /// Resolves a destination against an ordered rule list.
    /// </summary>
    /// <remarks>
    /// Longest prefix wins; when two rules share a prefix length the earlier one wins. An unmatched
    /// destination resolves to direct. That is the routing table's own behaviour rather than a
    /// fallback branch: a destination with no installed route never reaches the tunnel device in
    /// the first place.
    ///
    /// <para>Rules that fail validation are skipped, which is why the mesh prefix is needed here.
    /// Skipped rather than left to the caller to pre-filter, so that one bad rule cannot change
    /// what a good one decides no matter who assembled the list: a refused rule with a longer
    /// prefix would otherwise go on outranking a legal one, and what the operator was told was
    /// refused would not match where the traffic actually goes.</para>
    /// </remarks>
    public static PeerEgressRuleMatch Match(
        IReadOnlyList<PeerEgressRule> rules, string? destination, string? meshCidr)
    {
        if (rules.Count == 0 || !Ipv4Cidr.TryParseAddress(destination, out var address))
        {
            return Unmatched;
        }
        var best = Unmatched;
        var bestPrefix = -1;
        for (var index = 0; index < rules.Count; index++)
        {
            var rule = rules[index];
            if (Validate(rule, meshCidr) is not null)
            {
                continue;
            }
            if (!Ipv4Cidr.TryParse(rule.Match, out var cidr) || !cidr.Contains(address))
            {
                continue;
            }
            if (cidr.PrefixLength <= bestPrefix)
            {
                continue;
            }
            bestPrefix = cidr.PrefixLength;
            best = new PeerEgressRuleMatch(rule.Action,
                index,
                rule.Action == ActionEgress ? rule.EgressClientId : null);
        }
        return best;
    }

    private static bool LooksLikeDomain(string match)
    {
        foreach (var c in match)
        {
            if (c is (>= '0' and <= '9') or '.' or '/')
            {
                continue;
            }
            return true;
        }
        return false;
    }
}
