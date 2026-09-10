using Specus.Protocol.PeerEgress;

namespace Specus.Client.PeerMesh;

/// <summary>What a route is for.</summary>
internal enum PeerEgressRouteKind
{
    /// <summary>Sends a prefix into the TUN for the data plane to handle.</summary>
    Tun,

    /// <summary>
    /// Pins one address to the physical path.
    /// </summary>
    /// <remarks>
    /// The control connection, STUN and TURN, peer UDP endpoints and the egress peer's own address
    /// have to keep working over the real network. If a rule's prefix happened to contain one of
    /// them, its traffic would be routed into the tunnel that carries it, and the tunnel would be
    /// carrying its own transport.
    /// </remarks>
    Bypass
}

/// <summary>
/// One entry this feature wants to own.
/// </summary>
/// <param name="Cidr">Normalised, so the same route is never described two ways.</param>
/// <param name="Origin">What asked for this route, for the conflict message an operator reads.</param>
internal readonly record struct PeerEgressRoute(string Cidr, PeerEgressRouteKind Kind, string Origin);

/// <summary>A rule that was refused, paired with its code, so every problem is reported at once.</summary>
internal readonly record struct PeerEgressRuleRefusal(int Index, string Match, string Code);

/// <summary>The planner's answer: what to own, and which rules were thrown out getting there.</summary>
internal sealed record PeerEgressRoutePlan(
    IReadOnlyList<PeerEgressRoute> Routes, IReadOnlyList<PeerEgressRuleRefusal> Refused);

/// <summary>What to withdraw and what to add to move from one set to another.</summary>
internal sealed record PeerEgressRouteDifference(
    IReadOnlyList<PeerEgressRoute> Remove, IReadOnlyList<PeerEgressRoute> Add);

/// <summary>
/// Turning consumer rules into routes.
/// </summary>
/// <remarks>
/// Only exact prefixes are installed, and the planner invents none of its own: no default route,
/// and no <c>0.0.0.0/1</c> plus <c>128.0.0.0/1</c> pair standing in for one. A tool that captures
/// everything cannot be reasoned about by the person running it, and "unmatched traffic stays
/// local" stops being true the moment something covers all of it.
///
/// <para>Validation refuses only <c>/0</c>, though. An operator who writes those two halves by hand
/// still gets near-total capture, and the lower one is refused today only because it happens to
/// contain the mesh. Closing that means picking a minimum prefix length, which is a policy decision
/// rather than something to settle while porting.</para>
///
/// <para>The planner is pure. It says which routes should exist; the installer performs the
/// difference and can undo it. Splitting them is what lets rollback, conflict refusal and ownership
/// be tested without touching a real routing table.</para>
///
/// <para>Shared vector: <c>protocol/test-vectors/peer-egress-routes-v1.json</c>.</para>
/// </remarks>
internal static class PeerEgressRoutePlanner
{
    /// <summary>The name a kind carries in the journal and in the shared vector.</summary>
    public static string WireName(PeerEgressRouteKind kind) =>
        kind == PeerEgressRouteKind.Bypass ? "bypass" : "tun";

    public static PeerEgressRouteKind KindFromWireName(string? name) =>
        name == "bypass" ? PeerEgressRouteKind.Bypass : PeerEgressRouteKind.Tun;

    /// <summary>
    /// Works out the routes a rule set and a bypass set need.
    /// </summary>
    /// <remarks>
    /// Refused rules are returned rather than skipped silently: a rule an operator wrote and this
    /// feature ignored is a leak they have no way to notice.
    ///
    /// <para>The bypass list comes from runtime discovery rather than from configuration, so an
    /// entry that cannot be read is skipped. Refusing the whole plan over one would stop every rule
    /// because a single peer went away.</para>
    /// </remarks>
    public static PeerEgressRoutePlan Plan(
        IReadOnlyList<PeerEgressRule> rules, IReadOnlyList<string>? bypass, string? meshCidr)
    {
        var refused = new List<PeerEgressRuleRefusal>();
        var skip = new HashSet<int>();
        for (var index = 0; index < rules.Count; index++)
        {
            var code = PeerEgressRules.Validate(rules[index], meshCidr);
            if (code is not null)
            {
                refused.Add(new PeerEgressRuleRefusal(index, rules[index].Match, code));
                skip.Add(index);
            }
        }

        var seen = new HashSet<string>(StringComparer.Ordinal);
        var routes = new List<PeerEgressRoute>(rules.Count + (bypass?.Count ?? 0));

        // Bypass first: these are the addresses that must not be captured under any rule, and
        // adding them first means a rule naming the same prefix cannot displace one.
        foreach (var endpoint in bypass ?? [])
        {
            if (!Ipv4Cidr.TryParseAddress(endpoint?.Trim(), out var address))
            {
                continue;
            }
            var pinned = Ipv4Cidr.FormatAddress(address) + "/32";
            if (seen.Add(pinned))
            {
                routes.Add(new PeerEgressRoute(pinned, PeerEgressRouteKind.Bypass, "bypass"));
            }
        }

        for (var index = 0; index < rules.Count; index++)
        {
            if (skip.Contains(index))
            {
                continue;
            }
            var rule = rules[index];
            // A direct rule installs nothing. Traffic stays local by not having a route, which is
            // the same mechanism that makes unmatched traffic local, so there is one behaviour
            // rather than two that have to agree.
            //
            // A block rule does install one: the packet has to be captured before it can be
            // dropped, and the data plane is what drops it.
            var action = rule.Action?.Trim() ?? string.Empty;
            if (action is not (PeerEgressRules.ActionEgress or PeerEgressRules.ActionBlock))
            {
                continue;
            }
            if (!Ipv4Cidr.TryParse(rule.Match, out var cidr))
            {
                continue;
            }
            // Rendered the one way this feature writes a prefix, so a route installed in one run is
            // recognised as the same route in the next.
            var normalised = cidr.ToString();
            if (!seen.Add(normalised))
            {
                // Two rules over the same prefix need one route; the engine decides between them
                // per packet, and installing the prefix twice would make removal ambiguous.
                continue;
            }
            routes.Add(new PeerEgressRoute(normalised, PeerEgressRouteKind.Tun, "rule:" + rule.Match));
        }

        Sort(routes);
        return new PeerEgressRoutePlan(routes, refused);
    }

    /// <summary>
    /// Orders bypass entries first, then by prefix.
    /// </summary>
    /// <remarks>
    /// Bypass first because installation happens in this order: the addresses that keep the
    /// tunnel's own transport working are in place before anything is pointed into the tunnel.
    /// Deterministic order also means the journal and every log line read the same way run to run.
    /// </remarks>
    public static void Sort(List<PeerEgressRoute> routes) => routes.Sort(Compare);

    private static int Compare(PeerEgressRoute left, PeerEgressRoute right)
    {
        var order = Rank(left.Kind).CompareTo(Rank(right.Kind));
        if (order != 0)
        {
            return order;
        }
        if (!Ipv4Cidr.TryParse(left.Cidr, out var leftCidr) || !Ipv4Cidr.TryParse(right.Cidr, out var rightCidr))
        {
            // Falls back to text, so the ordering stays total on data the planner would never have
            // produced rather than throwing where a sort is expected to succeed.
            return string.CompareOrdinal(left.Cidr, right.Cidr);
        }
        order = leftCidr.Network.CompareTo(rightCidr.Network);
        return order != 0 ? order : leftCidr.PrefixLength.CompareTo(rightCidr.PrefixLength);
    }

    private static int Rank(PeerEgressRouteKind kind) => kind == PeerEgressRouteKind.Bypass ? 0 : 1;

    /// <summary>
    /// Reports what to add and what to withdraw to get from one set to another.
    /// </summary>
    /// <remarks>
    /// Withdrawals come back first so a caller applies them first. A prefix that moved from one
    /// kind to the other has to lose its old entry before the new one goes in, or the platform
    /// would either refuse the duplicate or silently keep whichever it saw first.
    /// </remarks>
    public static PeerEgressRouteDifference Diff(
        IReadOnlyList<PeerEgressRoute> current, IReadOnlyList<PeerEgressRoute> desired)
    {
        var desiredByCidr = new Dictionary<string, PeerEgressRoute>(StringComparer.Ordinal);
        foreach (var route in desired)
        {
            desiredByCidr[route.Cidr] = route;
        }
        var currentByCidr = new Dictionary<string, PeerEgressRoute>(StringComparer.Ordinal);
        foreach (var route in current)
        {
            currentByCidr[route.Cidr] = route;
        }

        var remove = new List<PeerEgressRoute>();
        foreach (var route in current)
        {
            if (!desiredByCidr.TryGetValue(route.Cidr, out var want) || want.Kind != route.Kind)
            {
                remove.Add(route);
            }
        }
        var add = new List<PeerEgressRoute>();
        foreach (var route in desired)
        {
            if (!currentByCidr.TryGetValue(route.Cidr, out var have) || have.Kind != route.Kind)
            {
                add.Add(route);
            }
        }
        Sort(remove);
        Sort(add);
        return new PeerEgressRouteDifference(remove, add);
    }
}
