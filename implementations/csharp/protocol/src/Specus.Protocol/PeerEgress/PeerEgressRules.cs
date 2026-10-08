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

    /// <summary>
    /// Null for a rule as written; only an explicit false switches the rule off. A switched-off rule
    /// stays in the list, takes no part in matching and installs no route.
    /// </summary>
    [JsonPropertyName("enabled")]
    public bool? Enabled { get; init; }

    /// <summary>Whether the user has taken this rule out of force.</summary>
    [JsonIgnore]
    public bool SwitchedOff => Enabled == false;
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
/// Whether phase two of peer egress runs (protocol/spec/peer-egress-dns.md, vector <c>phaseTwo</c>).
/// </summary>
/// <param name="Active">Both switches are on and the pool is usable.</param>
/// <param name="Code">Why a requested phase two does not run; null when it runs or was not asked for.</param>
/// <param name="Pool">The fake-IP pool, meaningful only while <paramref name="Active"/>.</param>
public readonly record struct PeerEgressPhaseTwo(bool Active, string? Code, Ipv4Cidr Pool)
{
    /// <summary>Phase two not asked for.</summary>
    public static PeerEgressPhaseTwo Off { get; } = new(false, null, default);

    /// <summary>The pool to validate and steer with, or null when phase two does not run.</summary>
    public Ipv4Cidr? RunningPool => Active ? Pool : null;
}

/// <summary>
/// Consumer-side rule validation and matching, as defined by protocol/spec/peer-egress.md and, for
/// domain rules, protocol/spec/peer-egress-dns.md.
/// </summary>
/// <remarks>
/// Phase two enters every check as one argument: the fake-IP pool while phase two runs, null while
/// it does not. Null is phase one exactly, down to the code a domain rule is refused with, so a node
/// that never turns the switch on behaves as it did before phase two existed.
/// </remarks>
public static class PeerEgressRules
{
    /// <summary>The Peer Mesh virtual network unless the deployment overrides it.</summary>
    public const string DefaultMeshCidr = "100.96.0.0/11";

    /// <summary>The fake-IP pool unless <c>peerEgressFakeIpCidr</c> names another.</summary>
    public const string DefaultFakeIpCidr = "198.18.0.0/15";

    /// <summary>The widest pool accepted.</summary>
    public const int FakeIpMinPrefix = 8;

    /// <summary>The narrowest pool accepted.</summary>
    public const int FakeIpMaxPrefix = 24;

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
    public static string? Validate(PeerEgressRule rule, string? meshCidr) => Validate(rule, meshCidr, null);

    /// <summary>
    /// Returns the failing code, or <c>null</c> when the rule is acceptable, with phase two running
    /// over <paramref name="fakeIpPool"/> or, when it is null, not running.
    /// </summary>
    /// <remarks>
    /// Phase two adds two things and changes nothing else about the order: a domain match is
    /// checked as a name instead of being refused, and an address rule may not reach into the pool,
    /// whose addresses only a domain rule hands out. The overlap is checked only while phase two
    /// runs; without it the pool is an ordinary range an address rule is free to cover.
    /// </remarks>
    public static string? Validate(PeerEgressRule rule, string? meshCidr, Ipv4Cidr? fakeIpPool) =>
        Validate(rule, meshCidr, fakeIpPool, ConsumerCarriesIpv6);

    /// <summary>
    /// Whether this consumer has an IPv6 data plane: IPv6 packets read from the TUN, IPv6 routes
    /// installed into it, and IPv6 carried to the egress. It does not yet, so a well-formed IPv6 rule
    /// is refused with <c>EGRESS_RULE_IPV6_UNSUPPORTED</c>: installing nothing for it and reporting it
    /// in force would send its destinations straight out of the local interface.
    /// </summary>
    /// <remarks>
    /// The rule is still read and checked in full first, so a mistake in it is reported as one, and
    /// how IPv6 rules match is pinned by the vector's <c>ipv6</c> section, which the tests run with
    /// this set.
    /// </remarks>
    public const bool ConsumerCarriesIpv6 = false;

    /// <summary>
    /// As <see cref="Validate(PeerEgressRule, string?, Ipv4Cidr?)"/>, with the consumer's IPv6 data
    /// plane stated.
    /// </summary>
    public static string? Validate(PeerEgressRule rule, string? meshCidr, Ipv4Cidr? fakeIpPool, bool carriesIpv6)
    {
        // Ahead of anything about the rule's content: a switched-off rule is the user's choice, and
        // should not have to be fixed before it may sit in the list.
        if (rule.SwitchedOff)
        {
            return PeerEgressCodes.RuleDisabled;
        }
        var match = rule.Match?.Trim() ?? string.Empty;
        if (match.Length == 0)
        {
            return PeerEgressCodes.RuleMalformed;
        }
        // A colon is unambiguous: the match is an IPv6 address or prefix, or it is malformed. The
        // mesh and the fake-IP pool are IPv4, so an IPv6 rule has neither to stay clear of.
        if (match.Contains(':', StringComparison.Ordinal))
        {
            if (!Ipv6Cidr.TryParse(match, out var prefix) || prefix.Mapped)
            {
                // An IPv4-mapped prefix reads, but no packet is ever addressed to one: the rule would
                // match nothing while its writer believed the IPv4 addresses covered.
                return PeerEgressCodes.RuleMalformed;
            }
            if (prefix.PrefixLength == 0)
            {
                return PeerEgressCodes.RuleDefaultRoute;
            }
            // Last: everything about the rule is right, and what is missing is this device's ability
            // to carry IPv6 at all.
            return ValidateTarget(rule) ?? (carriesIpv6 ? null : PeerEgressCodes.RuleIpv6Unsupported);
        }
        if (LooksLikeDomain(match))
        {
            if (fakeIpPool is null)
            {
                return PeerEgressCodes.RuleDomainUnsupported;
            }
            if (!PeerEgressNames.ValidMatch(match))
            {
                return PeerEgressCodes.RuleMalformed;
            }
        }
        else
        {
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
            if (fakeIpPool is { } pool && cidr.Overlaps(pool))
            {
                // A pool address stands for whatever name it was handed out for. An address rule
                // over it would be a second, competing answer to where that traffic goes.
                return PeerEgressCodes.RuleFakeIpOverlap;
            }
        }
        return ValidateTarget(rule);
    }

    /// <summary>
    /// The part of the order after the match: no port, a known action, and the egress an egress rule
    /// needs.
    /// </summary>
    private static string? ValidateTarget(PeerEgressRule rule)
    {
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
        IReadOnlyList<PeerEgressRule> rules, string? destination, string? meshCidr,
        Ipv4Cidr? fakeIpPool = null) => Match(rules, destination, meshCidr, fakeIpPool, ConsumerCarriesIpv6);

    /// <summary>
    /// As above, with the consumer's IPv6 data plane stated.
    /// </summary>
    /// <remarks>
    /// The families never compete: an IPv4 destination is decided by IPv4 rules alone and an IPv6 one
    /// by IPv6 rules alone, longest prefix within the family. Both are compared by value, so how a
    /// rule or a destination is spelled does not change the result.
    /// </remarks>
    public static PeerEgressRuleMatch Match(
        IReadOnlyList<PeerEgressRule> rules, string? destination, string? meshCidr,
        Ipv4Cidr? fakeIpPool, bool carriesIpv6)
    {
        var text = destination?.Trim() ?? string.Empty;
        var ipv6 = text.Contains(':', StringComparison.Ordinal);
        uint address = 0;
        var address6 = UInt128.Zero;
        var readable = ipv6 ? Ipv6Cidr.TryParseAddress(text, out address6) : Ipv4Cidr.TryParseAddress(text, out address);
        if (rules.Count == 0 || !readable)
        {
            return Unmatched;
        }
        var best = Unmatched;
        var bestPrefix = -1;
        for (var index = 0; index < rules.Count; index++)
        {
            var rule = rules[index];
            if (Validate(rule, meshCidr, fakeIpPool, carriesIpv6) is not null)
            {
                continue;
            }
            // A domain rule in force does not parse as a prefix and is passed over: it steers by the
            // name a pool address was handed out for, never by an address outside the pool.
            var match = rule.Match.Trim();
            var prefixLength = -1;
            if (match.Contains(':', StringComparison.Ordinal))
            {
                if (ipv6 && Ipv6Cidr.TryParse(match, out var cidr6) && cidr6.Contains(address6))
                {
                    prefixLength = cidr6.PrefixLength;
                }
            }
            else if (!ipv6 && Ipv4Cidr.TryParse(match, out var cidr) && cidr.Contains(address))
            {
                prefixLength = cidr.PrefixLength;
            }
            if (prefixLength <= bestPrefix)
            {
                continue;
            }
            bestPrefix = prefixLength;
            best = new PeerEgressRuleMatch(rule.Action,
                index,
                rule.Action == ActionEgress ? rule.EgressClientId : null);
        }
        return best;
    }

    /// <summary>
    /// Whether a rule's match is written as a domain rather than an address: the <c>kind</c> the
    /// status reports. A match with a colon is an IPv6 address, an address rule refused as such.
    /// </summary>
    public static bool IsDomainMatch(string? match)
    {
        var text = match?.Trim() ?? string.Empty;
        return text.Length != 0 && !text.Contains(':', StringComparison.Ordinal) && LooksLikeDomain(text);
    }

    /// <summary>
    /// Picks the domain rule that claims a name, or -1 when none does (vector <c>selection</c>).
    /// </summary>
    /// <remarks>
    /// An exact match wins over a suffix; among suffixes the one with more labels wins; after that
    /// the earlier rule. Rules not in force take no part, as in phase one. The egress's capability is
    /// deliberately not considered: a rule pointed at an egress that cannot resolve names still
    /// claims its names, so they are blocked rather than resolved locally.
    /// </remarks>
    public static int SelectDomainRule(
        IReadOnlyList<PeerEgressRule> rules, string? name, string? meshCidr, Ipv4Cidr fakeIpPool)
    {
        var query = PeerEgressNames.Normalize(name);
        var best = -1;
        var bestSuffix = true;
        var bestLabels = -1;
        for (var index = 0; index < rules.Count; index++)
        {
            var rule = rules[index];
            if (!IsDomainMatch(rule.Match) || Validate(rule, meshCidr, fakeIpPool) is not null)
            {
                continue;
            }
            var match = PeerEgressNames.Normalize(rule.Match);
            bool suffix;
            var labels = 0;
            if (match.StartsWith("*.", StringComparison.Ordinal))
            {
                var parent = match[2..];
                if (!query.EndsWith("." + parent, StringComparison.Ordinal))
                {
                    continue;
                }
                suffix = true;
                labels = parent.Count(c => c == '.') + 1;
            }
            else if (string.Equals(query, match, StringComparison.Ordinal))
            {
                suffix = false;
            }
            else
            {
                continue;
            }
            // Strictly better only, so an equal rule later in the list never displaces an earlier one.
            if (best < 0 || (bestSuffix && !suffix) || (bestSuffix && suffix && labels > bestLabels))
            {
                best = index;
                bestSuffix = suffix;
                bestLabels = labels;
            }
        }
        return best;
    }

    /// <summary>
    /// Why <c>peerEgressFakeIpCidr</c> cannot be used, or null when it can (vector <c>poolConfig</c>):
    /// an IPv4 prefix with zero host bits, /8 to /24, clear of the mesh. Overlap with this device's
    /// own interfaces is the caller's to check at startup, since it depends on the machine.
    /// </summary>
    public static string? FakeIpPoolProblem(string? cidr, string? meshCidr)
    {
        if (!Ipv4Cidr.TryParse(cidr?.Trim(), out var pool)
            || pool.PrefixLength is < FakeIpMinPrefix or > FakeIpMaxPrefix)
        {
            return PeerEgressCodes.FakeIpPoolInvalid;
        }
        var mesh = string.IsNullOrWhiteSpace(meshCidr) ? DefaultMeshCidr : meshCidr;
        if (Ipv4Cidr.TryParse(mesh, out var meshPrefix) && pool.Overlaps(meshPrefix))
        {
            return PeerEgressCodes.FakeIpPoolInvalid;
        }
        return null;
    }

    /// <summary>
    /// Whether phase two runs: asked for, on top of phase one, with a usable pool (vector
    /// <c>phaseTwo</c>). An unusable pool stops phase two alone; phase one carries on, and domain
    /// rules read as if the switch were off.
    /// </summary>
    public static PeerEgressPhaseTwo PhaseTwo(bool consumerEnabled, bool takeover, string? fakeIpCidr, string? meshCidr)
    {
        if (!consumerEnabled || !takeover)
        {
            return PeerEgressPhaseTwo.Off;
        }
        if (FakeIpPoolProblem(fakeIpCidr, meshCidr) is { } code)
        {
            return new PeerEgressPhaseTwo(false, code, default);
        }
        Ipv4Cidr.TryParse(fakeIpCidr?.Trim(), out var pool);
        return new PeerEgressPhaseTwo(true, null, pool);
    }

    /// <summary>
    /// The code the status gives a rule, null when it is in force (vector <c>ruleStatus</c>).
    /// </summary>
    /// <remarks>
    /// <see cref="Validate(PeerEgressRule, string?, Ipv4Cidr?)"/>, then the one check that is not
    /// about the rule itself: a domain rule whose egress is online and has not announced
    /// <c>domainTargetCapable</c>. Only online, because the catalogue says false for every offline
    /// egress; a rule to an offline egress is right and waiting, and its traffic is phase one's
    /// <c>egress-unavailable</c>, not a refused rule.
    /// </remarks>
    public static string? RuleStatus(PeerEgressRule rule, string? meshCidr, Ipv4Cidr? fakeIpPool,
        Func<long, bool> online, Func<long, bool> domainTargetCapable)
    {
        if (Validate(rule, meshCidr, fakeIpPool) is { } code)
        {
            return code;
        }
        if (IsDomainMatch(rule.Match)
            && (rule.Action?.Trim() ?? string.Empty) == ActionEgress
            && rule.EgressClientId is { } egress
            && online(egress) && !domainTargetCapable(egress))
        {
            return PeerEgressCodes.RuleEgressNoDomain;
        }
        return null;
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
