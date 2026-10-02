using Specus.Protocol.PeerEgress;

namespace Specus.Client.PeerMesh;

/// <summary>
/// What the last route apply left behind that cannot be recomputed.
/// </summary>
/// <remarks>
/// Only the conflicts, because only they came from outside: the installed set is in the journal,
/// and which rules are in force is recomputed from the rules.
/// </remarks>
internal sealed record PeerEgressApplyOutcome(long AtMillis,
    IReadOnlyList<PeerEgressRouteConflict> Conflicts, string Error, bool RolledBack, bool Applied)
{
    /// <summary>Nothing applied yet, which has to read differently from "applied nothing".</summary>
    public static PeerEgressApplyOutcome None { get; } =
        new(0L, [], string.Empty, false, false);
}

/// <summary>The consumer's own view, taken under its caller's lock.</summary>
/// <param name="Capable">Which egresses the last catalogue says resolve names.</param>
/// <param name="FakeIpPool">The pool while phase two runs, which is what domain rules are validated against.</param>
internal sealed record PeerEgressConsumerStatus(IReadOnlyList<PeerEgressRule> Rules,
    string MeshCidr, IReadOnlyDictionary<long, bool> Online, int Flows,
    IReadOnlyDictionary<string, long> Blocked,
    IReadOnlyDictionary<long, int>? FlowsByEgress = null,
    IReadOnlyDictionary<long, string>? Paths = null,
    IReadOnlyDictionary<long, bool>? Capable = null,
    Ipv4Cidr? FakeIpPool = null);

/// <summary>
/// The <c>consumer.dns</c> section, present only while <c>peerEgressDnsTakeover</c> is on
/// (protocol/spec/peer-egress-dns.md, section seven).
/// </summary>
/// <param name="Takeover">Whether the system's DNS points at the responder now: the journal is committed.</param>
/// <param name="Pool">The pool as configured, usable or not.</param>
/// <param name="Mappings">Mappings held when the snapshot was taken.</param>
/// <param name="Quarantined">Addresses still resting when the snapshot was taken.</param>
/// <param name="Code">
/// Why phase two does not run although it was asked for, or why the system's DNS is not taken over;
/// null otherwise.
/// </param>
internal sealed record PeerEgressDnsStatus(bool Takeover, string Pool, int Mappings, int Quarantined, string? Code)
{
    /// <summary>Whether phase two runs now: pool, route, responder.</summary>
    public bool Active { get; init; }

    /// <summary>The takeover journal: <c>none</c>, <c>pending</c> or <c>committed</c>.</summary>
    public string Journal { get; init; } = "none";

    /// <summary>With <c>EGRESS_DNS_TAKEOVER_REFUSED</c>: which check refused.</summary>
    public string? Reason { get; init; }

    /// <summary>
    /// With <c>EGRESS_DNS_TAKEOVER_FAILED</c>: the first line the failing command printed, or which
    /// running client holds the takeover.
    /// </summary>
    public string? Error { get; init; }

    /// <summary>The responder's listen address; null while phase two does not run.</summary>
    public string? Listen { get; init; }

    /// <summary>Where it forwards, as configured; empty when nothing is.</summary>
    public IReadOnlyList<string>? Upstreams { get; init; }

    /// <summary>What it has done with queries since it started; zeros before it ever ran.</summary>
    public PeerEgressDnsCounters? Queries { get; init; }
}

/// <summary>The egress role's own view, taken under its lock.</summary>
internal sealed record PeerEgressRuntimeStatus(bool Enabled, long Revision, int Flows,
    long TotalFlows, long BytesIn, long BytesOut, IReadOnlyDictionary<string, long> Refused);

/// <summary>
/// What an operator can read about this node's egress roles.
/// </summary>
/// <remarks>
/// Until this existed the feature could not say what it was doing. A rule an operator wrote and
/// this feature refused was written to the log once, at the moment it was refused, and then
/// nowhere: the route planner's own comment calls that "a leak they have no way to notice". Same
/// for a route that was not installed because something else already owned the prefix -- the
/// traffic goes out locally and every surface looks healthy.
///
/// <para>Two of the fields here are derived rather than remembered, and that is deliberate.
/// Whether a rule is in force is recomputed from the rule itself, the same way
/// <see cref="PeerEgressRules.Match"/> recomputes it before every decision, so the status cannot
/// drift from what steering actually does. Whether a route is installed cannot be derived -- the
/// answer came from the platform's routing table at apply time -- so that one is remembered.</para>
///
/// <para>Nothing secret travels here. Rule matches and prefixes are the operator's own
/// configuration and client IDs already appear in the peer list; tokens, keys and addresses learned
/// from other peers do not.</para>
///
/// <para>The shape is the one <c>protocol/spec/peer-egress.md</c> pins, because the Go and Java
/// clients write the same state file and any of the three CLIs reads whichever wrote it.</para>
/// </remarks>
internal static class PeerEgressStatus
{
    // The values of a peer entry's path: what carries frames to that egress now.
    internal const string PathDirect = "direct";
    internal const string PathRelay = "relay";
    internal const string PathNone = "none";

    /// <summary>The whole section, assembled for the state file.</summary>
    public static Dictionary<string, object?> Section(PeerEgressConsumerStatus? consumer,
        IReadOnlyList<PeerEgressRoute> installed, PeerEgressApplyOutcome outcome,
        PeerEgressRuntimeStatus? runtime) => Section(consumer, installed, outcome, runtime, true, []);

    /// <summary>
    /// The section with the consumer's master switch. Off, no consumer is built, so the rules come
    /// from the configuration; they are listed all the same, because "kept but not taking anything
    /// over" is a state to show rather than to hide.
    /// </summary>
    public static Dictionary<string, object?> Section(PeerEgressConsumerStatus? consumer,
        IReadOnlyList<PeerEgressRoute> installed, PeerEgressApplyOutcome outcome,
        PeerEgressRuntimeStatus? runtime, bool enabled, IReadOnlyList<PeerEgressRule>? configured,
        PeerEgressDnsStatus? dns = null)
    {
        var consumerSection = ConsumerSection(consumer, installed, outcome);
        consumerSection["enabled"] = enabled;
        if (!enabled && configured is { Count: > 0 })
        {
            consumerSection["rules"] = SwitchedOffRules(configured);
        }
        if (dns is not null)
        {
            consumerSection["dns"] = DnsSection(dns);
        }
        return new()
        {
            ["consumer"] = consumerSection,
            ["egress"] = EgressSection(runtime),
        };
    }

    /// <summary>
    /// Configured rules while the master switch is off. None is in force; a rule the user switched
    /// off says so itself, the rest name the master switch.
    /// </summary>
    internal static List<Dictionary<string, object?>> SwitchedOffRules(IReadOnlyList<PeerEgressRule> configured)
    {
        var rules = new List<Dictionary<string, object?>>(configured.Count);
        for (var index = 0; index < configured.Count; index++)
        {
            var rule = configured[index];
            var entry = new Dictionary<string, object?>
            {
                ["index"] = index,
                ["match"] = rule.Match?.Trim() ?? string.Empty,
                ["kind"] = Kind(rule),
                ["action"] = rule.Action?.Trim() ?? string.Empty,
                ["inForce"] = false,
                ["code"] = rule.SwitchedOff ? PeerEgressCodes.RuleDisabled : PeerEgressCodes.ConsumerDisabled,
            };
            if (rule.EgressClientId is { } egress and not 0)
            {
                entry["egressClientId"] = egress;
            }
            if (rule.Port is { } port and not 0)
            {
                entry["port"] = port;
            }
            rules.Add(entry);
        }
        return rules;
    }

    private static Dictionary<string, object?> ConsumerSection(PeerEgressConsumerStatus? consumer,
        IReadOnlyList<PeerEgressRoute> installed, PeerEgressApplyOutcome outcome)
    {
        var section = new Dictionary<string, object?>
        {
            ["active"] = consumer is not null,
            ["rules"] = Array.Empty<object>(),
            ["routes"] = Array.Empty<object>(),
            ["peers"] = Array.Empty<object>(),
            ["flows"] = 0,
            // Counted by reason rather than totalled: "no egress online" and "denied by the
            // egress" are the same number and completely different problems.
            ["blocked"] = new Dictionary<string, long>(),
        };
        if (consumer is null)
        {
            return section;
        }

        var rules = new List<Dictionary<string, object?>>();
        var peers = new SortedDictionary<long, bool>();
        for (var index = 0; index < consumer.Rules.Count; index++)
        {
            var rule = consumer.Rules[index];
            // RuleStatus returns null for a usable rule here, where the Go implementation returns an
            // empty string. Normalised at the boundary rather than compared against null twice
            // below: "in force" is one condition, and writing it two ways is how the two halves of
            // this section end up disagreeing about the same rule. It is the validation steering
            // uses, plus phase two's one check about the egress rather than the rule: a domain rule
            // to an online egress that does not resolve names.
            var code = PeerEgressRules.RuleStatus(rule, consumer.MeshCidr, consumer.FakeIpPool,
                egress => consumer.Online.TryGetValue(egress, out var up) && up,
                egress => consumer.Capable is not null && consumer.Capable.TryGetValue(egress, out var able) && able)
                ?? string.Empty;
            // inForce is the field worth having. A rule that is configured but refused reads false
            // and carries its code, which is the difference between "this rule is protecting me"
            // and "this rule is text in a file".
            var entry = new Dictionary<string, object?>
            {
                ["index"] = index,
                ["match"] = (rule.Match ?? string.Empty).Trim(),
                ["kind"] = Kind(rule),
                ["action"] = (rule.Action ?? string.Empty).Trim(),
                ["inForce"] = code.Length == 0,
            };
            if (code.Length != 0)
            {
                entry["code"] = code;
            }
            if (rule.EgressClientId is { } target && target != 0L)
            {
                entry["egressClientId"] = target;
                if (code.Length == 0)
                {
                    // Only rules that steer contribute a peer. A refused rule naming a peer would
                    // otherwise report an egress this node will never send to.
                    peers[target] = consumer.Online.TryGetValue(target, out var online) && online;
                }
            }
            if (rule.Port is { } port && port != 0)
            {
                entry["port"] = port;
            }
            rules.Add(entry);
        }
        section["rules"] = rules;
        section["peers"] = peers
            .Select(peer => new Dictionary<string, object?>
            {
                ["clientId"] = peer.Key,
                ["online"] = peer.Value,
                ["path"] = consumer.Paths is not null && consumer.Paths.TryGetValue(peer.Key, out var path) ? path : PathNone,
                ["flows"] = consumer.FlowsByEgress is not null && consumer.FlowsByEgress.TryGetValue(peer.Key, out var count) ? count : 0,
            })
            .ToList();
        section["flows"] = consumer.Flows;
        section["blocked"] = new SortedDictionary<string, long>(
            consumer.Blocked.ToDictionary(entry => entry.Key, entry => entry.Value));
        section["routes"] = RoutesSection(installed, outcome);
        if (outcome.Applied)
        {
            section["appliedAtUnixMs"] = outcome.AtMillis;
            section["rolledBack"] = outcome.RolledBack;
            if (outcome.Error.Length != 0)
            {
                section["routeError"] = outcome.Error;
            }
        }
        return section;
    }

    /// <summary>What a rule's match is written as: a name or an address.</summary>
    internal static string Kind(PeerEgressRule rule) =>
        PeerEgressRules.IsDomainMatch(rule.Match) ? KindDomain : KindCidr;

    internal const string KindCidr = "cidr";
    internal const string KindDomain = "domain";

    /// <summary>
    /// <c>consumer.dns</c>, in the order the spec lists it. The responder's fields are there while
    /// it answers; the journal arrives with step five. What is not delivered is left out rather than
    /// written empty.
    /// </summary>
    private static Dictionary<string, object?> DnsSection(PeerEgressDnsStatus dns)
    {
        var section = new Dictionary<string, object?> { ["active"] = dns.Active, ["takeover"] = dns.Takeover };
        if (dns.Listen is not null)
        {
            section["listen"] = dns.Listen;
        }
        section["pool"] = dns.Pool;
        section["mappings"] = dns.Mappings;
        section["quarantined"] = dns.Quarantined;
        if (dns.Upstreams is not null)
        {
            section["upstreams"] = dns.Upstreams;
        }
        section["journal"] = dns.Journal;
        if (dns.Queries is { } queries)
        {
            section["queries"] = new Dictionary<string, object?>
            {
                ["answered"] = queries.Answered,
                ["forwarded"] = queries.Forwarded,
                ["failed"] = queries.Failed,
            };
        }
        if (dns.Code is not null)
        {
            section["code"] = dns.Code;
        }
        if (dns.Reason is not null)
        {
            section["reason"] = dns.Reason;
        }
        if (dns.Error is not null)
        {
            section["error"] = dns.Error;
        }
        return section;
    }

    /// <summary>The routes this feature owns and the ones it wanted and did not get.</summary>
    /// <remarks>
    /// The installed set comes from the journal rather than from the last apply, because the
    /// journal is what a restart adopts: after a crash the routes are still in the table and the
    /// apply that put them there belongs to a process that is gone.
    /// </remarks>
    private static List<Dictionary<string, object?>> RoutesSection(
        IReadOnlyList<PeerEgressRoute> installed, PeerEgressApplyOutcome outcome)
    {
        var routes = installed.Select(route => new Dictionary<string, object?>
        {
            ["cidr"] = route.Cidr,
            ["kind"] = PeerEgressRoutePlanner.WireName(route.Kind),
            ["origin"] = route.Origin,
            ["installed"] = true,
        }).ToList();
        // A route refused because the prefix already had an owner is still listed, with installed
        // false and what owns it. Dropping it would make the status look clean while the traffic it
        // was meant to capture leaves by the physical interface.
        routes.AddRange(outcome.Conflicts.Select(conflict => new Dictionary<string, object?>
        {
            ["cidr"] = conflict.Route.Cidr,
            ["kind"] = PeerEgressRoutePlanner.WireName(conflict.Route.Kind),
            ["origin"] = conflict.Route.Origin,
            ["installed"] = false,
            ["conflict"] = conflict.Existing,
        }));
        return routes
            .OrderBy(entry => entry["cidr"] as string, StringComparer.Ordinal)
            .ThenBy(entry => entry["origin"] as string, StringComparer.Ordinal)
            .ToList();
    }

    private static Dictionary<string, object?> EgressSection(PeerEgressRuntimeStatus? runtime)
    {
        var section = new Dictionary<string, object?>
        {
            ["active"] = false,
            ["flows"] = 0,
            ["refused"] = new Dictionary<string, long>(),
        };
        if (runtime is null)
        {
            return section;
        }
        section["active"] = runtime.Enabled;
        section["flows"] = runtime.Flows;
        section["refused"] = new SortedDictionary<string, long>(
            runtime.Refused.ToDictionary(entry => entry.Key, entry => entry.Value));
        section["totalFlows"] = runtime.TotalFlows;
        section["bytesIn"] = runtime.BytesIn;
        section["bytesOut"] = runtime.BytesOut;
        if (runtime.Revision != 0L)
        {
            section["revision"] = runtime.Revision;
        }
        return section;
    }
}
