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
internal sealed record PeerEgressConsumerStatus(IReadOnlyList<PeerEgressRule> Rules,
    string MeshCidr, IReadOnlyDictionary<long, bool> Online, int Flows,
    IReadOnlyDictionary<string, long> Blocked);

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
    /// <summary>The whole section, assembled for the state file.</summary>
    public static Dictionary<string, object?> Section(PeerEgressConsumerStatus? consumer,
        IReadOnlyList<PeerEgressRoute> installed, PeerEgressApplyOutcome outcome,
        PeerEgressRuntimeStatus? runtime) => new()
        {
            ["consumer"] = ConsumerSection(consumer, installed, outcome),
            ["egress"] = EgressSection(runtime),
        };

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
            // Validate returns null for a usable rule here, where the Go implementation returns an
            // empty string. Normalised at the boundary rather than compared against null twice
            // below: "in force" is one condition, and writing it two ways is how the two halves of
            // this section end up disagreeing about the same rule.
            var code = PeerEgressRules.Validate(rule, consumer.MeshCidr) ?? string.Empty;
            // inForce is the field worth having. A rule that is configured but refused reads false
            // and carries its code, which is the difference between "this rule is protecting me"
            // and "this rule is text in a file".
            var entry = new Dictionary<string, object?>
            {
                ["index"] = index,
                ["match"] = (rule.Match ?? string.Empty).Trim(),
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
