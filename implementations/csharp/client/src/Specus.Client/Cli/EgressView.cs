using System.Text;
using System.Text.Json;

namespace Specus.Client.Cli;

/// <summary>
/// Rendering the egress section of a live instance's state for a person.
/// </summary>
/// <remarks>
/// The JSON form carries everything; this decides what a person is shown. The rule it follows is to
/// print the problems and count the rest: a rule that is configured but not in force, a route this
/// feature wanted and did not get, an egress peer a rule names that is offline -- or online and
/// still unable to take a flow, because the catalogue does not offer it or its client is too old.
/// Those are the ways the feature can be doing nothing while every other surface looks healthy, and
/// they are the reason the section exists.
///
/// <para>So a working node prints two lines and a broken one prints those two plus exactly what is
/// wrong. Listing the healthy rules too would push the one line that matters off the screen on any
/// node with a real rule set.</para>
///
/// <para>Every read here tolerates a missing or wrongly typed field rather than asserting one,
/// because the state file may have been written by the Go or Java client. A status command that
/// threw on a field somebody spelled differently would be worse than one that prints a zero.</para>
/// </remarks>
internal static class EgressView
{
    internal static List<string> Lines(JsonElement? section)
    {
        if (section is not { ValueKind: JsonValueKind.Object } present)
        {
            return ["  No egress state. This build reported none."];
        }
        var lines = ConsumerLines(Child(present, "consumer"));
        lines.AddRange(EgressLines(Child(present, "egress")));
        return lines;
    }

    private static List<string> ConsumerLines(JsonElement? consumer)
    {
        // Rules saved with the master switch off are a state of their own, and the one where nothing
        // is in force by design; said as such rather than folded into "not configured". A state file
        // from a build without the switch has no such field and reads as before.
        if (consumer is { } switched
            && switched.ValueKind == JsonValueKind.Object
            && switched.TryGetProperty("enabled", out var enabled) && enabled.ValueKind == JsonValueKind.False
            && switched.TryGetProperty("rules", out var configured) && configured.ValueKind == JsonValueKind.Array
            && configured.GetArrayLength() > 0)
        {
            return [$"  consumer: takeover off | {configured.GetArrayLength()} rules saved, none in force (peerEgressEnabled is false)"];
        }
        if (consumer is not { } present || !Flag(present, "active"))
        {
            return ["  consumer: not configured (no rules have been applied)"];
        }
        var rules = Items(present, "rules");
        var routes = Items(present, "routes");
        var peers = Items(present, "peers");
        var refused = rules.Count(rule => !Flag(rule, "inForce"));
        var notInstalled = routes.Count(route => !Flag(route, "installed"));
        var offline = peers.Count(peer => !Flag(peer, "online"));
        var relayed = peers.Count(peer => Text(peer, "path") == "relay");

        var lines = new List<string>
        {
            $"  consumer: {rules.Count} rules ({refused} not in force)"
                + $" | {routes.Count} routes ({notInstalled} not installed)"
                + $" | {Number(present, "flows")} flows"
                + $" | {peers.Count} egress peers ({offline} offline, {relayed} via relay)",
        };

        // Then the problems, one line each, in the order an operator would act on them: a rule
        // that is not in force steers nothing at all, a route that is not installed means the
        // traffic leaves locally, and an offline peer means the rule is in force with nowhere to
        // send.
        lines.AddRange(rules.Where(rule => !Flag(rule, "inForce")).Select(rule =>
            $"    rule {Number(rule, "index")} \"{Text(rule, "match")}\""
                + $": NOT IN FORCE ({Text(rule, "code")})"));
        foreach (var route in routes.Where(route => !Flag(route, "installed")))
        {
            lines.Add($"    route {Text(route, "cidr")} ({Text(route, "origin")})"
                + $": NOT INSTALLED, already present: {Text(route, "conflict")}");
            lines.Add("      fix: remove or narrow that route, or change the rule; the client retries every 60 s");
        }
        // Each problem is followed by what to do about it, in the same words in every runtime and on
        // the local page. A peer that is online with no path yet is a problem too: its rules are in
        // force and have nowhere to send. So is one the catalogue does not offer to this device, or
        // whose client does not support peer egress: online, and its destinations blocked all the
        // same. One line pair per peer, the first that holds, in the order protocol/spec/peer-egress.md
        // pins (能力不支持): offline, not offered, unsupported, no path.
        foreach (var peer in peers)
        {
            var id = Number(peer, "clientId");
            var standing = Text(peer, "standing");
            if (!Flag(peer, "online"))
            {
                lines.Add($"    egress peer {id}: offline, so its rules have nowhere to send");
                lines.Add($"      fix: start egress device {id} or restore its connection; until then its destinations are blocked, not sent locally");
            }
            else if (standing == "not-offered")
            {
                lines.Add($"    egress peer {id}: not offered to this device by the server's egress catalog");
                lines.Add("      fix: ask an administrator to enable its egress policy and allow this device, and check the mesh ACL and the tenant switch; until then its destinations are blocked, not sent locally");
            }
            else if (standing == "unsupported")
            {
                lines.Add($"    egress peer {id}: online, but its client does not support peer egress");
                lines.Add($"      fix: upgrade the client on egress device {id}; until then its destinations are blocked, not sent locally");
            }
            else if (Text(peer, "path") == "none")
            {
                lines.Add($"    egress peer {id}: online but no path to it yet");
                lines.Add("      fix: wait for a direct or relay path; if it lasts, check that both devices reach the server over UDP");
            }
        }
        // Once, not per peer: it is about the server. Only "none" says it; "waiting" is the first
        // 30 seconds of every session, and a state file without the field is from a build that did
        // not know to ask.
        if (Text(present, "catalog") == "none")
        {
            lines.Add("    server: sent no egress catalog; it may be too old for peer egress");
            lines.Add("      fix: upgrade the server; until then whether an egress takes a flow is up to the egress itself");
        }

        var error = Text(present, "routeError");
        if (error.Length != 0)
        {
            lines.Add($"    route install failed: {error} (rolledBack={Flag(present, "rolledBack")})");
            lines.Add("      fix: " + RouteErrorFix(error));
        }
        var blocked = Counts(present, "blocked");
        if (blocked.Count != 0)
        {
            lines.Add("    blocked: " + Join(blocked));
        }
        return lines;
    }

    /// <summary>
    /// What to do about a failed route install. A refused permission is the common case and has one
    /// answer; anything else is in the log line of the command that failed.
    /// </summary>
    internal static string RouteErrorFix(string message)
    {
        var lower = message.ToLowerInvariant();
        return new[] { "permission", "denied", "not permitted", "elevat", "access" }.Any(lower.Contains)
            ? "run the client as administrator or root, with peerMeshDevice set to auto"
            : "the client log names the route command that failed; fix what it reports and restart the client";
    }

    private static List<string> EgressLines(JsonElement? egress)
    {
        if (egress is not { } present || !Flag(present, "active"))
        {
            // Not a problem and not hidden either. A node that is only a consumer says so, which
            // is what tells an operator who expected it to serve that no policy has arrived.
            return ["  egress: not serving (no policy has enabled it)"];
        }
        var lines = new List<string>
        {
            $"  egress: serving | {Number(present, "flows")} flows"
                + $" | {Number(present, "totalFlows")} total"
                + $" | in {Number(present, "bytesIn")} B | out {Number(present, "bytesOut")} B",
        };
        var refused = Counts(present, "refused");
        if (refused.Count != 0)
        {
            // By code, because each code is a different conversation to have with whoever owns the
            // other end.
            lines.Add("    refused: " + Join(refused));
        }
        return lines;
    }

    private static JsonElement? Child(JsonElement parent, string name) =>
        parent.ValueKind == JsonValueKind.Object
            && parent.TryGetProperty(name, out var value)
            && value.ValueKind == JsonValueKind.Object
                ? value
                : null;

    private static List<JsonElement> Items(JsonElement parent, string name)
    {
        if (parent.ValueKind != JsonValueKind.Object
            || !parent.TryGetProperty(name, out var value)
            || value.ValueKind != JsonValueKind.Array)
        {
            return [];
        }
        return value.EnumerateArray().Where(item => item.ValueKind == JsonValueKind.Object).ToList();
    }

    private static bool Flag(JsonElement parent, string name) =>
        parent.ValueKind == JsonValueKind.Object
            && parent.TryGetProperty(name, out var value)
            && value.ValueKind == JsonValueKind.True;

    private static long Number(JsonElement parent, string name) =>
        parent.ValueKind == JsonValueKind.Object
            && parent.TryGetProperty(name, out var value)
            && value.ValueKind == JsonValueKind.Number
            && value.TryGetInt64(out var number)
                ? number
                : 0L;

    private static string Text(JsonElement parent, string name) =>
        parent.ValueKind == JsonValueKind.Object
            && parent.TryGetProperty(name, out var value)
            && value.ValueKind == JsonValueKind.String
                ? value.GetString() ?? string.Empty
                : string.Empty;

    private static SortedDictionary<string, long> Counts(JsonElement parent, string name)
    {
        var counts = new SortedDictionary<string, long>(StringComparer.Ordinal);
        if (parent.ValueKind != JsonValueKind.Object
            || !parent.TryGetProperty(name, out var value)
            || value.ValueKind != JsonValueKind.Object)
        {
            return counts;
        }
        foreach (var field in value.EnumerateObject())
        {
            // Zeros are dropped rather than printed. A counter that has never fired says nothing,
            // and a line of them would bury the one that has.
            if (field.Value.ValueKind == JsonValueKind.Number
                && field.Value.TryGetInt64(out var count) && count != 0)
            {
                counts[field.Name] = count;
            }
        }
        return counts;
    }

    private static string Join(SortedDictionary<string, long> counts)
    {
        var text = new StringBuilder();
        foreach (var (name, count) in counts)
        {
            if (text.Length != 0)
            {
                text.Append(", ");
            }
            text.Append(name).Append('=').Append(count);
        }
        return text.ToString();
    }
}
