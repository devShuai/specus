using System.Text;
using System.Text.Json;

namespace Specus.Client.Cli;

/// <summary>
/// Rendering the egress section of a live instance's state for a person.
/// </summary>
/// <remarks>
/// The JSON form carries everything; this decides what a person is shown. The rule it follows is to
/// print the problems and count the rest: a rule that is configured but not in force, a route this
/// feature wanted and did not get, an egress peer a rule names that is offline. Those are the three
/// ways the feature can be doing nothing while every other surface looks healthy, and they are the
/// reason the section exists.
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

        var lines = new List<string>
        {
            $"  consumer: {rules.Count} rules ({refused} not in force)"
                + $" | {routes.Count} routes ({notInstalled} not installed)"
                + $" | {Number(present, "flows")} flows"
                + $" | {peers.Count} egress peers ({offline} offline)",
        };

        // Then the problems, one line each, in the order an operator would act on them: a rule
        // that is not in force steers nothing at all, a route that is not installed means the
        // traffic leaves locally, and an offline peer means the rule is in force with nowhere to
        // send.
        lines.AddRange(rules.Where(rule => !Flag(rule, "inForce")).Select(rule =>
            $"    rule {Number(rule, "index")} \"{Text(rule, "match")}\""
                + $": NOT IN FORCE ({Text(rule, "code")})"));
        lines.AddRange(routes.Where(route => !Flag(route, "installed")).Select(route =>
            $"    route {Text(route, "cidr")} ({Text(route, "origin")})"
                + $": NOT INSTALLED, already present: {Text(route, "conflict")}"));
        lines.AddRange(peers.Where(peer => !Flag(peer, "online")).Select(peer =>
            $"    egress peer {Number(peer, "clientId")}"
                + ": offline, so its rules have nowhere to send"));

        var error = Text(present, "routeError");
        if (error.Length != 0)
        {
            lines.Add($"    route install failed: {error} (rolledBack={Flag(present, "rolledBack")})");
        }
        var blocked = Counts(present, "blocked");
        if (blocked.Count != 0)
        {
            lines.Add("    blocked: " + Join(blocked));
        }
        return lines;
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
