using System.Text.Json;

namespace Specus.Protocol.PeerEgress;

/// <summary>
/// The <c>egress-config</c> push, as a client reads it.
/// </summary>
/// <remarks>
/// The message is produced by three server implementations and read by three clients, so what a
/// client makes of it is a contract. The parts most likely to drift are the ones a JSON library
/// decides rather than the protocol: what an absent field becomes, and whether a value is normalised
/// before it is compared.
///
/// <para>Shared vector: <c>protocol/test-vectors/peer-egress-control-v1.json</c>.</para>
/// </remarks>
/// <param name="Revision">The snapshot number, for the caller's monotonic guard.</param>
public sealed record PeerEgressConfigMessage(long Revision, PeerEgressPolicy Policy)
{
    public const string Type = "egress-config";

    /// <summary>
    /// Reads a push, returning null for anything that is not one.
    /// </summary>
    /// <remarks>
    /// Refused: a type naming something else, a payload that is not an object, or text that is not
    /// JSON. Reading a catalogue as a policy would install one.
    ///
    /// <para>The revision guard is deliberately not here. It is the caller's state, and this has to
    /// give the same answer for the same message every time it is called.</para>
    /// </remarks>
    public static PeerEgressConfigMessage? Decode(string? payload)
    {
        if (string.IsNullOrEmpty(payload))
        {
            return null;
        }
        JsonDocument document;
        try
        {
            document = JsonDocument.Parse(payload);
        }
        catch (JsonException)
        {
            return null;
        }
        using (document)
        {
            var message = document.RootElement;
            if (message.ValueKind != JsonValueKind.Object
                || !message.TryGetProperty("type", out var type)
                || type.ValueKind != JsonValueKind.String
                || type.GetString() != Type)
            {
                return null;
            }

            var consumers = new List<long>();
            if (message.TryGetProperty("allowedConsumerClientIds", out var ids)
                && ids.ValueKind == JsonValueKind.Array)
            {
                foreach (var entry in ids.EnumerateArray())
                {
                    if (entry.TryGetInt64(out var value))
                    {
                        consumers.Add(value);
                    }
                }
            }

            var rules = new List<PeerEgressDestinationRule>();
            if (message.TryGetProperty("destinationRules", out var raw)
                && raw.ValueKind == JsonValueKind.Array)
            {
                foreach (var node in raw.EnumerateArray())
                {
                    if (node.ValueKind != JsonValueKind.Object)
                    {
                        continue;
                    }
                    rules.Add(new PeerEgressDestinationRule
                    {
                        Cidr = Text(node, "cidr"),
                        Protocols = Strings(node, "protocols"),
                        PortRanges = PortRanges(node),
                    });
                }
            }

            // Absent limits decode as zeros rather than as the record's defaults. Whether a zero
            // means "use the default" or "no limit" is the runtime's decision, and inventing a
            // number here would hide from it that the server named none.
            message.TryGetProperty("limits", out var limits);
            var policy = new PeerEgressPolicy
            {
                Enabled = message.TryGetProperty("enabled", out var enabled)
                    && enabled.ValueKind == JsonValueKind.True,
                // Trimmed and uppercased before it is stored. The judgment layer compares this for
                // equality against a scope it computes itself, so a push saying "public" would be
                // refused by an implementation that kept the raw string. An absent scope stays
                // empty, which denies: a missing authorization field must not fall back to the
                // permissive value.
                Scope = Text(message, "scope").Trim().ToUpperInvariant(),
                AllowedConsumerClientIds = consumers,
                DestinationRules = rules,
                Limits = new PeerEgressLimits
                {
                    MaxConcurrentFlows = Number(limits, "maxConcurrentFlows"),
                    MaxFlowsPerConsumer = Number(limits, "maxFlowsPerConsumer"),
                    IdleTimeoutSeconds = Number(limits, "idleTimeoutSeconds"),
                },
            };
            return new PeerEgressConfigMessage(Number64(message, "revision"), policy);
        }
    }

    private static string Text(JsonElement parent, string name) =>
        parent.ValueKind == JsonValueKind.Object
        && parent.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String
            ? value.GetString() ?? string.Empty
            : string.Empty;

    private static int Number(JsonElement parent, string name) =>
        parent.ValueKind == JsonValueKind.Object
        && parent.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.Number
        && value.TryGetInt32(out var parsed)
            ? parsed
            : 0;

    private static long Number64(JsonElement parent, string name) =>
        parent.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.Number
        && value.TryGetInt64(out var parsed)
            ? parsed
            : 0;

    private static IReadOnlyList<string> Strings(JsonElement parent, string name)
    {
        var values = new List<string>();
        if (parent.TryGetProperty(name, out var array) && array.ValueKind == JsonValueKind.Array)
        {
            foreach (var entry in array.EnumerateArray())
            {
                values.Add(entry.GetString() ?? string.Empty);
            }
        }
        return values;
    }

    private static IReadOnlyList<int[]> PortRanges(JsonElement node)
    {
        var ranges = new List<int[]>();
        if (node.TryGetProperty("portRanges", out var array) && array.ValueKind == JsonValueKind.Array)
        {
            foreach (var pair in array.EnumerateArray())
            {
                if (pair.ValueKind != JsonValueKind.Array)
                {
                    continue;
                }
                var bounds = new List<int>();
                foreach (var bound in pair.EnumerateArray())
                {
                    bounds.Add(bound.TryGetInt32(out var value) ? value : 0);
                }
                ranges.Add([.. bounds]);
            }
        }
        return ranges;
    }
}
