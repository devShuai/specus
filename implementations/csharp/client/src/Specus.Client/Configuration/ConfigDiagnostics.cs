using System.Text.Json;

namespace Specus.Client.Configuration;

internal static class ConfigDiagnostics
{
    internal static void Report(string json, SpecusClientConfig effective, Action<string> warning)
    {
        using var raw = JsonDocument.Parse(json, new JsonDocumentOptions
        {
            CommentHandling = JsonCommentHandling.Skip, AllowTrailingCommas = true,
        });
        using var shape = JsonDocument.Parse(JsonSerializer.Serialize(new SpecusClientConfig()));
        Unknown(raw.RootElement, shape.RootElement, "", warning);
        foreach (var property in raw.RootElement.EnumerateObject())
        {
            int? actual = property.Name.Equals("peerMeshMtu", StringComparison.OrdinalIgnoreCase) ? effective.PeerMeshMtu
                : property.Name.Equals("updateCheckIntervalHours", StringComparison.OrdinalIgnoreCase) ? effective.UpdateCheckIntervalHours : null;
            if (actual is not null && (!property.Value.TryGetInt32(out var input) || input != actual))
                warning($"{property.Name} normalized to {actual}");
        }
        EgressRules(effective, warning);
    }

    /// <summary>Names every egress rule that will not be in force, before anything connects.</summary>
    /// <remarks>
    /// A warning rather than a failure, matching the runtime: a refused rule is skipped and the rest
    /// take effect. The index and the code are printed and the match is not, since configuration
    /// warnings do not print configuration values. Checked against the default mesh network, because
    /// the real one arrives from the server at login.
    /// </remarks>
    private static void EgressRules(SpecusClientConfig effective, Action<string> warning)
    {
        var rules = effective.PeerEgressRules ?? [];
        for (var index = 0; index < rules.Count; index++)
        {
            var rule = rules[index];
            var code = rule is null
                ? Specus.Protocol.PeerEgress.PeerEgressCodes.RuleMalformed
                : Specus.Protocol.PeerEgress.PeerEgressRules.Validate(rule,
                    Specus.Protocol.PeerEgress.PeerEgressRules.DefaultMeshCidr);
            if (code is not null)
                warning($"peerEgressRules[{index}] is not in force: {code}");
        }
    }

    private static void Unknown(JsonElement raw, JsonElement shape, string prefix, Action<string> warning)
    {
        foreach (var property in raw.EnumerateObject())
        {
            var known = shape.EnumerateObject().FirstOrDefault(p => p.Name.Equals(property.Name, StringComparison.OrdinalIgnoreCase));
            if (known.Equals(default(JsonProperty)))
            {
                if (prefix.Length == 0 && property.Name is "upstreamTls" or "openUpdatePage")
                    warning($"{property.Name} is a shared configuration field not used by .NET");
                else
                    warning($"Unknown configuration field {JsonSerializer.Serialize(prefix + property.Name)}; ignored");
            }
            else if (property.Value.ValueKind == JsonValueKind.Object && known.Value.ValueKind == JsonValueKind.Object)
                Unknown(property.Value, known.Value, prefix + known.Name + ".", warning);
        }
    }
}
