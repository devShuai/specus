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
