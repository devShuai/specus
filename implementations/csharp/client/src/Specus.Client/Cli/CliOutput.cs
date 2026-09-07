using System.Text.Json;
using System.Text.Json.Nodes;
using Specus.Client.Configuration;

namespace Specus.Client.Cli;

internal static class CliOutput
{
    internal static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);
    internal static int Result(bool json, string command, int code, object? data, string message)
    {
        if (command is "show" or "validate") command = "config " + command;
        if (json) Console.WriteLine(JsonSerializer.Serialize(new { schemaVersion = 1, command, ok = code == 0, exitCode = code, data, error = code == 0 ? null : message }, JsonOptions));
        else if (code == 0) Console.WriteLine(message);
        else Console.Error.WriteLine(message);
        return code;
    }
    internal static string SafeUrl(string raw)
    {
        if (!Uri.TryCreate(raw, UriKind.Absolute, out var uri)) return "<invalid>";
        return new UriBuilder(uri) { UserName = "", Password = "", Query = "", Fragment = "" }.Uri.AbsoluteUri;
    }
    internal static JsonNode RedactedConfig(SpecusClientConfig config)
    {
        var node = JsonSerializer.SerializeToNode(config)!;
        node["apiKey"] = "<redacted>"; node["secret"] = "<redacted>"; node["serverBaseUrl"] = SafeUrl(config.ServerBaseUrl);
        return node;
    }

    internal static string StateSummary(string command, object result)
    {
        var data = JsonSerializer.SerializeToElement(result, JsonOptions);
        var text = new System.Text.StringBuilder();
        foreach (var row in data.GetProperty("instances").EnumerateArray())
        {
            text.AppendLine($"PID {row.GetProperty("pid")} | {row.GetProperty("phase").GetString()}");
            if (command == "status") text.AppendLine($"  control authenticated: {row.GetProperty("controlAuthenticated")} | forwarding ready: {row.GetProperty("businessReady")} (targets not probed)");
            else
            {
                var items = row.GetProperty(command);
                if (items.GetArrayLength() == 0) text.AppendLine("  No entries. Check status for channel readiness.");
                foreach (var item in items.EnumerateArray())
                    text.AppendLine(command == "peers"
                        ? $"  {item.GetProperty("clientName").GetRawText()} | {item.GetProperty("virtualIp").GetRawText()} | online={item.GetProperty("online")}"
                        : $"  {item.GetProperty("name").GetRawText()} | {item.GetProperty("application").GetRawText()} | {item.GetProperty("accessTarget").GetRawText()} | available={item.GetProperty("available")}");
            }
        }
        return text.ToString().TrimEnd();
    }
}
