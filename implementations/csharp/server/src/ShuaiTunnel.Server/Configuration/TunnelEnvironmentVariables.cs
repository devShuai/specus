using System.Collections;
using Microsoft.Extensions.Configuration;

namespace ShuaiTunnel.Server.Configuration;

/// <summary>
/// Maps Java-style deployment variables such as TUNNEL_NETTY_PORT to the ASP.NET
/// configuration shape used by this rewrite, e.g. Tunnel:Netty:Port.
/// </summary>
public static class TunnelEnvironmentVariables
{
    private const string Prefix = "TUNNEL_";

    public static void AddTunnelEnvironmentVariables(this ConfigurationManager configuration)
    {
        configuration.AddInMemoryCollection(BuildConfigurationMapFromEnvironment(Environment.GetEnvironmentVariables()));
    }

    public static IDictionary<string, string?> BuildConfigurationMap(
        IEnumerable<KeyValuePair<string, string?>> variables)
    {
        var result = new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase);
        foreach (var (rawKey, value) in variables)
        {
            AddIfTunnelVariable(result, rawKey, value);
        }
        return result;
    }

    private static IDictionary<string, string?> BuildConfigurationMapFromEnvironment(IDictionary variables)
    {
        var result = new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase);
        foreach (DictionaryEntry entry in variables)
        {
            AddIfTunnelVariable(result, entry.Key as string, entry.Value?.ToString());
        }
        return result;
    }

    private static void AddIfTunnelVariable(IDictionary<string, string?> result, string? rawKey, string? value)
    {
        if (rawKey is null
            || !rawKey.StartsWith(Prefix, StringComparison.OrdinalIgnoreCase)
            || value is null)
        {
            return;
        }

        var key = MapKey(rawKey[Prefix.Length..]);
        if (key is not null)
        {
            result[key] = value;
        }
    }

    private static string? MapKey(string key)
    {
        if (string.IsNullOrWhiteSpace(key))
        {
            return null;
        }

        if (key.Contains("__", StringComparison.Ordinal))
        {
            var normalized = key.Replace("__", ":", StringComparison.Ordinal);
            return StartsWithKnownRoot(normalized) ? normalized : $"Tunnel:{normalized}";
        }

        var parts = key.Split('_', StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length == 0)
        {
            return null;
        }

        if (parts[0].Equals("CONNECTIONSTRINGS", StringComparison.OrdinalIgnoreCase)
            || (parts[0].Equals("CONNECTION", StringComparison.OrdinalIgnoreCase)
                && parts.Length > 1
                && parts[1].Equals("STRINGS", StringComparison.OrdinalIgnoreCase)))
        {
            var nameStart = parts[0].Equals("CONNECTION", StringComparison.OrdinalIgnoreCase) ? 2 : 1;
            return nameStart < parts.Length ? $"ConnectionStrings:{ToPascal(parts[nameStart..])}" : null;
        }

        if (parts.Length == 1)
        {
            return $"Tunnel:{ToSectionName(parts[0])}";
        }

        if (parts.Length >= 2
            && parts[0].Equals("CONNECTION", StringComparison.OrdinalIgnoreCase))
        {
            if (parts[1].Equals("DETAIL", StringComparison.OrdinalIgnoreCase))
            {
                return parts.Length == 2
                    ? "Tunnel:ConnectionRecord:DetailRetentionDays"
                    : $"Tunnel:ConnectionRecord:Detail{ToPascal(parts[2..])}";
            }

            if (parts[1].Equals("ARCHIVE", StringComparison.OrdinalIgnoreCase))
            {
                return parts.Length == 2
                    ? "Tunnel:ConnectionRecord:ArchiveIntervalMs"
                    : $"Tunnel:ConnectionRecord:Archive{ToPascal(parts[2..])}";
            }
        }

        if (parts.Length >= 2
            && parts[0].Equals("CLIENT", StringComparison.OrdinalIgnoreCase)
            && parts[1].Equals("AUTH", StringComparison.OrdinalIgnoreCase))
        {
            return parts.Length == 2
                ? "Tunnel:ClientAuth"
                : $"Tunnel:ClientAuth:{ToPascal(parts[2..])}";
        }

        if (parts.Length == 3
            && parts[0].Equals("LOGIN", StringComparison.OrdinalIgnoreCase)
            && parts[1].Equals("EXECUTOR", StringComparison.OrdinalIgnoreCase))
        {
            return parts[2].ToUpperInvariant() switch
            {
                "CORE" => "Tunnel:Login:ExecutorCoreSize",
                "MAX" => "Tunnel:Login:ExecutorMaxSize",
                "QUEUE" => "Tunnel:Login:ExecutorQueueCapacity",
                _ => null,
            };
        }

        if (parts.Length >= 2
            && parts[0].Equals("PEER", StringComparison.OrdinalIgnoreCase)
            && parts[1].Equals("MESH", StringComparison.OrdinalIgnoreCase))
        {
            return parts.Length == 2
                ? "Tunnel:PeerMesh"
                : $"Tunnel:PeerMesh:{ToPascal(parts[2..])}";
        }

        return $"Tunnel:{ToSectionName(parts[0])}:{ToPascal(parts[1..])}";
    }

    private static bool StartsWithKnownRoot(string key) =>
        key.StartsWith("Tunnel:", StringComparison.OrdinalIgnoreCase)
        || key.StartsWith("ConnectionStrings:", StringComparison.OrdinalIgnoreCase)
        || key.StartsWith("Kestrel:", StringComparison.OrdinalIgnoreCase);

    private static string ToSectionName(string token) => token.ToUpperInvariant() switch
    {
        "DB" => "Database",
        "OIDC" => "Oidc",
        _ => ToPascal(token),
    };

    private static string ToPascal(IEnumerable<string> tokens) =>
        string.Concat(tokens.Select(ToPascal));

    private static string ToPascal(string token)
    {
        if (string.IsNullOrEmpty(token))
        {
            return string.Empty;
        }

        var lower = token.ToLowerInvariant();
        return char.ToUpperInvariant(lower[0]) + lower[1..];
    }
}
