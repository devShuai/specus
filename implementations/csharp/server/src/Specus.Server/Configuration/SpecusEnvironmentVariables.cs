using System.Collections;
using Microsoft.Extensions.Configuration;

namespace Specus.Server.Configuration;

/// <summary>
/// Maps Java-style deployment variables such as SPECUS_NETTY_PORT to the ASP.NET
/// configuration shape used by this rewrite, e.g. Specus:Netty:Port.
/// </summary>
public static class SpecusEnvironmentVariables
{
    private const string Prefix = "SPECUS_";

    public static void AddSpecusEnvironmentVariables(this ConfigurationManager configuration)
    {
        configuration.AddInMemoryCollection(BuildConfigurationMapFromEnvironment(Environment.GetEnvironmentVariables()));
    }

    public static IDictionary<string, string?> BuildConfigurationMap(
        IEnumerable<KeyValuePair<string, string?>> variables)
    {
        var result = new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase);
        foreach (var (rawKey, value) in variables)
        {
            AddIfSpecusVariable(result, rawKey, value);
        }
        return result;
    }

    private static IDictionary<string, string?> BuildConfigurationMapFromEnvironment(IDictionary variables)
    {
        var result = new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase);
        foreach (DictionaryEntry entry in variables)
        {
            AddIfSpecusVariable(result, entry.Key as string, entry.Value?.ToString());
        }
        return result;
    }

    private static void AddIfSpecusVariable(IDictionary<string, string?> result, string? rawKey, string? value)
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
            if (key.Equals("Specus:PeerMesh:PublicStunServers", StringComparison.OrdinalIgnoreCase))
            {
                AddStringList(result, key, value);
                return;
            }
            result[key] = value;
        }
    }

    private static void AddStringList(IDictionary<string, string?> result, string key, string value)
    {
        var index = 0;
        foreach (var item in value.Split([',', ';'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            result[$"{key}:{index++}"] = item;
        }
    }

    private static string? MapKey(string key)
    {
        if (string.IsNullOrWhiteSpace(key))
        {
            return null;
        }

        // This setting belongs directly to the Specus root. The generic underscore mapper would
        // incorrectly turn SPECUS_TRUSTED_PROXIES into Specus:Trusted:Proxies, which the
        // SpecusOptions binder never reads.
        if (key.Equals("TRUSTED_PROXIES", StringComparison.OrdinalIgnoreCase))
        {
            return "Specus:TrustedProxies";
        }

        if (key.StartsWith("CLIENT_PACKAGES_", StringComparison.OrdinalIgnoreCase))
        {
            var suffix = key["CLIENT_PACKAGES_".Length..]
                .Split('_', StringSplitOptions.RemoveEmptyEntries);
            return suffix.Length == 0 ? "Specus:ClientPackages" : $"Specus:ClientPackages:{ToPascal(suffix)}";
        }

        if (key.Contains("__", StringComparison.Ordinal))
        {
            var normalized = key.Replace("__", ":", StringComparison.Ordinal);
            return StartsWithKnownRoot(normalized) ? normalized : $"Specus:{normalized}";
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
            return $"Specus:{ToSectionName(parts[0])}";
        }

        if (parts.Length >= 2
            && parts[0].Equals("CONNECTION", StringComparison.OrdinalIgnoreCase))
        {
            if (parts[1].Equals("DETAIL", StringComparison.OrdinalIgnoreCase))
            {
                return parts.Length == 2
                    ? "Specus:ConnectionRecord:DetailRetentionDays"
                    : $"Specus:ConnectionRecord:Detail{ToPascal(parts[2..])}";
            }

            if (parts[1].Equals("ARCHIVE", StringComparison.OrdinalIgnoreCase))
            {
                return parts.Length == 2
                    ? "Specus:ConnectionRecord:ArchiveIntervalMs"
                    : $"Specus:ConnectionRecord:Archive{ToPascal(parts[2..])}";
            }
        }

        if (parts.Length >= 2
            && parts[0].Equals("CLIENT", StringComparison.OrdinalIgnoreCase)
            && parts[1].Equals("AUTH", StringComparison.OrdinalIgnoreCase))
        {
            return parts.Length == 2
                ? "Specus:ClientAuth"
                : $"Specus:ClientAuth:{ToPascal(parts[2..])}";
        }

        if (parts.Length == 3
            && parts[0].Equals("LOGIN", StringComparison.OrdinalIgnoreCase)
            && parts[1].Equals("EXECUTOR", StringComparison.OrdinalIgnoreCase))
        {
            return parts[2].ToUpperInvariant() switch
            {
                "CORE" => "Specus:Login:ExecutorCoreSize",
                "MAX" => "Specus:Login:ExecutorMaxSize",
                "QUEUE" => "Specus:Login:ExecutorQueueCapacity",
                _ => null,
            };
        }

        if (parts.Length >= 2
            && parts[0].Equals("PEER", StringComparison.OrdinalIgnoreCase)
            && parts[1].Equals("MESH", StringComparison.OrdinalIgnoreCase))
        {
            return parts.Length == 2
                ? "Specus:PeerMesh"
                : $"Specus:PeerMesh:{ToPascal(parts[2..])}";
        }

        if (parts.Length >= 2
            && parts[0].Equals("OBJECT", StringComparison.OrdinalIgnoreCase)
            && parts[1].Equals("STORAGE", StringComparison.OrdinalIgnoreCase))
        {
            if (parts.Length == 3 && parts[2].Equals("PREFIX", StringComparison.OrdinalIgnoreCase))
            {
                return "Specus:ObjectStorage:ObjectPrefix";
            }
            return parts.Length == 2
                ? "Specus:ObjectStorage"
                : $"Specus:ObjectStorage:{ToPascal(parts[2..])}";
        }

        if (parts.Length >= 2
            && parts[0].Equals("MEDIA", StringComparison.OrdinalIgnoreCase)
            && parts[1].Equals("CAPTURE", StringComparison.OrdinalIgnoreCase))
        {
            if (parts.Length == 3 && parts[2].Equals("PREFIX", StringComparison.OrdinalIgnoreCase))
            {
                return "Specus:MediaCapture:ObjectPrefix";
            }
            return parts.Length == 2
                ? "Specus:MediaCapture"
                : $"Specus:MediaCapture:{ToPascal(parts[2..])}";
        }

        if (parts.Length >= 2
            && parts[0].Equals("PUBLIC", StringComparison.OrdinalIgnoreCase)
            && parts[1].Equals("TRANSFER", StringComparison.OrdinalIgnoreCase))
        {
            return parts.Length == 2
                ? "Specus:PublicTransfer"
                : $"Specus:PublicTransfer:{ToPascal(parts[2..])}";
        }

        return $"Specus:{ToSectionName(parts[0])}:{ToPascal(parts[1..])}";
    }

    private static bool StartsWithKnownRoot(string key) =>
        key.StartsWith("Specus:", StringComparison.OrdinalIgnoreCase)
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
