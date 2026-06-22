using System.Text.Json;

namespace ShuaiTunnel.Client.Configuration;

/// <summary>
/// Loads <c>tunnelClientConfig.json</c> from disk, mirroring the Java client's lookup order:
/// first the absolute path under the current working directory, then the relative path.
/// Unknown fields are tolerated (System.Text.Json default behavior).
/// </summary>
public static class TunnelClientConfigLoader
{
    private const string FileName = "tunnelClientConfig.json";

    /// <summary>
    /// Loads the config from the first matching location, or returns the explicit override.
    /// Throws <see cref="FileNotFoundException"/> when neither candidate exists.
    /// </summary>
    public static TunnelClientConfig Load(string? overridePath = null)
    {
        var path = ResolvePath(overridePath);
        var json = File.ReadAllText(path);
        var config = JsonSerializer.Deserialize<TunnelClientConfig>(json, JsonOptions)
            ?? throw new InvalidDataException($"Empty tunnel client config at {path}");
        Validate(config, path);
        return config;
    }

    /// <summary>Returns the absolute path the loader will read from.</summary>
    public static string ResolvePath(string? overridePath)
    {
        if (!string.IsNullOrWhiteSpace(overridePath))
        {
            return Path.GetFullPath(overridePath);
        }
        var cwd = Directory.GetCurrentDirectory();
        var primary = Path.Combine(cwd, FileName);
        if (File.Exists(primary))
        {
            return primary;
        }
        var fallback = Path.GetFullPath(FileName);
        if (File.Exists(fallback))
        {
            return fallback;
        }
        throw new FileNotFoundException(
            $"未找到 tunnelClientConfig.json. 已检查路径: [{primary}], [{fallback}]");
    }

    internal static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNameCaseInsensitive = true,
        ReadCommentHandling = JsonCommentHandling.Skip,
        AllowTrailingCommas = true,
    };

    private static void Validate(TunnelClientConfig config, string path)
    {
        if (string.IsNullOrWhiteSpace(config.ClientName))
        {
            throw new InvalidDataException($"{path}: clientName 不能为空");
        }
        if (string.IsNullOrWhiteSpace(config.Password))
        {
            throw new InvalidDataException($"{path}: password 不能为空");
        }
        if (string.IsNullOrWhiteSpace(config.RemoteAddress))
        {
            throw new InvalidDataException($"{path}: remoteAddress 不能为空");
        }
        if (config.RemotePort <= 0 || config.RemotePort > 65535)
        {
            throw new InvalidDataException($"{path}: remotePort 无效");
        }
    }
}
