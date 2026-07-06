using System.Text.Json;

namespace ShuaiTunnel.Client.Configuration;

/// <summary>
/// Loads <c>client.jsonc</c> from disk, mirroring the Java client's lookup order:
/// first the absolute path under the current working directory, then the relative path.
/// Unknown fields are tolerated (System.Text.Json default behavior).
/// </summary>
public static class TunnelClientConfigLoader
{
    private const string FileName = "client.jsonc";

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
        config.Normalize();
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
            $"未找到 client.jsonc. 已检查路径: [{primary}], [{fallback}]");
    }

    internal static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNameCaseInsensitive = true,
        ReadCommentHandling = JsonCommentHandling.Skip,
        AllowTrailingCommas = true,
    };

    private static void Validate(TunnelClientConfig config, string path)
    {
        if (string.IsNullOrWhiteSpace(config.ServerBaseUrl))
        {
            throw new InvalidDataException($"{path}: serverBaseUrl 不能为空");
        }
        if (!Uri.TryCreate(config.ServerBaseUrl, UriKind.Absolute, out var uri)
            || (uri.Scheme != Uri.UriSchemeHttp && uri.Scheme != Uri.UriSchemeHttps))
        {
            throw new InvalidDataException($"{path}: serverBaseUrl 必须是 http/https 绝对地址");
        }

        if (string.IsNullOrWhiteSpace(config.ApiKey))
        {
            throw new InvalidDataException($"{path}: 必须配置 apiKey");
        }
        if (string.IsNullOrWhiteSpace(config.Secret))
        {
            throw new InvalidDataException($"{path}: 必须配置 secret");
        }
    }
}
