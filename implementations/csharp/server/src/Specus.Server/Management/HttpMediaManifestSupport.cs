using System.Net;
using System.Text.RegularExpressions;

namespace Specus.Server.Management;

internal static class HttpMediaManifestSupport
{
    public const string HlsManifest = "HLS_MANIFEST";
    public const string DashManifest = "DASH_MANIFEST";
    public const string Progressive = "PROGRESSIVE";
    public const string MediaSegment = "MEDIA_SEGMENT";

    private static readonly Regex HlsUriAttribute = new(
        "URI=(\\\"([^\\\"]+)\\\"|'([^']+)')", RegexOptions.Compiled);
    private static readonly Regex DashUriAttribute = new(
        "(media|initialization|sourceURL|href)\\s*=\\s*(\\\"([^\\\"]+)\\\"|'([^']+)')",
        RegexOptions.Compiled | RegexOptions.IgnoreCase);
    private static readonly Regex DashBaseUrl = new(
        "<BaseURL(\\s[^>]*)?>([^<]+)</BaseURL>",
        RegexOptions.Compiled | RegexOptions.IgnoreCase | RegexOptions.Singleline);
    private static readonly Regex ContentRangePattern = new(
        "^bytes\\s+(\\d+)-(\\d+)/(\\d+|\\*)$",
        RegexOptions.Compiled | RegexOptions.IgnoreCase);
    private static readonly Regex NumberInName = new(
        "(\\d+)(?=\\.[^.]+$)", RegexOptions.Compiled);
    private static readonly Regex DynamicMpd = new(
        "<MPD\\b[^>]*\\btype\\s*=\\s*[\"']dynamic[\"']",
        RegexOptions.Compiled | RegexOptions.IgnoreCase);

    public static string? Classify(string sourceUrl, string? contentType, int statusCode,
        string? contentRange)
    {
        var type = MediaType(contentType);
        var path = PathOnly(sourceUrl).ToLowerInvariant();
        if (type is "application/vnd.apple.mpegurl" or "application/x-mpegurl" or "audio/mpegurl"
            || path.EndsWith(".m3u8", StringComparison.Ordinal))
        {
            return HlsManifest;
        }
        if (type == "application/dash+xml" || path.EndsWith(".mpd", StringComparison.Ordinal))
        {
            return DashManifest;
        }
        if (IsSegmentPath(path) || type is "video/mp2t" or "application/octet-stream")
        {
            return MediaSegment;
        }
        if (type.StartsWith("video/", StringComparison.Ordinal)
            || type.StartsWith("audio/", StringComparison.Ordinal)
            || IsProgressivePath(path) || statusCode == 206 && contentRange is not null)
        {
            return Progressive;
        }
        return null;
    }

    public static ContentRange? ParseContentRange(string? value)
    {
        if (value is null)
        {
            return null;
        }
        var match = ContentRangePattern.Match(value.Trim());
        if (!match.Success
            || !long.TryParse(match.Groups[1].Value, out var start)
            || !long.TryParse(match.Groups[2].Value, out var end))
        {
            return null;
        }
        long? total = null;
        if (match.Groups[3].Value != "*")
        {
            if (!long.TryParse(match.Groups[3].Value, out var parsedTotal) || parsedTotal < 0)
            {
                return null;
            }
            total = parsedTotal;
        }
        return end < start || total is not null && end >= total
            ? null
            : new ContentRange(start, end, total);
    }

    public static long? InferSequence(string sourceUrl)
    {
        var match = NumberInName.Match(PathOnly(sourceUrl));
        return match.Success && long.TryParse(match.Groups[1].Value, out var result) ? result : null;
    }

    public static bool IsInitializationSegment(string sourceUrl)
    {
        var path = PathOnly(sourceUrl).ToLowerInvariant();
        var file = path[(path.LastIndexOf('/') + 1)..];
        return file.StartsWith("init.", StringComparison.Ordinal)
               || file.StartsWith("init-", StringComparison.Ordinal)
               || file.Contains("initialization", StringComparison.Ordinal);
    }

    public static bool IsManifest(string? kind) => kind is HlsManifest or DashManifest;

    public static ParsedManifest Parse(string kind, string sourceUrl, string text) => kind switch
    {
        HlsManifest => ParseHls(sourceUrl, text),
        DashManifest => ParseDash(sourceUrl, text),
        _ => new ParsedManifest(false, []),
    };

    public static string Rewrite(string kind, string sourceUrl, string text, string assetBasePath) => kind switch
    {
        HlsManifest => RewriteHls(sourceUrl, text, assetBasePath),
        DashManifest => RewriteDash(sourceUrl, text, assetBasePath),
        _ => text,
    };

    public static string ResolveSourceUrl(string baseSourceUrl, string? reference)
    {
        if (string.IsNullOrWhiteSpace(reference) || reference.StartsWith("data:", StringComparison.Ordinal))
        {
            return reference ?? string.Empty;
        }
        try
        {
            var baseUri = new Uri("https://capture.invalid" + NormalizeSourceUrl(baseSourceUrl));
            var resolved = new Uri(baseUri, reference.Trim());
            return NormalizeSourceUrl(resolved.PathAndQuery);
        }
        catch (UriFormatException)
        {
            return NormalizeSourceUrl(reference);
        }
    }

    public static string NormalizeSourceUrl(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return "/";
        }
        var normalized = value.Trim();
        if (Uri.TryCreate(normalized, UriKind.Absolute, out var absolute))
        {
            normalized = string.IsNullOrWhiteSpace(absolute.AbsolutePath)
                ? "/" + absolute.Query
                : absolute.PathAndQuery;
        }
        if (!normalized.StartsWith('/'))
        {
            normalized = "/" + normalized;
        }
        return normalized.Length <= 3072 ? normalized : normalized[..3072];
    }

    private static ParsedManifest ParseHls(string sourceUrl, string text)
    {
        var references = new List<ManifestReference>();
        long mediaSequence = 0;
        var endList = false;
        var hasMediaSegment = false;
        foreach (var line in Lines(text))
        {
            var trimmed = line.Trim();
            if (trimmed.StartsWith("#EXT-X-MEDIA-SEQUENCE:", StringComparison.Ordinal))
            {
                _ = long.TryParse(trimmed[(trimmed.IndexOf(':') + 1)..].Trim(), out mediaSequence);
            }
            else if (trimmed == "#EXT-X-ENDLIST")
            {
                endList = true;
            }

            foreach (Match match in HlsUriAttribute.Matches(line))
            {
                var uri = First(match.Groups[2].Value, match.Groups[3].Value);
                var relation = trimmed.StartsWith("#EXT-X-MAP", StringComparison.Ordinal)
                    ? "INITIALIZATION"
                    : trimmed.StartsWith("#EXT-X-KEY", StringComparison.Ordinal) ? "KEY" : "ASSET";
                references.Add(new ManifestReference(relation, null, uri,
                    ResolveSourceUrl(sourceUrl, uri)));
            }
            if (trimmed.Length > 0 && !trimmed.StartsWith('#'))
            {
                var relation = PathOnly(trimmed).EndsWith(".m3u8", StringComparison.OrdinalIgnoreCase)
                    ? "PLAYLIST" : "SEGMENT";
                hasMediaSegment |= relation == "SEGMENT";
                references.Add(new ManifestReference(relation,
                    relation == "SEGMENT" ? mediaSequence++ : null, trimmed,
                    ResolveSourceUrl(sourceUrl, trimmed)));
            }
        }
        return new ParsedManifest(hasMediaSegment && !endList, references);
    }

    private static ParsedManifest ParseDash(string sourceUrl, string text)
    {
        var references = new List<ManifestReference>();
        long sequence = 0;
        foreach (Match match in DashUriAttribute.Matches(text))
        {
            var name = match.Groups[1].Value.ToLowerInvariant();
            var uri = First(match.Groups[3].Value, match.Groups[4].Value);
            var relation = name is "initialization" or "sourceurl" ? "INITIALIZATION" : "SEGMENT";
            references.Add(new ManifestReference(relation, relation == "SEGMENT" ? sequence++ : null,
                uri, ResolveSourceUrl(sourceUrl, uri)));
        }
        foreach (Match match in DashBaseUrl.Matches(text))
        {
            var uri = match.Groups[2].Value.Trim();
            if (uri.Length > 0)
            {
                references.Add(new ManifestReference("BASE", null, uri,
                    ResolveSourceUrl(sourceUrl, uri)));
            }
        }
        return new ParsedManifest(DynamicMpd.IsMatch(text), references);
    }

    private static string RewriteHls(string sourceUrl, string text, string assetBasePath)
    {
        var lines = Lines(text);
        for (var index = 0; index < lines.Length; index++)
        {
            var rewritten = HlsUriAttribute.Replace(lines[index], match =>
            {
                var original = First(match.Groups[2].Value, match.Groups[3].Value);
                return $"URI=\"{AssetUrl(assetBasePath, ResolveSourceUrl(sourceUrl, original))}\"";
            });
            var trimmed = rewritten.Trim();
            if (trimmed.Length > 0 && !trimmed.StartsWith('#'))
            {
                rewritten = AssetUrl(assetBasePath, ResolveSourceUrl(sourceUrl, trimmed));
            }
            lines[index] = rewritten;
        }
        return string.Join('\n', lines);
    }

    private static string RewriteDash(string sourceUrl, string text, string assetBasePath)
    {
        var rewritten = DashUriAttribute.Replace(text, match =>
        {
            var original = First(match.Groups[3].Value, match.Groups[4].Value);
            return $"{match.Groups[1].Value}=\"{XmlEscape(AssetUrl(assetBasePath, ResolveSourceUrl(sourceUrl, original)))}\"";
        });
        return DashBaseUrl.Replace(rewritten, match =>
        {
            var prefix = match.Groups[1].Success ? match.Groups[1].Value : string.Empty;
            var value = XmlEscape(AssetUrl(assetBasePath,
                ResolveSourceUrl(sourceUrl, match.Groups[2].Value.Trim())));
            return $"<BaseURL{prefix}>{value}</BaseURL>";
        });
    }

    private static string AssetUrl(string basePath, string sourceUrl) =>
        basePath + "?url=" + Uri.EscapeDataString(sourceUrl).Replace("%24", "$", StringComparison.OrdinalIgnoreCase);

    private static bool IsProgressivePath(string path) =>
        new[] { ".mp4", ".webm", ".mkv", ".mov", ".m4v", ".mp3", ".m4a", ".ogg", ".opus", ".wav", ".flac" }
            .Any(extension => path.EndsWith(extension, StringComparison.Ordinal));

    private static bool IsSegmentPath(string path) =>
        new[] { ".ts", ".m4s", ".cmfv", ".cmfa", ".aac", ".vtt", ".key" }
            .Any(extension => path.EndsWith(extension, StringComparison.Ordinal));

    private static string[] Lines(string text) => Regex.Split(text, "\\r\\n|\\n|\\r");
    private static string PathOnly(string? sourceUrl) => sourceUrl?.Split('?', 2)[0] ?? string.Empty;
    private static string MediaType(string? contentType) =>
        contentType?.Split(';', 2)[0].Trim().ToLowerInvariant() ?? string.Empty;
    private static string First(string first, string second) => first.Length > 0 ? first : second;
    private static string XmlEscape(string value) => WebUtility.HtmlEncode(value).Replace("'", "&apos;", StringComparison.Ordinal);

    public sealed record ContentRange(long Start, long End, long? Total);
    public sealed record ManifestReference(string RelationType, long? Sequence, string OriginalUri,
        string ResolvedSourceUrl);
    public sealed record ParsedManifest(bool Live, IReadOnlyList<ManifestReference> References);
}
