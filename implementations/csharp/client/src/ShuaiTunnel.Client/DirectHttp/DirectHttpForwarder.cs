using System.Net;
using System.Net.Http.Headers;
using System.Net.Security;
using ShuaiTunnel.Protocol.Packets;

namespace ShuaiTunnel.Client.DirectHttp;

/// <summary>
/// Forwards <see cref="DirectHttpRequestPacket"/> calls to a configured upstream base URL,
/// honoring the route-containment, header-filtering, HTTPS trust, body caps, and range bounding
/// of the Java <c>DirectHttpForwarder</c>. Errors are translated to a <c>502</c>
/// <see cref="DirectHttpResponsePacket"/> with the exception message in <c>Error</c>.
/// </summary>
public sealed class DirectHttpForwarder
{
    public const int MaxRequestBodySize = 16 * 1024 * 1024;
    public const int MaxResponseBodySize = 64 * 1024 * 1024;
    public const int MaxBodySize = MaxRequestBodySize;
    public const int FailureStatus = 502;
    private const long MaxRangeBytes = 8L * 1024 * 1024;

    // Hop-by-hop headers per RFC 7230; never forwarded in either direction.
    public static readonly IReadOnlySet<string> SkippedHeaders =
        new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "connection", "content-length", "host", "keep-alive",
            "proxy-authenticate", "proxy-authorization", "te", "trailer",
            "transfer-encoding", "upgrade",
        };

    private readonly HttpClient _httpClient;

    public DirectHttpForwarder(HttpClient httpClient)
    {
        _httpClient = httpClient;
    }

    /// <summary>Builds a default <see cref="HttpClient"/> matching the Java client's timeouts.</summary>
    public static HttpClient BuildDefaultClient()
    {
        return new HttpClient(BuildDefaultHandler()) { Timeout = TimeSpan.FromSeconds(20) };
    }

    public static SocketsHttpHandler BuildDefaultHandler()
    {
        var handler = new SocketsHttpHandler
        {
            AllowAutoRedirect = false,
            AutomaticDecompression = DecompressionMethods.None,
            ConnectTimeout = TimeSpan.FromSeconds(5),
            PooledConnectionLifetime = TimeSpan.FromMinutes(2),
            UseProxy = false,
            // Java DirectHttpForwarder trusts operator-configured LAN HTTPS upstreams, which
            // commonly use self-signed certificates for PVE, NAS, Nacos, and similar services.
            SslOptions = new SslClientAuthenticationOptions
            {
                RemoteCertificateValidationCallback = static (_, _, _, _) => true,
            },
        };
        return handler;
    }

    public async Task<DirectHttpResponsePacket> ForwardAsync(
        DirectHttpRequestPacket request,
        IReadOnlyDictionary<string, string> routes,
        CancellationToken cancellationToken)
    {
        if (request.Body is { Length: > MaxRequestBodySize })
        {
            return Failure(request.RequestId, "HTTP 请求体超过限制");
        }
        if (string.IsNullOrWhiteSpace(request.Route) || !routes.TryGetValue(request.Route!, out var baseUrl))
        {
            return Failure(request.RequestId, "未配置 HTTP route");
        }
        if (!TryBuildTarget(baseUrl, request.RelativePath, request.RawQuery, out var target, out var buildError))
        {
            return Failure(request.RequestId, buildError);
        }

        using var message = new HttpRequestMessage(new HttpMethod(request.RequestMethod ?? "GET"), target);
        if (request.Body is { Length: > 0 })
        {
            message.Content = new ByteArrayContent(request.Body);
        }
        var originalRange = FirstHeader(request.Headers, "range");
        var boundedRange = BoundedRange(originalRange);
        CopyRequestHeaders(request.Headers, message, skipRange: boundedRange is not null);
        if (boundedRange is not null)
        {
            message.Headers.TryAddWithoutValidation("Range", boundedRange);
        }

        try
        {
            using var response = await _httpClient
                .SendAsync(message, HttpCompletionOption.ResponseHeadersRead, cancellationToken)
                .ConfigureAwait(false);
            var body = await ReadBodyAsync(response, cancellationToken).ConfigureAwait(false);
            return new DirectHttpResponsePacket
            {
                RequestId = request.RequestId,
                StatusCode = (int)response.StatusCode,
                Headers = CollectResponseHeaders(response),
                Body = body,
                Error = null,
            };
        }
        catch (Exception ex) when (ex is not OperationCanceledException || !cancellationToken.IsCancellationRequested)
        {
            return Failure(request.RequestId, ex.Message);
        }
    }

    private static DirectHttpResponsePacket Failure(string? requestId, string message)
    {
        return new DirectHttpResponsePacket
        {
            RequestId = requestId,
            StatusCode = FailureStatus,
            Headers = null,
            Body = null,
            Error = message,
        };
    }

    /// <summary>
    /// Builds the upstream target URL with the same containment rules as the Java forwarder:
    /// http/https only, no base query/fragment, no <c>.</c>/<c>..</c> segments, scheme/host/port
    /// preserved, and the upstream path must stay under the base path.
    /// </summary>
    public static bool TryBuildTarget(
        string baseUrl, string? relativePath, string? rawQuery, out Uri target, out string error)
    {
        target = null!;
        error = "";
        if (string.IsNullOrWhiteSpace(baseUrl))
        {
            error = "未配置 HTTP route";
            return false;
        }
        if (!Uri.TryCreate(baseUrl, UriKind.Absolute, out var baseUri))
        {
            error = "HTTP route 地址无效";
            return false;
        }
        var scheme = baseUri.Scheme.ToLowerInvariant();
        if (scheme != "http" && scheme != "https")
        {
            error = "HTTP route 仅支持 http 和 https";
            return false;
        }
        if (!string.IsNullOrEmpty(baseUri.Query) || !string.IsNullOrEmpty(baseUri.Fragment))
        {
            error = "HTTP route 地址无效";
            return false;
        }
        if (string.IsNullOrEmpty(baseUri.Host))
        {
            error = "HTTP route 地址无效";
            return false;
        }

        var path = string.IsNullOrWhiteSpace(relativePath) ? "/" : relativePath!;
        if (!path.StartsWith('/'))
        {
            error = "HTTP 转发路径无效";
            return false;
        }
        if (path.Contains('\r') || path.Contains('\n'))
        {
            error = "HTTP 转发路径无效";
            return false;
        }
        if (ContainsDotSegment(path))
        {
            error = "HTTP 转发路径越界";
            return false;
        }

        var baseText = baseUrl.Trim();
        if (baseText.EndsWith("/", StringComparison.Ordinal))
        {
            baseText = baseText[..^1];
        }
        var combined = baseText + path + (string.IsNullOrWhiteSpace(rawQuery) ? "" : "?" + rawQuery);
        if (!Uri.TryCreate(combined, UriKind.Absolute, out var candidate))
        {
            error = "HTTP 转发目标越界";
            return false;
        }
        if (!string.Equals(candidate.Scheme, baseUri.Scheme, StringComparison.OrdinalIgnoreCase)
            || !string.Equals(candidate.Host, baseUri.Host, StringComparison.OrdinalIgnoreCase)
            || candidate.Port != baseUri.Port)
        {
            error = "HTTP 转发目标越界";
            return false;
        }

        var basePath = baseUri.AbsolutePath.TrimEnd('/');
        var basePrefix = basePath.Length == 0 ? "/" : basePath;
        var candidatePath = candidate.AbsolutePath;
        if (basePrefix == "/")
        {
            // any same-host path is in-scope
        }
        else if (candidatePath != basePrefix && !candidatePath.StartsWith(basePrefix + "/", StringComparison.Ordinal))
        {
            error = "HTTP 转发路径越界";
            return false;
        }

        // Walk segments to reject "." and ".." as in the Java forwarder.
        foreach (var segment in candidatePath.Split('/', StringSplitOptions.RemoveEmptyEntries))
        {
            var decoded = Uri.UnescapeDataString(segment);
            if (decoded == "." || decoded == "..")
            {
                error = "HTTP 转发路径越界";
                return false;
            }
        }

        target = candidate;
        return true;
    }

    private static bool ContainsDotSegment(string path)
    {
        foreach (var segment in path.Split('/', StringSplitOptions.RemoveEmptyEntries))
        {
            var decoded = Uri.UnescapeDataString(segment);
            if (decoded == "." || decoded == "..")
            {
                return true;
            }
        }
        return false;
    }

    private static void CopyRequestHeaders(IReadOnlyList<string>? headers, HttpRequestMessage message, bool skipRange)
    {
        if (headers is null)
        {
            return;
        }
        foreach (var header in headers)
        {
            var idx = header.IndexOf(':');
            if (idx <= 0)
            {
                continue;
            }
            var name = header[..idx];
            if (skipRange && string.Equals(name, "range", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }
            if (SkippedHeaders.Contains(name))
            {
                continue;
            }
            // Preserve any leading space after ':' so the original value bytes survive the
            // round-trip (matches the Java forwarder, which does not trim).
            var value = header[(idx + 1)..];
            if (!message.Headers.TryAddWithoutValidation(name, value))
            {
                message.Content?.Headers.TryAddWithoutValidation(name, value);
            }
        }
    }

    private static string? FirstHeader(IReadOnlyList<string>? headers, string headerName)
    {
        if (headers is null)
        {
            return null;
        }
        foreach (var header in headers)
        {
            var idx = header.IndexOf(':');
            if (idx > 0 && string.Equals(header[..idx], headerName, StringComparison.OrdinalIgnoreCase))
            {
                return header[(idx + 1)..];
            }
        }
        return null;
    }

    public static string? BoundedRange(string? rangeHeader)
    {
        if (rangeHeader is null)
        {
            return null;
        }
        var value = rangeHeader.Trim();
        if (!value.StartsWith("bytes=", StringComparison.OrdinalIgnoreCase))
        {
            return null;
        }
        var spec = value["bytes=".Length..].Trim();
        if (spec.Length == 0 || spec.Contains(',', StringComparison.Ordinal))
        {
            return null;
        }
        var dash = spec.IndexOf('-');
        if (dash < 0)
        {
            return null;
        }

        var startPart = spec[..dash].Trim();
        var endPart = spec[(dash + 1)..].Trim();
        if (startPart.Length == 0)
        {
            if (endPart.Length == 0 || !long.TryParse(endPart, out var suffixLength) || suffixLength <= 0)
            {
                return null;
            }
            return "bytes=-" + Math.Min(suffixLength, MaxRangeBytes);
        }

        if (!long.TryParse(startPart, out var start) || start < 0)
        {
            return null;
        }
        var maxEnd = BoundedRangeEnd(start);
        if (endPart.Length == 0)
        {
            return $"bytes={start}-{maxEnd}";
        }
        if (!long.TryParse(endPart, out var end) || end < start)
        {
            return null;
        }
        return $"bytes={start}-{Math.Min(end, maxEnd)}";
    }

    private static long BoundedRangeEnd(long start)
    {
        var delta = MaxRangeBytes - 1;
        return long.MaxValue - start < delta ? long.MaxValue : start + delta;
    }

    private static List<string> CollectResponseHeaders(HttpResponseMessage response)
    {
        var headers = new List<string>();
        AppendHeaders(response.Headers, headers);
        if (response.Content is not null)
        {
            AppendHeaders(response.Content.Headers, headers);
        }
        return headers;
    }

    private static void AppendHeaders(HttpHeaders source, List<string> sink)
    {
        foreach (var kv in source)
        {
            if (SkippedHeaders.Contains(kv.Key))
            {
                continue;
            }
            foreach (var value in kv.Value)
            {
                sink.Add($"{kv.Key}:{value}");
            }
        }
    }

    private static async Task<byte[]> ReadBodyAsync(HttpResponseMessage response, CancellationToken token)
    {
        if (response.Content is null)
        {
            return Array.Empty<byte>();
        }
        if (response.Content.Headers.ContentLength is long announced && announced > MaxResponseBodySize)
        {
            throw new InvalidOperationException("HTTP 响应体超过限制");
        }
        await using var stream = await response.Content.ReadAsStreamAsync(token).ConfigureAwait(false);
        using var memory = new MemoryStream();
        var buffer = new byte[64 * 1024];
        long total = 0;
        while (true)
        {
            var read = await stream.ReadAsync(buffer, token).ConfigureAwait(false);
            if (read <= 0)
            {
                break;
            }
            total += read;
            if (total > MaxResponseBodySize)
            {
                throw new InvalidOperationException("HTTP 响应体超过限制");
            }
            memory.Write(buffer, 0, read);
        }
        return memory.ToArray();
    }
}
