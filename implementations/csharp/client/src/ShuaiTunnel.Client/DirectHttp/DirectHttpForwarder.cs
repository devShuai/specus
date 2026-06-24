using System.Net;
using System.Net.Http.Headers;
using ShuaiTunnel.Protocol.Packets;

namespace ShuaiTunnel.Client.DirectHttp;

/// <summary>
/// Forwards <see cref="DirectHttpRequestPacket"/> calls to a configured upstream base URL,
/// honoring the route-containment, header-filtering, and 16&#160;MiB body caps of the Java
/// <c>DirectHttpForwarder</c>. Errors are translated to a <c>502</c>
/// <see cref="DirectHttpResponsePacket"/> with the exception message in <c>Error</c>.
/// </summary>
public sealed class DirectHttpForwarder
{
    public const int MaxBodySize = 16 * 1024 * 1024;
    public const int FailureStatus = 502;

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
        var handler = new SocketsHttpHandler
        {
            AllowAutoRedirect = false,
            AutomaticDecompression = DecompressionMethods.None,
            ConnectTimeout = TimeSpan.FromSeconds(5),
            PooledConnectionLifetime = TimeSpan.FromMinutes(2),
        };
        return new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(20) };
    }

    public async Task<DirectHttpResponsePacket> ForwardAsync(
        DirectHttpRequestPacket request,
        IReadOnlyDictionary<string, string> routes,
        CancellationToken cancellationToken)
    {
        if (request.Body is { Length: > MaxBodySize })
        {
            return Failure(request.RequestId, "请求体超过 16MB 上限");
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
        CopyRequestHeaders(request.Headers, message);

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
            error = "目标地址无效";
            return false;
        }
        var scheme = baseUri.Scheme.ToLowerInvariant();
        if (scheme != "http" && scheme != "https")
        {
            error = "目标 scheme 必须是 http/https";
            return false;
        }
        if (!string.IsNullOrEmpty(baseUri.Query) || !string.IsNullOrEmpty(baseUri.Fragment))
        {
            error = "目标地址不能包含 query 或 fragment";
            return false;
        }
        if (string.IsNullOrEmpty(baseUri.Host))
        {
            error = "目标地址缺少 host";
            return false;
        }

        var path = string.IsNullOrWhiteSpace(relativePath) ? "/" : relativePath!;
        if (!path.StartsWith('/'))
        {
            error = "relativePath 必须以 / 开头";
            return false;
        }
        // Reject network-path references like "//host/path" (RFC 3986 §4.2) — they would
        // hop to a different authority via Uri resolution.
        if (path.StartsWith("//", StringComparison.Ordinal))
        {
            error = "relativePath 跨主机";
            return false;
        }
        if (path.Contains('\r') || path.Contains('\n'))
        {
            error = "relativePath 含有非法控制字符";
            return false;
        }

        var basePath = baseUri.AbsolutePath.TrimEnd('/');
        var combined = basePath + path;
        if (!string.IsNullOrWhiteSpace(rawQuery))
        {
            combined += "?" + rawQuery;
        }
        var builder = new UriBuilder(baseUri) { Path = "", Query = "" };
        if (!Uri.TryCreate(builder.Uri, combined, out var candidate))
        {
            error = "目标地址拼接失败";
            return false;
        }
        if (!string.Equals(candidate.Scheme, baseUri.Scheme, StringComparison.OrdinalIgnoreCase)
            || !string.Equals(candidate.Host, baseUri.Host, StringComparison.OrdinalIgnoreCase)
            || candidate.Port != baseUri.Port)
        {
            error = "目标地址跨主机";
            return false;
        }

        var basePrefix = basePath.Length == 0 ? "/" : basePath;
        var candidatePath = candidate.AbsolutePath;
        if (basePrefix == "/")
        {
            // any same-host path is in-scope
        }
        else if (candidatePath != basePrefix && !candidatePath.StartsWith(basePrefix + "/", StringComparison.Ordinal))
        {
            error = "请求路径越出 route 范围";
            return false;
        }

        // Walk segments to reject "." and ".." as in the Java forwarder.
        foreach (var segment in candidatePath.Split('/', StringSplitOptions.RemoveEmptyEntries))
        {
            if (segment == "." || segment == "..")
            {
                error = "请求路径包含非法段";
                return false;
            }
        }

        target = candidate;
        return true;
    }

    private static void CopyRequestHeaders(IReadOnlyList<string>? headers, HttpRequestMessage message)
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
        if (response.Content.Headers.ContentLength is long announced && announced > MaxBodySize)
        {
            throw new InvalidOperationException("响应体超过 16MB 上限");
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
            if (total > MaxBodySize)
            {
                throw new InvalidOperationException("响应体超过 16MB 上限");
            }
            memory.Write(buffer, 0, read);
        }
        return memory.ToArray();
    }
}
