using System.Collections.Frozen;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Specus.Protocol.Packets;
using Specus.Server.Configuration;
using Specus.Server.Data;
using Specus.Server.Management;
using Specus.Server.Nat;

namespace Specus.Server.Http;

/// <summary>
/// Public HTTP ingress for browser/API traffic that should be carried through a connected specus
/// client. This is the ASP.NET endpoint counterpart to Java's <c>HttpSpecusController</c>; it
/// strips hop-by-hop headers, bounds request bodies, and delegates the control-channel round trip
/// to <see cref="DirectHttpDispatcher"/>.
/// </summary>
public static class DirectHttpEndpoints
{
    private static readonly FrozenSet<string> SkippedHeaders = new[]
    {
        "connection",
        "content-length",
        "host",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
    }.ToFrozenSet(StringComparer.OrdinalIgnoreCase);

    private static readonly string[] Methods = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"];

    public static void MapDirectHttpSpecus(this WebApplication app)
    {
        app.MapMethods("/http/{clientName}/{route}/{**rest}", Methods, ForwardAsync);
        app.MapMethods("/http/{clientName}/{route}", Methods, ForwardAsync);
    }

    private static async Task ForwardAsync(HttpContext context, string clientName, string route,
        string? rest, DirectHttpDispatcher dispatcher, TrafficUsageService traffic,
        IOptions<DirectHttpOptions> options, SpecusDbContext db, TrafficInspectionService inspection)
    {
        var startedAt = DateTimeOffset.UtcNow;
        var relativePath = RelativePath(context, rest);
        var requestHeaders = RequestHeaders(context.Request);
        var requestCapture = new LimitedCapture(64 * 1024);
        var responseCapture = new LimitedCapture(64 * 1024);
        var requestMetadata = new Dictionary<string, object?>
        {
            ["source"] = "http",
            ["phase"] = "request",
            ["method"] = context.Request.Method,
            ["route"] = route,
            ["relativePath"] = relativePath,
            ["rawQuery"] = context.Request.QueryString.HasValue
                ? context.Request.QueryString.Value!.TrimStart('?')
                : null,
            ["headers"] = requestHeaders,
            ["contentLength"] = context.Request.ContentLength ?? -1L,
            ["trailerNames"] = DeclaredRequestTrailers(context.Request),
        };
        if (context.Request.ContentLength > options.Value.MaxRequestBodySize)
        {
            const string message = "HTTP 请求体超过限制";
            var responseBody = Encoding.UTF8.GetBytes(message);
            await inspection.RecordHttpExchangeAsync(new HttpExchangeCapture(clientName, route,
                    context.Request.Method, relativePath, context.Request.QueryString.Value?.TrimStart('?'),
                    requestHeaders, Array.Empty<byte>(),
                    StatusCodes.Status413PayloadTooLarge, PlainErrorHeaders(), responseBody, startedAt,
                    context.Connection.RemoteIpAddress?.ToString(), message), context.RequestAborted)
                .ConfigureAwait(false);
            await WriteTextErrorAsync(context.Response, StatusCodes.Status413PayloadTooLarge,
                message).ConfigureAwait(false);
            return;
        }

        try
        {
            await using var stream = await dispatcher.OpenAsync(clientName, requestMetadata,
                    context.RequestAborted).ConfigureAwait(false);
            using var pumpCts = CancellationTokenSource.CreateLinkedTokenSource(context.RequestAborted);
            var pumpTask = PumpRequestAsync(context, stream, traffic, clientName, route,
                requestCapture, options.Value.MaxRequestBodySize, pumpCts.Token);

            using var headCts = CancellationTokenSource.CreateLinkedTokenSource(context.RequestAborted);
            headCts.CancelAfter(TimeSpan.FromMilliseconds(Math.Max(1, options.Value.TimeoutMs)));
            Dictionary<string, object?> head;
            try
            {
                head = await stream.WaitResponseHeadAsync(headCts.Token).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (headCts.IsCancellationRequested
                                                     && !context.RequestAborted.IsCancellationRequested)
            {
                await stream.ResetAsync(1, "HTTP response header timeout", CancellationToken.None)
                    .ConfigureAwait(false);
                throw new DirectHttpSpecusException(StatusCodes.Status504GatewayTimeout, "HTTP 转发请求超时");
            }

            var statusCode = AsInt(head, "statusCode");
            if (statusCode is not int validStatusCode || validStatusCode is < 100 or > 599)
            {
                await stream.ResetAsync(2, "invalid HTTP response status", CancellationToken.None)
                    .ConfigureAwait(false);
                throw new DirectHttpSpecusException(StatusCodes.Status502BadGateway, "HTTP 响应状态无效");
            }
            var originalResponseHeaders = AsStrings(head, "headers");
            var responseHeaders = originalResponseHeaders;
            foreach (var trailerName in AsStrings(head, "trailerNames"))
            {
                if (IsValidHeaderName(trailerName))
                {
                    context.Response.DeclareTrailer(trailerName);
                }
            }

            var rewrite = await IsPathRewriteEnabledAsync(db, clientName, route, context.RequestAborted)
                    .ConfigureAwait(false)
                && IsRewritable(originalResponseHeaders);
            using var rewriteBuffer = new MemoryStream();
            var responseStarted = false;
            long responseBytes = 0;
            List<string>? responseTrailers = null;

            void StartResponse()
            {
                if (responseStarted)
                {
                    return;
                }
                context.Response.StatusCode = validStatusCode;
                CopyHeaders(responseHeaders, context.Response);
                responseStarted = true;
            }

            while (true)
            {
                var item = await stream.ReadResponseAsync(context.RequestAborted).ConfigureAwait(false);
                if (item.End)
                {
                    responseTrailers = AsStrings(item.Metadata, "trailers");
                    break;
                }
                var data = item.Data ?? Array.Empty<byte>();
                responseBytes += data.Length;
                if (responseBytes > DirectHttpOptionsMaxResponseBytes)
                {
                    await stream.ResetAsync(3, "HTTP response body exceeds limit", CancellationToken.None)
                        .ConfigureAwait(false);
                    throw new DirectHttpSpecusException(StatusCodes.Status502BadGateway, "HTTP 响应体超过限制");
                }

                if (rewrite && rewriteBuffer.Length + data.Length <= options.Value.RewriteMaxBodyBytes)
                {
                    await rewriteBuffer.WriteAsync(data, context.RequestAborted).ConfigureAwait(false);
                    await stream.ConsumeResponseAsync(data.Length, context.RequestAborted).ConfigureAwait(false);
                    continue;
                }
                if (rewrite)
                {
                    rewrite = false;
                    StartResponse();
                    var buffered = rewriteBuffer.ToArray();
                    await WriteResponseChunkAsync(context.Response, buffered, responseCapture,
                        traffic, clientName, route, context.RequestAborted).ConfigureAwait(false);
                }
                StartResponse();
                await WriteResponseChunkAsync(context.Response, data, responseCapture,
                    traffic, clientName, route, context.RequestAborted).ConfigureAwait(false);
                await stream.ConsumeResponseAsync(data.Length, context.RequestAborted).ConfigureAwait(false);
            }

            if (rewrite)
            {
                var body = rewriteBuffer.ToArray();
                if (ResponseRewriter.TryRewrite(body, clientName, route, originalResponseHeaders,
                        options.Value.RewriteMaxBodyBytes, out var rewritten))
                {
                    body = rewritten;
                    responseHeaders = StripRewriteHeaders(responseHeaders);
                }
                StartResponse();
                await WriteResponseChunkAsync(context.Response, body, responseCapture,
                    traffic, clientName, route, context.RequestAborted).ConfigureAwait(false);
            }
            else if (!responseStarted)
            {
                StartResponse();
            }

            foreach (var trailer in responseTrailers ?? [])
            {
                AppendResponseTrailer(context.Response, trailer);
            }
            if (!pumpTask.IsCompleted)
            {
                pumpCts.Cancel();
            }
            await inspection.RecordHttpExchangeAsync(new HttpExchangeCapture(clientName, route,
                    context.Request.Method, relativePath, context.Request.QueryString.Value?.TrimStart('?'),
                    requestHeaders, requestCapture.Bytes(), context.Response.StatusCode,
                    originalResponseHeaders, responseCapture.Bytes(), startedAt,
                    context.Connection.RemoteIpAddress?.ToString(), null), context.RequestAborted)
                .ConfigureAwait(false);
        }
        catch (DirectHttpSpecusException ex)
        {
            var responseBody = Encoding.UTF8.GetBytes(ex.Message);
            await inspection.RecordHttpExchangeAsync(new HttpExchangeCapture(clientName, route,
                    context.Request.Method, relativePath, context.Request.QueryString.Value?.TrimStart('?'),
                    requestHeaders, requestCapture.Bytes(),
                    ex.StatusCode, PlainErrorHeaders(), responseBody, startedAt, context.Connection.RemoteIpAddress?.ToString(),
                    ex.Message), CancellationToken.None)
                .ConfigureAwait(false);
            await WriteTextErrorAsync(context.Response, ex.StatusCode, ex.Message).ConfigureAwait(false);
        }
    }

    private const int DirectHttpOptionsMaxResponseBytes = 64 * 1024 * 1024;

    private static async Task PumpRequestAsync(HttpContext context, HttpSpecusStream stream,
        TrafficUsageService traffic, string clientName, string route, LimitedCapture capture,
        int maxBytes, CancellationToken cancellationToken)
    {
        var buffer = new byte[64 * 1024];
        long total = 0;
        try
        {
            while (true)
            {
                var read = await context.Request.Body.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
                if (read == 0)
                {
                    var trailers = RequestTrailers(context);
                    await stream.FinishRequestAsync(trailers.Count == 0
                            ? null
                            : new Dictionary<string, object?> { ["trailers"] = trailers }, cancellationToken)
                        .ConfigureAwait(false);
                    return;
                }
                total += read;
                capture.Write(buffer.AsSpan(0, read));
                if (total > maxBytes)
                {
                    await stream.ResetAsync(4, "HTTP request body exceeds limit", CancellationToken.None)
                        .ConfigureAwait(false);
                    return;
                }
                await stream.SendDataAsync(buffer.AsMemory(0, read), cancellationToken).ConfigureAwait(false);
                traffic.RecordHttpUpload(clientName, route, read);
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
        }
        catch (Exception)
        {
            await stream.ResetAsync(5, "HTTP request stream failed", CancellationToken.None)
                .ConfigureAwait(false);
            throw;
        }
    }

    private static string RelativePath(HttpContext context, string? rest)
    {
        var rawTarget = context.Features.Get<IHttpRequestFeature>()?.RawTarget;
        if (!string.IsNullOrEmpty(rawTarget))
        {
            var queryIndex = rawTarget.IndexOf('?', StringComparison.Ordinal);
            var rawPath = queryIndex >= 0 ? rawTarget[..queryIndex] : rawTarget;
            const string prefix = "/http/";
            if (rawPath.StartsWith(prefix, StringComparison.Ordinal))
            {
                var clientSeparator = rawPath.IndexOf('/', prefix.Length);
                if (clientSeparator >= 0)
                {
                    var routeSeparator = rawPath.IndexOf('/', clientSeparator + 1);
                    return routeSeparator >= 0 ? PreserveRawPathEncoding(rawPath[routeSeparator..]) : "/";
                }
                return "/";
            }
        }

        return string.IsNullOrWhiteSpace(rest) ? "/" : PreserveRawPathEncoding("/" + rest);
    }

    private static string PreserveRawPathEncoding(string path)
    {
        var builder = new StringBuilder(path.Length);
        for (var i = 0; i < path.Length;)
        {
            var ch = path[i];
            if (ch == '%' && i + 2 < path.Length && IsHex(path[i + 1]) && IsHex(path[i + 2]))
            {
                builder.Append(path, i, 3);
                i += 3;
                continue;
            }

            if (ch <= 0x7f && IsRawPathSafeAscii(ch))
            {
                builder.Append(ch);
                i++;
                continue;
            }

            var consumed = char.IsHighSurrogate(ch) && i + 1 < path.Length && char.IsLowSurrogate(path[i + 1])
                ? 2
                : 1;
            foreach (var b in Encoding.UTF8.GetBytes(path.AsSpan(i, consumed).ToString()))
            {
                builder.Append('%');
                builder.Append(b.ToString("X2", System.Globalization.CultureInfo.InvariantCulture));
            }
            i += consumed;
        }
        return builder.ToString();
    }

    private static bool IsHex(char ch) =>
        ch is >= '0' and <= '9' or >= 'a' and <= 'f' or >= 'A' and <= 'F';

    private static bool IsRawPathSafeAscii(char ch) =>
        ch is >= 'A' and <= 'Z'
            or >= 'a' and <= 'z'
            or >= '0' and <= '9'
            or '/'
            or '-'
            or '.'
            or '_'
            or '~'
            or '!'
            or '$'
            or '&'
            or '\''
            or '('
            or ')'
            or '*'
            or '+'
            or ','
            or ';'
            or '='
            or ':'
            or '@';

    private static List<string> RequestHeaders(HttpRequest request)
    {
        var headers = new List<string>();
        foreach (var (name, values) in request.Headers)
        {
            if (!ShouldForward(name))
            {
                continue;
            }

            foreach (var value in values)
            {
                headers.Add($"{name}:{value}");
            }
        }
        return headers;
    }

    private static List<string> PlainErrorHeaders() => ["Content-Type:text/plain;charset=UTF-8"];

    private static void CopyHeaders(List<string>? source, HttpResponse response)
    {
        if (source is null)
        {
            return;
        }

        foreach (var header in source)
        {
            var separator = header.IndexOf(':', StringComparison.Ordinal);
            if (separator <= 0)
            {
                continue;
            }
            var name = header[..separator];
            if (ShouldForward(name))
            {
                response.Headers.Append(name, header[(separator + 1)..]);
            }
        }
    }

    private static async Task<bool> IsPathRewriteEnabledAsync(SpecusDbContext db, string clientName, string route,
        CancellationToken cancellationToken)
    {
        var account = await db.ClientAccounts.AsNoTracking()
            .FirstOrDefaultAsync(c => c.ClientName == clientName, cancellationToken)
            .ConfigureAwait(false);
        if (account is null)
        {
            return false;
        }
        return await db.HttpRouteMappings.AsNoTracking()
            .Where(r => r.ClientId == account.Id && r.Route == route)
            .Select(r => r.PathRewriteEnabled)
            .FirstOrDefaultAsync(cancellationToken)
            .ConfigureAwait(false);
    }

    private static List<string>? StripRewriteHeaders(List<string>? source)
    {
        if (source is null)
        {
            return null;
        }
        var result = new List<string>(source.Count);
        foreach (var header in source)
        {
            var separator = header.IndexOf(':', StringComparison.Ordinal);
            if (separator <= 0)
            {
                result.Add(header);
                continue;
            }
            var name = header[..separator].Trim();
            if (name.Equals("content-encoding", StringComparison.OrdinalIgnoreCase)
                || name.Equals("content-length", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }
            result.Add(header);
        }
        return result;
    }

    private static readonly FrozenSet<string> RewritableContentTypes = new[]
    {
        "text/html", "text/css", "text/javascript", "application/javascript",
        "application/x-javascript", "application/ecmascript", "text/ecmascript",
    }.ToFrozenSet(StringComparer.OrdinalIgnoreCase);

    private static bool IsRewritable(IReadOnlyList<string>? headers)
    {
        foreach (var header in headers ?? [])
        {
            var separator = header.IndexOf(':');
            if (separator > 0 && header[..separator].Equals("content-type", StringComparison.OrdinalIgnoreCase))
            {
                var contentType = header[(separator + 1)..].Split(';', 2)[0].Trim();
                return RewritableContentTypes.Contains(contentType);
            }
        }
        return false;
    }

    private static async Task WriteResponseChunkAsync(HttpResponse response, byte[] data,
        LimitedCapture capture, TrafficUsageService traffic, string clientName, string route,
        CancellationToken cancellationToken)
    {
        if (data.Length == 0)
        {
            return;
        }
        await response.Body.WriteAsync(data, cancellationToken).ConfigureAwait(false);
        await response.Body.FlushAsync(cancellationToken).ConfigureAwait(false);
        capture.Write(data);
        traffic.RecordHttpDownload(clientName, route, data.Length);
    }

    private static int? AsInt(Dictionary<string, object?>? metadata, string key)
    {
        if (metadata is null || !metadata.TryGetValue(key, out var value) || value is null)
        {
            return null;
        }
        return value switch
        {
            int number => number,
            long number when number is >= int.MinValue and <= int.MaxValue => (int)number,
            double number when number is >= int.MinValue and <= int.MaxValue => (int)number,
            JsonValue json when json.TryGetValue<int>(out var number) => number,
            JsonElement json when json.TryGetInt32(out var number) => number,
            _ when int.TryParse(value.ToString(), out var number) => number,
            _ => null,
        };
    }

    private static List<string> AsStrings(Dictionary<string, object?>? metadata, string key)
    {
        if (metadata is null || !metadata.TryGetValue(key, out var value) || value is null)
        {
            return [];
        }
        return value switch
        {
            IEnumerable<string> values => values.ToList(),
            JsonArray array => array.Select(static item => item?.GetValue<string>())
                .Where(static item => item is not null).Cast<string>().ToList(),
            JsonElement { ValueKind: JsonValueKind.Array } array => array.EnumerateArray()
                .Where(static item => item.ValueKind == JsonValueKind.String)
                .Select(static item => item.GetString()!).ToList(),
            IEnumerable<object?> values => values.Where(static item => item is not null)
                .Select(static item => item!.ToString()!).ToList(),
            _ => [],
        };
    }

    private static List<string> DeclaredRequestTrailers(HttpRequest request) =>
        request.Headers["Trailer"].SelectMany(static value =>
                (value ?? "").Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            .Where(IsValidHeaderName).Distinct(StringComparer.OrdinalIgnoreCase).ToList();

    private static List<string> RequestTrailers(HttpContext context)
    {
        var feature = context.Features.Get<IHttpRequestTrailersFeature>();
        if (feature is null || !feature.Available)
        {
            return [];
        }
        var result = new List<string>();
        foreach (var (name, values) in feature.Trailers)
        {
            if (!IsValidHeaderName(name))
            {
                continue;
            }
            result.AddRange(values.Select(value => $"{name}:{value}"));
        }
        return result;
    }

    private static void AppendResponseTrailer(HttpResponse response, string line)
    {
        var separator = line.IndexOf(':');
        if (separator <= 0)
        {
            return;
        }
        var name = line[..separator].Trim();
        if (IsValidHeaderName(name))
        {
            response.AppendTrailer(name, line[(separator + 1)..].Trim());
        }
    }

    private static bool IsValidHeaderName(string name) =>
        !string.IsNullOrWhiteSpace(name) && name.All(static ch =>
            char.IsAsciiLetterOrDigit(ch) || "!#$%&'*+-.^_`|~".Contains(ch));

    private sealed class LimitedCapture
    {
        private readonly object _sync = new();
        private readonly int _limit;
        private readonly MemoryStream _buffer = new();

        public LimitedCapture(int limit) => _limit = Math.Max(0, limit);

        public void Write(ReadOnlySpan<byte> data)
        {
            lock (_sync)
            {
                var remaining = _limit - checked((int)_buffer.Length);
                if (remaining > 0)
                {
                    _buffer.Write(data[..Math.Min(data.Length, remaining)]);
                }
            }
        }

        public byte[] Bytes()
        {
            lock (_sync)
            {
                return _buffer.ToArray();
            }
        }
    }

    private static bool ShouldForward(string name) => !SkippedHeaders.Contains(name);

    private static async Task WriteTextErrorAsync(HttpResponse response, int statusCode, string message)
    {
        response.StatusCode = statusCode;
        response.ContentType = "text/plain;charset=UTF-8";
        await response.WriteAsync(message, Encoding.UTF8).ConfigureAwait(false);
    }
}
