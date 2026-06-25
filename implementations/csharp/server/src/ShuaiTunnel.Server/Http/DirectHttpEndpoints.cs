using System.Buffers;
using System.Collections.Frozen;
using System.Text;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using ShuaiTunnel.Protocol.Packets;
using ShuaiTunnel.Server.Configuration;
using ShuaiTunnel.Server.Data;
using ShuaiTunnel.Server.Management;
using ShuaiTunnel.Server.Nat;

namespace ShuaiTunnel.Server.Http;

/// <summary>
/// Public HTTP ingress for browser/API traffic that should be carried through a connected tunnel
/// client. This is the ASP.NET endpoint counterpart to Java's <c>HttpTunnelController</c>; it
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

    public static void MapDirectHttpTunnel(this WebApplication app)
    {
        app.MapMethods("/http/{clientName}/{route}/{**rest}", Methods, ForwardAsync);
        app.MapMethods("/http/{clientName}/{route}", Methods, ForwardAsync);
    }

    private static async Task ForwardAsync(HttpContext context, string clientName, string route,
        string? rest, DirectHttpDispatcher dispatcher, TrafficUsageService traffic,
        IOptions<DirectHttpOptions> options, TunnelDbContext db, TrafficInspectionService inspection)
    {
        var startedAt = DateTimeOffset.UtcNow;
        var bodyRead = await ReadBodyAsync(context.Request, options.Value.MaxRequestBodySize)
            .ConfigureAwait(false);
        var requestBody = bodyRead.Body;
        var relativePath = RelativePath(context, rest);
        var packet = new DirectHttpRequestPacket
        {
            RequestMethod = context.Request.Method,
            Route = route,
            RelativePath = relativePath,
            RawQuery = context.Request.QueryString.HasValue
                ? context.Request.QueryString.Value!.TrimStart('?')
                : null,
            Headers = RequestHeaders(context.Request),
            Body = requestBody,
        };
        if (bodyRead.TooLarge)
        {
            const string message = "HTTP 请求体超过限制";
            var responseBody = Encoding.UTF8.GetBytes(message);
            await inspection.RecordHttpExchangeAsync(new HttpExchangeCapture(clientName, route,
                    packet.RequestMethod, packet.RelativePath, packet.RawQuery, packet.Headers, requestBody,
                    StatusCodes.Status413PayloadTooLarge, PlainErrorHeaders(), responseBody, startedAt,
                    context.Connection.RemoteIpAddress?.ToString(), message), context.RequestAborted)
                .ConfigureAwait(false);
            await WriteTextErrorAsync(context.Response, StatusCodes.Status413PayloadTooLarge,
                message).ConfigureAwait(false);
            return;
        }

        try
        {
            var response = await dispatcher.ForwardAsync(clientName, packet, context.RequestAborted)
                .ConfigureAwait(false);
            traffic.RecordHttpUpload(clientName, route, requestBody.Length);
            var responseBody = response.Body ?? Array.Empty<byte>();
            traffic.RecordHttpDownload(clientName, route, responseBody.Length);

            if (!string.IsNullOrEmpty(response.Error))
            {
                var statusCode = response.StatusCode > 0 ? response.StatusCode : StatusCodes.Status502BadGateway;
                responseBody = Encoding.UTF8.GetBytes(response.Error);
                await inspection.RecordHttpExchangeAsync(new HttpExchangeCapture(clientName, route,
                        packet.RequestMethod, packet.RelativePath, packet.RawQuery, packet.Headers, requestBody,
                        statusCode, PlainErrorHeaders(), responseBody, startedAt, context.Connection.RemoteIpAddress?.ToString(),
                        response.Error), context.RequestAborted)
                    .ConfigureAwait(false);
                await WriteTextErrorAsync(context.Response, statusCode, response.Error).ConfigureAwait(false);
                return;
            }

            context.Response.StatusCode = response.StatusCode > 0 ? response.StatusCode : StatusCodes.Status200OK;
            var originalResponseHeaders = response.Headers;
            var responseHeaders = originalResponseHeaders;
            if (await IsPathRewriteEnabledAsync(db, clientName, route, context.RequestAborted)
                    .ConfigureAwait(false)
                && ResponseRewriter.TryRewrite(responseBody, clientName, route, originalResponseHeaders,
                    options.Value.RewriteMaxBodyBytes, out var rewritten))
            {
                responseBody = rewritten;
                responseHeaders = StripRewriteHeaders(responseHeaders);
            }
            CopyHeaders(responseHeaders, context.Response);
            await inspection.RecordHttpExchangeAsync(new HttpExchangeCapture(clientName, route,
                    packet.RequestMethod, packet.RelativePath, packet.RawQuery, packet.Headers, requestBody,
                    context.Response.StatusCode, originalResponseHeaders, responseBody, startedAt,
                    context.Connection.RemoteIpAddress?.ToString(), null), context.RequestAborted)
                .ConfigureAwait(false);
            await context.Response.Body.WriteAsync(responseBody).ConfigureAwait(false);
        }
        catch (DirectHttpTunnelException ex)
        {
            var responseBody = Encoding.UTF8.GetBytes(ex.Message);
            await inspection.RecordHttpExchangeAsync(new HttpExchangeCapture(clientName, route,
                    packet.RequestMethod, packet.RelativePath, packet.RawQuery, packet.Headers, requestBody,
                    ex.StatusCode, PlainErrorHeaders(), responseBody, startedAt, context.Connection.RemoteIpAddress?.ToString(),
                    ex.Message), CancellationToken.None)
                .ConfigureAwait(false);
            await WriteTextErrorAsync(context.Response, ex.StatusCode, ex.Message).ConfigureAwait(false);
        }
    }

    private static async Task<RequestBodyRead> ReadBodyAsync(HttpRequest request, int maxBytes)
    {
        var initialCapacity = request.ContentLength is > 0 and <= int.MaxValue
            ? (int)Math.Min(request.ContentLength.Value, maxBytes + 1L)
            : 0;
        using var buffer = initialCapacity > 0 ? new MemoryStream(initialCapacity) : new MemoryStream();
        var chunk = ArrayPool<byte>.Shared.Rent(16 * 1024);
        try
        {
            int read;
            while ((read = await request.Body.ReadAsync(chunk).ConfigureAwait(false)) > 0)
            {
                if (buffer.Length + read > maxBytes)
                {
                    var remaining = Math.Max(0, maxBytes + 1 - (int)buffer.Length);
                    if (remaining > 0)
                    {
                        buffer.Write(chunk, 0, Math.Min(read, remaining));
                    }
                    return new RequestBodyRead(buffer.ToArray(), TooLarge: true);
                }
                buffer.Write(chunk, 0, read);
            }
            return new RequestBodyRead(buffer.ToArray(), TooLarge: false);
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(chunk);
        }
    }

    private readonly record struct RequestBodyRead(byte[] Body, bool TooLarge);

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

    private static async Task<bool> IsPathRewriteEnabledAsync(TunnelDbContext db, string clientName, string route,
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

    private static bool ShouldForward(string name) => !SkippedHeaders.Contains(name);

    private static async Task WriteTextErrorAsync(HttpResponse response, int statusCode, string message)
    {
        response.StatusCode = statusCode;
        response.ContentType = "text/plain;charset=UTF-8";
        await response.WriteAsync(message, Encoding.UTF8).ConfigureAwait(false);
    }
}
