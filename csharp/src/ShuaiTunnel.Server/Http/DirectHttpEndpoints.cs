using System.Text;
using Microsoft.Extensions.Options;
using ShuaiTunnel.Protocol.Packets;
using ShuaiTunnel.Server.Configuration;
using ShuaiTunnel.Server.Nat;

namespace ShuaiTunnel.Server.Http;

public static class DirectHttpEndpoints
{
    private static readonly HashSet<string> SkippedHeaders = new(StringComparer.OrdinalIgnoreCase)
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
    };

    public static void MapDirectHttpTunnel(this WebApplication app)
    {
        var methods = new[] { "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS" };
        app.MapMethods("/http/{clientName}/{route}/{**rest}", methods, ForwardAsync);
        app.MapMethods("/http/{clientName}/{route}", methods, ForwardAsync);
    }

    private static async Task ForwardAsync(HttpContext context, string clientName, string route,
        string? rest, DirectHttpDispatcher dispatcher, TrafficUsageService traffic,
        IOptions<DirectHttpOptions> options)
    {
        var requestBody = await ReadBodyAsync(context.Request, options.Value.MaxRequestBodySize)
            .ConfigureAwait(false);
        if (requestBody is null)
        {
            await WriteTextErrorAsync(context.Response, StatusCodes.Status413PayloadTooLarge,
                "HTTP 请求体超过限制").ConfigureAwait(false);
            return;
        }

        var relativePath = string.IsNullOrWhiteSpace(rest) ? "/" : "/" + rest;
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

        try
        {
            var response = await dispatcher.ForwardAsync(clientName, packet, context.RequestAborted)
                .ConfigureAwait(false);
            traffic.RecordUpload(clientName, requestBody.Length);
            var responseBody = response.Body ?? Array.Empty<byte>();
            traffic.RecordDownload(clientName, responseBody.Length);

            if (!string.IsNullOrEmpty(response.Error))
            {
                await WriteTextErrorAsync(context.Response,
                    response.StatusCode > 0 ? response.StatusCode : StatusCodes.Status502BadGateway,
                    response.Error).ConfigureAwait(false);
                return;
            }

            context.Response.StatusCode = response.StatusCode > 0 ? response.StatusCode : StatusCodes.Status200OK;
            CopyHeaders(response.Headers, context.Response);
            await context.Response.Body.WriteAsync(responseBody).ConfigureAwait(false);
        }
        catch (DirectHttpTunnelException ex)
        {
            await WriteTextErrorAsync(context.Response, ex.StatusCode, ex.Message).ConfigureAwait(false);
        }
    }

    private static async Task<byte[]?> ReadBodyAsync(HttpRequest request, int maxBytes)
    {
        using var buffer = new MemoryStream();
        var chunk = new byte[16 * 1024];
        int read;
        while ((read = await request.Body.ReadAsync(chunk).ConfigureAwait(false)) > 0)
        {
            if (buffer.Length + read > maxBytes)
            {
                return null;
            }
            buffer.Write(chunk, 0, read);
        }
        return buffer.ToArray();
    }

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

    private static bool ShouldForward(string name) => !SkippedHeaders.Contains(name);

    private static async Task WriteTextErrorAsync(HttpResponse response, int statusCode, string message)
    {
        response.StatusCode = statusCode;
        response.ContentType = "text/plain;charset=UTF-8";
        await response.WriteAsync(message, Encoding.UTF8).ConfigureAwait(false);
    }
}
