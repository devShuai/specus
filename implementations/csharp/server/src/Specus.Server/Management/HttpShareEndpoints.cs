using System.Globalization;
using System.Text.Json;
using Microsoft.Extensions.Options;
using Specus.Server.Configuration;
using Specus.Server.Http;
using Specus.Server.Security;

namespace Specus.Server.Management;

/// <summary>
/// The management API of temporary HTTP shares and the anonymous token exchange
/// (temporary-http-share.md §4, §5.2). Answers are JSON written here directly so status codes,
/// <c>{"code"}</c> bodies and cache headers are exactly the contract's.
/// </summary>
public static class HttpShareEndpoints
{
    internal const string ManagementCacheControl = "private, no-store";
    private const int MaxManagementBodyBytes = 16 * 1024;

    /// <summary>
    /// True for the paths of the share management endpoints (§4), so the 401 of the shared
    /// authentication layer carries their cache header as well. The anonymous exchange is not one.
    /// </summary>
    internal static bool IsManagementPath(PathString path)
    {
        if (path.Equals("/api/admin/http-access-audit", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }
        if (!path.StartsWithSegments("/api/admin/http-routes", StringComparison.OrdinalIgnoreCase,
                out var rest) || !rest.HasValue)
        {
            return false;
        }
        // rest is "/{routeId}/shares[/{shareId}[/revoke]]" or "/{routeId}/access-audit".
        var segments = rest.Value!.TrimEnd('/').Split('/');
        if (segments.Length < 3 || segments[1].Length == 0)
        {
            return false;
        }
        return segments.Length switch
        {
            3 => segments[2].Equals("shares", StringComparison.OrdinalIgnoreCase)
                 || segments[2].Equals("access-audit", StringComparison.OrdinalIgnoreCase),
            4 => segments[2].Equals("shares", StringComparison.OrdinalIgnoreCase) && segments[3].Length > 0,
            5 => segments[2].Equals("shares", StringComparison.OrdinalIgnoreCase) && segments[3].Length > 0
                 && segments[4].Equals("revoke", StringComparison.OrdinalIgnoreCase),
            _ => false,
        };
    }

    public static void MapHttpShareApi(this WebApplication app)
    {
        app.MapPost("/api/admin/http-routes/{routeId}/shares",
            async (HttpContext context, string routeId, IOptions<AuthOptions> authOptions,
                HttpShareService shares) =>
            {
                var body = await ReadBodyAsync(context.Request, MaxManagementBodyBytes).ConfigureAwait(false);
                var result = await shares.CreateAsync(ManagementContext.From(context, authOptions.Value),
                    routeId, body, context.RequestAborted).ConfigureAwait(false);
                await WriteAsync(context.Response, result, ManagementCacheControl).ConfigureAwait(false);
            });

        app.MapGet("/api/admin/http-routes/{routeId}/shares",
            async (HttpContext context, string routeId, IOptions<AuthOptions> authOptions,
                HttpShareService shares) =>
            {
                var result = await shares.ListAsync(ManagementContext.From(context, authOptions.Value),
                    routeId, context.RequestAborted).ConfigureAwait(false);
                await WriteAsync(context.Response, result, ManagementCacheControl).ConfigureAwait(false);
            });

        app.MapGet("/api/admin/http-routes/{routeId}/shares/{shareId}",
            async (HttpContext context, string routeId, string shareId, IOptions<AuthOptions> authOptions,
                HttpShareService shares) =>
            {
                var result = await shares.GetAsync(ManagementContext.From(context, authOptions.Value),
                    routeId, shareId, context.RequestAborted).ConfigureAwait(false);
                await WriteAsync(context.Response, result, ManagementCacheControl).ConfigureAwait(false);
            });

        app.MapPost("/api/admin/http-routes/{routeId}/shares/{shareId}/revoke",
            async (HttpContext context, string routeId, string shareId, IOptions<AuthOptions> authOptions,
                HttpShareService shares) =>
            {
                var body = await ReadBodyAsync(context.Request, MaxManagementBodyBytes).ConfigureAwait(false);
                var result = await shares.RevokeAsync(ManagementContext.From(context, authOptions.Value),
                    routeId, shareId, body, context.RequestAborted).ConfigureAwait(false);
                await WriteAsync(context.Response, result, ManagementCacheControl).ConfigureAwait(false);
            });

        app.MapGet("/api/admin/http-routes/{routeId}/access-audit",
            async (HttpContext context, string routeId, IOptions<AuthOptions> authOptions,
                HttpShareService shares) =>
            {
                var query = context.Request.Query;
                var result = await shares.RouteAuditAsync(ManagementContext.From(context, authOptions.Value),
                    routeId, Single(query["limit"]), Single(query["before"]), context.RequestAborted)
                    .ConfigureAwait(false);
                await WriteAsync(context.Response, result, ManagementCacheControl).ConfigureAwait(false);
            });

        app.MapGet("/api/admin/http-access-audit",
            async (HttpContext context, IOptions<AuthOptions> authOptions, HttpShareService shares) =>
            {
                var query = context.Request.Query;
                var result = await shares.TenantAuditAsync(ManagementContext.From(context, authOptions.Value),
                    Single(query["routeId"]), Single(query["limit"]), Single(query["before"]),
                    context.RequestAborted).ConfigureAwait(false);
                await WriteAsync(context.Response, result, ManagementCacheControl).ConfigureAwait(false);
            });

        app.MapPost("/api/public/http-shares/exchange", ExchangeAsync);
    }

    /// <summary>
    /// POST /api/public/http-shares/exchange: JSON only (a cross-site form cannot submit it), the
    /// body is exactly <c>{"token": "..."}</c>, and every request from the rate-limit step on is
    /// charged to the source address resolved through the trusted proxies.
    /// </summary>
    private static async Task ExchangeAsync(HttpContext context, HttpShareService shares,
        HttpShareExchangeRateLimiter limiter, ClientAddressResolver addresses, HttpShareClock clock)
    {
        const string cacheControl = "no-store";
        context.Response.Headers["Referrer-Policy"] = "no-referrer";
        if (!IsJsonMediaType(context.Request.ContentType))
        {
            await WriteAsync(context.Response, HttpShareService.ShareResponse.Error(
                StatusCodes.Status415UnsupportedMediaType, HttpShareCodes.RequestInvalid), cacheControl)
                .ConfigureAwait(false);
            return;
        }
        var body = await ReadBodyAsync(context.Request, HttpShareProtocol.ExchangeMaxBodyBytes)
            .ConfigureAwait(false);
        var token = body is null ? null : ExchangeToken(body.Value);
        if (token is null)
        {
            await WriteAsync(context.Response, HttpShareService.ShareResponse.Error(
                StatusCodes.Status400BadRequest, HttpShareCodes.RequestInvalid), cacheControl)
                .ConfigureAwait(false);
            return;
        }
        if (!limiter.TryAcquire(addresses.Resolve(context), clock.NowMs, out var waitMs))
        {
            await WriteAsync(context.Response, HttpShareService.ShareResponse.Error(
                    StatusCodes.Status429TooManyRequests, HttpShareCodes.RateLimited) with
                {
                    RetryAfterSeconds = GcraRateLimiter.RetryAfterSeconds(waitMs),
                }, cacheControl)
                .ConfigureAwait(false);
            return;
        }
        var result = await shares.ExchangeAsync(token, context.RequestAborted).ConfigureAwait(false);
        await WriteAsync(context.Response, result, cacheControl).ConfigureAwait(false);
    }

    internal static bool IsJsonMediaType(string? contentType) =>
        contentType is not null
        && contentType.Split(';', 2)[0].Trim().Equals("application/json", StringComparison.OrdinalIgnoreCase);

    /// <summary>The token of a body that is an object whose only member is the string <c>token</c>.</summary>
    internal static string? ExchangeToken(ReadOnlyMemory<byte> body)
    {
        try
        {
            using var document = JsonDocument.Parse(body);
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object)
            {
                return null;
            }
            string? token = null;
            var members = 0;
            foreach (var property in root.EnumerateObject())
            {
                members++;
                if (property.Name == "token" && property.Value.ValueKind == JsonValueKind.String)
                {
                    token = property.Value.GetString();
                }
            }
            return members == 1 ? token : null;
        }
        catch (Exception error) when (error is JsonException or InvalidOperationException)
        {
            return null;
        }
    }

    /// <summary>The request body, or null when it is longer than <paramref name="maxBytes"/>.</summary>
    internal static async Task<ReadOnlyMemory<byte>?> ReadBodyAsync(HttpRequest request, int maxBytes)
    {
        if (request.ContentLength > maxBytes)
        {
            return null;
        }
        using var buffer = new MemoryStream();
        var chunk = new byte[4096];
        while (true)
        {
            var read = await request.Body.ReadAsync(chunk, request.HttpContext.RequestAborted).ConfigureAwait(false);
            if (read == 0)
            {
                return buffer.ToArray();
            }
            if (buffer.Length + read > maxBytes)
            {
                return null;
            }
            buffer.Write(chunk, 0, read);
        }
    }

    internal static async Task WriteAsync(HttpResponse response, HttpShareService.ShareResponse result,
        string cacheControl)
    {
        response.StatusCode = result.StatusCode;
        response.Headers.CacheControl = cacheControl;
        if (result.SetCookie is not null)
        {
            response.Headers.Append("Set-Cookie", result.SetCookie);
        }
        if (result.RetryAfterSeconds is { } retryAfter)
        {
            response.Headers.RetryAfter = retryAfter.ToString(CultureInfo.InvariantCulture);
        }
        response.ContentType = "application/json; charset=utf-8";
        await response.WriteAsync(result.Body.ToJsonString(HttpShareService.JsonOptions)).ConfigureAwait(false);
    }

    private static string? Single(Microsoft.Extensions.Primitives.StringValues values) =>
        values.Count == 0 ? null : values.Count == 1 ? values[0] : string.Empty;
}
