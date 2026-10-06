using System.Globalization;
using System.Net.WebSockets;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.Extensions.Options;
using Specus.Server.Configuration;
using Specus.Server.Management;
using Specus.Server.Nat;

namespace Specus.Server.Http;

/// <summary>
/// <c>ANY /http-share/{shareId}/**</c>: the visitor side of temporary HTTP shares
/// (temporary-http-share.md §6). Every decision is taken before the body is read, a NAT stream is
/// opened or a 101 is answered, in the order of §6.1; the admitted request is then forwarded with
/// the route's own semantics through the same code as <c>/http/</c>.
/// </summary>
public static partial class DirectHttpEndpoints
{
    /// <summary>NAT RST error code for a stream cut because its share ended.</summary>
    private const uint ShareEndedResetCode = 8;
    private const string ShareEndedReason = "http share ended";

    private static async Task ForwardShareAsync(HttpContext context, DirectHttpDispatcher dispatcher,
        TrafficUsageService traffic, IOptions<DirectHttpOptions> options, TrafficInspectionService inspection,
        HttpMediaCaptureService mediaCaptures, ILoggerFactory loggerFactory, HttpShareService shares,
        HttpShareStreamRegistry streams, HttpShareRequestRateLimiter limiter, HttpShareClock clock)
    {
        var startedAt = DateTimeOffset.UtcNow;
        var rest = RawSharePath(context)[HttpShareProtocol.SharePathRoot.Length..];
        var slash = rest.IndexOf('/', StringComparison.Ordinal);
        var shareId = slash < 0 ? rest : rest[..slash];
        if (!HttpShareProtocol.IsShareId(shareId))
        {
            await WriteShareRefusalAsync(context, StatusCodes.Status404NotFound, HttpShareCodes.NotFound)
                .ConfigureAwait(false);
            return;
        }
        if (slash < 0)
        {
            // The cookie path ends with a slash; without it the browser would not send the cookie.
            var query = RawQuery(context.Request.QueryString);
            context.Response.StatusCode = StatusCodes.Status308PermanentRedirect;
            context.Response.Headers.CacheControl = "no-store";
            context.Response.Headers.Location = HttpShareProtocol.SharePath(shareId)
                                                + (string.IsNullOrEmpty(query) ? string.Empty : "?" + query);
            return;
        }
        var relativePath = "/" + rest[(slash + 1)..];

        var decision = await shares.AuthorizeVisitorAsync(shareId, context.Request.Headers.Cookie,
            context.RequestAborted).ConfigureAwait(false);
        if (!decision.Admitted)
        {
            if (decision.ClearCookie)
            {
                context.Response.Headers.Append("Set-Cookie", HttpShareProtocol.ClearCookieHeader(shareId));
            }
            await WriteShareRefusalAsync(context, decision.StatusCode, decision.Code!).ConfigureAwait(false);
            return;
        }
        var share = decision.Share!;
        var upgrade = RawServerWebSocketConnection.LooksLikeWebSocketUpgrade(context.Request);
        var refusal = HttpShareProtocol.ScopeDecision(share.Access, share.PathPrefix, context.Request.Method,
            relativePath, upgrade);
        if (refusal is not null)
        {
            if (refusal.StatusCode == StatusCodes.Status405MethodNotAllowed)
            {
                context.Response.Headers.Allow = "GET, HEAD";
            }
            await WriteShareRefusalAsync(context, refusal.StatusCode, refusal.Code).ConfigureAwait(false);
            return;
        }

        // Concurrency and rate are charged only once the credential and the scope have passed, so
        // a third party who knows the share id cannot use up a legitimate visitor's budget.
        using var lease = streams.TryAcquire(shareId, share.ExpiresAt);
        if (lease is null)
        {
            context.Response.Headers.RetryAfter = "1";
            await WriteShareRefusalAsync(context, StatusCodes.Status429TooManyRequests, HttpShareCodes.Busy)
                .ConfigureAwait(false);
            return;
        }
        if (!limiter.TryAcquire(shareId, clock.NowMs, out var waitMs))
        {
            context.Response.Headers.RetryAfter =
                GcraRateLimiter.RetryAfterSeconds(waitMs).ToString(CultureInfo.InvariantCulture);
            await WriteShareRefusalAsync(context, StatusCodes.Status429TooManyRequests, HttpShareCodes.RateLimited)
                .ConfigureAwait(false);
            return;
        }

        // The route's current name on its client's current name: renames never break a share.
        var target = new ForwardTarget(decision.Client!.ClientName, decision.Route!.Route, relativePath,
            StripAuthorization: false,
            PathRewriteEnabled: decision.Route.PathRewriteEnabled,
            RewritePrefix: HttpShareProtocol.SharePathRoot + shareId,
            ShareId: shareId,
            Cut: lease.CutToken);
        if (upgrade)
        {
            await ForwardWebSocketUpgradeAsync(context, target, dispatcher).ConfigureAwait(false);
            return;
        }
        await ForwardHttpAsync(context, target, dispatcher, traffic, options.Value, inspection,
            mediaCaptures, loggerFactory.CreateLogger(LoggerCategory), startedAt).ConfigureAwait(false);
    }

    /// <summary>The raw (still percent-encoded) request path under <c>/http-share/</c>, without the query.</summary>
    private static string RawSharePath(HttpContext context)
    {
        var rawTarget = context.Features.Get<IHttpRequestFeature>()?.RawTarget;
        if (!string.IsNullOrEmpty(rawTarget))
        {
            var queryIndex = rawTarget.IndexOf('?', StringComparison.Ordinal);
            var rawPath = queryIndex >= 0 ? rawTarget[..queryIndex] : rawTarget;
            if (rawPath.StartsWith(HttpShareProtocol.SharePathRoot, StringComparison.Ordinal))
            {
                return rawPath;
            }
        }
        return PreserveRawPathEncoding(context.Request.Path.Value ?? HttpShareProtocol.SharePathRoot);
    }

    /// <summary>
    /// For a share, the forwarded headers without the share cookie: every other cookie pair is kept
    /// in order and joined into one Cookie header, which is left out when nothing remains. The
    /// token therefore never reaches the device.
    /// </summary>
    private static List<string> ShareRequestHeaders(ForwardTarget target, List<string> headers)
    {
        if (target.ShareId is null)
        {
            return headers;
        }
        var cookies = new List<string>();
        var result = new List<string>(headers.Count);
        var cookieIndex = -1;
        foreach (var header in headers)
        {
            var separator = header.IndexOf(':', StringComparison.Ordinal);
            if (separator > 0 && header[..separator].Trim().Equals("Cookie", StringComparison.OrdinalIgnoreCase))
            {
                cookieIndex = cookieIndex < 0 ? result.Count : cookieIndex;
                cookies.Add(header[(separator + 1)..]);
                continue;
            }
            result.Add(header);
        }
        var forwarded = HttpShareProtocol.ForwardedCookie(cookies);
        if (forwarded is not null)
        {
            result.Insert(cookieIndex, "Cookie:" + forwarded);
        }
        return result;
    }

    /// <summary>A share never relays a Cookie trailer: it could carry the share token.</summary>
    private static List<string> ShareTrailerNames(ForwardTarget target, List<string> names) =>
        target.ShareId is null
            ? names
            : names.Where(static name => !name.Equals("Cookie", StringComparison.OrdinalIgnoreCase)).ToList();

    private static async Task ResetQuietlyAsync(HttpSpecusStream stream)
    {
        try
        {
            await stream.ResetAsync(ShareEndedResetCode, ShareEndedReason, CancellationToken.None)
                .ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is IOException or InvalidOperationException or ObjectDisposedException
                                       or OperationCanceledException)
        {
            // The device side is already gone; the public response has been aborted either way.
        }
    }

    /// <summary>
    /// Ends a WebSocket whose share has ended: RST to the device, close code 1008 to the visitor,
    /// then the pumps are stopped.
    /// </summary>
    private static async Task CutWebSocketAsync(RawServerWebSocketConnection socket, WebSocketSpecusStream stream,
        WebSocketTunnelCloseState closeState, CancellationTokenSource pumpCts, Task browserToClient,
        Task clientToBrowser)
    {
        // Marked first so the client pump does not answer the RST with its own close code.
        closeState.MarkClientInitiated();
        try
        {
            await stream.ResetAsync(ShareEndedResetCode, ShareEndedReason, CancellationToken.None)
                .ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is IOException or InvalidOperationException or ObjectDisposedException
                                       or OperationCanceledException)
        {
            // The device side is already gone.
        }
        await SafeSendBrowserCloseAsync(socket, (ushort)WebSocketCloseStatus.PolicyViolation, "share ended")
            .ConfigureAwait(false);
        pumpCts.Cancel();
        foreach (var pump in new[] { browserToClient, clientToBrowser })
        {
            try
            {
                await pump.ConfigureAwait(false);
            }
            catch (Exception)
            {
                // The tunnel is being torn down; a pump failing on the reset stream is expected.
            }
        }
    }

    private static async Task WriteShareRefusalAsync(HttpContext context, int statusCode, string code)
    {
        context.Response.StatusCode = statusCode;
        context.Response.Headers.CacheControl = "no-store";
        context.Response.ContentType = "application/json; charset=utf-8";
        await context.Response.WriteAsync(new JsonObject { ["code"] = code }.ToJsonString())
            .ConfigureAwait(false);
    }
}
