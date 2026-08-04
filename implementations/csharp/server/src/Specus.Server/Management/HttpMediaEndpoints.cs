using System.Net;
using System.Text;
using Microsoft.Extensions.Options;
using Specus.Server.Configuration;
using Specus.Server.Data.Entities;

namespace Specus.Server.Management;

public static class HttpMediaEndpoints
{
    private const string AdminBase = "/api/admin/traffic/media-captures";
    private const string PublicBase = "/api/public/media-playback";

    public static void MapHttpMediaApi(this WebApplication app)
    {
        app.MapGet(AdminBase, async (HttpContext http, long? clientId, string? route,
            int? page, int? size, HttpMediaCaptureService captures, IOptions<AuthOptions> auth,
            CancellationToken cancellationToken) => await captures.ListAsync(
                ManagementContext.From(http, auth.Value), clientId, route, page ?? 0, size ?? 50,
                cancellationToken).ConfigureAwait(false));

        app.MapPost(AdminBase + "/{id:long}/playback-ticket", async (HttpContext http, long id,
            bool? backfillMissing, HttpMediaCaptureService captures,
            HttpMediaPlaybackService playback, HttpMediaPlaybackTicketService tickets,
            IOptions<AuthOptions> auth, CancellationToken cancellationToken) =>
        {
            var capture = await FindAdminCaptureAsync(http, captures,
                ManagementContext.From(http, auth.Value), id, cancellationToken).ConfigureAwait(false);
            if (capture is null)
            {
                return Results.Empty;
            }
            var ticket = await tickets.CreateAsync(capture, playback, backfillMissing ?? false,
                cancellationToken).ConfigureAwait(false);
            return Results.Ok(ticket);
        });

        app.MapMethods(AdminBase + "/{id:long}/play", ["GET", "HEAD"],
            async (HttpContext http, long id, HttpMediaCaptureService captures,
                HttpMediaPlaybackService playback, IOptions<AuthOptions> auth,
                CancellationToken cancellationToken) =>
            {
                var capture = await FindAdminCaptureAsync(http, captures,
                    ManagementContext.From(http, auth.Value), id, cancellationToken).ConfigureAwait(false);
                if (capture is null)
                {
                    return;
                }
                await WritePlaybackAsync(http, playback, capture, cancellationToken).ConfigureAwait(false);
            });

        app.MapGet(AdminBase + "/{id:long}/manifest", async (HttpContext http, long id,
            HttpMediaCaptureService captures, IOptions<AuthOptions> auth,
            CancellationToken cancellationToken) =>
        {
            var capture = await FindAdminCaptureAsync(http, captures,
                ManagementContext.From(http, auth.Value), id, cancellationToken).ConfigureAwait(false);
            if (capture is null)
            {
                return;
            }
            await WriteManifestSafelyAsync(http, captures, capture,
                $"{AdminBase}/{capture.Id}/asset", cancellationToken).ConfigureAwait(false);
        });

        app.MapMethods(AdminBase + "/{id:long}/asset", ["GET", "HEAD"],
            async (HttpContext http, long id, string url, HttpMediaCaptureService captures,
                HttpMediaPlaybackService playback, IOptions<AuthOptions> auth,
                CancellationToken cancellationToken) =>
            {
                var anchor = await FindAdminCaptureAsync(http, captures,
                    ManagementContext.From(http, auth.Value), id, cancellationToken).ConfigureAwait(false);
                if (anchor is null)
                {
                    return;
                }
                HttpMediaCapture target;
                try
                {
                    target = await captures.LatestForSourceAsync(anchor, url, cancellationToken)
                        .ConfigureAwait(false);
                }
                catch (ArgumentException ex)
                {
                    await WriteEndpointErrorAsync(http, StatusCodes.Status404NotFound, ex.Message,
                        cancellationToken).ConfigureAwait(false);
                    return;
                }
                if (HttpMediaManifestSupport.IsManifest(target.MediaKind))
                {
                    await WriteManifestSafelyAsync(http, captures, target,
                        $"{AdminBase}/{target.Id}/asset", cancellationToken).ConfigureAwait(false);
                    return;
                }
                await WritePlaybackAsync(http, playback, target, cancellationToken).ConfigureAwait(false);
            });

        app.MapMethods(PublicBase + "/{ticket}/play", ["GET", "HEAD"],
            async (HttpContext http, string ticket, HttpMediaCaptureService captures,
                HttpMediaPlaybackService playback, HttpMediaPlaybackTicketService tickets,
                CancellationToken cancellationToken) =>
            {
                var resolved = await ResolveTicketAsync(http, tickets, ticket, cancellationToken)
                    .ConfigureAwait(false);
                if (resolved is null)
                {
                    return;
                }
                var capture = await FindPublicCaptureAsync(http, captures, resolved, cancellationToken)
                    .ConfigureAwait(false);
                if (capture is null)
                {
                    return;
                }
                await WritePublicPlaybackAsync(http, playback, resolved, capture, capture.SourceUrl,
                    cancellationToken).ConfigureAwait(false);
            });

        app.MapMethods(PublicBase + "/{ticket}/manifest", ["GET", "HEAD"],
            async (HttpContext http, string ticket, HttpMediaCaptureService captures,
                HttpMediaPlaybackTicketService tickets, CancellationToken cancellationToken) =>
            {
                var resolved = await ResolveTicketAsync(http, tickets, ticket, cancellationToken)
                    .ConfigureAwait(false);
                if (resolved is null)
                {
                    return;
                }
                var capture = await FindPublicCaptureAsync(http, captures, resolved, cancellationToken)
                    .ConfigureAwait(false);
                if (capture is null)
                {
                    return;
                }
                await WriteManifestSafelyAsync(http, captures, capture, resolved.AssetBasePath,
                    cancellationToken).ConfigureAwait(false);
            });

        app.MapMethods(PublicBase + "/{ticket}/asset", ["GET", "HEAD"],
            async (HttpContext http, string ticket, string url, HttpMediaCaptureService captures,
                HttpMediaPlaybackService playback, HttpMediaPlaybackTicketService tickets,
                CancellationToken cancellationToken) =>
            {
                var resolved = await ResolveTicketAsync(http, tickets, ticket, cancellationToken)
                    .ConfigureAwait(false);
                if (resolved is null)
                {
                    return;
                }
                var anchor = await FindPublicCaptureAsync(http, captures, resolved, cancellationToken)
                    .ConfigureAwait(false);
                if (anchor is null)
                {
                    return;
                }
                HttpMediaCapture target;
                try
                {
                    target = await captures.LatestForSourceAsync(anchor, url, cancellationToken)
                        .ConfigureAwait(false);
                }
                catch (ArgumentException)
                {
                    if (resolved.BackfillMissing)
                    {
                        RedirectToOrigin(http.Response, anchor, url);
                    }
                    else
                    {
                        await WriteCacheMissAsync(http, StatusCodes.Status404NotFound,
                            "媒体资源尚未缓存", 0, cancellationToken).ConfigureAwait(false);
                    }
                    return;
                }
                if (HttpMediaManifestSupport.IsManifest(target.MediaKind))
                {
                    await WriteManifestSafelyAsync(http, captures, target, resolved.AssetBasePath,
                        cancellationToken).ConfigureAwait(false);
                    return;
                }
                await WritePublicPlaybackAsync(http, playback, resolved, target, url,
                    cancellationToken).ConfigureAwait(false);
            });
    }

    private static async Task WritePlaybackAsync(HttpContext http,
        HttpMediaPlaybackService playback, HttpMediaCapture capture,
        CancellationToken cancellationToken)
    {
        try
        {
            var plan = await playback.PlanAsync(capture, http.Request.Headers.Range.ToString(),
                cancellationToken).ConfigureAwait(false);
            await WritePlanAsync(http, playback, plan, cancellationToken).ConfigureAwait(false);
        }
        catch (HttpMediaPlaybackService.MediaRangeException ex)
        {
            await WriteCacheMissAsync(http, StatusCodes.Status416RangeNotSatisfiable, ex.Message,
                ex.TotalBytes, cancellationToken).ConfigureAwait(false);
        }
    }

    private static async Task WritePublicPlaybackAsync(HttpContext http,
        HttpMediaPlaybackService playback,
        HttpMediaPlaybackTicketService.ResolvedTicket ticket, HttpMediaCapture capture,
        string originSourceUrl, CancellationToken cancellationToken)
    {
        try
        {
            var plan = await playback.PlanAsync(capture, http.Request.Headers.Range.ToString(),
                cancellationToken).ConfigureAwait(false);
            await WritePlanAsync(http, playback, plan, cancellationToken).ConfigureAwait(false);
        }
        catch (HttpMediaPlaybackService.MediaRangeException ex)
        {
            if (ticket.BackfillMissing)
            {
                RedirectToOrigin(http.Response, capture, originSourceUrl);
            }
            else
            {
                await WriteCacheMissAsync(http, StatusCodes.Status416RangeNotSatisfiable,
                    ex.Message, ex.TotalBytes, cancellationToken).ConfigureAwait(false);
            }
        }
        catch (InvalidOperationException ex)
        {
            await WriteEndpointErrorAsync(http, StatusCodes.Status409Conflict, ex.Message,
                cancellationToken).ConfigureAwait(false);
        }
    }

    private static async Task WritePlanAsync(HttpContext http, HttpMediaPlaybackService playback,
        HttpMediaPlaybackService.PlaybackPlan plan, CancellationToken cancellationToken)
    {
        http.Response.StatusCode = plan.Partial ? StatusCodes.Status206PartialContent
            : StatusCodes.Status200OK;
        http.Response.ContentType = plan.ContentType;
        if (!string.IsNullOrWhiteSpace(plan.ContentEncoding))
        {
            http.Response.Headers.ContentEncoding = plan.ContentEncoding;
        }
        http.Response.Headers.AcceptRanges = "bytes";
        http.Response.Headers.CacheControl = "private, no-store";
        if (!string.IsNullOrWhiteSpace(plan.Etag))
        {
            http.Response.Headers.ETag = plan.Etag;
        }
        if (plan.Partial)
        {
            http.Response.Headers.ContentRange = $"bytes {plan.Start}-{plan.End}/{plan.TotalBytes}";
        }
        http.Response.ContentLength = plan.ContentLength;
        if (!HttpMethods.IsHead(http.Request.Method))
        {
            await playback.StreamAsync(plan, http.Response.Body, cancellationToken)
                .ConfigureAwait(false);
        }
    }

    private static async Task WriteManifestSafelyAsync(HttpContext http,
        HttpMediaCaptureService captures, HttpMediaCapture capture, string assetBasePath,
        CancellationToken cancellationToken)
    {
        string manifest;
        try
        {
            manifest = await captures.RewrittenManifestAsync(capture, assetBasePath,
                cancellationToken).ConfigureAwait(false);
        }
        catch (ArgumentException ex)
        {
            await WriteEndpointErrorAsync(http, StatusCodes.Status404NotFound, ex.Message,
                cancellationToken).ConfigureAwait(false);
            return;
        }
        catch (InvalidOperationException ex)
        {
            await WriteEndpointErrorAsync(http, StatusCodes.Status409Conflict, ex.Message,
                cancellationToken).ConfigureAwait(false);
            return;
        }
        var bytes = Encoding.UTF8.GetBytes(manifest);
        http.Response.StatusCode = StatusCodes.Status200OK;
        http.Response.ContentType = capture.MediaKind == HttpMediaManifestSupport.HlsManifest
            ? "application/vnd.apple.mpegurl; charset=utf-8" : "application/dash+xml; charset=utf-8";
        http.Response.Headers.CacheControl = "no-store";
        http.Response.ContentLength = bytes.Length;
        if (!HttpMethods.IsHead(http.Request.Method))
        {
            await http.Response.Body.WriteAsync(bytes, cancellationToken).ConfigureAwait(false);
        }
    }

    private static async Task<HttpMediaPlaybackTicketService.ResolvedTicket?> ResolveTicketAsync(
        HttpContext http, HttpMediaPlaybackTicketService tickets, string token,
        CancellationToken cancellationToken)
    {
        try
        {
            return tickets.Resolve(token);
        }
        catch (ArgumentException ex)
        {
            http.Response.StatusCode = StatusCodes.Status404NotFound;
            http.Response.ContentType = "text/plain;charset=UTF-8";
            http.Response.Headers.CacheControl = "private, no-store";
            var bytes = Encoding.UTF8.GetBytes(ex.Message);
            http.Response.ContentLength = bytes.Length;
            if (!HttpMethods.IsHead(http.Request.Method))
            {
                await http.Response.Body.WriteAsync(bytes, cancellationToken).ConfigureAwait(false);
            }
            return null;
        }
    }

    private static async Task<HttpMediaCapture?> FindPublicCaptureAsync(HttpContext http,
        HttpMediaCaptureService captures, HttpMediaPlaybackTicketService.ResolvedTicket ticket,
        CancellationToken cancellationToken)
    {
        try
        {
            return await captures.FindByTicketAsync(ticket.CaptureId, ticket.TenantId,
                cancellationToken).ConfigureAwait(false);
        }
        catch (ArgumentException ex)
        {
            await WriteCacheMissAsync(http, StatusCodes.Status404NotFound, ex.Message, 0,
                cancellationToken).ConfigureAwait(false);
            return null;
        }
    }

    private static async Task<HttpMediaCapture?> FindAdminCaptureAsync(HttpContext http,
        HttpMediaCaptureService captures, ManagementContext context, long id,
        CancellationToken cancellationToken)
    {
        try
        {
            return await captures.RequireAccessibleAsync(context, id, cancellationToken)
                .ConfigureAwait(false);
        }
        catch (ArgumentException ex)
        {
            await WriteEndpointErrorAsync(http, StatusCodes.Status404NotFound, ex.Message,
                cancellationToken).ConfigureAwait(false);
            return null;
        }
    }

    private static void RedirectToOrigin(HttpResponse response, HttpMediaCapture capture,
        string sourceUrl)
    {
        response.StatusCode = StatusCodes.Status307TemporaryRedirect;
        response.Headers.Location = "/http/" + Uri.EscapeDataString(capture.ClientName) + "/"
                                    + Uri.EscapeDataString(capture.Route) + SafeSourceUrl(sourceUrl);
        response.Headers.CacheControl = "private, no-store";
        response.ContentLength = 0;
    }

    private static string SafeSourceUrl(string? sourceUrl)
    {
        var normalized = (sourceUrl ?? "/").Replace("\r", string.Empty, StringComparison.Ordinal)
            .Replace("\n", string.Empty, StringComparison.Ordinal).Trim();
        if (!normalized.StartsWith('/'))
        {
            normalized = "/" + normalized;
        }
        if (Uri.TryCreate(normalized, UriKind.Relative, out _))
        {
            return normalized;
        }
        var queryIndex = normalized.IndexOf('?');
        var path = queryIndex < 0 ? normalized : normalized[..queryIndex];
        var query = queryIndex < 0 ? string.Empty : normalized[queryIndex..];
        return string.Join('/', path.Split('/').Select(segment => Uri.EscapeDataString(segment))) + query;
    }

    private static async Task WriteCacheMissAsync(HttpContext http, int statusCode,
        string? message, long totalBytes, CancellationToken cancellationToken)
    {
        http.Response.StatusCode = statusCode;
        http.Response.Headers.AcceptRanges = "bytes";
        http.Response.Headers.CacheControl = "private, no-store";
        if (statusCode == StatusCodes.Status416RangeNotSatisfiable && totalBytes > 0)
        {
            http.Response.Headers.ContentRange = "bytes */" + totalBytes;
        }
        var bytes = Encoding.UTF8.GetBytes(message ?? string.Empty);
        http.Response.ContentType = "text/plain;charset=UTF-8";
        http.Response.ContentLength = bytes.Length;
        if (bytes.Length > 0 && !HttpMethods.IsHead(http.Request.Method))
        {
            await http.Response.Body.WriteAsync(bytes, cancellationToken).ConfigureAwait(false);
        }
    }

    private static async Task WriteEndpointErrorAsync(HttpContext http, int statusCode,
        string? message, CancellationToken cancellationToken)
    {
        http.Response.StatusCode = statusCode;
        http.Response.Headers.CacheControl = "private, no-store";
        var bytes = Encoding.UTF8.GetBytes(message ?? string.Empty);
        http.Response.ContentType = "text/plain;charset=UTF-8";
        http.Response.ContentLength = bytes.Length;
        if (bytes.Length > 0 && !HttpMethods.IsHead(http.Request.Method))
        {
            await http.Response.Body.WriteAsync(bytes, cancellationToken).ConfigureAwait(false);
        }
    }
}
