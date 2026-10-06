using System.Globalization;
using Microsoft.Extensions.Options;
using Specus.Server.Configuration;
using Specus.Server.Management;

namespace Specus.Server.Connectivity;

/// <summary>
/// <c>POST /api/admin/http-routes/{routeId}/connectivity-check</c>. Bearer authentication (401)
/// happens in the admin middleware before this runs; this handler validates the body (400), then
/// hands the route id to <see cref="ConnectivityCheckService"/>. Every answer carries
/// <c>Cache-Control: private, no-store</c>; refusals are exactly <c>{"code":"..."}</c>.
/// </summary>
internal static class ConnectivityCheckEndpoint
{
    public const string Pattern = "/api/admin/http-routes/{routeId}/connectivity-check";

    private const string PathSuffix = "/connectivity-check";

    /// <summary>True for this endpoint's path, so the 401 can carry its cache header as well.</summary>
    public static bool Matches(PathString path) =>
        path.StartsWithSegments("/api/admin/http-routes", StringComparison.OrdinalIgnoreCase)
        && path.Value!.EndsWith(PathSuffix, StringComparison.OrdinalIgnoreCase);

    public static async Task HandleAsync(HttpContext context, string routeId, IOptions<AuthOptions> authOptions,
        ConnectivityCheckService service, TimeProvider time, IHostApplicationLifetime lifetime)
    {
        // The budget and checkedAt count from here, the start of request handling.
        var start = ConnectivityCheckStart.Now(time);
        context.Response.Headers.CacheControl = ConnectivityCheck.CacheControl;

        ManagementContext caller;
        try
        {
            caller = ManagementContext.From(context, authOptions.Value);
        }
        catch (UnauthorizedAccessException)
        {
            context.Response.StatusCode = StatusCodes.Status401Unauthorized;
            await context.Response.WriteAsJsonAsync(new { error = "未授权" }).ConfigureAwait(false);
            return;
        }

        // The body is validated before the route is looked up.
        var path = await ReadPathAsync(context.Request, context.RequestAborted).ConfigureAwait(false);
        if (path is null)
        {
            await WriteAsync(context.Response, ConnectivityCheckResult.Refuse(StatusCodes.Status400BadRequest,
                ConnectivityCode.RequestInvalid)).ConfigureAwait(false);
            return;
        }
        if (!long.TryParse(routeId, NumberStyles.None, CultureInfo.InvariantCulture, out var id) || id <= 0)
        {
            await WriteAsync(context.Response, ConnectivityCheckResult.Refuse(StatusCodes.Status404NotFound,
                ConnectivityCode.TargetNotFound)).ConfigureAwait(false);
            return;
        }

        // Caller disconnect and shutdown both reset an in-flight probe.
        using var cancellation = CancellationTokenSource.CreateLinkedTokenSource(
            context.RequestAborted, lifetime.ApplicationStopping);
        ConnectivityCheckResult result;
        try
        {
            result = await service.CheckAsync(caller, id, path, start, cancellation.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (context.RequestAborted.IsCancellationRequested)
        {
            return;
        }
        catch (OperationCanceledException) when (lifetime.ApplicationStopping.IsCancellationRequested)
        {
            result = ConnectivityCheckResult.Refuse(StatusCodes.Status503ServiceUnavailable,
                ConnectivityCode.Unavailable, 1);
        }
        await WriteAsync(context.Response, result).ConfigureAwait(false);
    }

    /// <summary>The probe path from the body, or null when the body is not acceptable.</summary>
    private static async Task<string?> ReadPathAsync(HttpRequest request, CancellationToken cancellationToken)
    {
        if (request.ContentLength > ConnectivityCheck.MaxBodyBytes)
        {
            return null;
        }
        // One byte more than allowed tells an oversized body without reading all of it.
        var buffer = new byte[ConnectivityCheck.MaxBodyBytes + 1];
        var total = 0;
        try
        {
            while (total < buffer.Length)
            {
                var read = await request.Body.ReadAsync(buffer.AsMemory(total), cancellationToken)
                    .ConfigureAwait(false);
                if (read == 0)
                {
                    break;
                }
                total += read;
            }
        }
        catch (BadHttpRequestException)
        {
            return null;
        }
        return ConnectivityCheckRequest.ParsePath(buffer.AsSpan(0, total));
    }

    private static async Task WriteAsync(HttpResponse response, ConnectivityCheckResult result)
    {
        response.StatusCode = result.HttpStatus;
        response.Headers.CacheControl = ConnectivityCheck.CacheControl;
        if (result.RetryAfterSeconds is int retryAfter)
        {
            response.Headers.RetryAfter = retryAfter.ToString(CultureInfo.InvariantCulture);
        }
        response.ContentType = "application/json; charset=utf-8";
        await response.WriteAsync(result.BodyJson()).ConfigureAwait(false);
    }
}
