using Microsoft.Extensions.Options;
using Specus.Server.Configuration;
using Specus.Server.Management;

namespace Specus.Server.ProductMetrics;

/// <summary>
/// <c>/api/admin/product-metrics</c> (protocol/spec/product-metrics.md section 7). Authentication is
/// the shared admin layer; the tenant and the username come from the session only. Bodies are read
/// raw, at most one byte past the limit, validated against the closed schema and never logged.
/// </summary>
public static class ProductMetricsEndpoints
{
    private const string Prefix = "/api/admin/product-metrics";

    /// <summary>
    /// Every product metrics answer is private and uncacheable, the shared layer's 401 included, so
    /// the header is set before anything else runs.
    /// </summary>
    public static WebApplication UseProductMetricsNoStore(this WebApplication app)
    {
        app.Use(async (context, next) =>
        {
            if (context.Request.Path.StartsWithSegments(Prefix, StringComparison.OrdinalIgnoreCase))
            {
                context.Response.Headers.CacheControl = ProductMetricsModel.CacheControl;
            }
            await next().ConfigureAwait(false);
        });
        return app;
    }

    public static void MapProductMetricsApi(this WebApplication app)
    {
        app.MapGet(Prefix + "/settings",
            async (HttpContext context, IOptions<AuthOptions> auth, ProductMetricsService service,
                CancellationToken cancellationToken) =>
                Respond(context, await service.GetSettingsAsync(ManagementContext.From(context, auth.Value),
                    cancellationToken).ConfigureAwait(false)));

        app.MapPut(Prefix + "/settings",
            async (HttpContext context, IOptions<AuthOptions> auth, ProductMetricsService service,
                CancellationToken cancellationToken) =>
            {
                var caller = ManagementContext.From(context, auth.Value);
                if (!caller.IsAdmin)
                {
                    return Respond(context, ProductMetricsResult.Forbidden);
                }
                var body = await ReadLimitedAsync(context.Request, cancellationToken).ConfigureAwait(false);
                if (body is null || body.Length > ProductMetricsModel.MaxBodyBytes)
                {
                    return Respond(context, ProductMetricsResult.Code(StatusCodes.Status400BadRequest,
                        "PRODUCT_METRICS_INVALID"));
                }
                return Respond(context, await service.PutSettingsAsync(caller, body, cancellationToken)
                    .ConfigureAwait(false));
            });

        app.MapDelete(Prefix + "/data",
            async (HttpContext context, IOptions<AuthOptions> auth, ProductMetricsService service,
                CancellationToken cancellationToken) =>
                Respond(context, await service.PurgeAsync(ManagementContext.From(context, auth.Value),
                    cancellationToken).ConfigureAwait(false)));

        app.MapPost(Prefix + "/transfer-outcomes",
            async (HttpContext context, IOptions<AuthOptions> auth, ProductMetricsService service,
                CancellationToken cancellationToken) =>
            {
                var caller = ManagementContext.From(context, auth.Value);
                var body = await ReadLimitedAsync(context.Request, cancellationToken).ConfigureAwait(false);
                if (body is null)
                {
                    return Respond(context, ProductMetricsResult.Code(StatusCodes.Status400BadRequest,
                        "PRODUCT_METRICS_INVALID"));
                }
                return Respond(context, await service.IngestAsync(caller, body, cancellationToken)
                    .ConfigureAwait(false));
            });

        app.MapGet(Prefix + "/summary",
            async (HttpContext context, IOptions<AuthOptions> auth, ProductMetricsService service,
                CancellationToken cancellationToken) =>
                Respond(context, await service.SummaryAsync(ManagementContext.From(context, auth.Value),
                    context.Request.Query, cancellationToken).ConfigureAwait(false)));
    }

    private static IResult Respond(HttpContext context, ProductMetricsResult result)
    {
        context.Response.Headers.CacheControl = ProductMetricsModel.CacheControl;
        return Results.Json(result.Body, statusCode: result.Status);
    }

    /// <summary>
    /// Reads at most MaxBodyBytes + 1 bytes: enough to tell an oversized body without reading it all.
    /// Null when the body cannot be read.
    /// </summary>
    private static async Task<byte[]?> ReadLimitedAsync(HttpRequest request, CancellationToken cancellationToken)
    {
        var buffer = new byte[ProductMetricsModel.MaxBodyBytes + 1];
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
        return buffer.AsSpan(0, total).ToArray();
    }
}
