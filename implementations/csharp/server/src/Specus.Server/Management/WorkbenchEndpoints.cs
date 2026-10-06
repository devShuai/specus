using System.Globalization;
using Microsoft.Extensions.Options;
using Specus.Server.Configuration;

namespace Specus.Server.Management;

/// <summary>
/// <c>/api/admin/workbench</c>: the caller's favourite services and recent opens
/// (protocol/spec/service-workbench.md section 5). Authentication is the shared admin layer, which
/// re-reads the account on every request; the identity is the one it resolved. No query parameter
/// and no request body is ever read, and every path segment is validated as text here.
/// </summary>
public static class WorkbenchEndpoints
{
    private const string Prefix = "/api/admin/workbench";
    private const string NoStore = "private, no-store";

    /// <summary>
    /// Every workbench response is private and uncacheable, the shared layer's 401 and 403 included,
    /// so the header is set before anything else runs.
    /// </summary>
    public static WebApplication UseWorkbenchNoStore(this WebApplication app)
    {
        app.Use(async (context, next) =>
        {
            if (context.Request.Path.StartsWithSegments(Prefix, StringComparison.OrdinalIgnoreCase))
            {
                context.Response.Headers.CacheControl = NoStore;
            }
            await next().ConfigureAwait(false);
        });
        return app;
    }

    public static void MapWorkbenchApi(this WebApplication app)
    {
        app.MapGet(Prefix,
            async (HttpContext context, IOptions<AuthOptions> authOptions, WorkbenchService service,
                CancellationToken cancellationToken) =>
                Respond(context, await service.GetAsync(ManagementContext.From(context, authOptions.Value),
                    cancellationToken).ConfigureAwait(false)));

        app.MapPut(Prefix + "/favorites/{kind}/{id}",
            (HttpContext context, string kind, string id, IOptions<AuthOptions> authOptions,
                    WorkbenchService service, WorkbenchRateLimiter limiter, WorkbenchClock clock,
                    CancellationToken cancellationToken) =>
                GrowAsync(context, kind, id, authOptions.Value, limiter, clock,
                    (managementContext, objectId) =>
                        service.AddFavoriteAsync(managementContext, kind, objectId, cancellationToken)));

        app.MapPost(Prefix + "/recents/{kind}/{id}",
            (HttpContext context, string kind, string id, IOptions<AuthOptions> authOptions,
                    WorkbenchService service, WorkbenchRateLimiter limiter, WorkbenchClock clock,
                    CancellationToken cancellationToken) =>
                GrowAsync(context, kind, id, authOptions.Value, limiter, clock,
                    (managementContext, objectId) =>
                        service.RecordVisitAsync(managementContext, kind, objectId, cancellationToken)));

        app.MapDelete(Prefix + "/favorites/{kind}/{id}",
            (HttpContext context, string kind, string id, IOptions<AuthOptions> authOptions,
                    WorkbenchService service, CancellationToken cancellationToken) =>
                RemoveAsync(context, WorkbenchLists.Favorite, kind, id, authOptions.Value, service,
                    cancellationToken));

        app.MapDelete(Prefix + "/recents/{kind}/{id}",
            (HttpContext context, string kind, string id, IOptions<AuthOptions> authOptions,
                    WorkbenchService service, CancellationToken cancellationToken) =>
                RemoveAsync(context, WorkbenchLists.Recent, kind, id, authOptions.Value, service,
                    cancellationToken));

        app.MapDelete(Prefix + "/favorites",
            async (HttpContext context, IOptions<AuthOptions> authOptions, WorkbenchService service,
                CancellationToken cancellationToken) =>
                Respond(context, await service.ClearAsync(ManagementContext.From(context, authOptions.Value),
                    WorkbenchLists.Favorite, cancellationToken).ConfigureAwait(false)));

        app.MapDelete(Prefix + "/recents",
            async (HttpContext context, IOptions<AuthOptions> authOptions, WorkbenchService service,
                CancellationToken cancellationToken) =>
                Respond(context, await service.ClearAsync(ManagementContext.From(context, authOptions.Value),
                    WorkbenchLists.Recent, cancellationToken).ConfigureAwait(false)));
    }

    /// <summary>
    /// Growth: validate the reference, then the identity's rate limit, then the service (store,
    /// visibility, bound). An invalid request consumes no rate; an admitted one costs whatever the
    /// outcome.
    /// </summary>
    private static async Task<IResult> GrowAsync(HttpContext context, string kind, string id, AuthOptions auth,
        WorkbenchRateLimiter limiter, WorkbenchClock clock,
        Func<ManagementContext, long, Task<WorkbenchResult>> operation)
    {
        var managementContext = ManagementContext.From(context, auth);
        if (!WorkbenchKinds.IsKnown(kind) || !WorkbenchService.TryParseObjectId(id, out var objectId))
        {
            return Invalid(context);
        }
        if (!limiter.TryAcquire(managementContext.TenantId, managementContext.Username, clock.NowMs(),
                out var retryAfterSeconds))
        {
            context.Response.Headers.RetryAfter = retryAfterSeconds.ToString(CultureInfo.InvariantCulture);
            return Respond(context, WorkbenchResult.Refused(StatusCodes.Status429TooManyRequests,
                WorkbenchCodes.RateLimited));
        }
        return Respond(context, await operation(managementContext, objectId).ConfigureAwait(false));
    }

    private static async Task<IResult> RemoveAsync(HttpContext context, string list, string kind, string id,
        AuthOptions auth, WorkbenchService service, CancellationToken cancellationToken)
    {
        var managementContext = ManagementContext.From(context, auth);
        if (!WorkbenchKinds.IsKnown(kind) || !WorkbenchService.TryParseObjectId(id, out var objectId))
        {
            return Invalid(context);
        }
        return Respond(context, await service.RemoveAsync(managementContext, list, kind, objectId,
            cancellationToken).ConfigureAwait(false));
    }

    private static IResult Invalid(HttpContext context) =>
        Respond(context, WorkbenchResult.Refused(StatusCodes.Status400BadRequest, WorkbenchCodes.RequestInvalid));

    private static IResult Respond(HttpContext context, WorkbenchResult result)
    {
        context.Response.Headers.CacheControl = NoStore;
        if (result.Document is not null)
        {
            return Results.Json(result.Document);
        }
        var code = result.Code ?? WorkbenchCodes.Unavailable;
        return Results.Json(new WorkbenchError(code, Describe(code)), statusCode: result.StatusCode);
    }

    private static string Describe(string code) => code switch
    {
        WorkbenchCodes.RequestInvalid => "kind or id is not valid",
        WorkbenchCodes.RateLimited => "too many workbench writes",
        WorkbenchCodes.TargetNotFound => "service not found",
        WorkbenchCodes.FavoritesFull => "favourites are full",
        _ => "workbench storage is unavailable",
    };
}
