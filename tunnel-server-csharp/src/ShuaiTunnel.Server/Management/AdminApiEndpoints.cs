using Microsoft.Extensions.Options;
using ShuaiTunnel.Server.Configuration;
using ShuaiTunnel.Server.Hosting;
using ShuaiTunnel.Server.Security;

namespace ShuaiTunnel.Server.Management;

public static class AdminApiEndpoints
{
    public static WebApplication UseAdminApiExceptionHandling(this WebApplication app)
    {
        app.Use(async (context, next) =>
        {
            try
            {
                await next().ConfigureAwait(false);
            }
            catch (ArgumentException ex) when (IsAdminSurface(context.Request.Path))
            {
                context.Response.StatusCode = StatusCodes.Status400BadRequest;
                await context.Response.WriteAsJsonAsync(new { error = ex.Message }).ConfigureAwait(false);
            }
            catch (InvalidOperationException ex) when (IsAdminSurface(context.Request.Path))
            {
                context.Response.StatusCode = StatusCodes.Status409Conflict;
                await context.Response.WriteAsJsonAsync(new { error = ex.Message }).ConfigureAwait(false);
            }
        });
        return app;
    }

    public static WebApplication UseAdminApiAuthentication(this WebApplication app)
    {
        app.Use(async (context, next) =>
        {
            if (!RequiresAdminAuth(context.Request.Path))
            {
                await next().ConfigureAwait(false);
                return;
            }

            var header = context.Request.Headers.Authorization.ToString();
            const string prefix = "Bearer ";
            var token = header.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)
                ? header[prefix.Length..].Trim()
                : null;
            var tokens = context.RequestServices.GetRequiredService<AdminBearerTokenValidator>();
            var principal = await tokens.ValidateAsync(token, context.RequestAborted).ConfigureAwait(false);
            if (principal is null)
            {
                context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                await context.Response.WriteAsJsonAsync(new { error = "未授权" }).ConfigureAwait(false);
                return;
            }

            context.User = principal;
            await next().ConfigureAwait(false);
        });
        return app;
    }

    public static void MapAdminApi(this WebApplication app)
    {
        app.MapPost("/auth/login", (AdminLoginRequest? request, LocalTokenService tokens) =>
        {
            if (request is null || !tokens.Authenticate(request.Username, request.Password))
            {
                return Results.Json(new { error = "用户名或密码错误" },
                    statusCode: StatusCodes.Status401Unauthorized);
            }

            return Results.Ok(tokens.IssueTokenBody(request.Username!));
        });

        app.MapPost("/auth/refresh", (HttpContext context, LocalTokenService tokens) =>
        {
            if (!string.Equals(context.User.FindFirst("iss")?.Value, LocalTokenService.Issuer,
                    StringComparison.Ordinal))
            {
                return Results.Json(new { error = "OIDC 令牌不能通过该端点续期" },
                    statusCode: StatusCodes.Status400BadRequest);
            }

            var username = context.User.Identity?.Name;
            if (string.IsNullOrWhiteSpace(username))
            {
                return Results.Json(new { error = "未授权" },
                    statusCode: StatusCodes.Status401Unauthorized);
            }

            return Results.Ok(tokens.IssueTokenBody(username));
        });

        app.MapGet("/oidc-config", (IOptions<OidcOptions> options, LocalTokenService tokens) =>
        {
            var oidc = options.Value;
            return Results.Ok(new
            {
                configured = !string.IsNullOrWhiteSpace(oidc.ClientId),
                authorizationEndpoint = oidc.AuthorizationEndpoint,
                endSessionEndpoint = oidc.EndSessionEndpoint,
                clientId = oidc.ClientId,
                redirectUri = oidc.RedirectUri,
                scope = oidc.Scope,
                passwordLoginEnabled = tokens.IsPasswordLoginEnabled,
            });
        });

        app.MapPost("/oidc/token",
            (OidcTokenExchangeRequest? request, OidcTokenExchangeService exchange,
                CancellationToken cancellationToken) =>
                exchange.ExchangeAsync(request, cancellationToken));

        app.MapGet("/api/admin/overview",
            (ManagementQueryService service, CancellationToken cancellationToken) =>
                service.GetOverviewAsync(cancellationToken));

        app.MapPost("/api/admin/database/initialize",
            (DatabaseInitializer initializer, CancellationToken cancellationToken) =>
                initializer.InitializeAsync(cancellationToken));

        app.MapGet("/api/admin/clients",
            (ManagementQueryService service, CancellationToken cancellationToken) =>
                service.ListClientsAsync(cancellationToken));

        app.MapPost("/api/admin/clients",
            async (ClientMutation request, ManagementMutationService service, CancellationToken cancellationToken) =>
            {
                var created = await service.CreateClientAsync(request, cancellationToken).ConfigureAwait(false);
                return Results.Json(created, statusCode: StatusCodes.Status201Created);
            });

        app.MapPut("/api/admin/clients/{id:long}",
            (long id, ClientMutation request, ManagementMutationService service, CancellationToken cancellationToken) =>
                service.UpdateClientAsync(id, request, cancellationToken));

        app.MapDelete("/api/admin/clients/{id:long}",
            async (long id, ManagementMutationService service, CancellationToken cancellationToken) =>
            {
                await service.DeleteClientAsync(id, cancellationToken).ConfigureAwait(false);
                return Results.NoContent();
            });

        app.MapGet("/api/admin/tunnels",
            (long? clientId, ManagementMutationService service, CancellationToken cancellationToken) =>
                service.ListTunnelsAsync(clientId, cancellationToken));

        app.MapPost("/api/admin/clients/{id:long}/tunnels",
            async (long id, TunnelMappingMutation request, ManagementMutationService service,
                CancellationToken cancellationToken) =>
            {
                var created = await service.CreateTunnelAsync(id, request, cancellationToken).ConfigureAwait(false);
                return Results.Json(created, statusCode: StatusCodes.Status201Created);
            });

        app.MapPut("/api/admin/tunnels/{tunnelId:long}",
            (long tunnelId, TunnelMappingMutation request, ManagementMutationService service,
                CancellationToken cancellationToken) =>
                service.UpdateTunnelAsync(tunnelId, request, cancellationToken));

        app.MapDelete("/api/admin/tunnels/{tunnelId:long}",
            async (long tunnelId, ManagementMutationService service, CancellationToken cancellationToken) =>
            {
                await service.DeleteTunnelAsync(tunnelId, cancellationToken).ConfigureAwait(false);
                return Results.NoContent();
            });

        app.MapPost("/api/admin/clients/{id:long}/nat-control",
            (long id, ManagementMutationService service, CancellationToken cancellationToken) =>
                service.PushNatControlAsync(id, cancellationToken));

        app.MapGet("/api/admin/http-routes",
            (long? clientId, ManagementMutationService service, CancellationToken cancellationToken) =>
                service.ListHttpRoutesAsync(clientId, cancellationToken));

        app.MapPost("/api/admin/clients/{id:long}/http-routes",
            async (long id, HttpRouteMutation request, ManagementMutationService service,
                CancellationToken cancellationToken) =>
            {
                var created = await service.CreateHttpRouteAsync(id, request, cancellationToken).ConfigureAwait(false);
                return Results.Json(created, statusCode: StatusCodes.Status201Created);
            });

        app.MapPut("/api/admin/http-routes/{routeId:long}",
            (long routeId, HttpRouteMutation request, ManagementMutationService service,
                CancellationToken cancellationToken) =>
                service.UpdateHttpRouteAsync(routeId, request, cancellationToken));

        app.MapDelete("/api/admin/http-routes/{routeId:long}",
            async (long routeId, ManagementMutationService service, CancellationToken cancellationToken) =>
            {
                await service.DeleteHttpRouteAsync(routeId, cancellationToken).ConfigureAwait(false);
                return Results.NoContent();
            });

        app.MapGet("/api/admin/connections",
            (long? clientId, bool? success, string? from, string? to, int? page, int? size,
                ManagementQueryService service, CancellationToken cancellationToken) =>
                service.ListConnectionsAsync(clientId, success, from, to, page, size, cancellationToken));

        app.MapGet("/api/admin/traffic",
            (long? clientId, int? limit, ManagementQueryService service, CancellationToken cancellationToken) =>
                service.ListTrafficAsync(clientId, limit, cancellationToken));

        app.MapGet("/api/admin/connection-stats",
            (string? clientName, int? limit, ManagementQueryService service, CancellationToken cancellationToken) =>
                service.ListConnectionStatsAsync(clientName, limit, cancellationToken));
    }

    private static bool RequiresAdminAuth(PathString path) =>
        path.StartsWithSegments("/api/admin", StringComparison.OrdinalIgnoreCase)
        || path.Equals("/auth/refresh", StringComparison.OrdinalIgnoreCase);

    private static bool IsAdminSurface(PathString path) =>
        RequiresAdminAuth(path)
        || path.Equals("/auth/login", StringComparison.OrdinalIgnoreCase);
}
