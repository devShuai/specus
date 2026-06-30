using Microsoft.Extensions.Options;
using ShuaiTunnel.Server.Configuration;
using ShuaiTunnel.Server.Hosting;
using ShuaiTunnel.Server.PeerMesh;
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
            catch (UnauthorizedAccessException ex) when (IsAdminSurface(context.Request.Path))
            {
                context.Response.StatusCode = StatusCodes.Status403Forbidden;
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
        app.MapPost("/auth/login", async (AdminLoginRequest? request, LocalTokenService tokens,
            ManagementUserService users, CancellationToken cancellationToken) =>
        {
            var user = request is null
                ? null
                : await users.AuthenticateAsync(request.Username, request.Password, cancellationToken)
                    .ConfigureAwait(false);
            if (user is null)
            {
                return Results.Json(new { error = "用户名或密码错误" },
                    statusCode: StatusCodes.Status401Unauthorized);
            }

            return Results.Ok(tokens.IssueTokenBody(user.Username, user.TenantId, user.Role));
        });

        app.MapPost("/auth/refresh", (HttpContext context, LocalTokenService tokens,
            IOptions<AuthOptions> authOptions) =>
        {
            if (!string.Equals(context.User.FindFirst("iss")?.Value, LocalTokenService.Issuer,
                    StringComparison.Ordinal))
            {
                return Results.Json(new { error = "OIDC 令牌不能通过该端点续期" },
                    statusCode: StatusCodes.Status400BadRequest);
            }

            var principal = ManagementContext.From(context, authOptions.Value);
            return Results.Ok(tokens.IssueTokenBody(principal.Username, principal.TenantId, principal.Role));
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

        app.MapGet("/api/public/client-downloads",
            (ManagementQueryService service, CancellationToken cancellationToken) =>
                service.ListPublicClientDownloadsAsync(cancellationToken));

        app.MapGet("/api/public/peer-mesh/stun-config",
            (HttpContext context, PeerMeshService service) =>
                Results.Ok(service.PublicStunConfig(ForwardedHost(context))));

        app.MapGet("/api/admin/me",
            (HttpContext context, IOptions<AuthOptions> authOptions, ManagementUserService service,
                CancellationToken cancellationToken) =>
                service.CurrentUserAsync(ManagementContext.From(context, authOptions.Value), cancellationToken));

        app.MapGet("/api/admin/users",
            (HttpContext context, IOptions<AuthOptions> authOptions, ManagementUserService service,
                CancellationToken cancellationToken) =>
                service.ListUsersAsync(ManagementContext.From(context, authOptions.Value), cancellationToken));

        app.MapPost("/api/admin/users",
            async (HttpContext context, UserMutation request, IOptions<AuthOptions> authOptions,
                ManagementUserService service, CancellationToken cancellationToken) =>
            {
                var created = await service.CreateUserAsync(
                    ManagementContext.From(context, authOptions.Value), request, cancellationToken)
                    .ConfigureAwait(false);
                return Results.Json(created, statusCode: StatusCodes.Status201Created);
            });

        app.MapPut("/api/admin/users/{username}",
            (HttpContext context, string username, UserMutation request, IOptions<AuthOptions> authOptions,
                ManagementUserService service, CancellationToken cancellationToken) =>
                service.UpdateUserAsync(ManagementContext.From(context, authOptions.Value), username,
                    request, cancellationToken));

        app.MapDelete("/api/admin/users/{username}",
            async (HttpContext context, string username, IOptions<AuthOptions> authOptions,
                ManagementUserService service, CancellationToken cancellationToken) =>
            {
                await service.DeleteUserAsync(ManagementContext.From(context, authOptions.Value),
                        username, cancellationToken)
                    .ConfigureAwait(false);
                return Results.NoContent();
            });

        app.MapGet("/api/admin/overview",
            (HttpContext context, IOptions<AuthOptions> authOptions, ManagementQueryService service,
                CancellationToken cancellationToken) =>
                service.GetOverviewAsync(ManagementContext.From(context, authOptions.Value), cancellationToken));

        app.MapPost("/api/admin/database/initialize",
            (HttpContext context, IOptions<AuthOptions> authOptions, DatabaseInitializer initializer,
                CancellationToken cancellationToken) =>
            {
                var managementContext = ManagementContext.From(context, authOptions.Value);
                ManagementUserService.RequireAdmin(managementContext);
                return initializer.InitializeAsync(cancellationToken,
                    managementContext.TenantId, managementContext.Username);
            });

        app.MapGet("/api/admin/clients",
            (HttpContext context, IOptions<AuthOptions> authOptions, ManagementQueryService service,
                CancellationToken cancellationToken) =>
                service.ListClientsAsync(ManagementContext.From(context, authOptions.Value), cancellationToken));

        app.MapGet("/api/admin/clients/{id:long}",
            (HttpContext context, long id, IOptions<AuthOptions> authOptions, ManagementQueryService service,
                CancellationToken cancellationToken) =>
                service.GetClientAsync(ManagementContext.From(context, authOptions.Value), id, cancellationToken));

        app.MapPost("/api/admin/clients",
            async (HttpContext context, ClientMutation request, IOptions<AuthOptions> authOptions,
                ManagementMutationService service, CancellationToken cancellationToken) =>
            {
                var created = await service.CreateClientAsync(
                    ManagementContext.From(context, authOptions.Value), request, cancellationToken)
                    .ConfigureAwait(false);
                return Results.Json(created, statusCode: StatusCodes.Status201Created);
            });

        app.MapPut("/api/admin/clients/{id:long}",
            (HttpContext context, long id, ClientMutation request, IOptions<AuthOptions> authOptions,
                ManagementMutationService service, CancellationToken cancellationToken) =>
                service.UpdateClientAsync(ManagementContext.From(context, authOptions.Value), id,
                    request, cancellationToken));

        app.MapDelete("/api/admin/clients/{id:long}",
            async (HttpContext context, long id, IOptions<AuthOptions> authOptions,
                ManagementMutationService service, CancellationToken cancellationToken) =>
            {
                await service.DeleteClientAsync(ManagementContext.From(context, authOptions.Value),
                        id, cancellationToken)
                    .ConfigureAwait(false);
                return Results.NoContent();
            });

        app.MapGet("/api/admin/client-credentials",
            (HttpContext context, IOptions<AuthOptions> authOptions, ManagementMutationService service,
                CancellationToken cancellationToken) =>
                service.ListCredentialsAsync(ManagementContext.From(context, authOptions.Value),
                    cancellationToken));

        app.MapPost("/api/admin/client-credentials",
            async (HttpContext context, CredentialMutation request, IOptions<AuthOptions> authOptions,
                ManagementMutationService service, CancellationToken cancellationToken) =>
            {
                var created = await service.CreateCredentialAsync(
                    ManagementContext.From(context, authOptions.Value), request, cancellationToken)
                    .ConfigureAwait(false);
                return Results.Json(created, statusCode: StatusCodes.Status201Created);
            });

        app.MapPut("/api/admin/client-credentials/{id:long}",
            (HttpContext context, long id, CredentialMutation request, IOptions<AuthOptions> authOptions,
                ManagementMutationService service, CancellationToken cancellationToken) =>
                service.UpdateCredentialAsync(ManagementContext.From(context, authOptions.Value), id,
                    request, cancellationToken));

        app.MapDelete("/api/admin/client-credentials/{id:long}",
            async (HttpContext context, long id, IOptions<AuthOptions> authOptions,
                ManagementMutationService service, CancellationToken cancellationToken) =>
            {
                await service.DeleteCredentialAsync(ManagementContext.From(context, authOptions.Value),
                        id, cancellationToken)
                    .ConfigureAwait(false);
                return Results.NoContent();
            });

        app.MapGet("/api/admin/client-downloads",
            (HttpContext context, IOptions<AuthOptions> authOptions, ManagementMutationService service,
                CancellationToken cancellationToken) =>
                service.ListClientDownloadsAsync(ManagementContext.From(context, authOptions.Value),
                    cancellationToken));

        app.MapPost("/api/admin/client-downloads",
            async (HttpContext context, ClientDownloadLinkMutation request, IOptions<AuthOptions> authOptions,
                ManagementMutationService service, CancellationToken cancellationToken) =>
            {
                var created = await service.CreateClientDownloadAsync(
                        ManagementContext.From(context, authOptions.Value), request, cancellationToken)
                    .ConfigureAwait(false);
                return Results.Json(created, statusCode: StatusCodes.Status201Created);
            });

        app.MapPut("/api/admin/client-downloads/{id:long}",
            (HttpContext context, long id, ClientDownloadLinkMutation request,
                IOptions<AuthOptions> authOptions, ManagementMutationService service,
                CancellationToken cancellationToken) =>
                service.UpdateClientDownloadAsync(ManagementContext.From(context, authOptions.Value),
                    id, request, cancellationToken));

        app.MapDelete("/api/admin/client-downloads/{id:long}",
            async (HttpContext context, long id, IOptions<AuthOptions> authOptions,
                ManagementMutationService service, CancellationToken cancellationToken) =>
            {
                await service.DeleteClientDownloadAsync(ManagementContext.From(context, authOptions.Value),
                        id, cancellationToken)
                    .ConfigureAwait(false);
                return Results.NoContent();
            });

        app.MapGet("/api/admin/tunnels",
            (HttpContext context, long? clientId, IOptions<AuthOptions> authOptions,
                ManagementMutationService service, CancellationToken cancellationToken) =>
                service.ListTunnelsAsync(ManagementContext.From(context, authOptions.Value),
                    clientId, cancellationToken));

        app.MapPost("/api/admin/clients/{id:long}/tunnels",
            async (HttpContext context, long id, TunnelMappingMutation request,
                IOptions<AuthOptions> authOptions, ManagementMutationService service,
                CancellationToken cancellationToken) =>
            {
                var created = await service.CreateTunnelAsync(
                    ManagementContext.From(context, authOptions.Value), id, request, cancellationToken)
                    .ConfigureAwait(false);
                return Results.Json(created, statusCode: StatusCodes.Status201Created);
            });

        app.MapPut("/api/admin/tunnels/{tunnelId:long}",
            (HttpContext context, long tunnelId, TunnelMappingMutation request,
                IOptions<AuthOptions> authOptions, ManagementMutationService service,
                CancellationToken cancellationToken) =>
                service.UpdateTunnelAsync(ManagementContext.From(context, authOptions.Value),
                    tunnelId, request, cancellationToken));

        app.MapDelete("/api/admin/tunnels/{tunnelId:long}",
            async (HttpContext context, long tunnelId, IOptions<AuthOptions> authOptions,
                ManagementMutationService service, CancellationToken cancellationToken) =>
            {
                await service.DeleteTunnelAsync(ManagementContext.From(context, authOptions.Value),
                        tunnelId, cancellationToken)
                    .ConfigureAwait(false);
                return Results.NoContent();
            });

        app.MapPost("/api/admin/clients/{id:long}/nat-control",
            (HttpContext context, long id, IOptions<AuthOptions> authOptions,
                ManagementMutationService service, CancellationToken cancellationToken) =>
                service.PushNatControlAsync(ManagementContext.From(context, authOptions.Value),
                    id, cancellationToken));

        app.MapPost("/api/admin/clients/{id:long}/force-refresh-port-mapping",
            (HttpContext context, long id, IOptions<AuthOptions> authOptions,
                ManagementMutationService service, CancellationToken cancellationToken) =>
                service.PushNatControlAsync(ManagementContext.From(context, authOptions.Value),
                    id, cancellationToken));

        app.MapGet("/api/admin/http-routes",
            (HttpContext context, long? clientId, IOptions<AuthOptions> authOptions,
                ManagementMutationService service, CancellationToken cancellationToken) =>
                service.ListHttpRoutesAsync(ManagementContext.From(context, authOptions.Value),
                    clientId, cancellationToken));

        app.MapPost("/api/admin/clients/{id:long}/http-routes",
            async (HttpContext context, long id, HttpRouteMutation request,
                IOptions<AuthOptions> authOptions, ManagementMutationService service,
                CancellationToken cancellationToken) =>
            {
                var created = await service.CreateHttpRouteAsync(
                    ManagementContext.From(context, authOptions.Value), id, request, cancellationToken)
                    .ConfigureAwait(false);
                return Results.Json(created, statusCode: StatusCodes.Status201Created);
            });

        app.MapPut("/api/admin/http-routes/{routeId:long}",
            (HttpContext context, long routeId, HttpRouteMutation request,
                IOptions<AuthOptions> authOptions, ManagementMutationService service,
                CancellationToken cancellationToken) =>
                service.UpdateHttpRouteAsync(ManagementContext.From(context, authOptions.Value),
                    routeId, request, cancellationToken));

        app.MapDelete("/api/admin/http-routes/{routeId:long}",
            async (HttpContext context, long routeId, IOptions<AuthOptions> authOptions,
                ManagementMutationService service, CancellationToken cancellationToken) =>
            {
                await service.DeleteHttpRouteAsync(ManagementContext.From(context, authOptions.Value),
                        routeId, cancellationToken)
                    .ConfigureAwait(false);
                return Results.NoContent();
            });

        app.MapGet("/api/admin/connections",
            (long? clientId, bool? success, string? from, string? to, int? page, int? size,
                HttpContext context, IOptions<AuthOptions> authOptions,
                ManagementQueryService service, CancellationToken cancellationToken) =>
                service.ListConnectionsAsync(ManagementContext.From(context, authOptions.Value),
                    clientId, success, from, to, page, size, cancellationToken));

        app.MapGet("/api/admin/traffic",
            (long? clientId, int? limit, bool? flush, HttpContext context, IOptions<AuthOptions> authOptions,
                ManagementQueryService service, CancellationToken cancellationToken) =>
                service.ListTrafficAsync(ManagementContext.From(context, authOptions.Value),
                    clientId, limit, flush ?? false, cancellationToken));

        app.MapGet("/api/admin/traffic/resources",
            (string? type, long? clientId, int? limit, bool? flush, HttpContext context, IOptions<AuthOptions> authOptions,
                ManagementQueryService service, CancellationToken cancellationToken) =>
                service.ListResourceTrafficAsync(ManagementContext.From(context, authOptions.Value),
                    type, clientId, limit, flush ?? false, cancellationToken));

        app.MapGet("/api/admin/traffic/http-exchanges",
            (long? clientId, string? route, string? responseBodyType, string? responseDataType,
                string? field, string? q, int? page, int? size, bool? flush, HttpContext context,
                IOptions<AuthOptions> authOptions, ManagementQueryService service,
                CancellationToken cancellationToken) =>
                service.ListHttpExchangesAsync(ManagementContext.From(context, authOptions.Value),
                    clientId, route, FirstText(responseBodyType, responseDataType), field, q,
                    page, size, flush ?? false, cancellationToken));

        app.MapGet("/api/admin/traffic/tcp-frames",
            (long? clientId, int? listenPort, int? page, int? size, int? limit, bool? flush,
                HttpContext context, IOptions<AuthOptions> authOptions, ManagementQueryService service,
                CancellationToken cancellationToken) =>
                service.ListTcpFramesAsync(ManagementContext.From(context, authOptions.Value),
                    clientId, listenPort, page, size, limit, flush ?? false, cancellationToken));

        app.MapGet("/api/admin/traffic/tcp-frames/{id:long}",
            async (long id, bool? flush, HttpContext context, IOptions<AuthOptions> authOptions,
                ManagementQueryService service, CancellationToken cancellationToken) =>
            {
                var frame = await service.GetTcpFrameAsync(
                        ManagementContext.From(context, authOptions.Value), id, flush ?? false, cancellationToken)
                    .ConfigureAwait(false);
                return frame is null ? Results.NotFound(new { error = "TCP frame not found" }) : Results.Ok(frame);
            });

        app.MapGet("/api/admin/traffic/tcp-streams",
            (string channelId, int? limit, bool? flush, HttpContext context, IOptions<AuthOptions> authOptions,
                ManagementQueryService service, CancellationToken cancellationToken) =>
                service.ListTcpStreamAsync(ManagementContext.From(context, authOptions.Value),
                    channelId, limit, flush ?? false, cancellationToken));

        app.MapGet("/api/admin/traffic/inspection-status",
            (TrafficInspectionService service) => Results.Ok(service.Snapshot()));

        app.MapGet("/api/admin/connection-stats",
            (string? clientName, int? limit, HttpContext context, IOptions<AuthOptions> authOptions,
                ManagementQueryService service, CancellationToken cancellationToken) =>
                service.ListConnectionStatsAsync(ManagementContext.From(context, authOptions.Value),
                    clientName, limit, cancellationToken));

        app.MapGet("/api/admin/peer-mesh/status",
            (PeerMeshService service) => Results.Ok(new { enabled = service.Enabled }));

        app.MapGet("/api/admin/peer-mesh/devices",
            (HttpContext context, IOptions<AuthOptions> authOptions, PeerMeshService service,
                CancellationToken cancellationToken) =>
                service.ListDevicesAsync(ManagementContext.From(context, authOptions.Value), cancellationToken));

        app.MapPut("/api/admin/peer-mesh/devices/{clientId:long}",
            (HttpContext context, long clientId, PeerMeshDeviceMutation request,
                IOptions<AuthOptions> authOptions, PeerMeshService service, CancellationToken cancellationToken) =>
                service.UpdateDeviceAsync(ManagementContext.From(context, authOptions.Value), clientId,
                    request, cancellationToken));

        app.MapGet("/api/admin/peer-mesh/acls",
            (HttpContext context, IOptions<AuthOptions> authOptions, PeerMeshService service,
                CancellationToken cancellationToken) =>
                service.ListAclsAsync(ManagementContext.From(context, authOptions.Value), cancellationToken));

        app.MapPost("/api/admin/peer-mesh/acls",
            async (HttpContext context, PeerMeshAclMutation request, IOptions<AuthOptions> authOptions,
                PeerMeshService service, CancellationToken cancellationToken) =>
            {
                var created = await service.CreateAclAsync(
                        ManagementContext.From(context, authOptions.Value), request, cancellationToken)
                    .ConfigureAwait(false);
                return Results.Json(created, statusCode: StatusCodes.Status201Created);
            });

        app.MapDelete("/api/admin/peer-mesh/acls/{id:long}",
            async (HttpContext context, long id, IOptions<AuthOptions> authOptions,
                PeerMeshService service, CancellationToken cancellationToken) =>
            {
                await service.DeleteAclAsync(ManagementContext.From(context, authOptions.Value),
                        id, cancellationToken)
                    .ConfigureAwait(false);
                return Results.NoContent();
            });

        app.MapGet("/api/admin/peer-mesh/sessions",
            async (int? limit, int? page, int? size, bool? openOnly, HttpContext context,
                IOptions<AuthOptions> authOptions, PeerMeshService service, CancellationToken cancellationToken) =>
            {
                var managementContext = ManagementContext.From(context, authOptions.Value);
                if (page.HasValue || size.HasValue || openOnly.HasValue)
                {
                    var result = await service.ListSessionsPageAsync(managementContext, page, size, openOnly ?? false,
                            cancellationToken)
                        .ConfigureAwait(false);
                    return Results.Json(result);
                }
                var items = await service.ListSessionsAsync(managementContext, limit, cancellationToken)
                    .ConfigureAwait(false);
                return Results.Json(items);
            });

        app.MapDelete("/api/admin/peer-mesh/sessions/{id:long}",
            (HttpContext context, long id, IOptions<AuthOptions> authOptions,
                PeerMeshService service, CancellationToken cancellationToken) =>
                service.ForceCloseAsync(ManagementContext.From(context, authOptions.Value),
                    id, cancellationToken));

        app.MapDelete("/api/admin/peer-mesh/sessions",
            (HttpContext context, IOptions<AuthOptions> authOptions,
                PeerMeshService service, CancellationToken cancellationToken) =>
                service.CloseOpenSessionsAsync(ManagementContext.From(context, authOptions.Value),
                    cancellationToken));
    }

    private static string? FirstText(string? first, string? second) =>
        string.IsNullOrWhiteSpace(first) ? second : first;

    private static string ForwardedHost(HttpContext context)
    {
        var forwarded = context.Request.Headers["X-Forwarded-Host"].ToString();
        if (string.IsNullOrWhiteSpace(forwarded))
        {
            forwarded = context.Request.Headers["Host"].ToString();
        }
        return string.IsNullOrWhiteSpace(forwarded) ? context.Request.Host.ToString() : forwarded.Split(',', 2)[0].Trim();
    }

    private static bool RequiresAdminAuth(PathString path) =>
        path.StartsWithSegments("/api/admin", StringComparison.OrdinalIgnoreCase)
        || path.Equals("/auth/refresh", StringComparison.OrdinalIgnoreCase);

    private static bool IsAdminSurface(PathString path) =>
        RequiresAdminAuth(path)
        || path.Equals("/auth/login", StringComparison.OrdinalIgnoreCase);
}
