using System.Collections.Concurrent;
using System.Net.WebSockets;
using System.Security.Claims;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using ShuaiTunnel.Server.Data;
using ShuaiTunnel.Server.Management;
using ShuaiTunnel.Server.Security;

namespace ShuaiTunnel.Server.WebSockets;

public sealed class ConnectionEventsHub
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

    private readonly ConcurrentDictionary<Guid, ConnectionEventSubscription> _sockets = new();
    private readonly IServiceScopeFactory _scopeFactory;
    private readonly ILogger<ConnectionEventsHub> _logger;

    public ConnectionEventsHub(IServiceScopeFactory scopeFactory, ILogger<ConnectionEventsHub> logger)
    {
        _scopeFactory = scopeFactory;
        _logger = logger;
    }

    public async Task AcceptAsync(HttpContext context, AdminBearerTokenValidator tokens)
    {
        if (!context.WebSockets.IsWebSocketRequest)
        {
            context.Response.StatusCode = StatusCodes.Status400BadRequest;
            return;
        }

        var token = AdminBearerTokenValidator.ExtractWebSocketToken(context.Request);
        var principal = await tokens.ValidateAsync(
            token,
            context.RequestAborted).ConfigureAwait(false);
        if (principal is null)
        {
            context.Response.StatusCode = StatusCodes.Status403Forbidden;
            context.Response.Headers["X-Auth-Reason"] = token is null ? "missing token" : "invalid token";
            return;
        }

        using var socket = await context.WebSockets.AcceptWebSocketAsync().ConfigureAwait(false);
        var id = Guid.NewGuid();
        _sockets[id] = new ConnectionEventSubscription(socket, SubscriptionPrincipal.From(principal));
        try
        {
            var buffer = new byte[1024];
            while (!context.RequestAborted.IsCancellationRequested
                && socket.State is WebSocketState.Open or WebSocketState.CloseSent)
            {
                var result = await socket.ReceiveAsync(buffer, context.RequestAborted).ConfigureAwait(false);
                if (result.MessageType == WebSocketMessageType.Close)
                {
                    break;
                }
            }
        }
        catch (OperationCanceledException)
        {
            // normal shutdown/client disconnect
        }
        finally
        {
            _sockets.TryRemove(id, out _);
            if (socket.State is WebSocketState.Open or WebSocketState.CloseReceived)
            {
                try
                {
                    await socket.CloseAsync(WebSocketCloseStatus.NormalClosure, "bye",
                        CancellationToken.None).ConfigureAwait(false);
                }
                catch (WebSocketException)
                {
                    // peer already gone
                }
            }
        }
    }

    public async Task BroadcastAsync(ConnectionEvent connectionEvent)
    {
        if (_sockets.IsEmpty)
        {
            return;
        }

        var payload = JsonSerializer.SerializeToUtf8Bytes(connectionEvent, JsonOptions);
        foreach (var (id, subscription) in _sockets.ToArray())
        {
            var socket = subscription.Socket;
            if (socket.State != WebSocketState.Open)
            {
                _sockets.TryRemove(id, out _);
                continue;
            }
            if (!await CanReceiveAsync(subscription.Principal, connectionEvent).ConfigureAwait(false))
            {
                continue;
            }

            try
            {
                await socket.SendAsync(payload, WebSocketMessageType.Text, endOfMessage: true,
                    CancellationToken.None).ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is WebSocketException or ObjectDisposedException
                or OperationCanceledException)
            {
                _logger.LogDebug(ex, "dropping connection event websocket {SocketId}", id);
                _sockets.TryRemove(id, out _);
            }
        }
    }

    private async ValueTask<bool> CanReceiveAsync(SubscriptionPrincipal principal,
        ConnectionEvent connectionEvent)
    {
        if (!string.IsNullOrWhiteSpace(connectionEvent.TenantId)
            && !ManagementContext.SameTenant(principal.TenantId, connectionEvent.TenantId))
        {
            return false;
        }
        if (principal.Admin)
        {
            return true;
        }
        if (connectionEvent.Connection.ClientId is not { } clientId
            || string.IsNullOrWhiteSpace(principal.Username))
        {
            return false;
        }

        await using var scope = _scopeFactory.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<TunnelDbContext>();
        return await db.ClientAccounts.AsNoTracking()
            .AnyAsync(c => c.Id == clientId
                           && c.TenantId == principal.TenantId
                           && c.OwnerUsername == principal.Username)
            .ConfigureAwait(false);
    }

    private sealed record ConnectionEventSubscription(WebSocket Socket, SubscriptionPrincipal Principal);

    private sealed record SubscriptionPrincipal(string Username, string TenantId, bool Admin)
    {
        public static SubscriptionPrincipal From(ClaimsPrincipal principal)
        {
            var username = principal.Identity?.Name
                           ?? principal.FindFirst(ClaimTypes.NameIdentifier)?.Value
                           ?? string.Empty;
            var tenantId = ManagementContext.NormalizeTenant(principal.FindFirst("tenant_id")?.Value);
            var role = principal.FindFirst(ClaimTypes.Role)?.Value
                       ?? principal.FindFirst("role")?.Value
                       ?? string.Empty;
            return new SubscriptionPrincipal(username, tenantId,
                string.Equals(role, "ADMIN", StringComparison.OrdinalIgnoreCase));
        }
    }
}

public static class ConnectionEventsWebSocketEndpoint
{
    public static void MapConnectionEventsWebSocket(this WebApplication app)
    {
        app.UseWebSockets();
        app.Map("/ws/connections", (HttpContext context, ConnectionEventsHub hub,
            AdminBearerTokenValidator tokens) => hub.AcceptAsync(context, tokens));
    }
}
