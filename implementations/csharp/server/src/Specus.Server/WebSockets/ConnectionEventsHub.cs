using System.Collections.Concurrent;
using System.Net.WebSockets;
using System.Security.Claims;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Specus.Server.Data;
using Specus.Server.Management;
using Specus.Server.Security;

namespace Specus.Server.WebSockets;

public sealed class ConnectionEventsHub
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

    private readonly ConcurrentDictionary<Guid, ConnectionEventSubscription> _sockets = new();
    private readonly IServiceScopeFactory _scopeFactory;
    private readonly WebSocketTicketService _tickets;
    private readonly PublicTransferCoordinationService _coordination;
    private readonly ILogger<ConnectionEventsHub> _logger;

    public ConnectionEventsHub(IServiceScopeFactory scopeFactory, WebSocketTicketService tickets,
        PublicTransferCoordinationService coordination, ILogger<ConnectionEventsHub> logger)
    {
        _scopeFactory = scopeFactory;
        _tickets = tickets;
        _coordination = coordination;
        _logger = logger;
        _coordination.AddListener(HandleClusterEventAsync);
    }

    public async Task AcceptAsync(HttpContext context)
    {
        if (!context.WebSockets.IsWebSocketRequest)
        {
            context.Response.StatusCode = StatusCodes.Status400BadRequest;
            return;
        }

        var ticket = WebSocketTicketService.ExtractTicket(context.Request);
        var claims = await _tickets.ConsumeAsync(ticket, WebSocketTicketService.ConnectionsScope,
            WebSocketTicketService.RequestAddress(context), context.RequestAborted).ConfigureAwait(false);
        if (claims is null || string.IsNullOrWhiteSpace(claims.Username))
        {
            context.Response.StatusCode = StatusCodes.Status403Forbidden;
            context.Response.Headers["X-Auth-Reason"] = ticket is null ? "missing ticket" : "invalid ticket";
            return;
        }

        var principal = claims.ToPrincipal();

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
        var payload = JsonSerializer.SerializeToUtf8Bytes(connectionEvent, JsonOptions);
        if (_coordination.Enabled)
        {
            try
            {
                await _coordination.PublishManagementAsync(connectionEvent.TenantId ?? string.Empty,
                    payload, CancellationToken.None).ConfigureAwait(false);
                return;
            }
            catch (Exception exception) when (exception is not OperationCanceledException)
            {
                _logger.LogWarning(exception,
                    "publishing management connection event failed; using local delivery");
            }
        }
        await BroadcastLocalAsync(connectionEvent, payload).ConfigureAwait(false);
    }

    private async Task HandleClusterEventAsync(PublicTransferClusterEvent clusterEvent)
    {
        if (clusterEvent.Kind != PublicTransferClusterFrame.KindManagement)
        {
            return;
        }
        try
        {
            var connectionEvent = JsonSerializer.Deserialize<ConnectionEvent>(clusterEvent.Payload,
                JsonOptions);
            if (connectionEvent is null || string.IsNullOrWhiteSpace(connectionEvent.TenantId)
                || !string.Equals(clusterEvent.GroupId,
                    PublicTransferCoordinationService.ManagementGroupId(connectionEvent.TenantId),
                    StringComparison.Ordinal))
            {
                _logger.LogWarning(
                    "discarding management cluster event with invalid tenant binding");
                return;
            }
            await BroadcastLocalAsync(connectionEvent, clusterEvent.Payload).ConfigureAwait(false);
        }
        catch (JsonException exception)
        {
            _logger.LogWarning(exception, "discarding invalid management cluster event");
        }
    }

    private async Task BroadcastLocalAsync(ConnectionEvent connectionEvent, byte[] payload)
    {
        if (_sockets.IsEmpty)
        {
            return;
        }
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
        var db = scope.ServiceProvider.GetRequiredService<SpecusDbContext>();
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
        app.Map("/ws/connections", (HttpContext context, ConnectionEventsHub hub) =>
            hub.AcceptAsync(context));
    }
}
