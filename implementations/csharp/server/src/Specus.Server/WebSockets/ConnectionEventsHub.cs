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
    private readonly ManagementWebSocketIdentity _identity;
    private readonly ClientAddressResolver _addressResolver;
    private readonly PublicTransferCoordinationService _coordination;
    private readonly ILogger<ConnectionEventsHub> _logger;

    public ConnectionEventsHub(IServiceScopeFactory scopeFactory, WebSocketTicketService tickets,
        ClientAddressResolver addressResolver,
        PublicTransferCoordinationService coordination, ILogger<ConnectionEventsHub> logger,
        ManagementWebSocketIdentity identity)
    {
        _scopeFactory = scopeFactory;
        _tickets = tickets;
        _identity = identity;
        _addressResolver = addressResolver;
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
            WebSocketTicketService.RequestAddress(_addressResolver, context), context.RequestAborted).ConfigureAwait(false);
        if (claims is null || string.IsNullOrWhiteSpace(claims.Username))
        {
            context.Response.StatusCode = StatusCodes.Status403Forbidden;
            context.Response.Headers["X-Auth-Reason"] = ticket is null ? "missing ticket" : "invalid ticket";
            return;
        }

        if (!await _identity.CurrentAsync(claims, context.RequestAborted).ConfigureAwait(false))
        {
            context.Response.StatusCode = StatusCodes.Status403Forbidden;
            context.Response.Headers["X-Auth-Reason"] = ManagementWebSocketIdentity.Revoked;
            return;
        }
        var principal = claims.ToPrincipal();
        var id = Guid.NewGuid();
        var subscriber = SubscriptionPrincipal.From(principal);
        await using var delivery = new ConnectionEventDelivery(async (connectionEvent, ct) =>
        {
            if (!await _identity.CurrentAsync(claims, ct).ConfigureAwait(false)) return ConnectionEventAccess.Revoked;
            return await CanReceiveAsync(subscriber, connectionEvent, ct).ConfigureAwait(false)
                ? ConnectionEventAccess.Allowed : ConnectionEventAccess.Filtered;
        }, () => _sockets.TryRemove(id, out _), exception =>
            _logger.LogWarning("connection event delivery stopped: socket={SocketId} error={ErrorType}", id, exception.GetType().Name),
            context.Abort);
        // Reserve before Accept: the client may publish an event as soon as HTTP upgrade
        // completes, before this continuation has a chance to register the live socket.
        _sockets[id] = new ConnectionEventSubscription(subscriber, delivery);
        WebSocket? socket = null;
        using var lifetime = CancellationTokenSource.CreateLinkedTokenSource(context.RequestAborted, delivery.ReceiveLifetime);
        try
        {
            socket = await context.WebSockets.AcceptWebSocketAsync().ConfigureAwait(false);
            delivery.Bind(socket);
            // A revocation can commit after the first check but before registration.
            if (!await _identity.CurrentAsync(claims, context.RequestAborted).ConfigureAwait(false))
            {
                await delivery.CloseAsync(WebSocketCloseStatus.PolicyViolation, ManagementWebSocketIdentity.Revoked).ConfigureAwait(false);
                return;
            }
            if (!delivery.Activate()) return;
            var buffer = new byte[1024];
            while (!context.RequestAborted.IsCancellationRequested
                && socket.State is WebSocketState.Open or WebSocketState.CloseSent)
            {
                var result = await socket.ReceiveAsync(buffer, lifetime.Token).ConfigureAwait(false);
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
        catch (WebSocketException exception)
        {
            _logger.LogDebug(exception, "connection events websocket disconnected: {SocketId}", id);
        }
        finally
        {
            _sockets.TryRemove(id, out _);
            await delivery.CloseAsync(WebSocketCloseStatus.NormalClosure, "bye").ConfigureAwait(false);
            socket?.Dispose();
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

    /// <summary>
    /// The account of this identity was deleted: its open sessions end (management-accounts.md
    /// section 7.1). A session keeps the identity it was opened with, so it would otherwise receive the
    /// events of a later account of the same name.
    /// </summary>
    public async Task CloseIdentityAsync(string tenantId, string username, string reason = "account deleted")
    {
        var closes = new List<Task>();
        foreach (var (id, subscription) in _sockets.ToArray())
        {
            if (!ManagementContext.SameTenant(subscription.Principal.TenantId, tenantId)
                || !string.Equals(subscription.Principal.Username, username, StringComparison.Ordinal))
            {
                continue;
            }
            _sockets.TryRemove(id, out _);
            closes.Add(subscription.Delivery.CloseAsync(WebSocketCloseStatus.PolicyViolation, reason));
        }
        await Task.WhenAll(closes).ConfigureAwait(false);
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

    private Task BroadcastLocalAsync(ConnectionEvent connectionEvent, byte[] payload)
    {
        var deliveries = _sockets.Values.ToArray()
            .Where(subscription => string.IsNullOrWhiteSpace(connectionEvent.TenantId)
                || ManagementContext.SameTenant(subscription.Principal.TenantId, connectionEvent.TenantId))
            .Select(subscription => subscription.Delivery.SendAsync(connectionEvent, payload));
        return Task.WhenAll(deliveries);
    }

    private async ValueTask<bool> CanReceiveAsync(SubscriptionPrincipal principal,
        ConnectionEvent connectionEvent, CancellationToken cancellationToken)
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
                           && c.OwnerUsername == principal.Username, cancellationToken)
            .ConfigureAwait(false);
    }

    private sealed record ConnectionEventSubscription(SubscriptionPrincipal Principal, ConnectionEventDelivery Delivery);

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
        app.Map("/ws/connections", (HttpContext context, ConnectionEventsHub hub) =>
            hub.AcceptAsync(context));
    }
}
