using System.Collections.Concurrent;
using System.Net.WebSockets;
using System.Security.Claims;
using System.Text;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Specus.Protocol;
using Specus.Protocol.Packets;
using Specus.Server.Authentication;
using Specus.Server.ControlChannel;
using Specus.Server.Data;
using Specus.Server.Data.Entities;
using Specus.Server.Management;
using Specus.Server.Security;
using Specus.Server.Sessions;

namespace Specus.Server.WebSockets;

/// <summary>
/// Authenticated management WebSocket used by the SPA to exchange messages with online specus
/// clients. The wire shape and tenant/owner checks match Java's
/// <c>ClientMessagesWebSocketHandler</c>.
/// </summary>
public sealed class ClientMessagesHub
{
    private const int MaxMessageChars = 64 * 1024;
    private const int MaxMessageUtf8Bytes = MaxMessageChars * 3;
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web)
    {
        DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull,
    };

    private readonly ConcurrentDictionary<Guid, Subscription> _subscriptions = new();
    private readonly IServiceScopeFactory _scopeFactory;
    private readonly SessionRegistry _sessions;
    private readonly WebSocketTicketService _tickets;
    private readonly ILogger<ClientMessagesHub> _logger;

    public ClientMessagesHub(IServiceScopeFactory scopeFactory, SessionRegistry sessions,
        WebSocketTicketService tickets,
        ILogger<ClientMessagesHub> logger)
    {
        _scopeFactory = scopeFactory;
        _sessions = sessions;
        _tickets = tickets;
        _logger = logger;
    }

    public async Task AcceptAsync(HttpContext context)
    {
        if (!context.WebSockets.IsWebSocketRequest)
        {
            context.Response.StatusCode = StatusCodes.Status400BadRequest;
            return;
        }

        var ticket = WebSocketTicketService.ExtractTicket(context.Request);
        var claims = await _tickets.ConsumeAsync(ticket, WebSocketTicketService.ClientMessagesScope,
            WebSocketTicketService.RequestAddress(context), context.RequestAborted).ConfigureAwait(false);
        if (claims is null || string.IsNullOrWhiteSpace(claims.Username))
        {
            context.Response.StatusCode = StatusCodes.Status403Forbidden;
            context.Response.Headers["X-Auth-Reason"] = ticket is null ? "missing ticket" : "invalid ticket";
            return;
        }

        var principal = claims.ToPrincipal();

        using var socket = await context.WebSockets.AcceptWebSocketAsync().ConfigureAwait(false);
        var subscription = Subscription.Create(socket, principal);
        _subscriptions[subscription.Id] = subscription;
        try
        {
            await SendAsync(subscription, new
            {
                type = "hello",
                channel = "client-messages",
                username = subscription.Username,
                tenantId = subscription.TenantId,
            }, context.RequestAborted).ConfigureAwait(false);

            while (!context.RequestAborted.IsCancellationRequested && socket.State == WebSocketState.Open)
            {
                var message = await ReceiveTextAsync(socket, context.RequestAborted).ConfigureAwait(false);
                if (message is null)
                {
                    break;
                }
                await HandleMessageAsync(subscription, message, context.RequestAborted).ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException)
        {
            // Normal request shutdown/client disconnect.
        }
        catch (WebSocketException ex)
        {
            _logger.LogDebug(ex, "client-messages websocket disconnected: {SocketId}", subscription.Id);
        }
        finally
        {
            _subscriptions.TryRemove(subscription.Id, out _);
            await CloseQuietlyAsync(socket).ConfigureAwait(false);
            subscription.Dispose();
        }
    }

    public async Task<bool> DeliverFromClientAsync(ClientAccount source, string targetAdminName,
        string body, CancellationToken cancellationToken)
    {
        var username = NormalizeAdminTarget(targetAdminName);
        if (string.IsNullOrWhiteSpace(username) || string.IsNullOrWhiteSpace(body))
        {
            return false;
        }

        var delivered = false;
        var payload = new
        {
            type = "message",
            direction = "in",
            fromClientName = source.ClientName,
            toClientName = "admin:" + username,
            message = body,
            createdAt = DateTimeOffset.UtcNow.ToString("O"),
        };
        foreach (var subscription in _subscriptions.Values)
        {
            if (!ManagementContext.SameTenant(subscription.TenantId, source.TenantId)
                || !string.Equals(subscription.Username, username, StringComparison.Ordinal))
            {
                continue;
            }
            try
            {
                await SendAsync(subscription, payload, cancellationToken).ConfigureAwait(false);
                delivered = true;
            }
            catch (Exception ex) when (ex is WebSocketException or ObjectDisposedException
                or OperationCanceledException)
            {
                _subscriptions.TryRemove(subscription.Id, out _);
                _logger.LogDebug(ex,
                    "client-message websocket delivery failed: source={Source} admin={Admin}",
                    source.ClientName, username);
            }
        }
        return delivered;
    }

    private async Task HandleMessageAsync(Subscription source, string json, CancellationToken cancellationToken)
    {
        ClientMessageCommand? command;
        try
        {
            command = JsonSerializer.Deserialize<ClientMessageCommand>(json, JsonOptions);
        }
        catch (JsonException)
        {
            await SendAsync(source, new { type = "error", error = "invalid-json" }, cancellationToken)
                .ConfigureAwait(false);
            return;
        }

        if (command is null || !string.Equals(command.Type, "message", StringComparison.Ordinal))
        {
            await SendErrorAsync(source, "unsupported-type", command?.MessageId, cancellationToken)
                .ConfigureAwait(false);
            return;
        }
        var targetName = command.ToClientName?.Trim() ?? string.Empty;
        var body = command.Message?.Trim() ?? string.Empty;
        if (targetName.Length == 0 || body.Length == 0)
        {
            await SendErrorAsync(source, "target-and-message-required", command.MessageId,
                cancellationToken).ConfigureAwait(false);
            return;
        }

        await using var scope = _scopeFactory.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<SpecusDbContext>();
        var target = await db.ClientAccounts.AsNoTracking()
            .FirstOrDefaultAsync(client => client.ClientName == targetName, cancellationToken)
            .ConfigureAwait(false);
        if (target is null || !target.Enabled || !ManagementContext.SameTenant(source.TenantId, target.TenantId)
            || (!source.Admin && !string.Equals(source.Username, target.OwnerUsername,
                StringComparison.Ordinal)))
        {
            await SendErrorAsync(source, "target-not-found", command.MessageId, cancellationToken)
                .ConfigureAwait(false);
            return;
        }

        var canReceive = await db.ClientSessions.AsNoTracking()
            .AnyAsync(session => session.TenantId == source.TenantId
                && session.ClientId == target.Id
                && session.Status == ClientAccountService.StatusNettyOnline
                && session.MessageReceiveCapable, cancellationToken)
            .ConfigureAwait(false);
        if (!canReceive)
        {
            await SendErrorAsync(source, "target-cannot-receive-message", command.MessageId,
                cancellationToken).ConfigureAwait(false);
            return;
        }

        var targetSession = _sessions.Find(target.ClientName);
        if (targetSession is null)
        {
            await SendErrorAsync(source, "target-offline", command.MessageId, cancellationToken)
                .ConfigureAwait(false);
            return;
        }

        _ = DeliverAndReportAsync(source, targetSession, target.ClientName, body,
            command.MessageId ?? string.Empty, cancellationToken);
    }

    private async Task DeliverAndReportAsync(Subscription source,
        SpecusConnectionContext targetSession, string targetClientName, string body,
        string messageId, CancellationToken sourceCancellationToken)
    {
        object status;
        try
        {
            await targetSession.Writer.WriteAsync(new MessageResponsePacket
            {
                ClientName = "admin:" + source.Username,
                ToClientName = targetClientName,
                MessageType = MessageType.ClientToClient,
                Message = body,
            }, targetSession.Lifetime).ConfigureAwait(false);
            status = new
            {
                type = "written",
                messageId,
                toClientName = targetClientName,
                message = body,
            };
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "admin client-message delivery failed: target={Target}",
                targetClientName);
            status = new
            {
                type = "failed",
                messageId,
                error = "target-write-failed",
            };
        }

        try
        {
            await SendAsync(source, status, sourceCancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex,
                "admin client-message status delivery failed: target={Target}", targetClientName);
        }
    }

    private static async Task<string?> ReceiveTextAsync(WebSocket socket, CancellationToken cancellationToken)
    {
        using var stream = new MemoryStream();
        var buffer = new byte[8192];
        while (true)
        {
            var result = await socket.ReceiveAsync(buffer, cancellationToken).ConfigureAwait(false);
            if (result.MessageType == WebSocketMessageType.Close)
            {
                return null;
            }
            if (result.MessageType != WebSocketMessageType.Text)
            {
                await socket.CloseAsync(WebSocketCloseStatus.InvalidMessageType, "text only",
                    CancellationToken.None).ConfigureAwait(false);
                return null;
            }
            if (stream.Length + result.Count > MaxMessageUtf8Bytes)
            {
                await socket.CloseAsync(WebSocketCloseStatus.MessageTooBig, "message too large",
                    CancellationToken.None).ConfigureAwait(false);
                return null;
            }
            stream.Write(buffer, 0, result.Count);
            if (result.EndOfMessage)
            {
                var text = Encoding.UTF8.GetString(stream.GetBuffer(), 0, checked((int)stream.Length));
                if (text.Length > MaxMessageChars)
                {
                    await socket.CloseAsync(WebSocketCloseStatus.MessageTooBig, "message too large",
                        CancellationToken.None).ConfigureAwait(false);
                    return null;
                }
                return text;
            }
        }
    }

    private static Task SendErrorAsync(Subscription subscription, string error, string? messageId,
        CancellationToken cancellationToken) => SendAsync(subscription, new
        {
            type = "error",
            error,
            messageId = messageId ?? string.Empty,
        }, cancellationToken);

    private static async Task SendAsync(Subscription subscription, object payload,
        CancellationToken cancellationToken)
    {
        var bytes = JsonSerializer.SerializeToUtf8Bytes(payload, JsonOptions);
        await subscription.SendLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (subscription.Socket.State != WebSocketState.Open)
            {
                throw new WebSocketException("socket is not open");
            }
            await subscription.Socket.SendAsync(bytes, WebSocketMessageType.Text, true, cancellationToken)
                .ConfigureAwait(false);
        }
        finally
        {
            subscription.SendLock.Release();
        }
    }

    private static async Task CloseQuietlyAsync(WebSocket socket)
    {
        if (socket.State is not (WebSocketState.Open or WebSocketState.CloseReceived))
        {
            return;
        }
        try
        {
            await socket.CloseAsync(WebSocketCloseStatus.NormalClosure, "bye", CancellationToken.None)
                .ConfigureAwait(false);
        }
        catch (WebSocketException)
        {
            // Peer already disconnected.
        }
    }

    private static string NormalizeAdminTarget(string? value)
    {
        var trimmed = value?.Trim() ?? string.Empty;
        const string prefix = "admin:";
        return trimmed.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)
            ? trimmed[prefix.Length..].Trim()
            : string.Empty;
    }

    private sealed record ClientMessageCommand(string? Type, string? MessageId,
        string? ToClientName, string? Message);

    private sealed class Subscription : IDisposable
    {
        public required Guid Id { get; init; }
        public required WebSocket Socket { get; init; }
        public required string Username { get; init; }
        public required string TenantId { get; init; }
        public required bool Admin { get; init; }
        public SemaphoreSlim SendLock { get; } = new(1, 1);

        public static Subscription Create(WebSocket socket, ClaimsPrincipal principal)
        {
            var username = principal.Identity?.Name
                ?? principal.FindFirstValue(ClaimTypes.NameIdentifier)
                ?? string.Empty;
            var tenantId = ManagementContext.NormalizeTenant(principal.FindFirst("tenant_id")?.Value);
            var role = principal.FindFirstValue(ClaimTypes.Role)
                ?? principal.FindFirst("role")?.Value;
            return new Subscription
            {
                Id = Guid.NewGuid(),
                Socket = socket,
                Username = username,
                TenantId = tenantId,
                Admin = string.Equals(role, "ADMIN", StringComparison.OrdinalIgnoreCase),
            };
        }

        public void Dispose() => SendLock.Dispose();
    }
}

public static class ClientMessagesWebSocketEndpoint
{
    public static void MapClientMessagesWebSocket(this WebApplication app) =>
        app.Map("/ws/client-messages", (HttpContext context, ClientMessagesHub hub) =>
            hub.AcceptAsync(context));
}
