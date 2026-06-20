using System.Collections.Concurrent;
using System.Net.WebSockets;
using System.Text.Json;
using ShuaiTunnel.Server.Management;
using ShuaiTunnel.Server.Security;

namespace ShuaiTunnel.Server.WebSockets;

public sealed class ConnectionEventsHub
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

    private readonly ConcurrentDictionary<Guid, WebSocket> _sockets = new();
    private readonly ILogger<ConnectionEventsHub> _logger;

    public ConnectionEventsHub(ILogger<ConnectionEventsHub> logger)
    {
        _logger = logger;
    }

    public async Task AcceptAsync(HttpContext context, AdminBearerTokenValidator tokens)
    {
        if (!context.WebSockets.IsWebSocketRequest)
        {
            context.Response.StatusCode = StatusCodes.Status400BadRequest;
            return;
        }

        var principal = await tokens.ValidateAsync(
            context.Request.Query["token"].ToString(),
            context.RequestAborted).ConfigureAwait(false);
        if (principal is null)
        {
            context.Response.StatusCode = StatusCodes.Status403Forbidden;
            context.Response.Headers["X-Auth-Reason"] = "invalid token";
            return;
        }

        using var socket = await context.WebSockets.AcceptWebSocketAsync().ConfigureAwait(false);
        var id = Guid.NewGuid();
        _sockets[id] = socket;
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
        foreach (var (id, socket) in _sockets.ToArray())
        {
            if (socket.State != WebSocketState.Open)
            {
                _sockets.TryRemove(id, out _);
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
