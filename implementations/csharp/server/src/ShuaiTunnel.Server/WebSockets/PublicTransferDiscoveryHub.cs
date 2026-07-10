using System.Collections.Concurrent;
using System.Net.WebSockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Options;
using ShuaiTunnel.Server.Configuration;

namespace ShuaiTunnel.Server.WebSockets;

/// <summary>Unauthenticated, room-isolated WebRTC discovery/signalling for public transfer.</summary>
public sealed class PublicTransferDiscoveryHub
{
    private const int MaxMessageChars = 64 * 1024;
    private const int MaxMessageUtf8Bytes = MaxMessageChars * 3;
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web)
    {
        DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull,
    };

    private readonly ConcurrentDictionary<Guid, Participant> _participants = new();
    private readonly PublicTransferOptions _options;
    private readonly ILogger<PublicTransferDiscoveryHub> _logger;

    public PublicTransferDiscoveryHub(IOptions<PublicTransferOptions> options,
        ILogger<PublicTransferDiscoveryHub> logger)
    {
        _options = options.Value;
        _logger = logger;
    }

    public async Task AcceptAsync(HttpContext context)
    {
        if (!context.WebSockets.IsWebSocketRequest)
        {
            context.Response.StatusCode = StatusCodes.Status400BadRequest;
            return;
        }

        using var socket = await context.WebSockets.AcceptWebSocketAsync().ConfigureAwait(false);
        var participant = Participant.From(context, socket);
        if (_participants.Values.Count(peer => peer.SameGroup(participant))
            >= Math.Max(1, _options.MaxDiscoveryPeersPerRoom))
        {
            await participant.SendAsync(new { type = "error", error = "room is full" },
                context.RequestAborted).ConfigureAwait(false);
            await CloseQuietlyAsync(socket, WebSocketCloseStatus.PolicyViolation, "room is full")
                .ConfigureAwait(false);
            participant.Dispose();
            return;
        }

        _participants[participant.Id] = participant;
        try
        {
            await participant.SendAsync(new
            {
                type = "hello",
                peerId = participant.PeerId,
                roomId = participant.RoomId,
                publicAddress = participant.PublicAddress,
                sharedRoom = participant.SharedRoom,
                connectedAt = participant.ConnectedAt,
            }, context.RequestAborted).ConfigureAwait(false);
            await BroadcastRosterAsync(participant, context.RequestAborted).ConfigureAwait(false);

            while (!context.RequestAborted.IsCancellationRequested && socket.State == WebSocketState.Open)
            {
                var message = await ReceiveTextAsync(socket, context.RequestAborted).ConfigureAwait(false);
                if (message is null)
                {
                    break;
                }
                if (!participant.RateWindow.Allow(
                    Math.Max(1, _options.DiscoveryMessageRateLimitPerConnection),
                    TimeSpan.FromSeconds(Math.Max(1L, _options.DiscoveryMessageRateLimitWindowSeconds))))
                {
                    await participant.SendAsync(new { type = "error", error = "rate limited" },
                        context.RequestAborted).ConfigureAwait(false);
                    await CloseQuietlyAsync(socket, WebSocketCloseStatus.PolicyViolation, "rate limited")
                        .ConfigureAwait(false);
                    break;
                }
                await HandleMessageAsync(participant, message, context.RequestAborted).ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException)
        {
            // Normal request shutdown/client disconnect.
        }
        catch (WebSocketException ex)
        {
            _logger.LogDebug(ex, "public transfer discovery disconnected: peer={Peer}",
                participant.PeerId);
        }
        finally
        {
            _participants.TryRemove(participant.Id, out _);
            await BroadcastRosterAsync(participant, CancellationToken.None).ConfigureAwait(false);
            await CloseQuietlyAsync(socket, WebSocketCloseStatus.NormalClosure, "bye")
                .ConfigureAwait(false);
            participant.Dispose();
        }
    }

    private async Task HandleMessageAsync(Participant source, string json,
        CancellationToken cancellationToken)
    {
        JsonElement root;
        try
        {
            using var document = JsonDocument.Parse(json);
            root = document.RootElement.Clone();
        }
        catch (JsonException)
        {
            await source.SendAsync(new { type = "error", error = "invalid message" }, cancellationToken)
                .ConfigureAwait(false);
            return;
        }

        var type = Text(root, "type", "signal");
        if (string.Equals(type, "ping", StringComparison.Ordinal))
        {
            await source.SendAsync(new { type = "pong", ts = DateTimeOffset.UtcNow.ToString("O") },
                cancellationToken).ConfigureAwait(false);
            return;
        }
        var targetPeerId = Text(root, "targetPeerId", string.Empty);
        JsonElement? payload = root.ValueKind == JsonValueKind.Object
            && root.TryGetProperty("payload", out var payloadValue)
                ? payloadValue.Clone()
                : null;
        var envelope = new SignalEnvelope(
            type,
            source.PeerId,
            string.IsNullOrWhiteSpace(targetPeerId) ? null : targetPeerId,
            source.RoomId,
            source.PublicAddress,
            payload);
        if (!string.IsNullOrWhiteSpace(targetPeerId))
        {
            var target = _participants.Values.FirstOrDefault(peer => peer.SameGroup(source)
                && string.Equals(peer.PeerId, targetPeerId, StringComparison.Ordinal));
            if (target is not null)
            {
                await SendOrRemoveAsync(target, envelope, cancellationToken).ConfigureAwait(false);
            }
            return;
        }
        await BroadcastAsync(source, envelope, excludeSource: true, cancellationToken)
            .ConfigureAwait(false);
    }

    private Task BroadcastRosterAsync(Participant group, CancellationToken cancellationToken)
    {
        var peers = _participants.Values
            .Where(peer => peer.SameGroup(group))
            .OrderBy(peer => peer.ConnectedAt, StringComparer.Ordinal)
            .Select(peer => new
            {
                peerId = peer.PeerId,
                displayName = peer.DisplayName,
                roomId = peer.RoomId,
                publicAddress = peer.PublicAddress,
                sharedRoom = peer.SharedRoom,
                connectedAt = peer.ConnectedAt,
            })
            .ToList();
        return BroadcastAsync(group, new
        {
            type = "roster",
            roomId = group.RoomId,
            publicAddress = group.PublicAddress,
            sharedRoom = group.SharedRoom,
            peers,
        }, excludeSource: false, cancellationToken);
    }

    private async Task BroadcastAsync(Participant group, object payload, bool excludeSource,
        CancellationToken cancellationToken)
    {
        foreach (var peer in _participants.Values)
        {
            if (!peer.SameGroup(group) || excludeSource && peer.Id == group.Id)
            {
                continue;
            }
            await SendOrRemoveAsync(peer, payload, cancellationToken).ConfigureAwait(false);
        }
    }

    private async Task SendOrRemoveAsync(Participant peer, object payload,
        CancellationToken cancellationToken)
    {
        try
        {
            await peer.SendAsync(payload, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is WebSocketException or ObjectDisposedException
            or OperationCanceledException)
        {
            _participants.TryRemove(peer.Id, out _);
            _logger.LogDebug(ex, "public transfer discovery send failed: peer={Peer}", peer.PeerId);
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

    private static async Task CloseQuietlyAsync(WebSocket socket, WebSocketCloseStatus status,
        string reason)
    {
        if (socket.State is not (WebSocketState.Open or WebSocketState.CloseReceived))
        {
            return;
        }
        try
        {
            await socket.CloseAsync(status, reason, CancellationToken.None).ConfigureAwait(false);
        }
        catch (WebSocketException)
        {
            // Peer already disconnected.
        }
    }

    /// <summary>
    /// Matches Jackson's <c>JsonNode.asText(fallback)</c> conversion used by the Java
    /// discovery handler: strings are preserved, scalar numbers/booleans use their JSON text,
    /// and null/missing/container values use the fallback.
    /// </summary>
    internal static string Text(JsonElement root, string property, string fallback)
    {
        if (root.ValueKind != JsonValueKind.Object
            || !root.TryGetProperty(property, out var value)
            || value.ValueKind is JsonValueKind.Null or JsonValueKind.Undefined)
        {
            return fallback;
        }

        return value.ValueKind switch
        {
            JsonValueKind.String => value.GetString() ?? fallback,
            JsonValueKind.Number => value.GetRawText(),
            JsonValueKind.True => "true",
            JsonValueKind.False => "false",
            _ => fallback,
        };
    }

    private sealed class Participant : IDisposable
    {
        private Participant(WebSocket socket, string peerId, string displayName, string roomId,
            string publicAddress, string roomKey, bool sharedRoom)
        {
            Id = Guid.NewGuid();
            Socket = socket;
            PeerId = peerId;
            DisplayName = displayName;
            RoomId = roomId;
            PublicAddress = publicAddress;
            RoomKey = roomKey;
            SharedRoom = sharedRoom;
            ConnectedAt = DateTimeOffset.UtcNow.ToString("O");
        }

        public Guid Id { get; }
        public WebSocket Socket { get; }
        public string PeerId { get; }
        public string DisplayName { get; }
        public string RoomId { get; }
        public string PublicAddress { get; }
        public string RoomKey { get; }
        public bool SharedRoom { get; }
        public string ConnectedAt { get; }
        public FixedRateWindow RateWindow { get; } = new();
        private SemaphoreSlim SendLock { get; } = new(1, 1);

        public bool SameGroup(Participant other) =>
            string.Equals(RoomId, other.RoomId, StringComparison.Ordinal)
            && string.Equals(RoomKey, other.RoomKey, StringComparison.Ordinal);

        public async Task SendAsync(object payload, CancellationToken cancellationToken)
        {
            var bytes = JsonSerializer.SerializeToUtf8Bytes(payload, JsonOptions);
            await SendLock.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                if (Socket.State != WebSocketState.Open)
                {
                    throw new WebSocketException("socket is not open");
                }
                await Socket.SendAsync(bytes, WebSocketMessageType.Text, true, cancellationToken)
                    .ConfigureAwait(false);
            }
            finally
            {
                SendLock.Release();
            }
        }

        public static Participant From(HttpContext context, WebSocket socket)
        {
            var roomId = Query(context, "roomId", "nearby", 120);
            var peerId = Query(context, "peerId", string.Empty, 120);
            if (string.IsNullOrWhiteSpace(peerId))
            {
                peerId = "web-" + Guid.NewGuid().ToString("N")[..8];
            }
            var displayName = Query(context, "displayName", "web", 120);
            var roomToken = Query(context, "roomToken", string.Empty, 512);
            var publicAddress = ResolvePublicAddress(context);
            var sharedRoom = !string.IsNullOrWhiteSpace(roomToken);
            var roomKey = sharedRoom
                ? "token:" + Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(roomToken)))
                    .ToLowerInvariant()
                : "public:" + publicAddress;
            return new Participant(socket, peerId, displayName, roomId, publicAddress, roomKey,
                sharedRoom);
        }

        private static string Query(HttpContext context, string name, string fallback, int maxLength)
        {
            var value = context.Request.Query[name].FirstOrDefault();
            if (string.IsNullOrWhiteSpace(value))
            {
                return fallback;
            }
            var normalized = value.Trim();
            return TruncateUtf16WithoutSplittingSurrogate(normalized, maxLength);
        }

        internal static string TruncateUtf16WithoutSplittingSurrogate(string value, int maxLength)
        {
            if (value.Length <= maxLength)
            {
                return value;
            }

            var end = maxLength;
            if (end > 0 && char.IsHighSurrogate(value[end - 1])
                && end < value.Length && char.IsLowSurrogate(value[end]))
            {
                end--;
            }
            return value[..end];
        }

        private static string ResolvePublicAddress(HttpContext context)
        {
            var realIp = context.Request.Headers["X-Real-IP"].FirstOrDefault();
            if (!string.IsNullOrWhiteSpace(realIp))
            {
                return realIp.Trim();
            }
            var forwarded = context.Request.Headers["X-Forwarded-For"].FirstOrDefault();
            if (!string.IsNullOrWhiteSpace(forwarded))
            {
                var last = forwarded.Split(',').LastOrDefault()?.Trim();
                if (!string.IsNullOrWhiteSpace(last))
                {
                    return last;
                }
            }
            return context.Connection.RemoteIpAddress?.ToString() ?? "unknown";
        }

        public void Dispose() => SendLock.Dispose();
    }

    private sealed class FixedRateWindow
    {
        private readonly object _sync = new();
        private DateTimeOffset _startedAt = DateTimeOffset.UtcNow;
        private int _count;

        public bool Allow(int limit, TimeSpan window)
        {
            lock (_sync)
            {
                var now = DateTimeOffset.UtcNow;
                if (now - _startedAt >= window)
                {
                    _startedAt = now;
                    _count = 0;
                }
                return ++_count <= limit;
            }
        }
    }

    private sealed record SignalEnvelope(string Type, string SourcePeerId, string? TargetPeerId,
        string RoomId, string PublicAddress, JsonElement? Payload);
}

public static class PublicTransferDiscoveryWebSocketEndpoint
{
    public static void MapPublicTransferDiscoveryWebSocket(this WebApplication app) =>
        app.Map("/ws/public-transfer/discovery",
            (HttpContext context, PublicTransferDiscoveryHub hub) => hub.AcceptAsync(context));
}
