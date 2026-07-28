using System.Collections.Concurrent;
using System.Net.WebSockets;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Options;
using Specus.Server.Configuration;
using Specus.Server.Security;
using StackExchange.Redis;

namespace Specus.Server.WebSockets;

/// <summary>Unauthenticated, room-isolated WebRTC discovery/signalling for public transfer.</summary>
public sealed class PublicTransferDiscoveryHub
{
    private const int MaxMessageChars = 64 * 1024;
    private const int MaxMessageUtf8Bytes = MaxMessageChars * 3;
    private const string DuplicatePeerIdError = "peer id is already connected";
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web)
    {
        DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull,
    };

    private readonly ConcurrentDictionary<Guid, Participant> _participants = new();
    private readonly ConcurrentDictionary<string, long> _localRosterRevisions = new(StringComparer.Ordinal);
    private readonly object _participantsGate = new();
    private readonly PublicTransferOptions _options;
    private readonly WebSocketTicketService _tickets;
    private readonly PublicTransferCoordinationService _coordination;
    private readonly ILogger<PublicTransferDiscoveryHub> _logger;

    public PublicTransferDiscoveryHub(IOptions<PublicTransferOptions> options,
        WebSocketTicketService tickets,
        PublicTransferCoordinationService coordination,
        ILogger<PublicTransferDiscoveryHub> logger)
    {
        _options = options.Value;
        _tickets = tickets;
        _coordination = coordination;
        _logger = logger;
        _coordination.AddListener(HandleCoordinationEventAsync);
    }

    public async Task AcceptAsync(HttpContext context)
    {
        if (!context.WebSockets.IsWebSocketRequest)
        {
            context.Response.StatusCode = StatusCodes.Status400BadRequest;
            return;
        }

        var ticket = WebSocketTicketService.ExtractTicket(context.Request);
        var claims = await _tickets.ConsumeAsync(ticket, WebSocketTicketService.PublicTransferScope,
            WebSocketTicketService.RequestAddress(context), context.RequestAborted).ConfigureAwait(false);
        if (claims is null || string.IsNullOrWhiteSpace(claims.PeerId)
            || string.IsNullOrWhiteSpace(claims.RoomId))
        {
            context.Response.StatusCode = StatusCodes.Status403Forbidden;
            context.Response.Headers["X-Auth-Reason"] = ticket is null ? "missing ticket" : "invalid ticket";
            return;
        }

        using var socket = await context.WebSockets.AcceptWebSocketAsync().ConfigureAwait(false);
        var participant = Participant.From(context, socket, claims);
        PublicTransferClusterRegistration registration;
        try
        {
            registration = await RegisterAsync(participant, context.RequestAborted)
                .ConfigureAwait(false);
        }
        catch (InvalidOperationException exception)
        {
            _logger.LogWarning(exception, "public transfer cluster registration failed");
            registration = new PublicTransferClusterRegistration("coordination unavailable", 0);
        }
        if (!registration.Accepted)
        {
            await participant.SendAsync(new { type = "error", error = registration.Error },
                context.RequestAborted).ConfigureAwait(false);
            await CloseQuietlyAsync(socket, WebSocketCloseStatus.PolicyViolation,
                    registration.Error ?? "registration rejected")
                .ConfigureAwait(false);
            participant.Dispose();
            return;
        }

        try
        {
            await participant.SendAsync(new
            {
                type = "hello",
                peerId = participant.PeerId,
                roomId = participant.RoomId,
                publicAddress = participant.PublicAddress,
                sharedRoom = participant.SharedRoom,
                roomRole = participant.RoomRole,
                rosterRevision = registration.Revision,
                connectedAt = participant.ConnectedAt,
            }, context.RequestAborted).ConfigureAwait(false);
            await BroadcastRosterAsync(participant, registration.Revision, context.RequestAborted)
                .ConfigureAwait(false);

            while (!context.RequestAborted.IsCancellationRequested && socket.State == WebSocketState.Open)
            {
                var message = await ReceiveMessageAsync(socket, context.RequestAborted).ConfigureAwait(false);
                if (message is null)
                {
                    break;
                }
                if (!await AllowMessageAsync(participant, context.RequestAborted).ConfigureAwait(false))
                {
                    await participant.SendAsync(new { type = "error", error = "rate limited" },
                        context.RequestAborted).ConfigureAwait(false);
                    await CloseQuietlyAsync(socket, WebSocketCloseStatus.PolicyViolation, "rate limited")
                        .ConfigureAwait(false);
                    break;
                }
                if (message.MessageType == WebSocketMessageType.Text)
                {
                    string text;
                    try
                    {
                        text = new UTF8Encoding(false, true).GetString(message.Payload);
                    }
                    catch (DecoderFallbackException)
                    {
                        await CloseQuietlyAsync(socket, WebSocketCloseStatus.InvalidPayloadData,
                            "invalid UTF-8").ConfigureAwait(false);
                        return;
                    }
                    if (text.Length > MaxMessageChars)
                    {
                        await CloseQuietlyAsync(socket, WebSocketCloseStatus.MessageTooBig,
                            "message too large").ConfigureAwait(false);
                        return;
                    }
                    await HandleMessageAsync(participant, text, context.RequestAborted)
                        .ConfigureAwait(false);
                }
                else
                {
                    try
                    {
                        var frame = PublicTransferRelayFrame.DecodeClient(message.Payload);
                        await HandleBinaryMessageAsync(participant, frame, context.RequestAborted)
                            .ConfigureAwait(false);
                    }
                    catch (ArgumentException)
                    {
                        await participant.SendAsync(new
                        {
                            type = "error",
                            error = "invalid binary relay frame",
                        }, context.RequestAborted).ConfigureAwait(false);
                        await CloseQuietlyAsync(socket, WebSocketCloseStatus.PolicyViolation,
                            "invalid binary relay frame").ConfigureAwait(false);
                        return;
                    }
                }
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
            var revision = await RemoveParticipantAsync(participant, CancellationToken.None)
                .ConfigureAwait(false);
            if (revision > 0)
            {
                await BroadcastRosterAsync(participant, revision, CancellationToken.None)
                    .ConfigureAwait(false);
            }
            await CloseQuietlyAsync(socket, WebSocketCloseStatus.NormalClosure, "bye")
                .ConfigureAwait(false);
            participant.Dispose();
        }
    }

    private async Task<PublicTransferClusterRegistration> RegisterAsync(Participant participant,
        CancellationToken cancellationToken)
    {
        if (_coordination.Enabled)
        {
            var registration = await _coordination.RegisterAsync(participant.ToCluster(),
                    _options.MaxDiscoveryPeersPerRoom, cancellationToken)
                .ConfigureAwait(false);
            if (registration.Accepted)
            {
                _participants[participant.Id] = participant;
            }
            return registration;
        }
        lock (_participantsGate)
        {
            var group = _participants.Values.Where(peer => peer.SameGroup(participant)).ToArray();
            if (group.Any(peer => string.Equals(peer.PeerId, participant.PeerId,
                    StringComparison.Ordinal)))
            {
                return new PublicTransferClusterRegistration(DuplicatePeerIdError, 0);
            }
            if (_participants.Values.Any(peer => string.Equals(peer.DisplayName,
                    participant.DisplayName, StringComparison.OrdinalIgnoreCase)))
            {
                return new PublicTransferClusterRegistration("client name is already in use", 0);
            }
            if (group.Length >= Math.Max(1, _options.MaxDiscoveryPeersPerRoom))
            {
                return new PublicTransferClusterRegistration("room is full", 0);
            }
            _participants[participant.Id] = participant;
            return new PublicTransferClusterRegistration(null,
                NextLocalRosterRevision(participant.GroupId));
        }
    }

    private async Task<ulong> RemoveParticipantAsync(Participant participant,
        CancellationToken cancellationToken)
    {
        var removed = false;
        lock (_participantsGate)
        {
            removed = _participants.TryRemove(participant.Id, out _);
        }
        if (!removed)
        {
            return 0;
        }
        if (_coordination.Enabled)
        {
            try
            {
                return await _coordination.UnregisterAsync(participant.ToCluster(), cancellationToken)
                    .ConfigureAwait(false);
            }
            catch (InvalidOperationException exception)
            {
                _logger.LogWarning(exception,
                    "public transfer cluster unregister failed: peer={Peer}", participant.PeerId);
                return 0;
            }
        }
        return NextLocalRosterRevision(participant.GroupId);
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
            if (_coordination.Enabled)
            {
                await _coordination.PublishTextAsync(source.GroupId, targetPeerId,
                    source.LeaseId, false, JsonSerializer.SerializeToUtf8Bytes(envelope, JsonOptions),
                    cancellationToken).ConfigureAwait(false);
                return;
            }
            var target = _participants.Values.FirstOrDefault(peer => peer.SameGroup(source)
                && string.Equals(peer.PeerId, targetPeerId, StringComparison.Ordinal));
            if (target is not null)
            {
                await SendOrRemoveAsync(target, envelope, cancellationToken).ConfigureAwait(false);
            }
            return;
        }
        if (_coordination.Enabled)
        {
            await _coordination.PublishTextAsync(source.GroupId, string.Empty, source.LeaseId,
                true, JsonSerializer.SerializeToUtf8Bytes(envelope, JsonOptions), cancellationToken)
                .ConfigureAwait(false);
            return;
        }
        await BroadcastAsync(source, envelope, excludeSource: true, cancellationToken)
            .ConfigureAwait(false);
    }

    private async Task HandleBinaryMessageAsync(Participant source,
        PublicTransferRelayClientFrame frame, CancellationToken cancellationToken)
    {
        var envelope = PublicTransferRelayFrame.EncodeServer(
            frame.TargetPeerId, source.PeerId, frame.AppFrame);
        if (_coordination.Enabled)
        {
            await _coordination.PublishBinaryAsync(source.GroupId, frame.TargetPeerId, envelope,
                cancellationToken).ConfigureAwait(false);
            return;
        }
        var target = _participants.Values.FirstOrDefault(peer => peer.SameGroup(source)
            && string.Equals(peer.PeerId, frame.TargetPeerId, StringComparison.Ordinal));
        if (target is null)
        {
            return;
        }
        try
        {
            await target.SendBinaryAsync(envelope, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is WebSocketException or ObjectDisposedException
            or OperationCanceledException)
        {
            await DropParticipantAsync(target, cancellationToken).ConfigureAwait(false);
            _logger.LogDebug(ex, "public transfer binary relay failed: peer={Peer}", target.PeerId);
        }
    }

    private async Task BroadcastRosterAsync(Participant group, ulong revision,
        CancellationToken cancellationToken)
    {
        if (_coordination.Enabled)
        {
            await _coordination.PublishRosterAsync(group.GroupId, revision, cancellationToken)
                .ConfigureAwait(false);
            return;
        }
        await EmitRosterAsync(group, revision, cancellationToken).ConfigureAwait(false);
    }

    private async Task EmitRosterAsync(Participant group, ulong eventRevision,
        CancellationToken cancellationToken)
    {
        IReadOnlyList<object> peers;
        var revision = eventRevision;
        if (_coordination.Enabled)
        {
            var roster = await _coordination.RosterAsync(group.GroupId, cancellationToken)
                .ConfigureAwait(false);
            revision = roster.Revision;
            peers = roster.Participants.Select(ClusterParticipantView).ToList();
        }
        else
        {
            peers = _participants.Values
                .Where(peer => peer.SameGroup(group))
                .OrderBy(peer => peer.ConnectedAt, StringComparer.Ordinal)
                .Select(ParticipantView)
                .ToList();
        }
        await BroadcastAsync(group, new
        {
            type = "roster",
            roomId = group.RoomId,
            publicAddress = group.PublicAddress,
            sharedRoom = group.SharedRoom,
            rosterRevision = revision,
            peers,
        }, excludeSource: false, cancellationToken).ConfigureAwait(false);
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
            await DropParticipantAsync(peer, cancellationToken).ConfigureAwait(false);
            _logger.LogDebug(ex, "public transfer discovery send failed: peer={Peer}", peer.PeerId);
        }
    }

    internal async Task RefreshClusterPresenceAsync(CancellationToken cancellationToken)
    {
        if (!_coordination.Enabled || _participants.IsEmpty)
        {
            return;
        }
        var groups = new HashSet<string>(StringComparer.Ordinal);
        try
        {
            foreach (var participant in _participants.Values.ToArray())
            {
                groups.Add(participant.GroupId);
                if (!await _coordination.RefreshAsync(participant.ToCluster(), cancellationToken)
                        .ConfigureAwait(false))
                {
                    await DropParticipantAsync(participant, cancellationToken).ConfigureAwait(false);
                }
            }
            foreach (var groupId in groups)
            {
                await _coordination.SweepAsync(groupId, cancellationToken).ConfigureAwait(false);
            }
        }
        catch (Exception exception) when (exception is InvalidOperationException or RedisException)
        {
            _logger.LogWarning(exception,
                "public transfer Redis coordination unavailable; closing local discovery sockets");
            foreach (var participant in _participants.Values.ToArray())
            {
                await DropParticipantAsync(participant, CancellationToken.None).ConfigureAwait(false);
            }
        }
    }

    internal async Task<ClientNameAvailability> CheckClientNameAvailabilityAsync(
        string? requestedClientName, string? excludePeerId, CancellationToken cancellationToken)
    {
        var clientName = NormalizeDisplayName(requestedClientName);
        var excluded = string.IsNullOrWhiteSpace(excludePeerId) ? string.Empty : excludePeerId.Trim();
        bool available;
        if (_coordination.Enabled)
        {
            available = await _coordination.IsClientNameAvailableAsync(clientName, excluded,
                cancellationToken).ConfigureAwait(false);
        }
        else
        {
            lock (_participantsGate)
            {
                available = _participants.Values
                    .Where(peer => excluded.Length == 0
                        || !string.Equals(peer.PeerId, excluded, StringComparison.Ordinal))
                    .All(peer => !string.Equals(peer.DisplayName, clientName,
                        StringComparison.OrdinalIgnoreCase));
            }
        }
        return new ClientNameAvailability(clientName, available);
    }

    private async Task<bool> AllowMessageAsync(Participant participant,
        CancellationToken cancellationToken)
    {
        var limit = Math.Max(1, _options.DiscoveryMessageRateLimitPerConnection);
        var windowSeconds = Math.Max(1L, _options.DiscoveryMessageRateLimitWindowSeconds);
        if (!_coordination.Enabled)
        {
            return participant.RateWindow.Allow(limit, TimeSpan.FromSeconds(windowSeconds));
        }
        try
        {
            return await _coordination.AllowRateAsync("discovery-message",
                participant.GroupId + "\n" + participant.PeerId, limit, windowSeconds,
                cancellationToken).ConfigureAwait(false);
        }
        catch (InvalidOperationException exception)
        {
            _logger.LogWarning(exception, "public transfer shared message rate limiter unavailable");
            return false;
        }
    }

    private async Task HandleCoordinationEventAsync(PublicTransferClusterEvent clusterEvent)
    {
        var local = _participants.Values
            .Where(participant => string.Equals(participant.GroupId, clusterEvent.GroupId,
                StringComparison.Ordinal))
            .ToArray();
        if (local.Length == 0)
        {
            return;
        }
        if (clusterEvent.Kind == PublicTransferClusterFrame.KindRoster)
        {
            try
            {
                await EmitRosterAsync(local[0], clusterEvent.Revision, CancellationToken.None)
                    .ConfigureAwait(false);
            }
            catch (InvalidOperationException exception)
            {
                _logger.LogWarning(exception, "public transfer cluster roster refresh failed");
                foreach (var participant in local)
                {
                    await DropParticipantAsync(participant, CancellationToken.None)
                        .ConfigureAwait(false);
                }
            }
            return;
        }

        foreach (var participant in local)
        {
            if (clusterEvent.TargetPeerId.Length > 0
                && !string.Equals(participant.PeerId, clusterEvent.TargetPeerId,
                    StringComparison.Ordinal)
                || clusterEvent.ExcludeSource
                && string.Equals(participant.LeaseId, clusterEvent.SourceLeaseId,
                    StringComparison.Ordinal))
            {
                continue;
            }
            try
            {
                if (clusterEvent.Kind == PublicTransferClusterFrame.KindText)
                {
                    await participant.SendTextBytesAsync(clusterEvent.Payload, CancellationToken.None)
                        .ConfigureAwait(false);
                }
                else if (clusterEvent.Kind == PublicTransferClusterFrame.KindBinary)
                {
                    await participant.SendBinaryAsync(clusterEvent.Payload, CancellationToken.None)
                        .ConfigureAwait(false);
                }
            }
            catch (Exception exception) when (exception is WebSocketException
                or ObjectDisposedException or OperationCanceledException)
            {
                await DropParticipantAsync(participant, CancellationToken.None).ConfigureAwait(false);
                _logger.LogDebug(exception,
                    "public transfer cluster delivery failed: peer={Peer}", participant.PeerId);
            }
        }
    }

    private async Task DropParticipantAsync(Participant participant,
        CancellationToken cancellationToken)
    {
        var revision = await RemoveParticipantAsync(participant, cancellationToken)
            .ConfigureAwait(false);
        await CloseQuietlyAsync(participant.Socket, WebSocketCloseStatus.InternalServerError,
            "coordination unavailable").ConfigureAwait(false);
        if (revision > 0)
        {
            try
            {
                await BroadcastRosterAsync(participant, revision, cancellationToken)
                    .ConfigureAwait(false);
            }
            catch (InvalidOperationException exception)
            {
                _logger.LogDebug(exception, "public transfer roster publish failed after disconnect");
            }
        }
    }

    private ulong NextLocalRosterRevision(string groupId) => checked((ulong)
        _localRosterRevisions.AddOrUpdate(groupId, 1, (_, revision) => checked(revision + 1)));

    private static object ParticipantView(Participant peer) => new
    {
        peerId = peer.PeerId,
        displayName = peer.DisplayName,
        roomId = peer.RoomId,
        publicAddress = peer.PublicAddress,
        sharedRoom = peer.SharedRoom,
        roomRole = peer.RoomRole,
        connectedAt = peer.ConnectedAt,
    };

    private static object ClusterParticipantView(PublicTransferClusterParticipant peer) => new
    {
        peerId = peer.PeerId,
        displayName = peer.DisplayName,
        roomId = peer.RoomId,
        publicAddress = peer.PublicAddress,
        sharedRoom = peer.SharedRoom,
        roomRole = peer.RoomRole,
        connectedAt = peer.ConnectedAt,
    };

    private static string NormalizeDisplayName(string? requestedClientName)
    {
        var value = requestedClientName?.Trim() ?? string.Empty;
        if (value.Length == 0)
        {
            throw new ArgumentException("clientName cannot be blank");
        }
        if (value.Length > 120 || value.Contains('\r') || value.Contains('\n'))
        {
            throw new ArgumentException("clientName is invalid");
        }
        return value;
    }

    private static async Task<ReceivedMessage?> ReceiveMessageAsync(WebSocket socket,
        CancellationToken cancellationToken)
    {
        using var stream = new MemoryStream();
        var buffer = new byte[8192];
        WebSocketMessageType? messageType = null;
        while (true)
        {
            var result = await socket.ReceiveAsync(buffer, cancellationToken).ConfigureAwait(false);
            if (result.MessageType == WebSocketMessageType.Close)
            {
                return null;
            }
            if (result.MessageType is not (WebSocketMessageType.Text or WebSocketMessageType.Binary)
                || messageType is not null && messageType != result.MessageType)
            {
                await socket.CloseAsync(WebSocketCloseStatus.InvalidMessageType, "unsupported message type",
                    CancellationToken.None).ConfigureAwait(false);
                return null;
            }
            messageType ??= result.MessageType;
            var limit = messageType == WebSocketMessageType.Binary
                ? PublicTransferRelayFrame.MaxWireBytes
                : MaxMessageUtf8Bytes;
            if (stream.Length + result.Count > limit)
            {
                await socket.CloseAsync(WebSocketCloseStatus.MessageTooBig, "message too large",
                    CancellationToken.None).ConfigureAwait(false);
                return null;
            }
            stream.Write(buffer, 0, result.Count);
            if (result.EndOfMessage)
            {
                return new ReceivedMessage(messageType.Value,
                    stream.GetBuffer().AsSpan(0, checked((int)stream.Length)).ToArray());
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
            LeaseId = Guid.NewGuid().ToString("N");
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
        public string LeaseId { get; }
        public WebSocket Socket { get; }
        public string PeerId { get; }
        public string DisplayName { get; }
        public string RoomId { get; }
        public string PublicAddress { get; }
        public string RoomKey { get; }
        public bool SharedRoom { get; }
        public string RoomRole { get; } = "EDITOR";
        public string ConnectedAt { get; }
        public string GroupId => PublicTransferCoordinationService.GroupId(RoomId, RoomKey);
        public FixedRateWindow RateWindow { get; } = new();
        private SemaphoreSlim SendLock { get; } = new(1, 1);

        public bool SameGroup(Participant other) =>
            string.Equals(RoomId, other.RoomId, StringComparison.Ordinal)
            && string.Equals(RoomKey, other.RoomKey, StringComparison.Ordinal);

        public async Task SendAsync(object payload, CancellationToken cancellationToken)
        {
            var bytes = JsonSerializer.SerializeToUtf8Bytes(payload, JsonOptions);
            await SendTextBytesAsync(bytes, cancellationToken).ConfigureAwait(false);
        }

        public async Task SendTextBytesAsync(ReadOnlyMemory<byte> payload,
            CancellationToken cancellationToken)
        {
            await SendLock.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                if (Socket.State != WebSocketState.Open)
                {
                    throw new WebSocketException("socket is not open");
                }
                await Socket.SendAsync(payload, WebSocketMessageType.Text, true, cancellationToken)
                    .ConfigureAwait(false);
            }
            finally
            {
                SendLock.Release();
            }
        }

        public async Task SendBinaryAsync(ReadOnlyMemory<byte> payload,
            CancellationToken cancellationToken)
        {
            await SendLock.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                if (Socket.State != WebSocketState.Open)
                {
                    throw new WebSocketException("socket is not open");
                }
                await Socket.SendAsync(payload, WebSocketMessageType.Binary, true, cancellationToken)
                    .ConfigureAwait(false);
            }
            finally
            {
                SendLock.Release();
            }
        }

        public static Participant From(HttpContext context, WebSocket socket,
            WebSocketTicketClaims claims)
        {
            var publicAddress = ResolvePublicAddress(context);
            var roomKey = claims.SharedRoom ? claims.RoomKey! : "public:" + publicAddress;
            return new Participant(socket, claims.PeerId!, claims.DisplayName ?? "web", claims.RoomId!,
                publicAddress, roomKey, claims.SharedRoom);
        }

        public PublicTransferClusterParticipant ToCluster() => new(LeaseId, PeerId, DisplayName,
            RoomId, PublicAddress, RoomKey, RoomRole, SharedRoom, ConnectedAt);

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

    private sealed record ReceivedMessage(WebSocketMessageType MessageType, byte[] Payload);

    internal sealed record ClientNameAvailability(string ClientName, bool Available);
}

public sealed class PublicTransferPresenceRefreshService : BackgroundService
{
    private readonly PublicTransferDiscoveryHub _hub;
    private readonly PublicTransferOptions _options;

    public PublicTransferPresenceRefreshService(PublicTransferDiscoveryHub hub,
        IOptions<PublicTransferOptions> options)
    {
        _hub = hub;
        _options = options.Value;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        if (!_options.ClusterEnabled)
        {
            return;
        }
        using var timer = new PeriodicTimer(TimeSpan.FromMilliseconds(
            Math.Max(1_000L, _options.PresenceRefreshIntervalMs)));
        while (await timer.WaitForNextTickAsync(stoppingToken).ConfigureAwait(false))
        {
            await _hub.RefreshClusterPresenceAsync(stoppingToken).ConfigureAwait(false);
        }
    }
}

public static class PublicTransferDiscoveryWebSocketEndpoint
{
    public static void MapPublicTransferDiscoveryWebSocket(this WebApplication app) =>
        app.Map("/ws/public-transfer/discovery",
            (HttpContext context, PublicTransferDiscoveryHub hub) => hub.AcceptAsync(context));
}
