using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Extensions.Logging;
using ShuaiTunnel.Client.Configuration;
using ShuaiTunnel.Client.Control;
using ShuaiTunnel.Protocol;
using ShuaiTunnel.Protocol.Packets;

namespace ShuaiTunnel.Client.PeerMesh;

internal sealed class PeerMeshClient : IAsyncDisposable
{
    private const string TypeConfig = "peer-config";
    private const string TypeRoster = "roster";
    private const string TypeSessionGrant = "session-grant";
    private const string TypeCandidates = "candidates";
    private const string TypePathReport = "path-report";
    private const string TypeTrafficReport = "traffic-report";
    private const string TypeDeviceReport = "device-report";
    private const string TypeClose = "close";

    private const string RelayProbePrimary = "primary";
    private const string RelayProbeAlternate = "alternate";
    private const string RelayProbeChangedPort = "changed-port";
    private const string PublicStunRolePrefix = "public-stun:";

    private const string ProbeMagic = "shuai-peer-mesh";
    private const string ProbeTypeCheck = "check";
    private const string ProbeTypeCheckResponse = "check-response";
    private const string NatTypeNoNat = "NO_NAT";
    private const string NatTypeSymmetric = "SYMMETRIC_NAT";
    private const string NatTypePortRestricted = "PORT_RESTRICTED_NAT";
    private const string NatTypePortPreserved = "PORT_PRESERVED_NAT";
    private const string NatTypeFullConeOrRestricted = "FULL_CONE_OR_RESTRICTED_NAT";
    private const string NatTypeNat = "NAT";
    private const int MaxPendingPacketsPerPeer = 32;
    private static readonly TimeSpan PendingPacketTtl = TimeSpan.FromSeconds(8);
    private static readonly TimeSpan PathPrepareMinInterval = TimeSpan.FromSeconds(2);
    private static readonly TimeSpan RelayFreshRequestInterval = TimeSpan.FromSeconds(60);
    private static readonly TimeSpan RelayExpiringRequestInterval = TimeSpan.FromSeconds(15);
    private static readonly TimeSpan AlternateProbeMinInterval = TimeSpan.FromSeconds(15);
    private static readonly TimeSpan TurnPermissionTtl = TimeSpan.FromMinutes(4);

    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web)
    {
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingDefault,
    };

    private readonly TunnelClientConfig _config;
    private readonly ILogger<PeerMeshClient> _logger;
    private readonly object _sync = new();
    private readonly Dictionary<long, PeerMeshPeer> _peers = new();
    private readonly Dictionary<long, PeerMeshSession> _sessions = new();
    private readonly Dictionary<string, PendingProbe> _pending = new(StringComparer.Ordinal);
    private readonly Dictionary<long, List<PendingVirtualPacket>> _pendingPackets = new();
    private readonly Dictionary<long, DateTimeOffset> _pathPreparedAt = new();
    private readonly Dictionary<string, string> _natByRole = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, string> _pendingStun = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, PeerCandidate> _srflxCandidates = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, DateTimeOffset> _turnPermissions = new(StringComparer.OrdinalIgnoreCase);

    private CancellationTokenSource? _cts;
    private UdpClient? _udp;
    private TunnelRuntimeState? _runtime;
    private FrameWriter? _writer;
    private PeerCandidate? _srflx;
    private PeerCandidate? _relay;
    private string? _relayId;
    private DateTimeOffset _relayTtl;
    private DateTimeOffset _lastRelayCandidateRequest;
    private DateTimeOffset _lastAlternateProbeRequest;
    private PeerKeyMaterial? _keyMaterial;
    private IPeerVirtualDevice? _device;

    public PeerMeshClient(TunnelClientConfig config, ILogger<PeerMeshClient> logger)
    {
        _config = config;
        _logger = logger;
    }

    public async Task StartAsync(TunnelRuntimeState runtime, FrameWriter writer, CancellationToken cancellationToken)
    {
        if (!runtime.PeerMesh.Enabled)
        {
            await StopAsync().ConfigureAwait(false);
            return;
        }
        await StopAsync().ConfigureAwait(false);
        var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        UdpClient udp;
        try
        {
            udp = new UdpClient(AddressFamily.InterNetwork);
            udp.Client.Bind(new IPEndPoint(IPAddress.Any, 0));
        }
        catch (Exception ex) when (ex is SocketException or ObjectDisposedException)
        {
            _logger.LogWarning(ex, "Peer Mesh UDP socket open failed");
            await ReportDeviceAsync(runtime, writer, "NOOP", $"Peer Mesh UDP socket open failed: {ex.Message}", "", "", cancellationToken)
                .ConfigureAwait(false);
            cts.Dispose();
            return;
        }

        PeerKeyMaterial? keyMaterial = null;
        try
        {
            keyMaterial = PeerKeyStore.KeyMaterial();
        }
        catch (Exception ex) when (ex is CryptographicException or PlatformNotSupportedException or IOException or UnauthorizedAccessException)
        {
            _logger.LogWarning(ex, "Peer Mesh X25519 key unavailable");
        }

        lock (_sync)
        {
            _runtime = runtime;
            _writer = writer;
            _udp = udp;
            _cts = cts;
            _keyMaterial = keyMaterial;
            _peers.Clear();
            _sessions.Clear();
            _pending.Clear();
            _pendingPackets.Clear();
            _pathPreparedAt.Clear();
            _natByRole.Clear();
            _pendingStun.Clear();
            _srflxCandidates.Clear();
            _turnPermissions.Clear();
            _srflx = null;
            _relay = null;
            _relayId = null;
            _relayTtl = DateTimeOffset.MinValue;
            _lastRelayCandidateRequest = DateTimeOffset.MinValue;
            _lastAlternateProbeRequest = DateTimeOffset.MinValue;
        }

        var device = PeerVirtualDevices.Create(_config, runtime.PeerMesh, _logger);
        string deviceError = keyMaterial is null
            ? "Peer Mesh X25519 key unavailable; UDP control plane stays up but session keys cannot be derived"
            : "";
        try
        {
            await device.StartAsync(HandleVirtualPacketAsync, cts.Token).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is IOException
            or SocketException
            or InvalidOperationException
            or UnauthorizedAccessException
            or PlatformNotSupportedException
            or EntryPointNotFoundException
            or DllNotFoundException)
        {
            _logger.LogWarning(ex, "Peer Mesh virtual device start failed");
            deviceError = FirstNonEmpty(deviceError, ex.Message);
            await device.DisposeAsync().ConfigureAwait(false);
            device = new NoopPeerVirtualDevice(_config.PeerMeshTunName, "ERROR", ex.Message);
        }
        lock (_sync)
        {
            _device = device;
        }
        _ = Task.Run(() => ReceiveLoopAsync(udp, cts.Token), CancellationToken.None);
        _ = Task.Run(() => MaintenanceLoopAsync(cts.Token), CancellationToken.None);
        await ReportDeviceAsync(runtime, writer, DeviceStatus(), FirstNonEmpty(deviceError, device.Error), "", "", cancellationToken).ConfigureAwait(false);
        await RequestRelayCandidatesAsync().ConfigureAwait(false);
    }

    public async Task HandleControlAsync(string payload, TunnelRuntimeState runtime, FrameWriter writer, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(payload))
        {
            return;
        }
        PeerControlMessage? message;
        try
        {
            message = JsonSerializer.Deserialize<PeerControlMessage>(payload, JsonOptions);
        }
        catch (JsonException ex)
        {
            _logger.LogWarning(ex, "PEER_CONTROL payload parse failed");
            return;
        }
        if (message is null)
        {
            return;
        }
        switch (message.Type)
        {
            case TypeConfig:
                if (message.PeerMesh is not null)
                {
                    runtime.PeerMesh = message.PeerMesh;
                }
                await StartAsync(runtime, writer, cancellationToken).ConfigureAwait(false);
                break;
            case TypeRoster:
                MergeRoster(message.Peers);
                await AnnounceCandidatesAsync().ConfigureAwait(false);
                break;
            case TypeSessionGrant:
                MergeSession(message);
                await AnnounceCandidatesAsync().ConfigureAwait(false);
                break;
            case TypeCandidates:
                MergePeerFromSignal(message);
                MergeSession(message);
                await SendConnectivityChecksAsync(message).ConfigureAwait(false);
                break;
            case TypeClose:
                CloseSession(message);
                break;
            default:
                _logger.LogDebug("ignored peer-control message type={Type}", message.Type);
                break;
        }
    }

    private async Task ReceiveLoopAsync(UdpClient udp, CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            UdpReceiveResult result;
            try
            {
                result = await udp.ReceiveAsync(cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                return;
            }
            catch (ObjectDisposedException)
            {
                return;
            }
            catch (SocketException ex)
            {
                _logger.LogWarning(ex, "Peer Mesh UDP receive failed");
                return;
            }
            await HandleUdpAsync(result.Buffer, result.RemoteEndPoint).ConfigureAwait(false);
        }
    }

    private async Task MaintenanceLoopAsync(CancellationToken cancellationToken)
    {
        using var timer = new PeriodicTimer(TimeSpan.FromSeconds(15));
        try
        {
            while (await timer.WaitForNextTickAsync(cancellationToken).ConfigureAwait(false))
            {
                CleanupProbes();
                CleanupPendingPackets();
                await RequestRelayCandidatesAsync().ConfigureAwait(false);
                await ProbeKnownCandidatesAsync().ConfigureAwait(false);
                await ReportTrafficDeltasAsync().ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException)
        {
            // Normal session shutdown.
        }
    }

    private async Task HandleUdpAsync(byte[] payload, IPEndPoint remote)
    {
        if (payload.Length == 0)
        {
            return;
        }
        var stun = StunMessage.Parse(payload);
        if (stun is not null)
        {
            await HandleStunTurnMessageAsync(stun, remote).ConfigureAwait(false);
            return;
        }
        if (PeerDataFrameCodec.LooksLikeDataFrame(payload))
        {
            await HandlePeerDataFrameAsync(payload, remote, "").ConfigureAwait(false);
            return;
        }
        var probe = JsonSerializer.Deserialize<PeerUdpProbe>(payload, JsonOptions);
        if (probe?.Magic == ProbeMagic)
        {
            await HandleProbeAsync(probe, remote, "").ConfigureAwait(false);
        }
    }

    private async Task HandleStunTurnMessageAsync(StunMessage message, IPEndPoint remote)
    {
        switch (message.Type)
        {
            case StunMessage.BindingSuccess:
                await HandleStunBindingSuccessAsync(message, remote).ConfigureAwait(false);
                break;
            case StunMessage.AllocateSuccess:
                await HandleTurnAllocatedAsync(message).ConfigureAwait(false);
                break;
            case StunMessage.RefreshSuccess:
                lock (_sync)
                {
                    _relayTtl = DateTimeOffset.UtcNow.AddSeconds(Math.Max(30, message.LifetimeSeconds(300)));
                }
                break;
            case StunMessage.CreatePermissionSuccess:
                _logger.LogTrace("Peer Mesh TURN permission created: tx={TransactionId}", message.TransactionIdHex);
                break;
            case StunMessage.DataIndication:
                var peer = message.XorPeerAddress();
                var inner = message.Data();
                if (peer is not null && inner is not null)
                {
                    await HandleUdpPayloadAsync(inner, remote, EndpointKey(peer)).ConfigureAwait(false);
                }
                break;
            case StunMessage.AllocateError:
            case StunMessage.RefreshError:
            case StunMessage.CreatePermissionError:
                _logger.LogWarning("Peer Mesh STUN/TURN error response: type=0x{Type:x}, tx={TransactionId}",
                    message.Type,
                    message.TransactionIdHex);
                break;
        }
    }

    private async Task HandleStunBindingSuccessAsync(StunMessage message, IPEndPoint remote)
    {
        var mapped = message.XorMappedAddress();
        if (mapped is null)
        {
            return;
        }
        string role;
        lock (_sync)
        {
            role = _pendingStun.Remove(message.TransactionIdHex, out var pendingRole)
                ? pendingRole
                : RelayProbePrimary;
        }
        var publicStun = IsPublicStunRole(role);
        var endpoint = EndpointKey(mapped);
        if (!publicStun)
        {
            lock (_sync)
            {
                _natByRole[NormalizeProbeRole(role)] = endpoint;
            }
            await ReportDeviceAsync(DeviceStatus(), "", NatType(), endpoint).ConfigureAwait(false);
            await RequestAlternateProbeAsync(role, message.OtherAddress(), remote).ConfigureAwait(false);
        }

        var candidate = new PeerCandidate(
            "srflx",
            "udp",
            mapped.Address.ToString(),
            mapped.Port,
            800,
            publicStun ? "public-stun" : "standard-stun",
            "");
        lock (_sync)
        {
            _srflxCandidates[CandidateEndpointKey(candidate)] = candidate;
            if (!publicStun)
            {
                _srflx = candidate;
            }
        }
        await AnnounceCandidatesAsync().ConfigureAwait(false);
    }

    private async Task HandleTurnAllocatedAsync(StunMessage message)
    {
        var relayed = message.XorRelayedAddress();
        var turnServer = RelayEndpoint();
        if (relayed is null || turnServer is null)
        {
            return;
        }
        var relayId = EndpointKey(relayed);
        var relayHost = RelayHost();
        lock (_sync)
        {
            _relayId = relayId;
            _relayTtl = DateTimeOffset.UtcNow.AddSeconds(Math.Max(30, message.LifetimeSeconds(300)));
            _relay = new PeerCandidate(
                "relay",
                "udp",
                relayHost,
                turnServer.Port,
                100,
                "standard-turn",
                relayId);
        }
        await AnnounceCandidatesAsync().ConfigureAwait(false);
    }

    private async Task HandleUdpPayloadAsync(byte[] payload, IPEndPoint remote, string relayFrom)
    {
        if (PeerDataFrameCodec.LooksLikeDataFrame(payload))
        {
            await HandlePeerDataFrameAsync(payload, remote, relayFrom).ConfigureAwait(false);
            return;
        }
        var probe = JsonSerializer.Deserialize<PeerUdpProbe>(payload, JsonOptions);
        if (probe?.Magic == ProbeMagic)
        {
            await HandleProbeAsync(probe, remote, relayFrom).ConfigureAwait(false);
        }
    }

    private async Task HandleProbeAsync(PeerUdpProbe probe, IPEndPoint remote, string relayFrom)
    {
        var runtime = Runtime();
        if (runtime is null || runtime.PeerMesh.ClientId <= 0 || probe.ToClientId != runtime.PeerMesh.ClientId)
        {
            return;
        }
        if (string.IsNullOrWhiteSpace(relayFrom) && ShouldAvoidDirectPath())
        {
            return;
        }
        if (string.Equals(probe.Type, ProbeTypeCheck, StringComparison.OrdinalIgnoreCase))
        {
            await ReplyProbeAsync(probe, remote, relayFrom).ConfigureAwait(false);
        }
        else if (string.Equals(probe.Type, ProbeTypeCheckResponse, StringComparison.OrdinalIgnoreCase))
        {
            await CompleteProbeAsync(probe, remote, relayFrom).ConfigureAwait(false);
        }
    }

    private async Task ReplyProbeAsync(PeerUdpProbe probe, IPEndPoint remote, string relayFrom)
    {
        PeerMeshSession? session;
        UdpClient? udp;
        lock (_sync)
        {
            _sessions.TryGetValue(probe.FromClientId, out session);
            udp = _udp;
        }
        if (session is null || session.Token != probe.Token || udp is null)
        {
            return;
        }
        await MarkPathFromInboundCheckAsync(session, remote, relayFrom).ConfigureAwait(false);
        var response = new PeerUdpProbe(ProbeMagic, ProbeTypeCheckResponse, probe.SessionId, probe.ToClientId, probe.FromClientId, probe.Nonce, probe.Token, probe.SentAtMillis);
        var body = JsonSerializer.SerializeToUtf8Bytes(response, JsonOptions);
        if (!string.IsNullOrWhiteSpace(relayFrom))
        {
            await SendRelayPayloadAsync(relayFrom, body).ConfigureAwait(false);
            return;
        }
        await udp.SendAsync(body, remote).ConfigureAwait(false);
    }

    private async Task MarkPathFromInboundCheckAsync(PeerMeshSession session, IPEndPoint remote, string relayFrom)
    {
        if (session.AesKey.Length != 32 || DateTimeOffset.UtcNow > session.ExpiresAt)
        {
            return;
        }
        PeerMeshSession? ready = null;
        lock (_sync)
        {
            if (!_sessions.TryGetValue(session.PeerId, out var current)
                || current.AesKey.Length != 32
                || DateTimeOffset.UtcNow > current.ExpiresAt)
            {
                return;
            }
            if (!string.IsNullOrWhiteSpace(relayFrom))
            {
                current.PathType = "RELAY";
                current.RelayTargetAllocationId = relayFrom;
                current.RemoteEndpoint = null;
                current.LastRelaySuccess = DateTimeOffset.UtcNow;
                ready = current;
            }
            else if (ShouldAvoidDirectPathLocked() || InCidr(remote.Address, _runtime?.PeerMesh.Cidr))
            {
                return;
            }
            else
            {
                current.PathType = "DIRECT";
                current.RemoteEndpoint = remote;
                current.RelayTargetAllocationId = "";
                current.LastDirectSuccess = DateTimeOffset.UtcNow;
                ready = current;
            }
        }
        if (ready is not null)
        {
            await FlushPendingPacketsAsync(ready).ConfigureAwait(false);
        }
    }

    private async Task CompleteProbeAsync(PeerUdpProbe probe, IPEndPoint remote, string relayFrom)
    {
        PendingProbe? pending = null;
        PeerMeshSession? session = null;
        lock (_sync)
        {
            if (_pending.Remove(probe.Nonce, out var value))
            {
                pending = value;
                _sessions.TryGetValue(value.PeerId, out session);
            }
        }
        if (pending is null || session is null || session.Id != probe.SessionId || session.Token != probe.Token)
        {
            return;
        }
        if (session.AesKey.Length == 0)
        {
            _logger.LogWarning("Peer Mesh UDP path checked but session key is unavailable: session={Session} peer={Peer}", session.Id, session.PeerId);
            return;
        }
        var rtt = (long)(DateTimeOffset.UtcNow - pending.SentAt).TotalMilliseconds;
        var path = pending.Relay || !string.IsNullOrWhiteSpace(relayFrom) ? "RELAY" : "DIRECT";
        var remoteText = path == "RELAY" ? $"relay:{FirstNonEmpty(relayFrom, pending.RelayId)}" : remote.ToString();
        if (path == "DIRECT" && (ShouldAvoidDirectPath() || IsMeshEndpoint(remote)))
        {
            return;
        }
        var now = DateTimeOffset.UtcNow;
        var shouldLog = false;
        var shouldReport = false;
        lock (_sync)
        {
            if (_sessions.TryGetValue(session.PeerId, out var current))
            {
                var previousPath = current.PathType;
                var previousRemote = current.LastPathRemoteText;
                if (path == "RELAY")
                {
                    if (current.HasHealthyDirect(now) && !ShouldAvoidDirectPathLocked())
                    {
                        return;
                    }
                    current.PathType = path;
                    current.RelayTargetAllocationId = pending.RelayId;
                    current.LastRelaySuccess = now;
                }
                else
                {
                    current.PathType = path;
                    current.RemoteEndpoint = remote;
                    current.RelayTargetAllocationId = "";
                    current.LastDirectSuccess = now;
                }
                var pathChanged = !string.Equals(previousPath, path, StringComparison.OrdinalIgnoreCase)
                    || !string.Equals(previousRemote, remoteText, StringComparison.Ordinal);
                if (pathChanged || current.LastPathLog == default || now - current.LastPathLog >= TimeSpan.FromMinutes(1))
                {
                    shouldLog = true;
                    current.LastPathLog = now;
                }
                if (pathChanged || current.LastPathReport == default || now - current.LastPathReport >= TimeSpan.FromMinutes(1))
                {
                    shouldReport = true;
                    current.LastPathReport = now;
                }
                current.LastPathRemoteText = remoteText;
            }
        }
        if (shouldLog)
        {
            _logger.LogInformation("Peer Mesh {Path} UDP path active: session={Session} peer={Peer} remote={Remote} rtt={Rtt}ms",
                path.ToLowerInvariant(), session.Id, session.PeerId, remoteText, rtt);
        }
        if (shouldReport)
        {
            await ReportPathAsync(session, path, LocalEndpoint(), remoteText, rtt).ConfigureAwait(false);
        }
        await FlushPendingPacketsAsync(session).ConfigureAwait(false);
    }

    private async ValueTask HandleVirtualPacketAsync(byte[] packet)
    {
        var target = PeerIpPacket.DestinationIPv4(packet);
        if (string.IsNullOrWhiteSpace(target))
        {
            return;
        }
        PeerMeshSession? session;
        PeerMeshPeer? peer;
        lock (_sync)
        {
            session = _sessions.Values.FirstOrDefault(item =>
                string.Equals(item.PeerVirtualIp, target, StringComparison.OrdinalIgnoreCase));
            peer = _peers.Values.FirstOrDefault(item =>
                string.Equals(item.VirtualIp, target, StringComparison.OrdinalIgnoreCase));
        }
        if (session is null)
        {
            if (peer is not null)
            {
                QueuePendingPacket(peer.ClientId, packet);
                await PreparePathForPeerAsync(peer, null).ConfigureAwait(false);
            }
            _logger.LogDebug("Peer Mesh virtual packet has no session: {Flow}", PeerIpPacket.FlowKey(packet));
            return;
        }
        try
        {
            if (!await SendEncryptedPayloadAsync(session.PeerId, packet).ConfigureAwait(false))
            {
                QueuePendingPacket(session.PeerId, packet);
                if (peer is null)
                {
                    lock (_sync)
                    {
                        _peers.TryGetValue(session.PeerId, out peer);
                    }
                }
                await PreparePathForPeerAsync(peer, session).ConfigureAwait(false);
            }
        }
        catch (Exception ex) when (ex is CryptographicException or SocketException or InvalidOperationException or ObjectDisposedException)
        {
            QueuePendingPacket(session.PeerId, packet);
            if (peer is null)
            {
                lock (_sync)
                {
                    _peers.TryGetValue(session.PeerId, out peer);
                }
            }
            await PreparePathForPeerAsync(peer, session).ConfigureAwait(false);
            _logger.LogWarning(ex, "Peer Mesh virtual packet send failed: session={Session} peer={Peer} flow={Flow}",
                session.Id,
                session.PeerId,
                PeerIpPacket.FlowKey(packet));
        }
    }

    private async Task<bool> SendEncryptedPayloadAsync(long peerId, byte[] payload)
    {
        UdpClient? udp;
        TunnelRuntimeState? runtime;
        PeerMeshSession? session;
        bool avoidDirect;
        lock (_sync)
        {
            udp = _udp;
            runtime = _runtime;
            _sessions.TryGetValue(peerId, out session);
            avoidDirect = ShouldAvoidDirectPathLocked();
        }
        if (udp is null || runtime is null || session is null || DateTimeOffset.UtcNow > session.ExpiresAt)
        {
            return false;
        }
        if (session.AesKey.Length != 32)
        {
            _logger.LogDebug("Peer Mesh session has no data key: session={Session} peer={Peer}", session.Id, session.PeerId);
            return false;
        }
        var useRelay = !string.IsNullOrWhiteSpace(session.RelayTargetAllocationId);
        if (!useRelay && (session.RemoteEndpoint is null || avoidDirect || IsMeshEndpoint(session.RemoteEndpoint)))
        {
            return false;
        }
        session.Sequence++;
        var frame = PeerDataFrameCodec.Encode(
            session.AesKey,
            session.Id,
            runtime.PeerMesh.ClientId,
            session.PeerId,
            session.Sequence,
            payload);
        if (useRelay)
        {
            return await SendRelayPayloadAsync(session.RelayTargetAllocationId, frame).ConfigureAwait(false);
        }
        await udp.SendAsync(frame, session.RemoteEndpoint).ConfigureAwait(false);
        lock (_sync)
        {
            if (_sessions.TryGetValue(peerId, out var current))
            {
                current.DirectBytesPending += frame.Length;
            }
        }
        return true;
    }

    private void QueuePendingPacket(long peerId, byte[] packet)
    {
        if (peerId <= 0 || packet.Length == 0)
        {
            return;
        }
        var now = DateTimeOffset.UtcNow;
        lock (_sync)
        {
            if (!_pendingPackets.TryGetValue(peerId, out var queue))
            {
                queue = [];
                _pendingPackets[peerId] = queue;
            }
            queue.RemoveAll(item => now - item.CreatedAt > PendingPacketTtl);
            while (queue.Count >= MaxPendingPacketsPerPeer)
            {
                queue.RemoveAt(0);
            }
            queue.Add(new PendingVirtualPacket(packet.ToArray(), now));
        }
    }

    private async Task FlushPendingPacketsAsync(PeerMeshSession session)
    {
        List<PendingVirtualPacket>? queue = null;
        lock (_sync)
        {
            if (_pendingPackets.Remove(session.PeerId, out var found))
            {
                queue = found;
            }
        }
        if (queue is null || queue.Count == 0)
        {
            return;
        }
        var now = DateTimeOffset.UtcNow;
        var flushed = 0;
        foreach (var item in queue)
        {
            if (now - item.CreatedAt > PendingPacketTtl)
            {
                continue;
            }
            try
            {
                if (await SendEncryptedPayloadAsync(session.PeerId, item.Packet).ConfigureAwait(false))
                {
                    flushed++;
                }
            }
            catch (Exception ex) when (ex is CryptographicException or SocketException or InvalidOperationException or ObjectDisposedException)
            {
                _logger.LogDebug(ex, "Peer Mesh pending virtual packet flush failed: session={Session} peer={Peer}",
                    session.Id,
                    session.PeerId);
            }
        }
        if (flushed > 0)
        {
            _logger.LogInformation("Peer Mesh pending virtual packet flushed: peer={Peer}, count={Count}", session.PeerId, flushed);
        }
    }

    private void CleanupPendingPackets()
    {
        var now = DateTimeOffset.UtcNow;
        lock (_sync)
        {
            foreach (var peerId in _pendingPackets.Keys.ToList())
            {
                var queue = _pendingPackets[peerId];
                queue.RemoveAll(item => now - item.CreatedAt > PendingPacketTtl);
                if (queue.Count == 0)
                {
                    _pendingPackets.Remove(peerId);
                }
            }
        }
    }

    private async Task PreparePathForPeerAsync(PeerMeshPeer? peer, PeerMeshSession? session)
    {
        if (peer is null || !peer.Online || string.IsNullOrWhiteSpace(peer.ClientName))
        {
            return;
        }
        var now = DateTimeOffset.UtcNow;
        List<PeerCandidate> candidates;
        lock (_sync)
        {
            if (_pathPreparedAt.TryGetValue(peer.ClientId, out var previous)
                && now - previous < PathPrepareMinInterval)
            {
                return;
            }
            _pathPreparedAt[peer.ClientId] = now;
            candidates = [.. peer.Candidates];
        }
        await RequestRelayCandidatesAsync().ConfigureAwait(false);
        await AnnounceCandidatesAsync().ConfigureAwait(false);
        if (session is not null && candidates.Count > 0)
        {
            await SendConnectivityChecksAsync(new PeerControlMessage
            {
                SourceClientId = peer.ClientId,
                Candidates = candidates,
            }).ConfigureAwait(false);
        }
    }

    private async Task HandlePeerDataFrameAsync(byte[] payload, IPEndPoint remote, string relayFrom)
    {
        if (string.IsNullOrWhiteSpace(relayFrom) && (ShouldAvoidDirectPath() || IsMeshEndpoint(remote)))
        {
            return;
        }
        List<PeerMeshSession> sessions;
        IPeerVirtualDevice? device;
        TunnelRuntimeState? runtime;
        lock (_sync)
        {
            sessions = _sessions.Values.Where(item => item.AesKey.Length == 32).ToList();
            device = _device;
            runtime = _runtime;
        }
        if (device is null || runtime is null || sessions.Count == 0)
        {
            return;
        }
        foreach (var session in sessions)
        {
            PeerDataFrame frame;
            try
            {
                frame = PeerDataFrameCodec.Decode(session.AesKey, payload);
            }
            catch (CryptographicException)
            {
                continue;
            }
            if (frame.SessionId != session.Id
                || frame.FromClientId != session.PeerId
                || frame.ToClientId != runtime.PeerMesh.ClientId)
            {
                continue;
            }
            PeerMeshSession? ready = null;
            lock (_sync)
            {
                if (!_sessions.TryGetValue(session.PeerId, out var current)
                    || DateTimeOffset.UtcNow > current.ExpiresAt
                    || !current.Replay.Accept(frame.Sequence))
                {
                    return;
                }
                var frameBytes = payload.LongLength;
                if (!string.IsNullOrWhiteSpace(relayFrom))
                {
                    current.PathType = "RELAY";
                    current.RelayTargetAllocationId = relayFrom;
                    current.RemoteEndpoint = null;
                    current.LastRelaySuccess = DateTimeOffset.UtcNow;
                }
                else
                {
                    current.PathType = "DIRECT";
                    current.RemoteEndpoint = remote;
                    current.RelayTargetAllocationId = "";
                    current.LastDirectSuccess = DateTimeOffset.UtcNow;
                    current.DirectBytesPending += frameBytes;
                }
                ready = current;
            }
            if (ready is not null)
            {
                await FlushPendingPacketsAsync(ready).ConfigureAwait(false);
            }
            if (device is NoopPeerVirtualDevice)
            {
                var reply = PeerIpPacket.IcmpEchoReplyFor(frame.Payload, runtime.PeerMesh.VirtualIp);
                if (reply is not null && ready is not null
                    && await SendEncryptedPayloadAsync(ready.PeerId, reply).ConfigureAwait(false))
                {
                    return;
                }
            }
            else
            {
                try
                {
                    await device.WritePacketAsync(frame.Payload, CancellationToken.None).ConfigureAwait(false);
                }
                catch (Exception ex) when (ex is IOException or InvalidOperationException or ObjectDisposedException)
                {
                    _logger.LogWarning(ex, "Peer Mesh virtual packet write failed: session={Session} peer={Peer}", session.Id, session.PeerId);
                }
                return;
            }
            try
            {
                await device.WritePacketAsync(frame.Payload, CancellationToken.None).ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is IOException or InvalidOperationException or ObjectDisposedException)
            {
                _logger.LogWarning(ex, "Peer Mesh virtual packet write failed: session={Session} peer={Peer}", session.Id, session.PeerId);
            }
            return;
        }
    }

    private void MergeRoster(IReadOnlyList<PeerMeshPeer>? peers)
    {
        if (peers is null)
        {
            return;
        }
        lock (_sync)
        {
            foreach (var peer in peers.Where(x => x.ClientId > 0))
            {
                if (_peers.TryGetValue(peer.ClientId, out var existing) && peer.Candidates.Count == 0)
                {
                    peer.Candidates.AddRange(existing.Candidates);
                }
                _peers[peer.ClientId] = peer;
            }
        }
    }

    private void MergePeerFromSignal(PeerControlMessage message)
    {
        var runtime = Runtime();
        if (runtime is null)
        {
            return;
        }
        var peer = message.SourceClientId != 0 && message.SourceClientId != runtime.PeerMesh.ClientId
            ? new PeerMeshPeer(message.SourceClientId, message.SourceClientName, message.SourceVirtualIp, message.SourcePublicKey, true, message.Candidates)
            : new PeerMeshPeer(message.TargetClientId, message.TargetClientName, message.TargetVirtualIp, message.TargetPublicKey, true, message.Candidates);
        if (peer.ClientId <= 0)
        {
            return;
        }
        lock (_sync)
        {
            if (_peers.TryGetValue(peer.ClientId, out var existing))
            {
                peer = peer with
                {
                    ClientName = FirstNonEmpty(peer.ClientName, existing.ClientName),
                    VirtualIp = FirstNonEmpty(peer.VirtualIp, existing.VirtualIp),
                    PublicKey = FirstNonEmpty(peer.PublicKey, existing.PublicKey),
                };
            }
            _peers[peer.ClientId] = peer;
        }
    }

    private void MergeSession(PeerControlMessage message)
    {
        var runtime = Runtime();
        if (runtime is null || message.SessionId is null || message.SessionId <= 0 || string.IsNullOrWhiteSpace(message.Token))
        {
            return;
        }
        var peerId = message.TargetClientId;
        var peerName = message.TargetClientName;
        var peerVirtualIp = message.TargetVirtualIp;
        var peerPublicKey = message.TargetPublicKey;
        if (peerId == 0 || peerId == runtime.PeerMesh.ClientId)
        {
            peerId = message.SourceClientId;
            peerName = message.SourceClientName;
            peerVirtualIp = message.SourceVirtualIp;
            peerPublicKey = message.SourcePublicKey;
        }
        if (peerId <= 0 || peerId == runtime.PeerMesh.ClientId)
        {
            return;
        }
        lock (_sync)
        {
            if (_peers.TryGetValue(peerId, out var peer))
            {
                peerName = FirstNonEmpty(peerName, peer.ClientName);
                peerVirtualIp = FirstNonEmpty(peerVirtualIp, peer.VirtualIp);
                peerPublicKey = FirstNonEmpty(peerPublicKey, peer.PublicKey);
            }
            var expiresAt = DateTimeOffset.UtcNow.AddHours(1);
            if (DateTimeOffset.TryParse(message.ExpiresAt, out var parsed))
            {
                expiresAt = parsed;
            }
            _sessions.TryGetValue(peerId, out var session);
            if (session is null || session.Id != message.SessionId)
            {
                session = new PeerMeshSession();
            }
            session.Id = message.SessionId.Value;
            session.PeerId = peerId;
            session.PeerName = peerName;
            session.PeerVirtualIp = peerVirtualIp;
            session.PeerPublicKey = peerPublicKey;
            session.Token = message.Token;
            session.ExpiresAt = expiresAt;
            session.PathType = message.PathType;
            session.AesKey = DeriveSessionKey(peerPublicKey, session.Id, session.Token, runtime.PeerMesh.ClientId, peerId);
            _sessions[peerId] = session;
        }
    }

    private byte[] DeriveSessionKey(string? peerPublicKey, long sessionId, string token, long localClientId, long peerId)
    {
        var keyMaterial = _keyMaterial;
        if (keyMaterial is null || string.IsNullOrWhiteSpace(peerPublicKey))
        {
            return [];
        }
        try
        {
            return PeerCrypto.DeriveAes256Key(keyMaterial.PrivateKeyBase64, peerPublicKey, sessionId, token, localClientId, peerId);
        }
        catch (Exception ex) when (ex is CryptographicException or PlatformNotSupportedException)
        {
            _logger.LogWarning(ex, "Peer Mesh session key derive failed: session={Session} peer={Peer}", sessionId, peerId);
            return [];
        }
    }

    private void CloseSession(PeerControlMessage message)
    {
        if (message.SessionId is null)
        {
            return;
        }
        lock (_sync)
        {
            foreach (var peerId in _sessions.Where(item => item.Value.Id == message.SessionId).Select(item => item.Key).ToList())
            {
                _sessions.Remove(peerId);
            }
        }
    }

    private async Task AnnounceCandidatesAsync()
    {
        var candidates = GatherCandidates();
        if (candidates.Count == 0)
        {
            await RequestRelayCandidatesAsync().ConfigureAwait(false);
            candidates = GatherCandidates();
        }
        if (candidates.Count == 0)
        {
            return;
        }
        TunnelRuntimeState? runtime;
        List<PeerMeshPeer> peers;
        lock (_sync)
        {
            runtime = _runtime;
            peers = _peers.Values.Where(x => x.Online && !string.IsNullOrWhiteSpace(x.ClientName)).ToList();
        }
        if (runtime is null)
        {
            return;
        }
        foreach (var peer in peers)
        {
            await SendPeerControlAsync(FirstNonEmpty(peer.ClientName), new PeerControlMessage
            {
                Type = TypeCandidates,
                SourceClientId = runtime.PeerMesh.ClientId,
                SourceClientName = runtime.PeerMesh.ClientName,
                SourceVirtualIp = runtime.PeerMesh.VirtualIp,
                SourcePublicKey = runtime.PeerMesh.ClientPublicKey,
                TargetClientId = peer.ClientId,
                TargetClientName = peer.ClientName,
                TargetVirtualIp = peer.VirtualIp,
                TargetPublicKey = peer.PublicKey,
                Candidates = candidates,
                CreatedAtMillis = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
            }).ConfigureAwait(false);
        }
    }

    private async Task SendConnectivityChecksAsync(PeerControlMessage message)
    {
        var runtime = Runtime();
        if (runtime is null)
        {
            return;
        }
        var peerId = message.SourceClientId == runtime.PeerMesh.ClientId ? message.TargetClientId : message.SourceClientId;
        PeerMeshSession? session;
        lock (_sync)
        {
            _sessions.TryGetValue(peerId, out session);
        }
        if (session is null)
        {
            return;
        }
        foreach (var candidate in message.Candidates.Where(x =>
            string.Equals(x.Transport, "udp", StringComparison.OrdinalIgnoreCase)
            && !string.IsNullOrWhiteSpace(x.Address)
            && x.Port > 0))
        {
            if (ShouldSkipDirectCandidate(candidate))
            {
                continue;
            }
            await SendProbeAsync(session, candidate).ConfigureAwait(false);
        }
    }

    private async Task ProbeKnownCandidatesAsync()
    {
        List<PeerMeshPeer> peers;
        lock (_sync)
        {
            peers = _peers.Values.Where(x => x.Online && x.Candidates.Count > 0).ToList();
        }
        foreach (var peer in peers)
        {
            await SendConnectivityChecksAsync(new PeerControlMessage { SourceClientId = peer.ClientId, Candidates = peer.Candidates })
                .ConfigureAwait(false);
        }
    }

    private async Task SendProbeAsync(PeerMeshSession session, PeerCandidate candidate)
    {
        UdpClient? udp;
        var runtime = Runtime();
        lock (_sync)
        {
            udp = _udp;
        }
        if (udp is null || runtime is null || DateTimeOffset.UtcNow > session.ExpiresAt)
        {
            return;
        }
        var nonce = RandomHex(12);
        var probe = new PeerUdpProbe(
            ProbeMagic,
            ProbeTypeCheck,
            session.Id,
            runtime.PeerMesh.ClientId,
            session.PeerId,
            nonce,
            session.Token,
            DateTimeOffset.UtcNow.ToUnixTimeMilliseconds());
        var body = JsonSerializer.SerializeToUtf8Bytes(probe, JsonOptions);
        var relay = string.Equals(candidate.Type, "relay", StringComparison.OrdinalIgnoreCase);
        if (!relay && ShouldSkipDirectCandidate(candidate))
        {
            return;
        }
        lock (_sync)
        {
            _pending[nonce] = new PendingProbe(session.Id, session.PeerId, DateTimeOffset.UtcNow, relay, candidate.RelayId);
        }
        if (relay)
        {
            await SendRelayPayloadAsync(candidate.RelayId, body).ConfigureAwait(false);
            return;
        }
        if (IPAddress.TryParse(candidate.Address, out var ip))
        {
            await udp.SendAsync(body, new IPEndPoint(ip, candidate.Port)).ConfigureAwait(false);
        }
    }

    private List<PeerCandidate> GatherCandidates()
    {
        UdpClient? udp;
        TunnelRuntimeState? runtime;
        List<PeerCandidate> srflxCandidates;
        PeerCandidate? relay;
        bool avoidDirect;
        lock (_sync)
        {
            udp = _udp;
            runtime = _runtime;
            srflxCandidates = _srflxCandidates.Values.ToList();
            relay = _relay;
            avoidDirect = ShouldAvoidDirectPathLocked();
        }
        if (udp is null || runtime is null)
        {
            return [];
        }
        var port = ((IPEndPoint)udp.Client.LocalEndPoint!).Port;
        var candidates = new List<PeerCandidate>();
        if (!avoidDirect)
        {
            foreach (var networkInterface in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (networkInterface.OperationalStatus != OperationalStatus.Up
                    || networkInterface.NetworkInterfaceType == NetworkInterfaceType.Loopback)
                {
                    continue;
                }
                foreach (var address in networkInterface.GetIPProperties().UnicastAddresses.Select(x => x.Address))
                {
                    if (address.AddressFamily != AddressFamily.InterNetwork || IPAddress.IsLoopback(address) || InCidr(address, runtime.PeerMesh.Cidr))
                    {
                        continue;
                    }
                    candidates.Add(new PeerCandidate("host", "udp", address.ToString(), port, 1000, networkInterface.Name, ""));
                }
            }
        }
        if (!avoidDirect)
        {
            candidates.AddRange(srflxCandidates);
        }
        if (relay is not null)
        {
            candidates.Add(relay);
        }
        return candidates;
    }

    private async Task RequestRelayCandidatesAsync()
    {
        var endpoint = RelayEndpoint();
        if (endpoint is null)
        {
            return;
        }
        var now = DateTimeOffset.UtcNow;
        bool fresh;
        lock (_sync)
        {
            fresh = !string.IsNullOrWhiteSpace(_relayId) && _relayTtl > now.AddMinutes(1);
            var expiring = string.IsNullOrWhiteSpace(_relayId) || _relayTtl <= now.AddMinutes(1);
            if (!expiring && now - _lastRelayCandidateRequest < RelayFreshRequestInterval)
            {
                return;
            }
            if (expiring && now - _lastRelayCandidateRequest < RelayExpiringRequestInterval)
            {
                return;
            }
            _lastRelayCandidateRequest = now;
        }
        await SendStunBindingAsync(endpoint, RelayProbePrimary).ConfigureAwait(false);
        await RequestPublicStunBindingsAsync().ConfigureAwait(false);
        if (fresh)
        {
            await SendStunRequestAsync(StunMessage.Of(
                StunMessage.RefreshRequest,
                StunMessage.NewTransactionId(),
                StunMessage.Lifetime(Math.Max(30, Runtime()?.PeerMesh.SessionTtlSeconds ?? 300))),
                endpoint).ConfigureAwait(false);
            return;
        }
        await SendStunRequestAsync(StunMessage.Of(
            StunMessage.AllocateRequest,
            StunMessage.NewTransactionId(),
            StunMessage.RequestedUdpTransportAttribute()),
            endpoint).ConfigureAwait(false);
    }

    private async Task SendStunBindingAsync(IPEndPoint endpoint, string role)
    {
        var transactionId = StunMessage.NewTransactionId();
        lock (_sync)
        {
            _pendingStun[Convert.ToHexString(transactionId).ToLowerInvariant()] = BindingProbeRole(role);
        }
        await SendStunRequestAsync(StunMessage.Of(
            StunMessage.BindingRequest,
            transactionId,
            StunMessage.Software("shuai-tunnel-peer-client")),
            endpoint).ConfigureAwait(false);
    }

    private async Task RequestPublicStunBindingsAsync()
    {
        var runtime = Runtime();
        if (runtime?.PeerMesh.PublicStunServers is not { Count: > 0 } servers)
        {
            RemovePublicStunCandidates();
            return;
        }
        RemovePublicStunCandidates();
        var sent = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var item in servers)
        {
            var endpoint = ParseStunServer(item);
            if (endpoint is null || !sent.Add($"{endpoint.Address}:{endpoint.Port}"))
            {
                continue;
            }
            await SendStunBindingAsync(endpoint, PublicStunRolePrefix + $"{endpoint.Address}:{endpoint.Port}")
                .ConfigureAwait(false);
        }
    }

    private void RemovePublicStunCandidates()
    {
        lock (_sync)
        {
            foreach (var key in _srflxCandidates
                         .Where(item => string.Equals(item.Value.Foundation, "public-stun", StringComparison.OrdinalIgnoreCase))
                         .Select(item => item.Key)
                         .ToList())
            {
                _srflxCandidates.Remove(key);
            }
        }
    }

    private async Task RequestAlternateProbeAsync(string role, IPEndPoint? alternate, IPEndPoint observed)
    {
        if (!string.Equals(NormalizeProbeRole(role), RelayProbePrimary, StringComparison.OrdinalIgnoreCase)
            || alternate is null)
        {
            return;
        }
        var now = DateTimeOffset.UtcNow;
        lock (_sync)
        {
            if (now - _lastAlternateProbeRequest < AlternateProbeMinInterval)
            {
                return;
            }
        }
        var address = IsUnspecifiedAddress(alternate.Address) ? observed.Address : alternate.Address;
        if (alternate.Port == observed.Port)
        {
            return;
        }
        lock (_sync)
        {
            _lastAlternateProbeRequest = now;
        }
        await SendStunBindingAsync(new IPEndPoint(address, alternate.Port), RelayProbeAlternate).ConfigureAwait(false);
    }

    private async Task SendStunRequestAsync(StunMessage message, IPEndPoint endpoint)
    {
        UdpClient? udp;
        lock (_sync)
        {
            udp = _udp;
        }
        if (udp is null)
        {
            return;
        }
        var body = message.ToBytes();
        await udp.SendAsync(body, endpoint).ConfigureAwait(false);
    }

    private async Task<bool> SendRelayPayloadAsync(string? toAllocationId, byte[] payload)
    {
        if (string.IsNullOrWhiteSpace(toAllocationId))
        {
            return false;
        }
        var endpoint = RelayEndpoint();
        if (endpoint is null)
        {
            return false;
        }
        string? allocationId;
        DateTimeOffset relayTtl;
        lock (_sync)
        {
            allocationId = _relayId;
            relayTtl = _relayTtl;
        }
        if (string.IsNullOrWhiteSpace(allocationId) || relayTtl <= DateTimeOffset.UtcNow)
        {
            return false;
        }
        var peer = ParseEndpoint(toAllocationId);
        if (peer is null)
        {
            return false;
        }
        await EnsureTurnPermissionAsync(peer).ConfigureAwait(false);
        var transactionId = StunMessage.NewTransactionId();
        await SendStunRequestAsync(StunMessage.Of(
            StunMessage.SendIndication,
            transactionId,
            StunMessage.XorPeerAddress(peer, transactionId),
            StunMessage.Data(payload)),
            endpoint).ConfigureAwait(false);
        return true;
    }

    private async Task EnsureTurnPermissionAsync(IPEndPoint peer)
    {
        var turnServer = RelayEndpoint();
        if (turnServer is null)
        {
            return;
        }
        var now = DateTimeOffset.UtcNow;
        var key = EndpointKey(peer);
        lock (_sync)
        {
            if (_turnPermissions.TryGetValue(key, out var expiresAt) && expiresAt - now > TimeSpan.FromSeconds(30))
            {
                return;
            }
            _turnPermissions[key] = now + TurnPermissionTtl;
        }
        var transactionId = StunMessage.NewTransactionId();
        await SendStunRequestAsync(StunMessage.Of(
            StunMessage.CreatePermissionRequest,
            transactionId,
            StunMessage.XorPeerAddress(peer, transactionId)),
            turnServer).ConfigureAwait(false);
    }

    private IPEndPoint? RelayEndpoint()
    {
        var runtime = Runtime();
        if (runtime is null)
        {
            return null;
        }
        var host = FirstNonEmpty(runtime.PeerMesh.TurnHost, runtime.PeerMesh.StunHost);
        var port = runtime.PeerMesh.TurnPort > 0 ? runtime.PeerMesh.TurnPort : runtime.PeerMesh.StunPort;
        if (string.IsNullOrWhiteSpace(host) || port <= 0)
        {
            return null;
        }
        if (!IPAddress.TryParse(host, out var ip))
        {
            try
            {
                ip = Dns.GetHostAddresses(host).FirstOrDefault(x => x.AddressFamily == AddressFamily.InterNetwork);
            }
            catch (SocketException ex)
            {
                _logger.LogWarning(ex, "Peer Mesh relay endpoint resolve failed: {Host}:{Port}", host, port);
            }
        }
        return ip is null ? null : new IPEndPoint(ip, port);
    }

    private string RelayHost()
    {
        var runtime = Runtime();
        return runtime is null ? "" : FirstNonEmpty(runtime.PeerMesh.TurnHost, runtime.PeerMesh.StunHost);
    }

    private IPEndPoint? ParseStunServer(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return null;
        }
        var normalized = value.Trim();
        if (normalized.StartsWith("stun://", StringComparison.OrdinalIgnoreCase))
        {
            normalized = normalized["stun://".Length..];
        }
        else if (normalized.StartsWith("stun:", StringComparison.OrdinalIgnoreCase))
        {
            normalized = normalized["stun:".Length..];
        }
        var slash = normalized.IndexOf('/', StringComparison.Ordinal);
        if (slash >= 0)
        {
            normalized = normalized[..slash];
        }
        if (string.IsNullOrWhiteSpace(normalized))
        {
            return null;
        }
        var host = normalized;
        var port = 3478;
        if (normalized.StartsWith("[", StringComparison.Ordinal))
        {
            var end = normalized.IndexOf(']', StringComparison.Ordinal);
            if (end > 0)
            {
                host = normalized[1..end];
                if (normalized.Length > end + 2
                    && normalized[end + 1] == ':'
                    && int.TryParse(normalized[(end + 2)..], out var parsedPort)
                    && parsedPort > 0)
                {
                    port = parsedPort;
                }
            }
        }
        else
        {
            var colon = normalized.LastIndexOf(':');
            if (colon > 0
                && int.TryParse(normalized[(colon + 1)..], out var parsedPort)
                && parsedPort > 0)
            {
                host = normalized[..colon];
                port = parsedPort;
            }
        }
        if (string.IsNullOrWhiteSpace(host))
        {
            return null;
        }
        if (!IPAddress.TryParse(host, out var ip))
        {
            try
            {
                ip = Dns.GetHostAddresses(host).FirstOrDefault(x => x.AddressFamily == AddressFamily.InterNetwork);
            }
            catch (SocketException ex)
            {
                _logger.LogDebug(ex, "Peer Mesh STUN endpoint resolve failed: {Host}:{Port}", host, port);
            }
        }
        return ip is null ? null : new IPEndPoint(ip, port);
    }

    private static IPEndPoint? ParseEndpoint(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return null;
        }
        var normalized = value.Trim();
        if (normalized.StartsWith("turn:", StringComparison.OrdinalIgnoreCase))
        {
            normalized = normalized["turn:".Length..];
        }
        if (IPEndPoint.TryParse(normalized, out var endpoint))
        {
            return endpoint;
        }
        var colon = normalized.LastIndexOf(':');
        if (colon <= 0 || !int.TryParse(normalized[(colon + 1)..], out var port) || port <= 0)
        {
            return null;
        }
        return IPAddress.TryParse(normalized[..colon], out var ip) ? new IPEndPoint(ip, port) : null;
    }

    private static string EndpointKey(IPEndPoint endpoint) => $"{endpoint.Address}:{endpoint.Port}";

    private static string CandidateEndpointKey(PeerCandidate candidate) =>
        $"{candidate.Type}|{candidate.Address}|{candidate.Port}|{candidate.Foundation}";

    private static string NormalizeProbeRole(string? role) =>
        string.Equals(role, RelayProbeAlternate, StringComparison.OrdinalIgnoreCase)
        || string.Equals(role, RelayProbeChangedPort, StringComparison.OrdinalIgnoreCase)
            ? role!
            : RelayProbePrimary;

    private static string BindingProbeRole(string? role) =>
        IsPublicStunRole(role) ? role!.Trim() : NormalizeProbeRole(role);

    private static bool IsPublicStunRole(string? role) =>
        !string.IsNullOrWhiteSpace(role) && role.StartsWith(PublicStunRolePrefix, StringComparison.OrdinalIgnoreCase);

    private static bool IsUnspecifiedAddress(IPAddress address) =>
        IPAddress.Any.Equals(address)
        || IPAddress.IPv6Any.Equals(address)
        || address.ToString() == "0.0.0.0"
        || address.ToString() == "::";

    private async Task ReportDeviceAsync(string status, string error, string natType, string endpoint)
    {
        var runtime = Runtime();
        var writer = Writer();
        if (runtime is null || writer is null)
        {
            return;
        }
        await ReportDeviceAsync(runtime, writer, status, error, natType, endpoint, CancellationToken.None).ConfigureAwait(false);
    }

    private async Task ReportDeviceAsync(TunnelRuntimeState runtime, FrameWriter writer, string status, string error, string natType, string endpoint, CancellationToken cancellationToken)
    {
        await SendPeerControlAsync("", new PeerControlMessage
        {
            Type = TypeDeviceReport,
            SourceClientId = runtime.PeerMesh.ClientId,
            SourceClientName = runtime.PeerMesh.ClientName,
            SourceVirtualIp = runtime.PeerMesh.VirtualIp,
            SourcePublicKey = runtime.PeerMesh.ClientPublicKey,
            VirtualDeviceMode = _config.PeerMeshDevice,
            VirtualDeviceName = _config.PeerMeshTunName,
            VirtualDeviceStatus = status,
            VirtualDeviceError = error,
            NatType = natType,
            LastEndpoint = endpoint,
            CreatedAtMillis = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
        }, writer, runtime, cancellationToken).ConfigureAwait(false);
    }

    private async Task ReportPathAsync(PeerMeshSession session, string pathType, string local, string remote, long rttMillis)
    {
        var runtime = Runtime();
        if (runtime is null)
        {
            return;
        }
        await SendPeerControlAsync("", new PeerControlMessage
        {
            Type = TypePathReport,
            SessionId = session.Id,
            SourceClientId = runtime.PeerMesh.ClientId,
            SourceClientName = runtime.PeerMesh.ClientName,
            SourceVirtualIp = runtime.PeerMesh.VirtualIp,
            SourcePublicKey = runtime.PeerMesh.ClientPublicKey,
            TargetClientId = session.PeerId,
            TargetClientName = session.PeerName,
            TargetVirtualIp = session.PeerVirtualIp,
            TargetPublicKey = session.PeerPublicKey,
            PathType = pathType,
            Status = "ACTIVE",
            RttMillis = rttMillis,
            LocalEndpoint = local,
            RemoteEndpoint = remote,
            CreatedAtMillis = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
        }).ConfigureAwait(false);
    }

    private async Task ReportTrafficDeltasAsync()
    {
        List<PeerControlMessage> reports = [];
        var runtime = Runtime();
        if (runtime is null)
        {
            return;
        }
        lock (_sync)
        {
            foreach (var session in _sessions.Values)
            {
                if (session.DirectBytesPending == 0)
                {
                    continue;
                }
                reports.Add(new PeerControlMessage
                {
                    Type = TypeTrafficReport,
                    SessionId = session.Id,
                    SourceClientId = runtime.PeerMesh.ClientId,
                    SourceClientName = runtime.PeerMesh.ClientName,
                    SourceVirtualIp = runtime.PeerMesh.VirtualIp,
                    SourcePublicKey = runtime.PeerMesh.ClientPublicKey,
                    TargetClientId = session.PeerId,
                    TargetClientName = session.PeerName,
                    TargetVirtualIp = session.PeerVirtualIp,
                    TargetPublicKey = session.PeerPublicKey,
                    DirectBytes = session.DirectBytesPending,
                    CreatedAtMillis = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                });
                session.DirectBytesPending = 0;
            }
        }
        foreach (var report in reports)
        {
            await SendPeerControlAsync("", report).ConfigureAwait(false);
        }
    }

    private async Task SendPeerControlAsync(string toClientName, PeerControlMessage message)
    {
        var runtime = Runtime();
        var writer = Writer();
        if (runtime is null || writer is null)
        {
            return;
        }
        await SendPeerControlAsync(toClientName, message, writer, runtime, CancellationToken.None).ConfigureAwait(false);
    }

    private static async Task SendPeerControlAsync(string toClientName, PeerControlMessage message, FrameWriter writer, TunnelRuntimeState runtime, CancellationToken cancellationToken)
    {
        await writer.WriteAsync(new MessageRequestPacket
        {
            ClientName = runtime.ClientName,
            ToClientName = toClientName,
            MessageType = MessageType.PeerControl,
            Message = JsonSerializer.Serialize(message, JsonOptions),
        }, cancellationToken).ConfigureAwait(false);
    }

    private void CleanupProbes()
    {
        lock (_sync)
        {
            var now = DateTimeOffset.UtcNow;
            foreach (var key in _pending.Where(item => now - item.Value.SentAt > TimeSpan.FromSeconds(30)).Select(item => item.Key).ToList())
            {
                _pending.Remove(key);
            }
            foreach (var key in _sessions.Where(item => now > item.Value.ExpiresAt).Select(item => item.Key).ToList())
            {
                _sessions.Remove(key);
            }
        }
    }

    private string LocalEndpoint()
    {
        lock (_sync)
        {
            return _udp?.Client.LocalEndPoint?.ToString() ?? "";
        }
    }

    private string DeviceStatus()
    {
        lock (_sync)
        {
            return _device?.Status
                ?? (string.Equals(_config.PeerMeshDevice, "noop", StringComparison.OrdinalIgnoreCase) ? "NOOP" : "UDP_READY");
        }
    }

    private string NatType()
    {
        lock (_sync)
        {
            return NatTypeLocked();
        }
    }

    private string NatTypeLocked()
    {
        _natByRole.TryGetValue(RelayProbePrimary, out var primary);
        _natByRole.TryGetValue(RelayProbeAlternate, out var alternate);
        _natByRole.TryGetValue(RelayProbeChangedPort, out var changedPort);
        if (!string.IsNullOrWhiteSpace(primary) && !string.IsNullOrWhiteSpace(alternate) && primary != alternate)
        {
            return NatTypeSymmetric;
        }
        var endpointText = FirstNonEmpty(primary, alternate, changedPort);
        if (string.IsNullOrWhiteSpace(endpointText) || !IPEndPoint.TryParse(endpointText, out var endpoint))
        {
            return "";
        }
        if (IsPortPreservedLocked(endpoint) && IsLocalAddress(endpoint.Address))
        {
            return NatTypeNoNat;
        }
        if (!string.IsNullOrWhiteSpace(primary) && !string.IsNullOrWhiteSpace(alternate))
        {
            if (!string.IsNullOrWhiteSpace(changedPort))
            {
                return NatTypeFullConeOrRestricted;
            }
            return NatTypePortRestricted;
        }
        if (!string.IsNullOrWhiteSpace(primary) && !string.IsNullOrWhiteSpace(changedPort))
        {
            return NatTypeFullConeOrRestricted;
        }
        return IsPortPreservedLocked(endpoint) ? NatTypePortPreserved : NatTypeNat;
    }

    private bool ShouldAvoidDirectPath()
    {
        lock (_sync)
        {
            return ShouldAvoidDirectPathLocked();
        }
    }

    private bool ShouldAvoidDirectPathLocked()
        => string.Equals(NatTypeLocked(), NatTypeSymmetric, StringComparison.OrdinalIgnoreCase);

    private bool ShouldSkipDirectCandidate(PeerCandidate candidate)
    {
        if (string.Equals(candidate.Type, "relay", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }
        if (ShouldAvoidDirectPath())
        {
            return true;
        }
        if (!IPAddress.TryParse(candidate.Address, out var address))
        {
            return false;
        }
        var runtime = Runtime();
        return runtime is not null && InCidr(address, runtime.PeerMesh.Cidr);
    }

    private bool IsMeshEndpoint(IPEndPoint endpoint)
    {
        var runtime = Runtime();
        return runtime is not null && InCidr(endpoint.Address, runtime.PeerMesh.Cidr);
    }

    private bool IsPortPreservedLocked(IPEndPoint endpoint)
    {
        return _udp?.Client.LocalEndPoint is IPEndPoint local
            && local.Port > 0
            && local.Port == endpoint.Port;
    }

    private static bool IsLocalAddress(IPAddress address)
    {
        foreach (var networkInterface in NetworkInterface.GetAllNetworkInterfaces())
        {
            if (networkInterface.OperationalStatus != OperationalStatus.Up)
            {
                continue;
            }
            foreach (var candidate in networkInterface.GetIPProperties().UnicastAddresses.Select(item => item.Address))
            {
                if (candidate.AddressFamily == AddressFamily.InterNetwork && candidate.Equals(address))
                {
                    return true;
                }
            }
        }
        return false;
    }

    private TunnelRuntimeState? Runtime()
    {
        lock (_sync)
        {
            return _runtime;
        }
    }

    private FrameWriter? Writer()
    {
        lock (_sync)
        {
            return _writer;
        }
    }

    private async Task StopAsync()
    {
        CancellationTokenSource? cts;
        UdpClient? udp;
        IPeerVirtualDevice? device;
        lock (_sync)
        {
            cts = _cts;
            udp = _udp;
            device = _device;
            _cts = null;
            _udp = null;
            _device = null;
            _runtime = null;
            _writer = null;
            _peers.Clear();
            _sessions.Clear();
            _pending.Clear();
            _pendingPackets.Clear();
            _pathPreparedAt.Clear();
            _natByRole.Clear();
            _pendingStun.Clear();
            _srflxCandidates.Clear();
            _turnPermissions.Clear();
            _srflx = null;
            _relay = null;
            _relayId = null;
            _relayTtl = DateTimeOffset.MinValue;
            _lastRelayCandidateRequest = DateTimeOffset.MinValue;
            _lastAlternateProbeRequest = DateTimeOffset.MinValue;
            _keyMaterial = null;
        }
        if (cts is not null)
        {
            await cts.CancelAsync().ConfigureAwait(false);
            cts.Dispose();
        }
        udp?.Dispose();
        if (device is not null)
        {
            await device.DisposeAsync().ConfigureAwait(false);
        }
    }

    public async ValueTask DisposeAsync()
    {
        await StopAsync().ConfigureAwait(false);
    }

    private static bool InCidr(IPAddress address, string? cidr)
    {
        if (string.IsNullOrWhiteSpace(cidr))
        {
            return false;
        }
        var parts = cidr.Split('/', 2);
        if (parts.Length != 2
            || !IPAddress.TryParse(parts[0], out var network)
            || !int.TryParse(parts[1], out var prefix)
            || prefix < 0
            || prefix > 32)
        {
            return false;
        }
        var value = BitConverter.ToUInt32(address.GetAddressBytes().Reverse().ToArray());
        var networkValue = BitConverter.ToUInt32(network.GetAddressBytes().Reverse().ToArray());
        var mask = prefix == 0 ? 0u : uint.MaxValue << (32 - prefix);
        return (value & mask) == (networkValue & mask);
    }

    private static string RandomHex(int bytes)
    {
        return Convert.ToHexString(RandomNumberGenerator.GetBytes(bytes)).ToLowerInvariant();
    }

    private static string FirstNonEmpty(params string?[] values)
    {
        return values.FirstOrDefault(value => !string.IsNullOrWhiteSpace(value))?.Trim() ?? "";
    }

    private sealed record PendingProbe(long SessionId, long PeerId, DateTimeOffset SentAt, bool Relay, string? RelayId);

    private sealed record PendingVirtualPacket(byte[] Packet, DateTimeOffset CreatedAt);

    private sealed class PeerMeshSession
    {
        public long Id { get; set; }
        public long PeerId { get; set; }
        public string? PeerName { get; set; }
        public string? PeerVirtualIp { get; set; }
        public string? PeerPublicKey { get; set; }
        public string Token { get; set; } = "";
        public DateTimeOffset ExpiresAt { get; set; }
        public IPEndPoint? RemoteEndpoint { get; set; }
        public string? RelayTargetAllocationId { get; set; }
        public string? PathType { get; set; }
        public DateTimeOffset LastDirectSuccess { get; set; }
        public DateTimeOffset LastRelaySuccess { get; set; }
        public DateTimeOffset LastPathLog { get; set; }
        public DateTimeOffset LastPathReport { get; set; }
        public string LastPathRemoteText { get; set; } = "";
        public byte[] AesKey { get; set; } = [];
        public PeerReplayWindow Replay { get; } = new();
        public long Sequence { get; set; }
        public long DirectBytesPending { get; set; }

        public bool HasHealthyDirect(DateTimeOffset now) =>
            string.Equals(PathType, "DIRECT", StringComparison.OrdinalIgnoreCase)
            && LastDirectSuccess != default
            && now - LastDirectSuccess <= TimeSpan.FromSeconds(45);
    }

    private sealed record PeerMeshPeer(
        [property: JsonPropertyName("clientId")] long ClientId,
        [property: JsonPropertyName("clientName")] string? ClientName,
        [property: JsonPropertyName("virtualIp")] string? VirtualIp,
        [property: JsonPropertyName("publicKey")] string? PublicKey,
        [property: JsonPropertyName("online")] bool Online,
        [property: JsonPropertyName("candidates")] List<PeerCandidate> Candidates);

    private sealed record PeerCandidate(
        [property: JsonPropertyName("type")] string? Type,
        [property: JsonPropertyName("transport")] string? Transport,
        [property: JsonPropertyName("address")] string? Address,
        [property: JsonPropertyName("port")] int Port,
        [property: JsonPropertyName("priority")] long Priority,
        [property: JsonPropertyName("foundation")] string? Foundation,
        [property: JsonPropertyName("relayId")] string? RelayId);

    private sealed class PeerControlMessage
    {
        [JsonPropertyName("type")]
        public string? Type { get; set; }
        [JsonPropertyName("sourceClientId")]
        public long SourceClientId { get; set; }
        [JsonPropertyName("sourceClientName")]
        public string? SourceClientName { get; set; }
        [JsonPropertyName("sourceVirtualIp")]
        public string? SourceVirtualIp { get; set; }
        [JsonPropertyName("sourcePublicKey")]
        public string? SourcePublicKey { get; set; }
        [JsonPropertyName("targetClientId")]
        public long TargetClientId { get; set; }
        [JsonPropertyName("targetClientName")]
        public string? TargetClientName { get; set; }
        [JsonPropertyName("targetVirtualIp")]
        public string? TargetVirtualIp { get; set; }
        [JsonPropertyName("targetPublicKey")]
        public string? TargetPublicKey { get; set; }
        [JsonPropertyName("sessionId")]
        public long? SessionId { get; set; }
        [JsonPropertyName("token")]
        public string? Token { get; set; }
        [JsonPropertyName("expiresAt")]
        public string? ExpiresAt { get; set; }
        [JsonPropertyName("pathType")]
        public string? PathType { get; set; }
        [JsonPropertyName("status")]
        public string? Status { get; set; }
        [JsonPropertyName("rttMillis")]
        public long? RttMillis { get; set; }
        [JsonPropertyName("localEndpoint")]
        public string? LocalEndpoint { get; set; }
        [JsonPropertyName("remoteEndpoint")]
        public string? RemoteEndpoint { get; set; }
        [JsonPropertyName("directBytes")]
        public long DirectBytes { get; set; }
        [JsonPropertyName("relayBytes")]
        public long RelayBytes { get; set; }
        [JsonPropertyName("natType")]
        public string? NatType { get; set; }
        [JsonPropertyName("lastEndpoint")]
        public string? LastEndpoint { get; set; }
        [JsonPropertyName("virtualDeviceMode")]
        public string? VirtualDeviceMode { get; set; }
        [JsonPropertyName("virtualDeviceName")]
        public string? VirtualDeviceName { get; set; }
        [JsonPropertyName("virtualDeviceStatus")]
        public string? VirtualDeviceStatus { get; set; }
        [JsonPropertyName("virtualDeviceError")]
        public string? VirtualDeviceError { get; set; }
        [JsonPropertyName("peerMesh")]
        public PeerMeshConfig? PeerMesh { get; set; }
        [JsonPropertyName("peers")]
        public List<PeerMeshPeer>? Peers { get; set; }
        [JsonPropertyName("candidates")]
        public List<PeerCandidate> Candidates { get; set; } = [];
        [JsonPropertyName("createdAtMillis")]
        public long CreatedAtMillis { get; set; }
    }

    private sealed record PeerUdpProbe(
        [property: JsonPropertyName("magic")] string? Magic,
        [property: JsonPropertyName("type")] string? Type,
        [property: JsonPropertyName("sessionId")] long SessionId,
        [property: JsonPropertyName("fromClientId")] long FromClientId,
        [property: JsonPropertyName("toClientId")] long ToClientId,
        [property: JsonPropertyName("nonce")] string Nonce,
        [property: JsonPropertyName("token")] string? Token,
        [property: JsonPropertyName("sentAtMillis")] long SentAtMillis);
}
