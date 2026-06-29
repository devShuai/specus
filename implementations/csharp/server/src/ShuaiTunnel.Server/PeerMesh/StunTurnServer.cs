using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using Microsoft.Extensions.Options;
using ShuaiTunnel.Server.Configuration;

namespace ShuaiTunnel.Server.PeerMesh;

public sealed class StunTurnServer : BackgroundService
{
    private const string SoftwareName = "shuai-tunnel-standard-stun-turn";
    private static readonly TimeSpan PermissionTtl = TimeSpan.FromSeconds(300);

    private readonly PeerMeshOptions _options;
    private readonly IServiceScopeFactory _scopeFactory;
    private readonly ILogger<StunTurnServer> _logger;
    private readonly ConcurrentDictionary<string, Allocation> _allocations = new(StringComparer.Ordinal);
    private readonly ConcurrentDictionary<string, string> _allocationByEndpoint = new(StringComparer.Ordinal);
    private UdpClient? _primary;
    private UdpClient? _alternate;

    public StunTurnServer(IOptions<PeerMeshOptions> options, IServiceScopeFactory scopeFactory,
        ILogger<StunTurnServer> logger)
    {
        _options = options.Value;
        _scopeFactory = scopeFactory;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        if (!_options.Enabled)
        {
            return;
        }

        try
        {
            _primary = new UdpClient(new IPEndPoint(IPAddress.Any, _options.StunTurnPort));
        }
        catch (Exception ex) when (ex is SocketException or ObjectDisposedException)
        {
            _logger.LogWarning(ex, "[peer-mesh] standard STUN/TURN UDP server failed to start on {Port}",
                _options.StunTurnPort);
            return;
        }

        var tasks = new List<Task>
        {
            ReceiveLoopAsync(_primary, "primary", stoppingToken),
            CleanupLoopAsync(stoppingToken),
        };

        var alternatePort = NatProbeAlternatePort();
        if (alternatePort > 0 && alternatePort != _options.StunTurnPort)
        {
            try
            {
                _alternate = new UdpClient(new IPEndPoint(IPAddress.Any, alternatePort));
                tasks.Add(ReceiveLoopAsync(_alternate, "alternate", stoppingToken));
                _logger.LogInformation("[peer-mesh] standard STUN alternate UDP port listening on {Port}",
                    alternatePort);
            }
            catch (SocketException ex)
            {
                _logger.LogWarning(ex, "[peer-mesh] standard STUN alternate UDP port {Port} unavailable",
                    alternatePort);
            }
        }

        _logger.LogInformation("[peer-mesh] standard STUN/TURN UDP server listening on {Port}",
            _options.StunTurnPort);
        await Task.WhenAll(tasks).ConfigureAwait(false);
    }

    public override Task StopAsync(CancellationToken cancellationToken)
    {
        _primary?.Dispose();
        _alternate?.Dispose();
        foreach (var allocation in _allocations.Values)
        {
            CloseAllocation(allocation);
        }
        return base.StopAsync(cancellationToken);
    }

    private async Task ReceiveLoopAsync(UdpClient socket, string probeRole, CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            UdpReceiveResult result;
            try
            {
                result = await socket.ReceiveAsync(cancellationToken).ConfigureAwait(false);
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
                if (!cancellationToken.IsCancellationRequested)
                {
                    _logger.LogDebug(ex, "[peer-mesh] STUN/TURN receive failed");
                }
                return;
            }

            try
            {
                await HandleAsync(result.Buffer, result.RemoteEndPoint, socket, probeRole, cancellationToken)
                    .ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is SocketException or InvalidOperationException or ObjectDisposedException)
            {
                _logger.LogDebug(ex, "[peer-mesh] STUN/TURN packet handling failed");
            }
        }
    }

    private async Task HandleAsync(byte[] payload, IPEndPoint remote, UdpClient receiveSocket, string probeRole,
        CancellationToken cancellationToken)
    {
        var message = StunMessage.Parse(payload);
        if (message is null)
        {
            return;
        }
        switch (message.Type)
        {
            case StunMessage.BindingRequest:
                await BindingAsync(message, remote, receiveSocket, probeRole).ConfigureAwait(false);
                break;
            case StunMessage.AllocateRequest:
                await AllocateRequestAsync(message, remote, cancellationToken).ConfigureAwait(false);
                break;
            case StunMessage.RefreshRequest:
                await RefreshAsync(message, remote).ConfigureAwait(false);
                break;
            case StunMessage.CreatePermissionRequest:
                await CreatePermissionAsync(message, remote).ConfigureAwait(false);
                break;
            case StunMessage.SendIndication:
                await SendIndicationAsync(message, remote, cancellationToken).ConfigureAwait(false);
                break;
            default:
                await SendErrorAsync(receiveSocket, remote, message, ErrorType(message.Type), 400, "unsupported-method")
                    .ConfigureAwait(false);
                break;
        }
    }

    private async Task BindingAsync(StunMessage request, IPEndPoint remote, UdpClient receiveSocket,
        string probeRole)
    {
        var attributes = new List<StunAttribute>
        {
            StunMessage.XorMappedAddress(remote, request.TransactionId),
            StunMessage.Software(SoftwareName),
            StunMessage.ResponseOrigin(AdvertisedSocketAddress(receiveSocket), request.TransactionId),
        };
        if (_alternate is not null)
        {
            attributes.Add(StunMessage.OtherAddress(AdvertisedSocketAddress(_alternate), request.TransactionId));
        }
        await SendStunAsync(receiveSocket, remote,
            new StunMessage(StunMessage.BindingSuccess, request.TransactionId, attributes)).ConfigureAwait(false);
        _logger.LogTrace("[peer-mesh] STUN binding role={Role} remote={Remote}", probeRole, remote);
    }

    private async Task AllocateRequestAsync(StunMessage request, IPEndPoint remote, CancellationToken cancellationToken)
    {
        if (!request.RequestedUdpTransport())
        {
            await SendErrorAsync(_primary, remote, request, StunMessage.AllocateError, 442, "unsupported-transport")
                .ConfigureAwait(false);
            return;
        }
        var allocation = Allocate(remote, cancellationToken);
        await SendStunAsync(_primary, remote, StunMessage.Of(
            StunMessage.AllocateSuccess,
            request.TransactionId,
            StunMessage.XorRelayedAddress(allocation.RelayAddress, request.TransactionId),
            StunMessage.XorMappedAddress(remote, request.TransactionId),
            StunMessage.Lifetime(_options.AllocationTtlSeconds),
            StunMessage.Software(SoftwareName))).ConfigureAwait(false);
    }

    private Allocation Allocate(IPEndPoint remote, CancellationToken cancellationToken = default)
    {
        var endpointKey = EndpointKey(remote);
        if (_allocationByEndpoint.TryGetValue(endpointKey, out var existingId)
            && _allocations.TryGetValue(existingId, out var existing)
            && !existing.Closed)
        {
            if (!IsExpired(existing))
            {
                existing.Remote = remote;
                existing.ExpiresAt = DateTimeOffset.UtcNow.AddSeconds(_options.AllocationTtlSeconds);
                return existing;
            }
            CloseAllocation(existing);
        }

        var relay = BindRelaySocket();
        var allocation = new Allocation(Guid.NewGuid().ToString(), remote, relay,
            AdvertisedSocketAddress(relay), DateTimeOffset.UtcNow.AddSeconds(_options.AllocationTtlSeconds));
        _allocations[allocation.Id] = allocation;
        _allocationByEndpoint[endpointKey] = allocation.Id;
        _ = Task.Run(() => RelayReceiveLoopAsync(allocation, cancellationToken), CancellationToken.None);
        _logger.LogInformation("[peer-mesh] TURN allocation created: client={Client}, relay={Relay}",
            remote, allocation.RelayAddress);
        return allocation;
    }

    private UdpClient BindRelaySocket()
    {
        var (min, max) = RelayPortRange(_options.RelayMinPort, _options.RelayMaxPort);
        var capacity = max - min + 1;
        var attempts = Math.Min(128, Math.Max(16, capacity));
        var start = Random.Shared.Next(capacity);
        for (var i = 0; i < attempts; i++)
        {
            var port = min + ((start + i) % capacity);
            try
            {
                return new UdpClient(new IPEndPoint(IPAddress.Any, port));
            }
            catch (SocketException)
            {
                // Try another relay port.
            }
        }
        return new UdpClient(new IPEndPoint(IPAddress.Any, 0));
    }

    private async Task RefreshAsync(StunMessage request, IPEndPoint remote)
    {
        var allocation = AllocationForRemote(remote);
        if (allocation is null)
        {
            await SendErrorAsync(_primary, remote, request, StunMessage.RefreshError, 437, "allocation-mismatch")
                .ConfigureAwait(false);
            return;
        }
        var lifetime = request.LifetimeSeconds(_options.AllocationTtlSeconds);
        if (lifetime <= 0)
        {
            CloseAllocation(allocation);
        }
        else
        {
            allocation.ExpiresAt = DateTimeOffset.UtcNow.AddSeconds(Math.Min(lifetime, _options.AllocationTtlSeconds));
        }
        await SendStunAsync(_primary, remote, StunMessage.Of(
            StunMessage.RefreshSuccess,
            request.TransactionId,
            StunMessage.Lifetime(lifetime <= 0 ? 0 : _options.AllocationTtlSeconds),
            StunMessage.Software(SoftwareName))).ConfigureAwait(false);
    }

    private async Task CreatePermissionAsync(StunMessage request, IPEndPoint remote)
    {
        var allocation = AllocationForRemote(remote);
        if (allocation is null)
        {
            await SendErrorAsync(_primary, remote, request, StunMessage.CreatePermissionError, 437,
                "allocation-mismatch").ConfigureAwait(false);
            return;
        }
        var expiresAt = DateTimeOffset.UtcNow.Add(PermissionTtl);
        foreach (var attribute in request.All(StunMessage.AttrXorPeerAddress))
        {
            var peer = new StunMessage(request.Type, request.TransactionId, [attribute]).XorPeerAddress();
            if (peer is not null)
            {
                allocation.Permissions[PermissionKey(peer)] = expiresAt;
            }
        }
        await SendStunAsync(_primary, remote, StunMessage.Of(
            StunMessage.CreatePermissionSuccess,
            request.TransactionId,
            StunMessage.Software(SoftwareName))).ConfigureAwait(false);
    }

    private async Task SendIndicationAsync(StunMessage request, IPEndPoint remote,
        CancellationToken cancellationToken)
    {
        var allocation = AllocationForRemote(remote);
        if (allocation is null)
        {
            return;
        }
        var peer = request.XorPeerAddress();
        var payload = request.Data();
        if (peer is null || payload is null || !HasPermission(allocation, peer))
        {
            return;
        }
        var header = PeerDataFrameHeader.Parse(payload);
        if (header is not null)
        {
            await using var scope = _scopeFactory.CreateAsyncScope();
            var peerMesh = scope.ServiceProvider.GetRequiredService<PeerMeshService>();
            if (!await peerMesh.AuthorizeRelayFrameAsync(header, payload.Length, cancellationToken)
                    .ConfigureAwait(false))
            {
                return;
            }
        }
        await allocation.Relay.SendAsync(payload, payload.Length, peer).ConfigureAwait(false);
    }

    private async Task RelayReceiveLoopAsync(Allocation allocation, CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested && !allocation.Closed)
        {
            UdpReceiveResult result;
            try
            {
                result = await allocation.Relay.ReceiveAsync(cancellationToken).ConfigureAwait(false);
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
                if (!allocation.Closed)
                {
                    _logger.LogDebug(ex, "[peer-mesh] TURN relay receive failed");
                }
                return;
            }
            if (!HasPermission(allocation, result.RemoteEndPoint))
            {
                continue;
            }
            await DispatchDataIndicationAsync(allocation, result.RemoteEndPoint, result.Buffer).ConfigureAwait(false);
        }
    }

    private async Task DispatchDataIndicationAsync(Allocation allocation, IPEndPoint peer, byte[] payload)
    {
        var tx = StunMessage.NewTransactionId();
        await SendStunAsync(_primary, allocation.Remote, StunMessage.Of(
            StunMessage.DataIndication,
            tx,
            StunMessage.XorPeerAddress(peer, tx),
            StunMessage.Data(payload))).ConfigureAwait(false);
    }

    private Allocation? AllocationForRemote(IPEndPoint remote)
    {
        if (!_allocationByEndpoint.TryGetValue(EndpointKey(remote), out var allocationId)
            || !_allocations.TryGetValue(allocationId, out var allocation)
            || allocation.Closed)
        {
            return null;
        }
        if (IsExpired(allocation))
        {
            CloseAllocation(allocation);
            return null;
        }
        allocation.Remote = remote;
        return allocation;
    }

    private static bool HasPermission(Allocation allocation, IPEndPoint peer) =>
        allocation.Permissions.TryGetValue(PermissionKey(peer), out var expiresAt)
        && expiresAt > DateTimeOffset.UtcNow;

    private static async Task SendStunAsync(UdpClient? socket, IPEndPoint remote, StunMessage response)
    {
        if (socket is null)
        {
            return;
        }
        var bytes = response.ToBytes();
        await socket.SendAsync(bytes, bytes.Length, remote).ConfigureAwait(false);
    }

    private static Task SendErrorAsync(UdpClient? socket, IPEndPoint remote, StunMessage request,
        ushort responseType, int code, string reason) =>
        SendStunAsync(socket, remote, StunMessage.Of(
            responseType,
            request.TransactionId,
            StunMessage.ErrorCode(code, reason),
            StunMessage.Software(SoftwareName)));

    private static ushort ErrorType(ushort requestType) => requestType switch
    {
        StunMessage.BindingRequest => StunMessage.BindingError,
        StunMessage.AllocateRequest => StunMessage.AllocateError,
        StunMessage.RefreshRequest => StunMessage.RefreshError,
        StunMessage.CreatePermissionRequest => StunMessage.CreatePermissionError,
        _ => StunMessage.BindingError,
    };

    private async Task CleanupLoopAsync(CancellationToken cancellationToken)
    {
        using var timer = new PeriodicTimer(TimeSpan.FromSeconds(30));
        try
        {
            while (await timer.WaitForNextTickAsync(cancellationToken).ConfigureAwait(false))
            {
                CleanupExpiredAllocations();
            }
        }
        catch (OperationCanceledException)
        {
            // Normal shutdown.
        }
    }

    private void CleanupExpiredAllocations()
    {
        foreach (var item in _allocations)
        {
            item.Value.Permissions
                .Where(entry => entry.Value <= DateTimeOffset.UtcNow)
                .Select(entry => entry.Key)
                .ToList()
                .ForEach(key => item.Value.Permissions.TryRemove(key, out _));
            if (IsExpired(item.Value))
            {
                CloseAllocation(item.Value);
            }
        }
    }

    private void CloseAllocation(Allocation allocation)
    {
        if (allocation.Closed)
        {
            return;
        }
        allocation.Closed = true;
        _allocations.TryRemove(allocation.Id, out _);
        _allocationByEndpoint.TryRemove(EndpointKey(allocation.Remote), out _);
        allocation.Relay.Dispose();
    }

    private int NatProbeAlternatePort()
    {
        if (_options.NatProbeAlternatePort > 0)
        {
            return _options.NatProbeAlternatePort;
        }
        var next = _options.StunTurnPort + 1;
        return next is > 0 and <= 65535 ? next : 0;
    }

    private IPEndPoint AdvertisedSocketAddress(UdpClient socket)
    {
        var local = socket.Client.LocalEndPoint as IPEndPoint ?? new IPEndPoint(IPAddress.Any, 0);
        return new IPEndPoint(AdvertisedAddress(local), local.Port);
    }

    private IPAddress AdvertisedAddress(IPEndPoint local)
    {
        if (!string.IsNullOrWhiteSpace(_options.PublicAddress))
        {
            var host = _options.PublicAddress.Trim();
            if (IPAddress.TryParse(host, out var configured))
            {
                return configured;
            }
            try
            {
                var resolved = Dns.GetHostAddresses(host)
                    .FirstOrDefault(address => address.AddressFamily is AddressFamily.InterNetwork or AddressFamily.InterNetworkV6);
                if (resolved is not null)
                {
                    return resolved;
                }
            }
            catch (SocketException)
            {
                // Fall through to local address.
            }
        }
        if (!Equals(local.Address, IPAddress.Any) && !Equals(local.Address, IPAddress.IPv6Any))
        {
            return local.Address;
        }
        try
        {
            using var socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
            socket.Connect("8.8.8.8", 80);
            if (socket.LocalEndPoint is IPEndPoint endpoint)
            {
                return endpoint.Address;
            }
        }
        catch (SocketException)
        {
            // Fall through.
        }
        return IPAddress.Loopback;
    }

    private static bool IsExpired(Allocation allocation) => allocation.ExpiresAt <= DateTimeOffset.UtcNow;

    private static string EndpointKey(IPEndPoint endpoint) => $"{endpoint.Address}:{endpoint.Port}";

    private static string PermissionKey(IPEndPoint endpoint) => endpoint.Address.ToString();

    private static (int Min, int Max) RelayPortRange(int min, int max)
    {
        min = min <= 0 ? 49152 : Math.Clamp(min, 1, 65535);
        max = max <= 0 ? 65535 : Math.Clamp(max, 1, 65535);
        return min <= max ? (min, max) : (max, min);
    }

    private sealed class Allocation
    {
        public Allocation(string id, IPEndPoint remote, UdpClient relay, IPEndPoint relayAddress,
            DateTimeOffset expiresAt)
        {
            Id = id;
            Remote = remote;
            Relay = relay;
            RelayAddress = relayAddress;
            ExpiresAt = expiresAt;
        }

        public string Id { get; }
        public IPEndPoint Remote { get; set; }
        public UdpClient Relay { get; }
        public IPEndPoint RelayAddress { get; }
        public DateTimeOffset ExpiresAt { get; set; }
        public ConcurrentDictionary<string, DateTimeOffset> Permissions { get; } = new(StringComparer.Ordinal);
        public bool Closed { get; set; }
    }
}
