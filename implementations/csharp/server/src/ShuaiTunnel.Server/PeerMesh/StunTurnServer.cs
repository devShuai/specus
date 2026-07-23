using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
	using System.Text.Json;
using System.Threading.Channels;
using Microsoft.Extensions.Options;
using ShuaiTunnel.Server.Configuration;

namespace ShuaiTunnel.Server.PeerMesh;

public sealed class StunTurnServer : BackgroundService
{
    private const string SoftwareName = "shuai-tunnel-standard-stun-turn";
    private static readonly TimeSpan PermissionTtl = TimeSpan.FromSeconds(300);
	private static readonly TimeSpan ChannelTtl = TimeSpan.FromSeconds(600);
	private const int PeerProbeMaxBytes = 2048;
	private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

    private readonly PeerMeshOptions _options;
    private readonly IServiceScopeFactory _scopeFactory;
    private readonly ILogger<StunTurnServer> _logger;
    private readonly TurnCredentialService _turnCredentials;
    private readonly ConcurrentDictionary<string, Allocation> _allocations = new(StringComparer.Ordinal);
    private readonly ConcurrentDictionary<string, string> _allocationByEndpoint = new(StringComparer.Ordinal);
    private readonly ConcurrentDictionary<string, string> _allocationByRelayEndpoint = new(StringComparer.Ordinal);
    private UdpClient? _primary;
    private UdpClient? _alternate;
    private Channel<Func<CancellationToken, Task>>? _relayQueue;

    public StunTurnServer(IOptions<PeerMeshOptions> options, IServiceScopeFactory scopeFactory,
        ILogger<StunTurnServer> logger, TurnCredentialService? turnCredentials = null)
    {
        _options = options.Value;
        _scopeFactory = scopeFactory;
        _logger = logger;
        _turnCredentials = turnCredentials ?? new TurnCredentialService(options);
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

        StartRelayWorkers(stoppingToken);
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
        _relayQueue?.Writer.TryComplete();
        _primary?.Dispose();
        _alternate?.Dispose();
        foreach (var allocation in _allocations.Values)
        {
            CloseAllocation(allocation);
        }
        return base.StopAsync(cancellationToken);
    }

    private void StartRelayWorkers(CancellationToken cancellationToken)
    {
        var workerCount = RelayWorkerCount(_options.RelayWorkerThreads);
        var queueCapacity = Math.Max(1, _options.RelayWorkerQueueCapacity);
        _relayQueue = Channel.CreateBounded<Func<CancellationToken, Task>>(new BoundedChannelOptions(queueCapacity)
        {
            SingleReader = false,
            SingleWriter = false,
            FullMode = BoundedChannelFullMode.Wait,
        });
        for (var i = 0; i < workerCount; i++)
        {
            _ = Task.Run(() => RelayWorkerLoopAsync(cancellationToken), CancellationToken.None);
        }
    }

    private async Task RelayWorkerLoopAsync(CancellationToken cancellationToken)
    {
        var reader = _relayQueue?.Reader;
        if (reader is null)
        {
            return;
        }
        try
        {
            while (!cancellationToken.IsCancellationRequested
                   && await reader.WaitToReadAsync(cancellationToken).ConfigureAwait(false))
            {
                while (reader.TryRead(out var task))
                {
                    try
                    {
                        await task(cancellationToken).ConfigureAwait(false);
                    }
                    catch (Exception ex) when (ex is SocketException or ObjectDisposedException or OperationCanceledException)
                    {
                        if (!cancellationToken.IsCancellationRequested)
                        {
                            _logger.LogDebug(ex, "[peer-mesh] TURN data indication failed");
                        }
                    }
                }
            }
        }
        catch (OperationCanceledException)
        {
            // Normal shutdown.
        }
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
		if (TurnChannelData.LooksLike(payload))
		{
			await HandleChannelDataAsync(payload, remote, cancellationToken).ConfigureAwait(false);
			return;
		}
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
                await AllocateRequestAuthenticatedAsync(message, payload, remote, cancellationToken)
                    .ConfigureAwait(false);
                break;
            case StunMessage.RefreshRequest:
                await RefreshAuthenticatedAsync(message, payload, remote).ConfigureAwait(false);
                break;
            case StunMessage.CreatePermissionRequest:
                await CreatePermissionAuthenticatedAsync(message, payload, remote).ConfigureAwait(false);
                break;
			case StunMessage.ChannelBindRequest:
				await ChannelBindAuthenticatedAsync(message, payload, remote).ConfigureAwait(false);
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
        => await AllocateRequestCoreAsync(request, remote, null, 0, false, cancellationToken).ConfigureAwait(false);

    private async Task AllocateRequestAuthenticatedAsync(StunMessage request, byte[] packet, IPEndPoint remote,
        CancellationToken cancellationToken)
    {
        var auth = await AuthenticateAsync(request, packet, remote, StunMessage.AllocateError)
            .ConfigureAwait(false);
        if (!auth.Allowed)
        {
            return;
        }
        if (auth.GeneralRelay)
        {
            var rejection = GeneralRelayQuotaRejection(remote);
            if (rejection is not null)
            {
                // Audit: general relay is driven by a public ICE config, rejections must be traceable.
                _logger.LogWarning("[peer-mesh][audit] general TURN allocation rejected: client={Client}, reason={Reason}",
                    remote, rejection);
                await SendErrorAsync(_primary, remote, request, StunMessage.AllocateError, 486, rejection)
                    .ConfigureAwait(false);
                return;
            }
        }
        await AllocateRequestCoreAsync(
                request, remote, auth.MessageIntegrityKey, auth.ClientId, auth.GeneralRelay, cancellationToken)
            .ConfigureAwait(false);
    }

    private async Task AllocateRequestCoreAsync(StunMessage request, IPEndPoint remote,
        byte[]? messageIntegrityKey, long clientId, bool generalRelay, CancellationToken cancellationToken)
    {
        if (!request.RequestedUdpTransport())
        {
            await SendErrorAsync(_primary, remote, request, StunMessage.AllocateError, 442, "unsupported-transport")
                .ConfigureAwait(false);
            return;
        }
        var allocation = AllocateForClient(remote, clientId, generalRelay, cancellationToken);
        await SendStunAsync(_primary, remote, StunMessage.Of(
            StunMessage.AllocateSuccess,
            request.TransactionId,
            StunMessage.XorRelayedAddress(allocation.RelayAddress, request.TransactionId),
            StunMessage.XorMappedAddress(remote, request.TransactionId),
            StunMessage.Lifetime(_options.AllocationTtlSeconds),
            StunMessage.Software(SoftwareName)), messageIntegrityKey).ConfigureAwait(false);
    }

    private Allocation Allocate(IPEndPoint remote, CancellationToken cancellationToken = default)
        => AllocateForClient(remote, 0, false, cancellationToken);

    private Allocation AllocateForClient(IPEndPoint remote, long clientId, bool generalRelay,
        CancellationToken cancellationToken = default)
    {
        var endpointKey = EndpointKey(remote);
        if (_allocationByEndpoint.TryGetValue(endpointKey, out var existingId)
            && _allocations.TryGetValue(existingId, out var existing)
            && !existing.Closed)
        {
            if (!IsExpired(existing) && existing.ClientId == clientId
                && existing.GeneralRelay == generalRelay)
            {
                existing.Remote = remote;
                existing.ExpiresAt = DateTimeOffset.UtcNow.AddSeconds(_options.AllocationTtlSeconds);
                return existing;
            }
            CloseAllocation(existing);
        }

        var relay = BindRelaySocket();
        var allocation = new Allocation(Guid.NewGuid().ToString(), remote, relay,
            AdvertisedSocketAddress(relay), DateTimeOffset.UtcNow.AddSeconds(_options.AllocationTtlSeconds),
            clientId)
        {
            GeneralRelay = generalRelay,
        };
        _allocations[allocation.Id] = allocation;
        _allocationByEndpoint[endpointKey] = allocation.Id;
        _allocationByRelayEndpoint[EndpointKey(allocation.RelayAddress)] = allocation.Id;
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
        => await RefreshCoreAsync(request, remote, null, 0).ConfigureAwait(false);

    private async Task RefreshAuthenticatedAsync(StunMessage request, byte[] packet, IPEndPoint remote)
    {
        var auth = await AuthenticateAsync(request, packet, remote, StunMessage.RefreshError)
            .ConfigureAwait(false);
        if (!auth.Allowed)
        {
            return;
        }
        await RefreshCoreAsync(request, remote, auth.MessageIntegrityKey, auth.ClientId).ConfigureAwait(false);
    }

    private async Task RefreshCoreAsync(StunMessage request, IPEndPoint remote,
        byte[]? messageIntegrityKey, long clientId)
    {
        var allocation = AllocationForRemote(remote);
        if (allocation is null || allocation.ClientId != clientId)
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
            StunMessage.Software(SoftwareName)), messageIntegrityKey).ConfigureAwait(false);
    }

    private async Task CreatePermissionAsync(StunMessage request, IPEndPoint remote)
        => await CreatePermissionCoreAsync(request, remote, null, 0).ConfigureAwait(false);

    private async Task CreatePermissionAuthenticatedAsync(StunMessage request, byte[] packet, IPEndPoint remote)
    {
        var auth = await AuthenticateAsync(request, packet, remote, StunMessage.CreatePermissionError)
            .ConfigureAwait(false);
        if (!auth.Allowed)
        {
            return;
        }
        await CreatePermissionCoreAsync(
                request, remote, auth.MessageIntegrityKey, auth.ClientId)
            .ConfigureAwait(false);
    }

    private async Task CreatePermissionCoreAsync(StunMessage request, IPEndPoint remote,
        byte[]? messageIntegrityKey, long clientId)
    {
        var allocation = AllocationForRemote(remote);
        if (allocation is null || allocation.ClientId != clientId)
        {
            await SendErrorAsync(_primary, remote, request, StunMessage.CreatePermissionError, 437,
                "allocation-mismatch").ConfigureAwait(false);
            return;
        }
        var expiresAt = DateTimeOffset.UtcNow.Add(PermissionTtl);
        foreach (var attribute in request.All(StunMessage.AttrXorPeerAddress))
        {
            var peer = new StunMessage(request.Type, request.TransactionId, [attribute]).XorPeerAddress();
            if (peer is null)
            {
                continue;
            }
            if (allocation.GeneralRelay && !IsRelayableDestination(peer))
            {
                _logger.LogWarning("[peer-mesh][audit] general TURN permission refused: client={Client}, peer={Peer}",
                    remote, peer);
                await SendErrorAsync(_primary, remote, request, StunMessage.CreatePermissionError, 403,
                    "forbidden-peer-address").ConfigureAwait(false);
                return;
            }
            allocation.Permissions[PermissionKey(peer)] = expiresAt;
        }
        await SendStunAsync(_primary, remote, StunMessage.Of(
            StunMessage.CreatePermissionSuccess,
            request.TransactionId,
            StunMessage.Software(SoftwareName)), messageIntegrityKey).ConfigureAwait(false);
    }

	private async Task ChannelBindAuthenticatedAsync(StunMessage request, byte[] packet, IPEndPoint remote)
	{
		var auth = await AuthenticateAsync(request, packet, remote, StunMessage.ChannelBindError)
			.ConfigureAwait(false);
		if (!auth.Allowed)
		{
			return;
		}
		var allocation = AllocationForRemote(remote);
		if (allocation is null || allocation.ClientId != auth.ClientId)
		{
			await SendErrorAsync(_primary, remote, request, StunMessage.ChannelBindError, 437,
				"allocation-mismatch").ConfigureAwait(false);
			return;
		}
		var channel = request.ChannelNumber();
		var peer = request.XorPeerAddress();
		if (channel is null || peer is null)
		{
			await SendErrorAsync(_primary, remote, request, StunMessage.ChannelBindError, 400,
				"invalid-channel-bind").ConfigureAwait(false);
			return;
		}
		if (allocation.GeneralRelay && !IsRelayableDestination(peer))
		{
			// ChannelBind implicitly creates a permission, so it needs the same destination policy.
			_logger.LogWarning("[peer-mesh][audit] general TURN channel bind refused: client={Client}, peer={Peer}",
				remote, peer);
			await SendErrorAsync(_primary, remote, request, StunMessage.ChannelBindError, 403,
				"forbidden-peer-address").ConfigureAwait(false);
			return;
		}
		var now = DateTimeOffset.UtcNow;
		if (allocation.ChannelsByNumber.TryGetValue(channel.Value, out var occupied)
			&& occupied.ExpiresAt > now && !SameEndpoint(occupied.Peer, peer))
		{
			await SendErrorAsync(_primary, remote, request, StunMessage.ChannelBindError, 400,
				"channel-in-use").ConfigureAwait(false);
			return;
		}
		var binding = new TurnChannelBinding(channel.Value, peer, now.Add(ChannelTtl));
		if (allocation.ChannelsByPeer.TryGetValue(EndpointKey(peer), out var previous)
			&& previous.Channel != channel.Value)
		{
			allocation.ChannelsByNumber.TryRemove(previous.Channel, out _);
		}
		allocation.ChannelsByNumber[channel.Value] = binding;
		allocation.ChannelsByPeer[EndpointKey(peer)] = binding;
		allocation.Permissions[PermissionKey(peer)] = now.Add(PermissionTtl);
		await SendStunAsync(_primary, remote, StunMessage.Of(
			StunMessage.ChannelBindSuccess,
			request.TransactionId,
			StunMessage.Software(SoftwareName)), auth.MessageIntegrityKey).ConfigureAwait(false);
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
		var target = AllocationForRelayEndpoint(peer);
		if (!AllowGeneralRelayTraffic(allocation, payload.Length))
		{
			return;
		}
		if (!await AuthorizeRelayPayloadAsync(
                payload, allocation, target, true, cancellationToken).ConfigureAwait(false))
		{
			return;
		}
        await allocation.Relay.SendAsync(payload, payload.Length, peer).ConfigureAwait(false);
    }

	private async Task HandleChannelDataAsync(byte[] packet, IPEndPoint remote,
		CancellationToken cancellationToken)
	{
		var frame = TurnChannelData.Parse(packet);
		var allocation = AllocationForRemote(remote);
		if (frame is null || allocation is null
			|| !allocation.ChannelsByNumber.TryGetValue(frame.Channel, out var binding)
			|| binding.ExpiresAt <= DateTimeOffset.UtcNow
			|| !HasPermission(allocation, binding.Peer))
		{
			return;
		}
		var target = AllocationForRelayEndpoint(binding.Peer);
		if (!AllowGeneralRelayTraffic(allocation, frame.Payload.Length))
		{
			return;
		}
		if (!await AuthorizeRelayPayloadAsync(
                frame.Payload, allocation, target, true, cancellationToken).ConfigureAwait(false))
		{
			return;
		}
		await allocation.Relay.SendAsync(frame.Payload, binding.Peer, cancellationToken).ConfigureAwait(false);
	}

    /// <summary>
    /// General relay admission quota. Returns a non-null reason when the request must be refused.
    /// </summary>
    private string? GeneralRelayQuotaRejection(IPEndPoint remote)
    {
        if (_options.GeneralRelayMaxAllocations <= 0)
        {
            return "general-relay-disabled";
        }
        var existingId = _allocationByEndpoint.TryGetValue(EndpointKey(remote), out var id) ? id : null;
        var total = 0;
        var sameAddress = 0;
        foreach (var (allocationId, item) in _allocations)
        {
            if (item.Closed || !item.GeneralRelay || string.Equals(allocationId, existingId, StringComparison.Ordinal))
            {
                continue;
            }
            total++;
            if (item.Remote.Address.Equals(remote.Address))
            {
                sameAddress++;
            }
        }
        if (total >= _options.GeneralRelayMaxAllocations)
        {
            return "general-relay-allocation-quota";
        }
        if (_options.GeneralRelayMaxAllocationsPerAddress > 0
            && sameAddress >= _options.GeneralRelayMaxAllocationsPerAddress)
        {
            return "general-relay-address-quota";
        }
        return null;
    }

    /// <summary>
    /// Per-allocation lifetime byte cap. Peer Mesh allocations are exempt.
    ///
    /// There is deliberately no packet-level rate limiting. TURN carries the browser's
    /// SCTP-over-DTLS (reliable transport); dropping packets to shape the rate wrecks SCTP
    /// congestion control and retransmission, which was the root cause of "web transfer relay
    /// file send fails". Abuse is bounded by admission (allocation count / per-address) and total
    /// volume: once an allocation exceeds max-bytes it is closed so SCTP fails cleanly instead of
    /// being dragged into loss.
    /// </summary>
    private bool AllowGeneralRelayTraffic(Allocation allocation, int bytes)
    {
        if (!allocation.GeneralRelay)
        {
            return true;
        }
        var total = Interlocked.Add(ref allocation.RelayedBytes, bytes);
        if (_options.GeneralRelayMaxBytes > 0 && total > _options.GeneralRelayMaxBytes)
        {
            if (Interlocked.Exchange(ref allocation.QuotaLogged, 1) == 0)
            {
                _logger.LogWarning("[peer-mesh][audit] general TURN byte quota exhausted, closing allocation: client={Client}, bytes={Bytes}",
                    allocation.Remote, total);
                CloseAllocation(allocation);
            }
            return false;
        }
        return true;
    }

    /// <summary>
    /// Restricts general relay destinations to public unicast addresses so the relay cannot be
    /// used as a jump host into the server's private network. Peer Mesh mode is exempt: local and
    /// private deployments legitimately use loopback and site-local relay addresses.
    /// </summary>
    internal static bool IsRelayableDestination(IPEndPoint? address)
    {
        if (address is null || address.Port <= 0)
        {
            return false;
        }
        var ip = address.Address;
        if (IPAddress.Any.Equals(ip) || IPAddress.IPv6Any.Equals(ip)
            || IPAddress.IsLoopback(ip) || ip.IsIPv6LinkLocal || ip.IsIPv6Multicast)
        {
            return false;
        }
        if (ip.AddressFamily == AddressFamily.InterNetwork)
        {
            var raw = ip.GetAddressBytes();
            // Note: 100.64.0.0/10 is deliberately allowed. It is RFC 6598 carrier-grade NAT; many
            // home and mobile users' public srflx addresses fall in it, and rejecting the whole
            // block would 403 those peers. General relay peers are the browser's real public
            // address, never a mesh virtual IP (which only exists inside the overlay).
            return raw[0] switch
            {
                10 => false,
                127 => false,
                169 when raw[1] == 254 => false,
                172 when raw[1] >= 16 && raw[1] <= 31 => false,
                192 when raw[1] == 168 => false,
                >= 224 => false,
                _ => true,
            };
        }
        var v6 = ip.GetAddressBytes();
        // IPv6 ULA fc00::/7
        return (v6[0] & 0xFE) != 0xFC;
    }

	private async Task<bool> AuthorizeRelayPayloadAsync(byte[] payload,
        Allocation? source, Allocation? target, bool account,
		CancellationToken cancellationToken)
	{
		// General TURN mode (public transfer): the payload is DTLS/SRTP/SCTP or a STUN
		// connectivity check, none of which can pass the Peer Mesh specific checks. Identity was
		// verified at Allocate, the destination at CreatePermission/ChannelBind, and the caller
		// already confirmed the permission. Outbound the local allocation is source, inbound target.
		if (source?.GeneralRelay == true || target?.GeneralRelay == true)
		{
			return true;
		}
		if (source is null || target is null)
		{
			return false;
		}
		var identified = _turnCredentials.AuthRequired;
		if (identified && (source.ClientId <= 0 || target.ClientId <= 0))
		{
			return false;
		}
		var sourceClientId = identified ? source.ClientId : 0L;
		var targetClientId = identified ? target.ClientId : 0L;
		var header = PeerDataFrameHeader.Parse(payload);
		if (header is not null)
		{
			await using var frameScope = _scopeFactory.CreateAsyncScope();
			var framePeerMesh = frameScope.ServiceProvider.GetRequiredService<PeerMeshService>();
			return account
				? await framePeerMesh.AuthorizeRelayFrameAsync(
                    header, sourceClientId, targetClientId, payload.Length, cancellationToken).ConfigureAwait(false)
				: await framePeerMesh.ValidateRelayFrameAsync(
                    header, sourceClientId, targetClientId, cancellationToken).ConfigureAwait(false);
		}
		if (payload.Length is < 2 or > PeerProbeMaxBytes || payload[0] != (byte)'{' || payload[^1] != (byte)'}')
		{
			return false;
		}
		RelayProbe? probe;
		try
		{
			probe = JsonSerializer.Deserialize<RelayProbe>(payload, JsonOptions);
		}
		catch (JsonException)
		{
			return false;
		}
		await using var probeScope = _scopeFactory.CreateAsyncScope();
		var peerMesh = probeScope.ServiceProvider.GetRequiredService<PeerMeshService>();
		return probe?.Magic == "shuai-peer-mesh"
			&& (!identified || (probe.FromClientId == sourceClientId && probe.ToClientId == targetClientId))
			&& await peerMesh.AuthorizeRelayProbeAsync(probe.SessionId, probe.FromClientId, probe.ToClientId,
				probe.Token, probe.Type, cancellationToken).ConfigureAwait(false);
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
			var source = AllocationForRelayEndpoint(result.RemoteEndPoint);
			if (!AllowGeneralRelayTraffic(allocation, result.Buffer.Length))
			{
				continue;
			}
			if (!await AuthorizeRelayPayloadAsync(
                    result.Buffer, source, allocation, false, cancellationToken).ConfigureAwait(false))
			{
				continue;
			}
            await DispatchDataIndicationAsync(allocation, result.RemoteEndPoint, result.Buffer).ConfigureAwait(false);
        }
    }

    private Task DispatchDataIndicationAsync(Allocation allocation, IPEndPoint peer, byte[] payload)
    {
        Func<CancellationToken, Task> task = token => SendDataIndicationAsync(allocation, peer, payload, token);
        var queue = _relayQueue;
        if (queue is null)
        {
            return task(CancellationToken.None);
        }
        if (!queue.Writer.TryWrite(task))
        {
            _logger.LogDebug("[peer-mesh] TURN data indication dropped");
        }
        return Task.CompletedTask;
    }

    private async Task SendDataIndicationAsync(Allocation allocation, IPEndPoint peer, byte[] payload,
        CancellationToken cancellationToken)
    {
        if (cancellationToken.IsCancellationRequested)
        {
            return;
        }
		if (allocation.ChannelsByPeer.TryGetValue(EndpointKey(peer), out var binding)
			&& binding.ExpiresAt > DateTimeOffset.UtcNow)
		{
			var channelData = TurnChannelData.Encode(binding.Channel, payload);
			if (_primary is not null)
			{
				await _primary.SendAsync(channelData, allocation.Remote, cancellationToken).ConfigureAwait(false);
			}
			return;
		}
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

    private Allocation? AllocationForRelayEndpoint(IPEndPoint? remote)
    {
        if (remote is null)
        {
            return null;
        }
        if (_allocationByRelayEndpoint.TryGetValue(EndpointKey(remote), out var allocationId)
            && _allocations.TryGetValue(allocationId, out var exact)
            && !exact.Closed && !IsExpired(exact))
        {
            return exact;
        }
        return _allocations.Values.FirstOrDefault(candidate =>
            !candidate.Closed && !IsExpired(candidate) && candidate.RelayAddress.Port == remote.Port);
    }

    private static bool HasPermission(Allocation allocation, IPEndPoint peer) =>
        allocation.Permissions.TryGetValue(PermissionKey(peer), out var expiresAt)
        && expiresAt > DateTimeOffset.UtcNow;

    private static async Task SendStunAsync(UdpClient? socket, IPEndPoint remote, StunMessage response)
        => await SendStunAsync(socket, remote, response, null).ConfigureAwait(false);

    private static async Task SendStunAsync(UdpClient? socket, IPEndPoint remote, StunMessage response,
        byte[]? messageIntegrityKey)
    {
        if (socket is null)
        {
            return;
        }
        var bytes = response.ToBytes(messageIntegrityKey);
        await socket.SendAsync(bytes, bytes.Length, remote).ConfigureAwait(false);
    }

    private static Task SendErrorAsync(UdpClient? socket, IPEndPoint remote, StunMessage request,
        ushort responseType, int code, string reason, params StunAttribute[] attributes)
    {
        var responseAttributes = new List<StunAttribute>
        {
            StunMessage.ErrorCode(code, reason),
            StunMessage.Software(SoftwareName),
        };
        responseAttributes.AddRange(attributes);
        return SendStunAsync(socket, remote,
            new StunMessage(responseType, request.TransactionId, responseAttributes));
    }

    private async Task<TurnAuth> AuthenticateAsync(StunMessage request, byte[] packet, IPEndPoint remote,
        ushort responseType)
    {
        if (!_turnCredentials.AuthRequired)
        {
            return TurnAuth.NoAuthentication;
        }
        var username = request.UsernameValue()?.Trim() ?? string.Empty;
        var realm = request.RealmValue()?.Trim() ?? string.Empty;
        var nonce = request.NonceValue()?.Trim() ?? string.Empty;
        if (!string.Equals(_turnCredentials.Realm, realm, StringComparison.Ordinal)
            || username.Length == 0 || nonce.Length == 0)
        {
            await SendTurnAuthErrorAsync(remote, request, responseType, 401, "unauthorized")
                .ConfigureAwait(false);
            return TurnAuth.Denied;
        }
        if (!string.Equals(_turnCredentials.Nonce, nonce, StringComparison.Ordinal))
        {
            await SendTurnAuthErrorAsync(remote, request, responseType, 438, "stale-nonce")
                .ConfigureAwait(false);
            return TurnAuth.Denied;
        }
        var credential = _turnCredentials.CredentialForUsername(username);
        if (!_turnCredentials.UsernameCredentialValid(username, credential))
        {
            await SendTurnAuthErrorAsync(remote, request, responseType, 401, "unauthorized")
                .ConfigureAwait(false);
            return TurnAuth.Denied;
        }
        var key = _turnCredentials.LongTermKey(username, credential);
        if (!StunMessage.VerifyMessageIntegrity(packet, key))
        {
            await SendTurnAuthErrorAsync(remote, request, responseType, 401, "bad-message-integrity")
                .ConfigureAwait(false);
            return TurnAuth.Denied;
        }
        return new TurnAuth(true, key, _turnCredentials.PeerMeshClientId(username),
            _turnCredentials.IsGeneralRelaySubject(username));
    }

    private Task SendTurnAuthErrorAsync(IPEndPoint remote, StunMessage request, ushort responseType,
        int code, string reason) => SendErrorAsync(_primary, remote, request, responseType, code, reason,
        StunMessage.Realm(_turnCredentials.Realm), StunMessage.Nonce(_turnCredentials.Nonce));

    private static ushort ErrorType(ushort requestType) => requestType switch
    {
        StunMessage.BindingRequest => StunMessage.BindingError,
        StunMessage.AllocateRequest => StunMessage.AllocateError,
        StunMessage.RefreshRequest => StunMessage.RefreshError,
        StunMessage.CreatePermissionRequest => StunMessage.CreatePermissionError,
		StunMessage.ChannelBindRequest => StunMessage.ChannelBindError,
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
			foreach (var binding in item.Value.ChannelsByNumber.Values
				.Where(binding => binding.ExpiresAt <= DateTimeOffset.UtcNow).ToList())
			{
				item.Value.ChannelsByNumber.TryRemove(binding.Channel, out _);
				item.Value.ChannelsByPeer.TryRemove(EndpointKey(binding.Peer), out _);
			}
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
        _allocationByRelayEndpoint.TryRemove(EndpointKey(allocation.RelayAddress), out _);
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

	private static bool SameEndpoint(IPEndPoint? first, IPEndPoint? second) =>
		first is not null && second is not null && first.Port == second.Port && first.Address.Equals(second.Address);

    private static string PermissionKey(IPEndPoint endpoint) => endpoint.Address.ToString();

    private static int RelayWorkerCount(int configured)
    {
        if (configured > 0)
        {
            return configured;
        }
        return Math.Max(2, Math.Min(8, Environment.ProcessorCount));
    }

    private static (int Min, int Max) RelayPortRange(int min, int max)
    {
        min = min <= 0 ? 49152 : Math.Clamp(min, 1, 65535);
        max = max <= 0 ? 65535 : Math.Clamp(max, 1, 65535);
        return min <= max ? (min, max) : (max, min);
    }

    private sealed class Allocation
    {
        public Allocation(string id, IPEndPoint remote, UdpClient relay, IPEndPoint relayAddress,
            DateTimeOffset expiresAt, long clientId)
        {
            Id = id;
            Remote = remote;
            Relay = relay;
            RelayAddress = relayAddress;
            ExpiresAt = expiresAt;
            ClientId = clientId;
        }

        public string Id { get; }
        public IPEndPoint Remote { get; set; }
        public UdpClient Relay { get; }
        public IPEndPoint RelayAddress { get; }
        public long ClientId { get; }
        /// <summary>Forwards arbitrary payloads with standard TURN semantics (public transfer).</summary>
        public bool GeneralRelay { get; init; }
        public long RelayedBytes;
        public int QuotaLogged;
        public DateTimeOffset ExpiresAt { get; set; }
        public ConcurrentDictionary<string, DateTimeOffset> Permissions { get; } = new(StringComparer.Ordinal);
		public ConcurrentDictionary<ushort, TurnChannelBinding> ChannelsByNumber { get; } = new();
		public ConcurrentDictionary<string, TurnChannelBinding> ChannelsByPeer { get; } = new(StringComparer.Ordinal);
        public bool Closed { get; set; }
    }

	private sealed record TurnChannelBinding(ushort Channel, IPEndPoint Peer, DateTimeOffset ExpiresAt);
	private sealed record RelayProbe(string? Magic, string? Type, long SessionId, long FromClientId,
		long ToClientId, string? Token);

    private sealed record TurnAuth(bool Allowed, byte[]? MessageIntegrityKey, long ClientId,
        bool GeneralRelay = false)
    {
        public static TurnAuth Denied { get; } = new(false, null, 0);
        public static TurnAuth NoAuthentication { get; } = new(true, null, 0);
    }
}
