using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Extensions.Options;
using ShuaiTunnel.Server.Configuration;

namespace ShuaiTunnel.Server.PeerMesh;

public sealed class StunTurnServer : BackgroundService
{
    private const string RelayMagic = "shuai-peer-relay";
    private const string TypeBinding = "binding";
    private const string TypeBindingResponse = "binding-response";
    private const string TypeAllocate = "allocate";
    private const string TypeAllocated = "allocated";
    private const string TypeRefresh = "refresh";
    private const string TypeSend = "send";
    private const string TypeData = "data";
    private const string TypeError = "error";
    private const string ProbePrimary = "primary";
    private const string ProbeAlternate = "alternate";
    private const string ProbeChangedPort = "changed-port";

    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web)
    {
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingDefault,
    };

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
            _logger.LogWarning(ex, "[peer-mesh] STUN/TURN-lite UDP server failed to start on {Port}", _options.StunTurnPort);
            return;
        }

        var tasks = new List<Task>
        {
            ReceiveLoopAsync(_primary, ProbePrimary, stoppingToken),
            CleanupLoopAsync(stoppingToken),
        };

        var alternatePort = NatProbeAlternatePort();
        if (alternatePort > 0 && alternatePort != _options.StunTurnPort)
        {
            try
            {
                _alternate = new UdpClient(new IPEndPoint(IPAddress.Any, alternatePort));
                tasks.Add(ReceiveLoopAsync(_alternate, ProbeAlternate, stoppingToken));
                _logger.LogInformation("[peer-mesh] NAT probe alternate UDP port listening on {Port}", alternatePort);
            }
            catch (SocketException ex)
            {
                _logger.LogWarning(ex, "[peer-mesh] NAT probe alternate UDP port {Port} unavailable", alternatePort);
            }
        }

        _logger.LogInformation("[peer-mesh] STUN/TURN-lite UDP server listening on {Port}", _options.StunTurnPort);
        await Task.WhenAll(tasks).ConfigureAwait(false);
    }

    public override Task StopAsync(CancellationToken cancellationToken)
    {
        _primary?.Dispose();
        _alternate?.Dispose();
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
                    _logger.LogDebug(ex, "[peer-mesh] STUN/TURN-lite receive failed");
                }
                return;
            }

            try
            {
                await HandleAsync(result.Buffer, result.RemoteEndPoint, socket, probeRole, cancellationToken)
                    .ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is JsonException
                or FormatException
                or SocketException
                or InvalidOperationException)
            {
                _logger.LogDebug(ex, "[peer-mesh] STUN/TURN-lite packet handling failed");
            }
        }
    }

    private async Task HandleAsync(byte[] payload, IPEndPoint remote, UdpClient receiveSocket, string probeRole,
        CancellationToken cancellationToken)
    {
        var message = Encoding.UTF8.GetString(payload).Trim();
        if (message.StartsWith('{'))
        {
            var relay = JsonSerializer.Deserialize<PeerRelayMessage>(message, JsonOptions);
            if (relay?.Magic == RelayMagic)
            {
                await HandleRelayMessageAsync(relay, remote, receiveSocket, probeRole, cancellationToken)
                    .ConfigureAwait(false);
                return;
            }
        }

        var response = message switch
        {
            var value when value.StartsWith("BINDING", StringComparison.OrdinalIgnoreCase) =>
                $"MAPPED {remote.Address} {remote.Port}",
            var value when value.StartsWith("ALLOCATE", StringComparison.OrdinalIgnoreCase) =>
                $"ALLOCATED {Allocate(remote).Id} {_options.AllocationTtlSeconds}",
            var value when value.StartsWith("REFRESH ", StringComparison.OrdinalIgnoreCase) =>
                RefreshText(value["REFRESH ".Length..].Trim(), remote),
            _ => "ERROR unsupported-command",
        };
        await SendTextAsync(receiveSocket, remote, response).ConfigureAwait(false);
    }

    private async Task HandleRelayMessageAsync(PeerRelayMessage message, IPEndPoint remote, UdpClient receiveSocket,
        string probeRole, CancellationToken cancellationToken)
    {
        switch (message.Type)
        {
            case TypeBinding:
                await BindingAsync(message, remote, receiveSocket, probeRole).ConfigureAwait(false);
                break;
            case TypeAllocate:
                await SendRelayResponseAsync(_primary, remote, AllocatedResponse(message, Allocate(remote).Id))
                    .ConfigureAwait(false);
                break;
            case TypeRefresh:
                await RefreshAsync(message, remote).ConfigureAwait(false);
                break;
            case TypeSend:
                await RelayDataAsync(message, remote, cancellationToken).ConfigureAwait(false);
                break;
            default:
                await SendRelayResponseAsync(_primary, remote, Error(message, "unsupported-command"))
                    .ConfigureAwait(false);
                break;
        }
    }

    private async Task BindingAsync(PeerRelayMessage request, IPEndPoint remote, UdpClient receiveSocket,
        string probeRole)
    {
        await SendRelayResponseAsync(receiveSocket, remote, BindingResponse(request, remote, receiveSocket, probeRole))
            .ConfigureAwait(false);
        if (probeRole == ProbePrimary && _alternate is not null)
        {
            await SendRelayResponseAsync(_alternate, remote, BindingResponse(request, remote, _alternate, ProbeChangedPort))
                .ConfigureAwait(false);
        }
    }

    private async Task RefreshAsync(PeerRelayMessage request, IPEndPoint remote)
    {
        if (string.IsNullOrWhiteSpace(request.AllocationId)
            || !_allocations.TryGetValue(request.AllocationId, out var allocation)
            || EndpointKey(allocation.Remote) != EndpointKey(remote))
        {
            await SendRelayResponseAsync(_primary, remote, Error(request, "allocation-not-found"))
                .ConfigureAwait(false);
            return;
        }
        var refreshed = allocation with { Remote = remote, ExpiresAt = DateTimeOffset.UtcNow.AddSeconds(_options.AllocationTtlSeconds) };
        _allocations[allocation.Id] = refreshed;
        _allocationByEndpoint[EndpointKey(remote)] = allocation.Id;
        await SendRelayResponseAsync(_primary, remote, AllocatedResponse(request, allocation.Id)).ConfigureAwait(false);
    }

    private async Task RelayDataAsync(PeerRelayMessage request, IPEndPoint remote, CancellationToken cancellationToken)
    {
        var source = SourceAllocation(request, remote);
        if (source is null)
        {
            await SendRelayResponseAsync(_primary, remote, Error(request, "allocation-not-found"))
                .ConfigureAwait(false);
            return;
        }
        if (string.IsNullOrWhiteSpace(request.ToAllocationId)
            || !_allocations.TryGetValue(request.ToAllocationId, out var target))
        {
            await SendRelayResponseAsync(_primary, remote, Error(request, "target-allocation-not-found"))
                .ConfigureAwait(false);
            return;
        }
        byte[] frame;
        try
        {
            frame = Convert.FromBase64String(request.PayloadBase64 ?? "");
        }
        catch (FormatException)
        {
            await SendRelayResponseAsync(_primary, remote, Error(request, "invalid-payload")).ConfigureAwait(false);
            return;
        }

        var header = PeerDataFrameHeader.Parse(frame);
        if (header is not null)
        {
            await using var scope = _scopeFactory.CreateAsyncScope();
            var peerMesh = scope.ServiceProvider.GetRequiredService<PeerMeshService>();
            if (!await peerMesh.AuthorizeRelayFrameAsync(header, frame.Length, cancellationToken).ConfigureAwait(false))
            {
                await SendRelayResponseAsync(_primary, remote, Error(request, "relay-session-denied"))
                    .ConfigureAwait(false);
                return;
            }
        }

        await SendRelayResponseAsync(_primary, target.Remote, new PeerRelayMessage
        {
            Magic = RelayMagic,
            Type = TypeData,
            TransactionId = request.TransactionId,
            FromAllocationId = source.Id,
            ToAllocationId = target.Id,
            PayloadBase64 = request.PayloadBase64,
        }).ConfigureAwait(false);
    }

    private Allocation Allocate(IPEndPoint remote)
    {
        var endpointKey = EndpointKey(remote);
        if (_allocationByEndpoint.TryGetValue(endpointKey, out var existingId)
            && _allocations.TryGetValue(existingId, out var existing))
        {
            var refreshed = existing with { Remote = remote, ExpiresAt = DateTimeOffset.UtcNow.AddSeconds(_options.AllocationTtlSeconds) };
            _allocations[existing.Id] = refreshed;
            return refreshed;
        }
        var allocation = new Allocation(Guid.NewGuid().ToString(), remote,
            DateTimeOffset.UtcNow.AddSeconds(_options.AllocationTtlSeconds));
        _allocations[allocation.Id] = allocation;
        _allocationByEndpoint[endpointKey] = allocation.Id;
        return allocation;
    }

    private Allocation? SourceAllocation(PeerRelayMessage request, IPEndPoint remote)
    {
        if (!string.IsNullOrWhiteSpace(request.AllocationId)
            && _allocations.TryGetValue(request.AllocationId, out var allocation)
            && EndpointKey(allocation.Remote) == EndpointKey(remote))
        {
            return allocation;
        }
        if (_allocationByEndpoint.TryGetValue(EndpointKey(remote), out var allocationId)
            && _allocations.TryGetValue(allocationId, out allocation))
        {
            return allocation;
        }
        return null;
    }

    private string RefreshText(string allocationId, IPEndPoint remote)
    {
        if (!_allocations.TryGetValue(allocationId, out var allocation)
            || EndpointKey(allocation.Remote) != EndpointKey(remote))
        {
            return "ERROR allocation-not-found";
        }
        _allocations[allocation.Id] = allocation with
        {
            Remote = remote,
            ExpiresAt = DateTimeOffset.UtcNow.AddSeconds(_options.AllocationTtlSeconds),
        };
        _allocationByEndpoint[EndpointKey(remote)] = allocation.Id;
        return $"REFRESHED {allocation.Id} {_options.AllocationTtlSeconds}";
    }

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
            if (!IsExpired(item.Value))
            {
                continue;
            }
            _allocations.TryRemove(item.Key, out _);
            _allocationByEndpoint.TryRemove(EndpointKey(item.Value.Remote), out _);
        }
    }

    private PeerRelayMessage BindingResponse(PeerRelayMessage request, IPEndPoint remote, UdpClient responseSocket,
        string probeRole)
    {
        var response = BaseResponse(request, TypeBindingResponse);
        response.ProbeRole = probeRole;
        response.MappedAddress = remote.Address.ToString();
        response.MappedPort = remote.Port;
        response.ObservedByAddress = AdvertisedAddress(responseSocket);
        response.ObservedByPort = ((IPEndPoint)responseSocket.Client.LocalEndPoint!).Port;
        if (_alternate is not null)
        {
            response.AlternateAddress = AdvertisedAddress(_alternate);
            response.AlternatePort = ((IPEndPoint)_alternate.Client.LocalEndPoint!).Port;
        }
        return response;
    }

    private PeerRelayMessage AllocatedResponse(PeerRelayMessage request, string allocationId)
    {
        var response = BaseResponse(request, TypeAllocated);
        response.AllocationId = allocationId;
        response.TtlSeconds = _options.AllocationTtlSeconds;
        return response;
    }

    private PeerRelayMessage BaseResponse(PeerRelayMessage request, string type) => new()
    {
        Magic = RelayMagic,
        Type = type,
        TransactionId = request.TransactionId,
    };

    private PeerRelayMessage Error(PeerRelayMessage request, string reason)
    {
        var response = BaseResponse(request, TypeError);
        response.Error = reason;
        return response;
    }

    private static async Task SendRelayResponseAsync(UdpClient? socket, IPEndPoint remote, PeerRelayMessage response)
    {
        if (socket is null)
        {
            return;
        }
        var bytes = JsonSerializer.SerializeToUtf8Bytes(response, JsonOptions);
        await socket.SendAsync(bytes, bytes.Length, remote).ConfigureAwait(false);
    }

    private static async Task SendTextAsync(UdpClient socket, IPEndPoint remote, string response)
    {
        var bytes = Encoding.UTF8.GetBytes(response);
        await socket.SendAsync(bytes, bytes.Length, remote).ConfigureAwait(false);
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

    private string AdvertisedAddress(UdpClient socket)
    {
        if (!string.IsNullOrWhiteSpace(_options.PublicAddress))
        {
            return _options.PublicAddress.Trim();
        }
        if (socket.Client.LocalEndPoint is not IPEndPoint local || local.Address.Equals(IPAddress.Any))
        {
            return "";
        }
        return local.Address.ToString();
    }

    private static bool IsExpired(Allocation allocation) => allocation.ExpiresAt <= DateTimeOffset.UtcNow;

    private static string EndpointKey(IPEndPoint endpoint) => $"{endpoint.Address}:{endpoint.Port}";

    private sealed record Allocation(string Id, IPEndPoint Remote, DateTimeOffset ExpiresAt);

    private sealed class PeerRelayMessage
    {
        [JsonPropertyName("magic")]
        public string? Magic { get; init; } = RelayMagic;
        [JsonPropertyName("type")]
        public string? Type { get; init; }
        [JsonPropertyName("transactionId")]
        public string? TransactionId { get; init; }
        [JsonPropertyName("probeRole")]
        public string? ProbeRole { get; set; }
        [JsonPropertyName("allocationId")]
        public string? AllocationId { get; set; }
        [JsonPropertyName("fromAllocationId")]
        public string? FromAllocationId { get; set; }
        [JsonPropertyName("toAllocationId")]
        public string? ToAllocationId { get; set; }
        [JsonPropertyName("mappedAddress")]
        public string? MappedAddress { get; set; }
        [JsonPropertyName("mappedPort")]
        public int MappedPort { get; set; }
        [JsonPropertyName("alternateAddress")]
        public string? AlternateAddress { get; set; }
        [JsonPropertyName("alternatePort")]
        public int AlternatePort { get; set; }
        [JsonPropertyName("observedByAddress")]
        public string? ObservedByAddress { get; set; }
        [JsonPropertyName("observedByPort")]
        public int ObservedByPort { get; set; }
        [JsonPropertyName("ttlSeconds")]
        public long TtlSeconds { get; set; }
        [JsonPropertyName("payloadBase64")]
        public string? PayloadBase64 { get; set; }
        [JsonPropertyName("error")]
        public string? Error { get; set; }
    }
}
