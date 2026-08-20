using System.Net;
using System.Net.Sockets;
using System.Collections.Concurrent;
using Microsoft.Extensions.Logging;
using Specus.Client.Configuration;

namespace Specus.Client.PeerMesh;

internal sealed class PeerServiceUdpBridge : IPeerServiceForwarder
{
    private readonly string _virtualIp;
    private readonly LocalPeerService _service;
    private readonly IPAddress _targetAddress;
    private readonly UdpClient _inbound;
    private readonly CancellationTokenSource _cts = new();
    private readonly ILogger? _logger;
    private readonly ConcurrentDictionary<string, UdpPeer> _peers = new(StringComparer.Ordinal);
    private readonly ConcurrentDictionary<string, byte> _auditedAccessEvents = new(StringComparer.Ordinal);
    private readonly SemaphoreSlim _slots = new(PeerServiceResourceLimiter.MaxUdpPerService,
        PeerServiceResourceLimiter.MaxUdpPerService);
    private long _bytesIn;
    private long _bytesOut;
    private long _totalConnections;
    private int _active;
    private int _disposed;

    private PeerServiceUdpBridge(string virtualIp, LocalPeerService service, IPAddress targetAddress,
        UdpClient inbound, ILogger? logger)
    {
        _virtualIp = virtualIp;
        _service = service;
        _targetAddress = targetAddress;
        _inbound = inbound;
        _logger = logger;
        _ = AcceptLoopAsync();
    }

    public static PeerServiceUdpBridge Bind(string virtualIp, LocalPeerService service, ILogger? logger)
    {
        if (!PeerServiceDiscovery.TryResolveLocalInterfaceTarget(service.TargetHost, out var targetAddress))
        {
            throw new InvalidOperationException("targetHost is not assigned to this device");
        }
        var inbound = new UdpClient(new IPEndPoint(IPAddress.Parse(virtualIp), service.PublishedPort));
        inbound.Client.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
        return new PeerServiceUdpBridge(virtualIp, service, targetAddress, inbound, logger);
    }

    public string ServiceId => _service.ServiceId;

    public (long BytesIn, long BytesOut, int Active, long Total) Snapshot() =>
        (Interlocked.Read(ref _bytesIn), Interlocked.Read(ref _bytesOut), _active, Interlocked.Read(ref _totalConnections));

    public bool Matches(string virtualIp, LocalPeerService service) =>
        _virtualIp == virtualIp
        && _service.ServiceId == service.ServiceId
        && _service.PublishedPort == service.PublishedPort
        && _service.TargetHost == service.TargetHost
        && _service.TargetPort == service.TargetPort
        && PeerServiceDiscovery.SameAllowedPeers(_service, service);

    private async Task AcceptLoopAsync()
    {
        var target = new IPEndPoint(_targetAddress, _service.TargetPort);
        while (!_cts.IsCancellationRequested)
        {
            UdpReceiveResult packet;
            try
            {
                packet = await _inbound.ReceiveAsync(_cts.Token).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                return;
            }
            catch (Exception ex)
            {
                _logger?.LogDebug(ex, "Peer-only UDP 桥接结束 service={ServiceId}", _service.ServiceId);
                return;
            }
            if (!PeerServiceDiscovery.IsSourceAllowed(packet.RemoteEndPoint.Address, _service))
            {
                AuditAccessOnce("deny", packet.RemoteEndPoint, "source-not-allowed");
                continue;
            }
            Interlocked.Add(ref _bytesIn, packet.Buffer.Length);
            var key = packet.RemoteEndPoint.ToString();
            if (!_peers.TryGetValue(key, out var binding))
            {
                if (!_slots.Wait(0))
                {
                    continue;
                }
                var lease = PeerServiceResourceLimiter.TryAcquireUdp(packet.RemoteEndPoint.Address);
                if (lease is null)
                {
                    _slots.Release();
                    continue;
                }
                UdpClient? outbound = null;
                try
                {
                    outbound = new UdpClient();
                    outbound.Connect(target);
                    binding = new UdpPeer(outbound, lease, _slots);
                }
                catch
                {
                    outbound?.Dispose();
                    lease.Dispose();
                    _slots.Release();
                    continue;
                }
                if (!_peers.TryAdd(key, binding))
                {
                    binding.Dispose();
                    if (!_peers.TryGetValue(key, out binding))
                    {
                        continue;
                    }
                }
                else
                {
                    AuditAccessOnce("allow", packet.RemoteEndPoint, "acl-authorized");
                    Interlocked.Increment(ref _totalConnections);
                    Interlocked.Increment(ref _active);
                    _ = ReplyLoopAsync(key, binding, packet.RemoteEndPoint);
                }
            }
            binding.Touch();
            try
            {
                await binding.Client.SendAsync(packet.Buffer, packet.Buffer.Length).ConfigureAwait(false);
            }
            catch
            {
                // next packet retries
            }
        }
    }

    private void AuditAccessOnce(string action, EndPoint source, string reason)
    {
        var sourceAddress = source.ToString() ?? "unknown";
        var key = $"{action}|{sourceAddress}";
        if (_auditedAccessEvents.Count < 128 && _auditedAccessEvents.TryAdd(key, 0))
        {
            _logger?.LogInformation(
                "[peer-service-access-audit] action={Action} serviceId={ServiceId} source={Source} reason={Reason}",
                action, _service.ServiceId, sourceAddress, reason);
        }
    }

    private async Task ReplyLoopAsync(string key, UdpPeer binding, IPEndPoint peer)
    {
        try
        {
            while (!_cts.IsCancellationRequested)
            {
                var receive = binding.Client.ReceiveAsync(_cts.Token).AsTask();
                var completed = await Task.WhenAny(receive, Task.Delay(TimeSpan.FromSeconds(60), _cts.Token))
                    .ConfigureAwait(false);
                if (completed != receive || DateTimeOffset.UtcNow - binding.LastSeen > TimeSpan.FromSeconds(60))
                {
                    return;
                }
                var packet = await receive.ConfigureAwait(false);
                Interlocked.Add(ref _bytesOut, packet.Buffer.Length);
                await _inbound.SendAsync(packet.Buffer, packet.Buffer.Length, peer).ConfigureAwait(false);
            }
        }
        catch
        {
            // peer mapping ends
        }
        finally
        {
            _peers.TryRemove(new KeyValuePair<string, UdpPeer>(key, binding));
            Interlocked.Decrement(ref _active);
            binding.Dispose();
        }
    }

    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }
        _logger?.LogInformation(
            "[peer-service-access-audit] action=revoke serviceId={ServiceId} activePeers={ActivePeers} reason=config-withdrawn-or-shutdown",
            _service.ServiceId, _peers.Count);
        _cts.Cancel();
        _inbound.Dispose();
        foreach (var peer in _peers.Values)
        {
            peer.Dispose();
        }
        _peers.Clear();
        _cts.Dispose();
    }

    private sealed class UdpPeer(UdpClient client, PeerServiceResourceLimiter.Lease lease,
        SemaphoreSlim serviceSlots) : IDisposable
    {
        private long _lastSeen = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        public UdpClient Client { get; } = client;
        public DateTimeOffset LastSeen => DateTimeOffset.FromUnixTimeMilliseconds(Interlocked.Read(ref _lastSeen));
        public void Touch() => Interlocked.Exchange(ref _lastSeen, DateTimeOffset.UtcNow.ToUnixTimeMilliseconds());

        private int _disposed;
        public void Dispose()
        {
            if (Interlocked.Exchange(ref _disposed, 1) != 0)
            {
                return;
            }
            Client.Dispose();
            lease.Dispose();
            serviceSlots.Release();
        }
    }
}
