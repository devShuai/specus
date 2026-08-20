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
    private readonly UdpClient _inbound;
    private readonly CancellationTokenSource _cts = new();
    private readonly ILogger? _logger;
    private readonly ConcurrentDictionary<string, UdpPeer> _peers = new(StringComparer.Ordinal);
    private long _bytesIn;
    private long _bytesOut;
    private long _totalConnections;
    private int _active;

    private PeerServiceUdpBridge(string virtualIp, LocalPeerService service, UdpClient inbound, ILogger? logger)
    {
        _virtualIp = virtualIp;
        _service = service;
        _inbound = inbound;
        _logger = logger;
        _ = AcceptLoopAsync();
    }

    public static PeerServiceUdpBridge Bind(string virtualIp, LocalPeerService service, ILogger? logger)
    {
        if (!PeerServiceDiscovery.IsLocalInterfaceTarget(service.TargetHost))
        {
            throw new InvalidOperationException("targetHost is not assigned to this device");
        }
        var inbound = new UdpClient(new IPEndPoint(IPAddress.Parse(virtualIp), service.PublishedPort));
        inbound.Client.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
        return new PeerServiceUdpBridge(virtualIp, service, inbound, logger);
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
        var target = new IPEndPoint(IPAddress.Parse(Resolve(_service.TargetHost)), _service.TargetPort);
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
                continue;
            }
            Interlocked.Add(ref _bytesIn, packet.Buffer.Length);
            var key = packet.RemoteEndPoint.ToString();
            if (!_peers.TryGetValue(key, out var binding))
            {
                if (_peers.Count >= 64)
                {
                    continue;
                }
                var outbound = new UdpClient();
                outbound.Connect(target);
                binding = new UdpPeer(outbound);
                if (!_peers.TryAdd(key, binding))
                {
                    outbound.Dispose();
                    binding = _peers[key];
                }
                else
                {
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
            binding.Client.Dispose();
        }
    }

    private static string Resolve(string host) =>
        string.Equals(host, "localhost", StringComparison.OrdinalIgnoreCase) ? "127.0.0.1" : host;

    public void Dispose()
    {
        _cts.Cancel();
        _inbound.Dispose();
        foreach (var peer in _peers.Values)
        {
            peer.Client.Dispose();
        }
        _peers.Clear();
        _cts.Dispose();
    }

    private sealed class UdpPeer(UdpClient client)
    {
        private long _lastSeen = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        public UdpClient Client { get; } = client;
        public DateTimeOffset LastSeen => DateTimeOffset.FromUnixTimeMilliseconds(Interlocked.Read(ref _lastSeen));
        public void Touch() => Interlocked.Exchange(ref _lastSeen, DateTimeOffset.UtcNow.ToUnixTimeMilliseconds());
    }
}
