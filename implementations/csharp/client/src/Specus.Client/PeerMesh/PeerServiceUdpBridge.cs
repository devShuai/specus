using System.Net;
using System.Net.Sockets;
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
    private readonly Dictionary<string, UdpClient> _peers = new(StringComparer.Ordinal);
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
        && _service.TargetPort == service.TargetPort;

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
            Interlocked.Add(ref _bytesIn, packet.Buffer.Length);
            var key = packet.RemoteEndPoint.ToString();
            if (!_peers.TryGetValue(key, out var outbound))
            {
                outbound = new UdpClient();
                outbound.Connect(target);
                _peers[key] = outbound;
                Interlocked.Increment(ref _totalConnections);
                Interlocked.Increment(ref _active);
                _ = ReplyLoopAsync(outbound, packet.RemoteEndPoint);
            }
            try
            {
                await outbound.SendAsync(packet.Buffer, packet.Buffer.Length).ConfigureAwait(false);
            }
            catch
            {
                // next packet retries
            }
        }
    }

    private async Task ReplyLoopAsync(UdpClient outbound, IPEndPoint peer)
    {
        try
        {
            while (!_cts.IsCancellationRequested)
            {
                var packet = await outbound.ReceiveAsync(_cts.Token).ConfigureAwait(false);
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
            Interlocked.Decrement(ref _active);
            outbound.Dispose();
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
            peer.Dispose();
        }
        _peers.Clear();
        _cts.Dispose();
    }
}
