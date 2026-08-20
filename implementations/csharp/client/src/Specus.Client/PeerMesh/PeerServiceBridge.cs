using System.Net;
using System.Net.Sockets;
using System.Collections.Concurrent;
using Microsoft.Extensions.Logging;
using Specus.Client.Configuration;

namespace Specus.Client.PeerMesh;

internal interface IPeerServiceForwarder : IDisposable
{
    string ServiceId { get; }
    bool Matches(string virtualIp, LocalPeerService service);
    (long BytesIn, long BytesOut, int Active, long Total) Snapshot();
}

internal sealed class PeerServiceBridge : IPeerServiceForwarder
{
    private readonly string _virtualIp;
    private readonly LocalPeerService _service;
    private readonly TcpListener _listener;
    private readonly CancellationTokenSource _cts = new();
    private readonly ILogger? _logger;
    private readonly ConcurrentDictionary<TcpClient, TcpClient> _splices = new();
    private readonly SemaphoreSlim _slots = new(64, 64);
    private readonly ConcurrentDictionary<string, byte> _auditedAccessEvents = new(StringComparer.Ordinal);
    private long _bytesIn;
    private long _bytesOut;
    private long _totalConnections;
    private int _disposed;

    private PeerServiceBridge(string virtualIp, LocalPeerService service, TcpListener listener, ILogger? logger)
    {
        _virtualIp = virtualIp;
        _service = service;
        _listener = listener;
        _logger = logger;
        _ = AcceptLoopAsync();
    }

    public static PeerServiceBridge Bind(string virtualIp, LocalPeerService service, ILogger? logger)
    {
        if (!PeerServiceDiscovery.IsLocalInterfaceTarget(service.TargetHost))
        {
            throw new InvalidOperationException("targetHost is not assigned to this device");
        }
        var listener = new TcpListener(IPAddress.Parse(virtualIp), service.PublishedPort);
        listener.Server.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
        listener.Start();
        return new PeerServiceBridge(virtualIp, service, listener, logger);
    }

    public string ServiceId => _service.ServiceId;

    public (long BytesIn, long BytesOut, int Active, long Total) Snapshot() =>
        (Interlocked.Read(ref _bytesIn), Interlocked.Read(ref _bytesOut), _splices.Count,
            Interlocked.Read(ref _totalConnections));

    public bool Matches(string virtualIp, LocalPeerService service) =>
        _virtualIp == virtualIp
        && _service.ServiceId == service.ServiceId
        && _service.PublishedPort == service.PublishedPort
        && _service.TargetHost == service.TargetHost
        && _service.TargetPort == service.TargetPort
        && PeerServiceDiscovery.SameAllowedPeers(_service, service);

    private async Task AcceptLoopAsync()
    {
        while (!_cts.IsCancellationRequested)
        {
            TcpClient inbound;
            try
            {
                inbound = await _listener.AcceptTcpClientAsync(_cts.Token).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                return;
            }
            catch
            {
                return;
            }
            if (inbound.Client.RemoteEndPoint is not IPEndPoint remote
                || !PeerServiceDiscovery.IsSourceAllowed(remote.Address, _service))
            {
                AuditAccessOnce("deny", inbound.Client.RemoteEndPoint, "source-not-allowed");
                inbound.Dispose();
                continue;
            }
            AuditAccessOnce("allow", remote, "acl-authorized");
            if (!_slots.Wait(0))
            {
                inbound.Dispose();
                continue;
            }
            _ = SpliceAsync(inbound);
        }
    }

    private void AuditAccessOnce(string action, EndPoint? source, string reason)
    {
        var sourceAddress = source?.ToString() ?? "unknown";
        var key = $"{action}|{sourceAddress}";
        if (_auditedAccessEvents.Count < 128 && _auditedAccessEvents.TryAdd(key, 0))
        {
            _logger?.LogInformation(
                "[peer-service-access-audit] action={Action} serviceId={ServiceId} source={Source} reason={Reason}",
                action, _service.ServiceId, sourceAddress, reason);
        }
    }

    private async Task SpliceAsync(TcpClient inbound)
    {
        using var inboundClient = inbound;
        using var outbound = new TcpClient();
        if (_cts.IsCancellationRequested || !_splices.TryAdd(inboundClient, outbound))
        {
            return;
        }
        Interlocked.Increment(ref _totalConnections);
        try
        {
            inboundClient.NoDelay = true;
            outbound.NoDelay = true;
            using var connectCts = new CancellationTokenSource(TimeSpan.FromSeconds(3));
            await outbound.ConnectAsync(_service.TargetHost, _service.TargetPort, connectCts.Token).ConfigureAwait(false);
            await using var inboundStream = inboundClient.GetStream();
            await using var outboundStream = outbound.GetStream();
            var up = CopyCountedAsync(inboundStream, outboundStream, incrementIn: true);
            var down = CopyCountedAsync(outboundStream, inboundStream, incrementIn: false);
            await Task.WhenAny(up, down).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _logger?.LogDebug(ex, "Peer-only 桥接转发失败 service={ServiceId}", _service.ServiceId);
        }
        finally
        {
            _splices.TryRemove(inboundClient, out _);
            _slots.Release();
        }
    }

    private async Task CopyCountedAsync(NetworkStream from, NetworkStream to, bool incrementIn)
    {
        var buffer = new byte[8192];
        while (!_cts.IsCancellationRequested)
        {
            var read = await from.ReadAsync(buffer, _cts.Token).ConfigureAwait(false);
            if (read <= 0)
            {
                return;
            }
            await to.WriteAsync(buffer.AsMemory(0, read), _cts.Token).ConfigureAwait(false);
            if (incrementIn)
            {
                Interlocked.Add(ref _bytesIn, read);
            }
            else
            {
                Interlocked.Add(ref _bytesOut, read);
            }
        }
    }

    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }
        _logger?.LogInformation(
            "[peer-service-access-audit] action=revoke serviceId={ServiceId} activeConnections={ActiveConnections} reason=config-withdrawn-or-shutdown",
            _service.ServiceId, _splices.Count);
        _cts.Cancel();
        try
        {
            _listener.Stop();
        }
        catch
        {
            // ignored
        }
        foreach (var splice in _splices)
        {
            splice.Key.Dispose();
            splice.Value.Dispose();
        }
        _splices.Clear();
        _cts.Dispose();
    }
}
