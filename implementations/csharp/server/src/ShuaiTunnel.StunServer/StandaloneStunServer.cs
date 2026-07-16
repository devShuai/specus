using System.Net;
using System.Net.Sockets;

namespace ShuaiTunnel.StunServer;

public sealed class StandaloneStunServer : IAsyncDisposable
{
    private const int MaxUdpPacketBytes = 65_507;

    private readonly StunServerConfig _config;
    private readonly StunBindingService _binding;
    private readonly StunRequestLimiter _limiter;
    private readonly StunMetrics _metrics = new();
    private readonly Dictionary<StunEndpointId, UdpClient> _sockets = [];
    private readonly StunMetricsHttpServer _metricsServer;
    private bool _disposed;

    public StandaloneStunServer(StunServerConfig config)
    {
        _config = config;
        _binding = new StunBindingService(
            config.Topology,
            config.Software,
            config.LegacySingleIpOtherAddress,
            config.Protection.MaxPaddingResponseBytes);
        _limiter = new StunRequestLimiter(config.Protection);
        _metricsServer = new StunMetricsHttpServer(
            config.Metrics,
            () => _metrics.Render(_limiter.TrackedSources()));
    }

    public async Task RunAsync(CancellationToken cancellationToken)
    {
        ThrowIfDisposed();
        BindEndpoints();
        _metricsServer.Start(cancellationToken);
        Console.WriteLine($"Standalone STUN server started: {_config.Describe()}");
        var workers = _config.Topology.Endpoints()
            .Select(endpoint => ReceiveLoopAsync(
                endpoint.Id,
                _sockets[endpoint.Id],
                cancellationToken))
            .ToList();
        try
        {
            await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            // Normal shutdown.
        }
        finally
        {
            CloseSockets();
            await Task.WhenAll(workers).ConfigureAwait(false);
            await _metricsServer.DisposeAsync().ConfigureAwait(false);
        }
    }

    private void BindEndpoints()
    {
        try
        {
            foreach (var endpoint in _config.Topology.Endpoints())
            {
                var socket = new UdpClient(endpoint.Bind.AddressFamily);
                socket.Client.Bind(endpoint.Bind);
                _sockets.Add(endpoint.Id, socket);
            }
        }
        catch
        {
            CloseSockets();
            throw;
        }
    }

    private async Task ReceiveLoopAsync(
        StunEndpointId incomingEndpoint,
        UdpClient socket,
        CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            UdpReceiveResult packet;
            try
            {
                packet = await socket.ReceiveAsync(cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                return;
            }
            catch (ObjectDisposedException)
            {
                return;
            }
            catch (SocketException) when (cancellationToken.IsCancellationRequested)
            {
                return;
            }
            await ProcessAsync(
                    incomingEndpoint,
                    packet.RemoteEndPoint,
                    packet.Buffer,
                    cancellationToken)
                .ConfigureAwait(false);
        }
    }

    private async Task ProcessAsync(
        StunEndpointId incomingEndpoint,
        IPEndPoint remote,
        byte[] packet,
        CancellationToken cancellationToken)
    {
        _metrics.RecordPacket(packet.Length);
        if (packet.Length > _config.Protection.MaxPacketBytes)
        {
            _metrics.RecordDrop("packet_too_large");
            return;
        }
        var decision = _limiter.Allow(remote.Address);
        if (decision != StunLimitDecision.Allowed)
        {
            _metrics.RecordDrop(decision switch
            {
                StunLimitDecision.GlobalRateLimit => "global_rate_limit",
                StunLimitDecision.SourceRateLimit => "source_rate_limit",
                StunLimitDecision.SourceTableFull => "source_table_full",
                _ => "unknown",
            });
            return;
        }
        var request = StunMessage.Parse(packet);
        if (request is null)
        {
            _metrics.RecordDrop("malformed");
            return;
        }
        if (request.Type != StunMessage.BindingRequest)
        {
            _metrics.RecordDrop("unsupported_method");
            return;
        }
        _metrics.RecordAcceptedRequest();
        if (request.Has(StunMessage.AttrChangeRequest))
        {
            _metrics.RecordFeature("change_request");
        }
        if (request.Has(StunMessage.AttrResponsePort))
        {
            _metrics.RecordFeature("response_port");
        }
        if (request.Has(StunMessage.AttrPadding))
        {
            _metrics.RecordFeature("padding");
        }

        var result = _binding.Process(request, remote, incomingEndpoint, packet.Length);
        byte[] response;
        try
        {
            response = result.Response.ToBytes();
        }
        catch (InvalidOperationException)
        {
            _metrics.RecordDrop("response_too_large");
            return;
        }
        if (response.Length > MaxUdpPacketBytes)
        {
            _metrics.RecordDrop("response_too_large");
            return;
        }
        if (!_sockets.TryGetValue(result.ResponseEndpoint, out var responseSocket))
        {
            _metrics.RecordDrop("response_endpoint_unavailable");
            return;
        }
        try
        {
            await responseSocket.SendAsync(response, result.ResponseTarget, cancellationToken)
                .ConfigureAwait(false);
        }
        catch (SocketException)
        {
            _metrics.RecordDrop("send_error");
            return;
        }
        _metrics.RecordResponse(
            result.Response.Type == StunMessage.BindingSuccess
                ? 200
                : result.Response.ErrorCodeValue(),
            response.Length);
    }

    private void CloseSockets()
    {
        foreach (var socket in _sockets.Values)
        {
            socket.Dispose();
        }
        _sockets.Clear();
    }

    private void ThrowIfDisposed()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
    }

    public async ValueTask DisposeAsync()
    {
        if (_disposed)
        {
            return;
        }
        _disposed = true;
        CloseSockets();
        await _metricsServer.DisposeAsync().ConfigureAwait(false);
    }
}
