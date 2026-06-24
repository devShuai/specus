using Microsoft.Extensions.Logging;
using ShuaiTunnel.Client.Configuration;
using ShuaiTunnel.Client.Control;
using ShuaiTunnel.Protocol.Packets;

namespace ShuaiTunnel.Client.DirectHttp;

/// <summary>
/// Receives <see cref="DirectHttpRequestPacket"/> from the control channel, runs the
/// forwarder on the thread pool (so the read loop is never blocked on upstream HTTP), and
/// writes the resulting <see cref="DirectHttpResponsePacket"/> back through the writer.
/// Holds the route map (volatile snapshot) and supports server-pushed hot reload.
/// </summary>
internal sealed class DirectHttpHandler
{
    private readonly FrameWriter _writer;
    private readonly DirectHttpForwarder _forwarder;
    private readonly ILogger _logger;
    private volatile IReadOnlyDictionary<string, string> _routes;

    public DirectHttpHandler(
        IEnumerable<HttpTunnelConfigEntry>? initialRoutes,
        FrameWriter writer,
        DirectHttpForwarder forwarder,
        ILogger logger)
    {
        _writer = writer;
        _forwarder = forwarder;
        _logger = logger;
        _routes = BuildMap(initialRoutes);
    }

    public IReadOnlyDictionary<string, string> SnapshotRoutes() => _routes;

    /// <summary>
    /// Replaces the route map with a server-pushed snapshot. A <c>null</c> argument keeps the
    /// current local fallback (matching the Java handler's "未接管" semantics).
    /// </summary>
    public void ApplyRoutes(IEnumerable<HttpTunnelConfigEntry>? next)
    {
        if (next is null)
        {
            return;
        }
        _routes = BuildMap(next);
    }

    public void Dispatch(DirectHttpRequestPacket packet, CancellationToken cancellationToken)
    {
        var routes = _routes;
        _ = Task.Run(async () =>
        {
            DirectHttpResponsePacket response;
            try
            {
                response = await _forwarder.ForwardAsync(packet, routes, cancellationToken).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "direct-http forward {requestId} crashed", packet.RequestId);
                response = new DirectHttpResponsePacket
                {
                    RequestId = packet.RequestId,
                    StatusCode = DirectHttpForwarder.FailureStatus,
                    Error = ex.Message,
                };
            }
            try
            {
                await _writer.WriteAsync(response, cancellationToken).ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                _logger.LogDebug(ex, "write direct-http response failed");
            }
        }, cancellationToken);
    }

    private static IReadOnlyDictionary<string, string> BuildMap(IEnumerable<HttpTunnelConfigEntry>? source)
    {
        if (source is null)
        {
            return new Dictionary<string, string>();
        }
        var map = new Dictionary<string, string>();
        foreach (var entry in source)
        {
            if (string.IsNullOrWhiteSpace(entry.Route))
            {
                continue;
            }
            map[entry.Route] = entry.TargetBaseUrl;
        }
        return map;
    }
}
