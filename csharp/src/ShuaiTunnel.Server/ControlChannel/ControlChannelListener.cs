using System.Net;
using System.Net.Sockets;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using ShuaiTunnel.Server.Configuration;

namespace ShuaiTunnel.Server.ControlChannel;

/// <summary>
/// Binds the TCP control channel listener and shepherds accepted connections into
/// <see cref="TunnelConnection"/> instances. One <see cref="ControlChannelListener"/> per
/// process; runs as an <see cref="IHostedService"/> alongside Kestrel.
///
/// <para>Configuration: port comes from <c>Tunnel:Netty:Port</c> (default 7010). Setting it to 0
/// asks the kernel for an ephemeral port; tests read the assigned port via
/// <see cref="BoundPort"/> after <see cref="StartAsync"/> returns.</para>
/// </summary>
public sealed class ControlChannelListener : IHostedService
{
    private readonly ILogger<ControlChannelListener> _logger;
    private readonly IOptions<NettyServerOptions> _options;
    private readonly IControlChannelDispatcher _dispatcher;
    private readonly ILoggerFactory _loggerFactory;
    private readonly CancellationTokenSource _shutdownCts = new();

    private TcpListener? _listener;
    private Task? _acceptLoop;

    /// <summary>Available after <see cref="StartAsync"/>. Returns -1 before bind succeeds.</summary>
    public int BoundPort { get; private set; } = -1;

    public ControlChannelListener(ILogger<ControlChannelListener> logger,
        IOptions<NettyServerOptions> options,
        IControlChannelDispatcher dispatcher,
        ILoggerFactory loggerFactory)
    {
        _logger = logger;
        _options = options;
        _dispatcher = dispatcher;
        _loggerFactory = loggerFactory;
    }

    public Task StartAsync(CancellationToken cancellationToken)
    {
        var configured = _options.Value.Port;
        _listener = new TcpListener(IPAddress.Any, configured);
        _listener.Server.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
        _listener.Start(backlog: 8192);
        BoundPort = ((IPEndPoint)_listener.LocalEndpoint).Port;
        _logger.LogInformation("control channel bound on port {Port}", BoundPort);

        _acceptLoop = Task.Run(AcceptLoopAsync, cancellationToken);
        return Task.CompletedTask;
    }

    public async Task StopAsync(CancellationToken cancellationToken)
    {
        _shutdownCts.Cancel();
        try { _listener?.Stop(); } catch { /* socket already torn down */ }

        if (_acceptLoop is not null)
        {
            try
            {
                await _acceptLoop.WaitAsync(cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                // Caller's cancellation token fired — listener stop already requested.
            }
        }
        _shutdownCts.Dispose();
    }

    private async Task AcceptLoopAsync()
    {
        var token = _shutdownCts.Token;
        while (!token.IsCancellationRequested)
        {
            Socket socket;
            try
            {
                socket = await _listener!.AcceptSocketAsync(token).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (ObjectDisposedException)
            {
                break;
            }
            catch (SocketException ex)
            {
                // Transient — log and keep accepting. The listener itself is still healthy.
                _logger.LogWarning(ex, "accept failed");
                continue;
            }

            // Match Java child options: TCP_NODELAY + SO_KEEPALIVE.
            socket.NoDelay = true;
            try
            {
                socket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.KeepAlive, true);
            }
            catch (SocketException)
            {
                // Best effort — older kernels may reject the setsockopt; not worth aborting.
            }

            var connection = new TunnelConnection(
                socket, _dispatcher,
                _loggerFactory.CreateLogger<TunnelConnection>(),
                _options.Value,
                token);

            // Fire-and-forget — the connection handles its own lifecycle and disposal. The
            // listener never awaits this task because there's no useful place to surface errors.
            _ = Task.Run(connection.RunAsync, token);
        }
    }
}
