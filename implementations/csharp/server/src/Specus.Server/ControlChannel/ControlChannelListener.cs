using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Specus.Server.Configuration;
using Specus.Server.Security;

namespace Specus.Server.ControlChannel;

/// <summary>
/// Binds the TCP control channel listener and shepherds accepted connections into
/// <see cref="SpecusConnection"/> instances. One <see cref="ControlChannelListener"/> per
/// process; runs as an <see cref="IHostedService"/> alongside Kestrel.
///
/// <para>Configuration: port comes from <c>Specus:Netty:Port</c> (default 7010). Setting it to 0
/// asks the kernel for an ephemeral port; tests read the assigned port via
/// <see cref="BoundPort"/> after <see cref="StartAsync"/> returns.</para>
/// </summary>
public sealed class ControlChannelListener : IHostedService
{
    private readonly ILogger<ControlChannelListener> _logger;
    private readonly IOptions<NettyServerOptions> _options;
    private readonly ControlChannelTlsProvider _tlsProvider;
    private readonly IControlChannelDispatcher _dispatcher;
    private readonly ILoggerFactory _loggerFactory;
    private readonly CancellationTokenSource _shutdownCts = new();

    private TcpListener? _listener;
    private Task? _acceptLoop;
    private X509Certificate2? _serverCertificate;

    /// <summary>Available after <see cref="StartAsync"/>. Returns -1 before bind succeeds.</summary>
    public int BoundPort { get; private set; } = -1;

    public ControlChannelListener(ILogger<ControlChannelListener> logger,
        IOptions<NettyServerOptions> options,
        ControlChannelTlsProvider tlsProvider,
        IControlChannelDispatcher dispatcher,
        ILoggerFactory loggerFactory)
    {
        _logger = logger;
        _options = options;
        _tlsProvider = tlsProvider;
        _dispatcher = dispatcher;
        _loggerFactory = loggerFactory;
    }

    public Task StartAsync(CancellationToken cancellationToken)
    {
        var configured = _options.Value.Port;
        _listener = new TcpListener(IPAddress.Any, configured);
        _listener.Server.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
        _listener.Start(backlog: 8192);
        _serverCertificate = _tlsProvider.GetServerCertificate();
        if (_serverCertificate is null)
        {
            _logger.LogInformation("[tls] control channel is PLAIN (TLS disabled)");
        }
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

            // Fire-and-forget — the connection handles its own lifecycle and disposal. The
            // listener never awaits this task because there's no useful place to surface errors.
            _ = Task.Run(() => RunAcceptedConnectionAsync(socket, token), token);
        }
    }

    private async Task RunAcceptedConnectionAsync(Socket socket, CancellationToken token)
    {
        Stream stream = new NetworkStream(socket, ownsSocket: false);
        try
        {
            if (_serverCertificate is not null)
            {
                var sslStream = new SslStream(stream, leaveInnerStreamOpen: false);
                stream = sslStream;
                await sslStream.AuthenticateAsServerAsync(new SslServerAuthenticationOptions
                {
                    ServerCertificate = _serverCertificate,
                    ClientCertificateRequired = false,
                    EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
                    CertificateRevocationCheckMode = X509RevocationMode.NoCheck,
                }, token).ConfigureAwait(false);
            }

            var connection = new SpecusConnection(
                socket,
                stream,
                _dispatcher,
                _loggerFactory.CreateLogger<SpecusConnection>(),
                _options.Value,
                token);
            await connection.RunAsync().ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is AuthenticationException or IOException or SocketException
            or ObjectDisposedException or OperationCanceledException)
        {
            _logger.LogDebug(ex, "control channel handshake failed");
            try { stream.Dispose(); } catch { /* already gone */ }
            try { socket.Close(); } catch { /* already gone */ }
        }
    }
}
