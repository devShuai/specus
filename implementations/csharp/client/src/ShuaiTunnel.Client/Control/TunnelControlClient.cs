using System.IO.Pipelines;
using System.Net.Sockets;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using ShuaiTunnel.Client.Configuration;
using ShuaiTunnel.Client.DirectHttp;
using ShuaiTunnel.Client.Nat;
using ShuaiTunnel.Protocol;
using ShuaiTunnel.Protocol.Codec;
using ShuaiTunnel.Protocol.Packets;

namespace ShuaiTunnel.Client.Control;

/// <summary>
/// Drives the control-channel connection: dial, login, packet dispatch, heartbeat, and
/// reconnect with exponential backoff. The reconnect counter only resets on
/// LOGIN_RESPONSE.Success=true so wrong-credential loops still escalate. Mirrors the Java
/// <c>NettyClient</c>.
/// </summary>
public sealed class TunnelControlClient : IAsyncDisposable
{
    private const int MaxFrameSize = 32 * 1024 * 1024;
    private const int ConnectTimeoutMs = 5000;
    private const int BaseBackoffSeconds = 2;
    private const int MaxBackoffSeconds = 60;

    private readonly ClientAuthService _auth;
    private readonly DirectHttpForwarder _httpForwarder;
    private readonly ILoggerFactory _loggerFactory;
    private readonly ILogger<TunnelControlClient> _logger;
    private int _backoffAttempts;
    private CancellationTokenSource? _sessionCts;
    private TunnelRuntimeState? _runtime;

    public TunnelControlClient(
        ClientAuthService auth,
        DirectHttpForwarder httpForwarder,
        ILoggerFactory loggerFactory)
    {
        _auth = auth;
        _httpForwarder = httpForwarder;
        _loggerFactory = loggerFactory;
        _logger = loggerFactory.CreateLogger<TunnelControlClient>();
    }

    /// <summary>Runs the reconnect loop until cancellation; never returns success.</summary>
    public async Task RunAsync(CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            try
            {
                await RunOnceAsync(cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                return;
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "control channel session ended");
            }

            if (cancellationToken.IsCancellationRequested)
            {
                return;
            }
            var delay = NextBackoff();
            _logger.LogInformation("reconnect attempt #{attempt} in {delay}s", _backoffAttempts, delay);
            try
            {
                await Task.Delay(TimeSpan.FromSeconds(delay), cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                return;
            }
        }
    }

    private int NextBackoff()
    {
        _backoffAttempts++;
        var shift = Math.Min(_backoffAttempts - 1, 5);
        var delay = BaseBackoffSeconds * (1 << shift);
        return Math.Min(delay, MaxBackoffSeconds);
    }

    private async Task RunOnceAsync(CancellationToken cancellationToken)
    {
        var runtime = await _auth.LoginAsync(cancellationToken).ConfigureAwait(false);
        _runtime = runtime;

        using var tcp = new TcpClient { NoDelay = true };
        tcp.Client.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.KeepAlive, true);
        using var connectCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        connectCts.CancelAfter(ConnectTimeoutMs);
        try
        {
            await tcp.ConnectAsync(runtime.NettyHost, runtime.NettyPort, connectCts.Token)
                .ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            throw new TimeoutException(
                $"connect to {runtime.NettyHost}:{runtime.NettyPort} timed out after {ConnectTimeoutMs} ms");
        }
        _logger.LogInformation("connected to {addr}:{port}", runtime.NettyHost, runtime.NettyPort);

        await using var stream = tcp.GetStream();
        await using var writer = new FrameWriter(stream);
        _sessionCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        var session = _sessionCts.Token;

        var directHttp = new DirectHttpHandler(
            runtime.HttpTunnelConfigList, writer, _httpForwarder, _loggerFactory.CreateLogger<DirectHttpHandler>());
        var nat = new NatClientHandler(
            runtime.TunnelConfigList, runtime.ClientName,
            writer, directHttp, _loggerFactory.CreateLogger<NatClientHandler>());
        nat.Bind(session);
        writer.WritabilityChanged += writable => nat.SetControlWritable(writable);

        await using var watchdog = new HeartbeatWatchdog(writer, _logger, reason =>
        {
            _logger.LogWarning("control channel closing: {reason}", reason);
            _sessionCts?.Cancel();
        });
        watchdog.Start(session);

        await SendLoginAsync(writer, session).ConfigureAwait(false);

        var reader = PipeReader.Create(stream);
        try
        {
            while (!session.IsCancellationRequested)
            {
                var packet = await FrameReader.ReadFrameAsync(reader, MaxFrameSize, session)
                    .ConfigureAwait(false);
                if (packet is null)
                {
                    _logger.LogInformation("server closed control connection");
                    break;
                }
                watchdog.MarkRead();
                await DispatchAsync(packet, writer, nat, directHttp, session).ConfigureAwait(false);
            }
        }
        finally
        {
            await reader.CompleteAsync().ConfigureAwait(false);
            await nat.DisposeAsync().ConfigureAwait(false);
            _sessionCts.Dispose();
            _sessionCts = null;
        }
    }

    private async Task SendLoginAsync(FrameWriter writer, CancellationToken cancellationToken)
    {
        var runtime = _runtime ?? throw new InvalidOperationException("client runtime is not initialized");
        var packet = new LoginRequestPacket
        {
            ClientName = runtime.ClientName,
            ClientSessionId = runtime.ClientSessionId,
            AccessToken = runtime.AccessToken,
        };
        await writer.WriteAsync(packet, cancellationToken).ConfigureAwait(false);
        _logger.LogDebug("sent login request for {client}, session={session}",
            runtime.ClientName, runtime.ClientSessionId);
    }

    private async Task DispatchAsync(
        Packet packet, FrameWriter writer, NatClientHandler nat,
        DirectHttpHandler directHttp, CancellationToken cancellationToken)
    {
        switch (packet)
        {
            case LoginResponsePacket response:
                if (response.Success)
                {
                    _logger.LogInformation("[{client}] 登录成功", response.ClientName);
                    _backoffAttempts = 0;
                    await nat.RegisterAllAsync().ConfigureAwait(false);
                    await nat.ReportHttpRoutesAsync().ConfigureAwait(false);
                }
                else
                {
                    _logger.LogWarning("[{client}] 登录失败: {reason}", response.ClientName, response.Reason);
                    _sessionCts?.Cancel();
                }
                break;

            case HeartbeatResponsePacket:
            case HeartbeatRequestPacket:
                // Inbound heartbeats only refresh reader-idle.
                break;

            case MessageResponsePacket message when message.MessageType == MessageType.NatControl:
                await ApplyNatControlAsync(message.Message ?? "", nat, directHttp).ConfigureAwait(false);
                break;

            case NatMessagePacket natMessage:
                await nat.HandleAsync(natMessage).ConfigureAwait(false);
                break;

            case DirectHttpRequestPacket http:
                directHttp.Dispatch(http, cancellationToken);
                break;

            case LogoutRequestPacket:
                _logger.LogInformation("收到服务端 logout 指令, 关闭控制连接");
                _sessionCts?.Cancel();
                break;

            default:
                _logger.LogDebug("dropped unhandled packet {command}", packet.Command);
                break;
        }

        // Suppress unused-parameter warning when only some branches need the writer.
        _ = writer;
    }

    private async Task ApplyNatControlAsync(
        string payload, NatClientHandler nat, DirectHttpHandler directHttp)
    {
        if (string.IsNullOrWhiteSpace(payload))
        {
            return;
        }
        TunnelConfigSnapshot? snapshot;
        try
        {
            snapshot = JsonSerializer.Deserialize<TunnelConfigSnapshot>(payload, TunnelClientConfigLoader.JsonOptions);
        }
        catch (JsonException ex)
        {
            _logger.LogWarning(ex, "NAT_CONTROL payload parse failed");
            return;
        }
        if (snapshot is null)
        {
            return;
        }
        await nat.ApplyConfigAsync(snapshot.TunnelConfigList).ConfigureAwait(false);
        directHttp.ApplyRoutes(snapshot.HttpTunnelConfigList);
    }

    public ValueTask DisposeAsync()
    {
        _sessionCts?.Cancel();
        _sessionCts?.Dispose();
        return ValueTask.CompletedTask;
    }
}
