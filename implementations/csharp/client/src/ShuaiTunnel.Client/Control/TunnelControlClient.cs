using System.IO.Pipelines;
using System.Net.Sockets;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using ShuaiTunnel.Client.Configuration;
using ShuaiTunnel.Client.DirectHttp;
using ShuaiTunnel.Client.Nat;
using ShuaiTunnel.Client.PeerMesh;
using ShuaiTunnel.Client.Runtime;
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
    private static readonly TimeSpan TokenRefreshMaxLead = TimeSpan.FromMinutes(5);
    private static readonly TimeSpan TokenRefreshMinLead = TimeSpan.FromSeconds(30);
    private static readonly TimeSpan TokenRefreshMinDelay = TimeSpan.FromSeconds(5);
    private static readonly TimeSpan TokenRefreshRetryDelay = TimeSpan.FromSeconds(60);

    private readonly TunnelClientConfig _config;
    private readonly ClientAuthService _auth;
    private readonly DirectHttpForwarder _httpForwarder;
    private readonly PeerMeshClient _peerMesh;
    private readonly ILoggerFactory _loggerFactory;
    private readonly ILogger<TunnelControlClient> _logger;
    private readonly ITunnelClientObserver? _observer;
    private int _backoffAttempts;
    private bool _resetBackoffOnNextHttpLogin;
    private CancellationTokenSource? _sessionCts;
    private TunnelRuntimeState? _runtime;
    private FrameWriter? _activeWriter;
    private volatile bool _loggedIn;

    public TunnelControlClient(
        TunnelClientConfig config,
        ClientAuthService auth,
        DirectHttpForwarder httpForwarder,
        ILoggerFactory loggerFactory,
        ITunnelClientObserver? observer = null)
    {
        _config = config;
        _auth = auth;
        _httpForwarder = httpForwarder;
        _observer = observer;
        _peerMesh = new PeerMeshClient(config, loggerFactory.CreateLogger<PeerMeshClient>(), observer);
        _loggerFactory = loggerFactory;
        _logger = loggerFactory.CreateLogger<TunnelControlClient>();
    }

    public async Task<ClientMessageSendResult> SendClientMessageAsync(
        string toClientName,
        string message,
        CancellationToken cancellationToken = default)
    {
        var target = toClientName.Trim();
        var body = message.Trim();
        if (string.IsNullOrWhiteSpace(target))
        {
            throw new ArgumentException("目标客户端不能为空。", nameof(toClientName));
        }
        if (string.IsNullOrWhiteSpace(body))
        {
            throw new ArgumentException("消息内容不能为空。", nameof(message));
        }

        var runtime = _runtime;
        if (runtime is null || _activeWriter is null || !_loggedIn)
        {
            throw new InvalidOperationException("客户端尚未登录控制通道。");
        }

        try
        {
            var peerResult = await _peerMesh.SendClientMessageAsync(target, body, cancellationToken)
                .ConfigureAwait(false);
            if (peerResult is not null)
            {
                PublishClientMessage(new ClientMessageSnapshot
                {
                    Id = peerResult.MessageId,
                    Direction = "OUT",
                    FromClientName = runtime.ClientName,
                    ToClientName = target,
                    Message = body,
                    Transport = peerResult.Transport,
                    Status = "sent",
                    CreatedAt = DateTimeOffset.Now,
                });
                return new ClientMessageSendResult
                {
                    MessageId = peerResult.MessageId,
                    Transport = peerResult.Transport,
                    FallbackUsed = false,
                };
            }
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _logger.LogDebug(ex, "peer client message path failed, using server fallback: target={Target}", target);
        }

        var writer = _activeWriter;
        var sessionCts = _sessionCts;
        runtime = _runtime;
        if (writer is null || sessionCts is null || runtime is null || sessionCts.IsCancellationRequested || !_loggedIn)
        {
            throw new InvalidOperationException("客户端控制通道不可用。");
        }

        var messageId = Guid.NewGuid().ToString("N");
        using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, sessionCts.Token);
        await writer.WriteAsync(new MessageRequestPacket
        {
            ClientName = runtime.ClientName,
            ToClientName = target,
            MessageType = MessageType.ClientToClient,
            Message = body,
        }, linkedCts.Token).ConfigureAwait(false);

        PublishClientMessage(new ClientMessageSnapshot
        {
            Id = messageId,
            Direction = "OUT",
            FromClientName = runtime.ClientName,
            ToClientName = target,
            Message = body,
            Transport = "server",
            Status = "submitted",
            CreatedAt = DateTimeOffset.Now,
        });
        return new ClientMessageSendResult
        {
            MessageId = messageId,
            Transport = "server",
            FallbackUsed = true,
        };
    }

    /// <summary>Runs the reconnect loop until cancellation; never returns success.</summary>
    public async Task RunAsync(CancellationToken cancellationToken)
    {
        PublishStatus("STARTING", "客户端启动中", running: true, controlConnected: false, loggedIn: false);
        while (!cancellationToken.IsCancellationRequested)
        {
            var reconnectImmediately = false;
            try
            {
                await RunOnceAsync(cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                return;
            }
            catch (ControlLoginRejectedException ex) when (ex.Action == ControlLoginFailureAction.RefreshImmediately)
            {
                _logger.LogWarning("control login failed: {reason}; refreshing credentials and reconnecting immediately",
                    ex.ReasonOrDefault);
                _resetBackoffOnNextHttpLogin = true;
                reconnectImmediately = true;
            }
            catch (ControlLoginRejectedException ex) when (ex.Action == ControlLoginFailureAction.Stop)
            {
                _logger.LogWarning("control login rejected: {reason}; stopping reconnect", ex.ReasonOrDefault);
                PublishStatus("STOPPED", ex.ReasonOrDefault, running: false, controlConnected: false, loggedIn: false);
                return;
            }
            catch (ControlLoginRejectedException ex)
            {
                _logger.LogWarning("control login failed: {reason}; reconnecting with backoff", ex.ReasonOrDefault);
                PublishStatus("RECONNECTING", ex.ReasonOrDefault, running: true, controlConnected: false, loggedIn: false);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "control channel session ended");
                PublishStatus("RECONNECTING", ex.Message, running: true, controlConnected: false, loggedIn: false);
            }

            if (cancellationToken.IsCancellationRequested)
            {
                return;
            }
            if (reconnectImmediately)
            {
                continue;
            }
            var delay = NextBackoff();
            _logger.LogInformation("reconnect attempt #{attempt} in {delay}s", _backoffAttempts, delay);
            PublishStatus("RECONNECTING", $"控制连接断开，{delay}s 后重连", running: true, controlConnected: false, loggedIn: false);
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
        PublishStatus("HTTP_LOGIN", "正在通过 HTTP 登录服务端", running: true, controlConnected: false, loggedIn: false);
        var runtime = await _auth.LoginAsync(cancellationToken).ConfigureAwait(false);
        if (_resetBackoffOnNextHttpLogin)
        {
            _resetBackoffOnNextHttpLogin = false;
            if (_backoffAttempts > 0)
            {
                _logger.LogInformation("客户端访问令牌刷新成功, reconnect backoff reset (was attempt #{attempt})",
                    _backoffAttempts);
            }
            _backoffAttempts = 0;
        }
        _runtime = runtime;
        PublishStatus("HTTP_LOGIN_OK", "HTTP 登录成功，准备建立控制连接", running: true, controlConnected: false, loggedIn: false);
        PublishRoutes(runtime.TunnelConfigList, runtime.HttpTunnelConfigList);

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
        PublishStatus("CONTROL_CONNECTED", $"已连接控制端 {runtime.NettyHost}:{runtime.NettyPort}", running: true, controlConnected: true, loggedIn: false);

        await using var stream = tcp.GetStream();
        await using var writer = new FrameWriter(stream);
        _activeWriter = writer;
        _loggedIn = false;
        _sessionCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        var sessionCts = _sessionCts;
        var session = sessionCts.Token;

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
        var refreshLoop = RefreshRuntimeLoopAsync(writer, nat, directHttp, session);

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
            _activeWriter = null;
            _loggedIn = false;
            sessionCts.Cancel();
            try
            {
                await refreshLoop.ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
            }
            await reader.CompleteAsync().ConfigureAwait(false);
            await nat.DisposeAsync().ConfigureAwait(false);
            await _peerMesh.DisposeAsync().ConfigureAwait(false);
            PublishStatus("SESSION_CLOSED", "控制会话已关闭", running: true, controlConnected: false, loggedIn: false);
            sessionCts.Dispose();
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

    private async Task RefreshRuntimeLoopAsync(
        FrameWriter writer, NatClientHandler nat, DirectHttpHandler directHttp, CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            var runtime = _runtime;
            if (runtime is null || runtime.TokenExpiresAt == default)
            {
                return;
            }

            var delay = TokenRefreshDelay(DateTimeOffset.UtcNow, runtime.TokenExpiresAt);
            try
            {
                await Task.Delay(delay, cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                return;
            }

            TunnelRuntimeState refreshed;
            try
            {
                refreshed = await _auth.LoginAsync(cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                return;
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "客户端访问令牌刷新失败，{delay}s 后重试",
                    (int)TokenRefreshRetryDelay.TotalSeconds);
                try
                {
                    await Task.Delay(TokenRefreshRetryDelay, cancellationToken).ConfigureAwait(false);
                }
                catch (OperationCanceledException)
                {
                    return;
                }
                continue;
            }

            if (_runtime is { } previous
                && (previous.NettyHost != refreshed.NettyHost || previous.NettyPort != refreshed.NettyPort))
            {
                _logger.LogInformation("HTTP 登录返回新的控制端地址 {oldHost}:{oldPort} -> {newHost}:{newPort}",
                    previous.NettyHost, previous.NettyPort, refreshed.NettyHost, refreshed.NettyPort);
            }
            _runtime = refreshed;
            await nat.ApplyConfigAsync(refreshed.TunnelConfigList).ConfigureAwait(false);
            directHttp.ApplyRoutes(refreshed.HttpTunnelConfigList);
            PublishRoutes(refreshed.TunnelConfigList, refreshed.HttpTunnelConfigList);
            await nat.ReportHttpRoutesAsync(force: true).ConfigureAwait(false);
            await _peerMesh.StartAsync(refreshed, writer, cancellationToken).ConfigureAwait(false);
            _logger.LogInformation("客户端访问令牌刷新成功: client={client}, session={session}",
                refreshed.ClientName, refreshed.ClientSessionId);
        }
    }

    private static TimeSpan TokenRefreshDelay(DateTimeOffset now, DateTimeOffset expiresAt)
    {
        var remaining = expiresAt - now;
        if (remaining <= TimeSpan.Zero)
        {
            return TokenRefreshMinDelay;
        }
        var lead = TokenRefreshLead(remaining);
        var delay = remaining - lead;
        return delay < TokenRefreshMinDelay ? TokenRefreshMinDelay : delay;
    }

    private static TimeSpan TokenRefreshLead(TimeSpan remaining)
    {
        if (remaining <= TokenRefreshMinLead * 2)
        {
            var half = TimeSpan.FromTicks(remaining.Ticks / 2);
            return half < TokenRefreshMinDelay ? TokenRefreshMinDelay : half;
        }
        var tenth = TimeSpan.FromTicks(remaining.Ticks / 10);
        if (tenth < TokenRefreshMinLead)
        {
            return TokenRefreshMinLead;
        }
        return tenth > TokenRefreshMaxLead ? TokenRefreshMaxLead : tenth;
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
                    _loggedIn = true;
                    PublishStatus("RUNNING", $"控制通道登录成功：{response.ClientName}", running: true, controlConnected: true, loggedIn: true);
                    await nat.RegisterAllAsync().ConfigureAwait(false);
                    await nat.ReportHttpRoutesAsync().ConfigureAwait(false);
                    await _peerMesh.StartAsync(_runtime ?? throw new InvalidOperationException("runtime missing"), writer, cancellationToken)
                        .ConfigureAwait(false);
                }
                else
                {
                    throw ControlLoginRejectedException.FromReason(response.Reason);
                }
                break;

            case HeartbeatResponsePacket:
            case HeartbeatRequestPacket:
                // Inbound heartbeats only refresh reader-idle.
                break;

            case MessageResponsePacket message when message.MessageType == MessageType.NatControl:
                await ApplyNatControlAsync(message.Message ?? "", nat, directHttp).ConfigureAwait(false);
                break;

            case MessageResponsePacket message when message.MessageType == MessageType.PeerControl:
                await ApplyPeerControlAsync(message.Message ?? "", writer, cancellationToken).ConfigureAwait(false);
                break;

            case MessageResponsePacket message when message.MessageType == MessageType.ClientToClient:
                ApplyClientMessage(message);
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

    private void ApplyClientMessage(MessageResponsePacket message)
    {
        var runtime = _runtime;
        PublishClientMessage(new ClientMessageSnapshot
        {
            Id = Guid.NewGuid().ToString("N"),
            Direction = "IN",
            FromClientName = FirstNonEmpty(message.ClientName, "server"),
            ToClientName = FirstNonEmpty(message.ToClientName, runtime?.ClientName),
            Message = message.Message ?? "",
            Transport = "server",
            Status = "received",
            CreatedAt = DateTimeOffset.Now,
        });
    }

    private async Task ApplyPeerControlAsync(string payload, FrameWriter writer, CancellationToken cancellationToken)
    {
        var runtime = _runtime;
        if (runtime is not null)
        {
            await _peerMesh.HandleControlAsync(payload, runtime, writer, cancellationToken).ConfigureAwait(false);
        }
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
        PublishRoutes(snapshot.TunnelConfigList, snapshot.HttpTunnelConfigList);
    }

    public ValueTask DisposeAsync()
    {
        _sessionCts?.Cancel();
        _sessionCts?.Dispose();
        return _peerMesh.DisposeAsync();
    }

    private void PublishStatus(
        string phase,
        string detail,
        bool running,
        bool controlConnected,
        bool loggedIn)
    {
        _observer?.OnStatusChanged(TunnelClientStatusSnapshot.FromRuntime(
            _runtime, phase, detail, running, controlConnected, loggedIn));
    }

    private void PublishRoutes(
        IEnumerable<TunnelConfigEntry>? tcpRoutes,
        IEnumerable<HttpTunnelConfigEntry>? httpRoutes)
    {
        _observer?.OnRoutesChanged(TunnelClientRoutesSnapshot.FromRoutes(tcpRoutes, httpRoutes));
    }

    private void PublishClientMessage(ClientMessageSnapshot snapshot)
    {
        _observer?.OnClientMessage(snapshot);
    }

    private static string FirstNonEmpty(params string?[] values)
    {
        return values.FirstOrDefault(value => !string.IsNullOrWhiteSpace(value))?.Trim() ?? "";
    }

    internal static ControlLoginFailureAction ClassifyControlLoginFailure(string? reason)
    {
        if (!string.IsNullOrEmpty(reason)
            && reason.Contains("访问令牌已过期", StringComparison.Ordinal))
        {
            return ControlLoginFailureAction.RefreshImmediately;
        }
        if (!string.IsNullOrEmpty(reason)
            && (reason.Contains("服务器繁忙", StringComparison.Ordinal)
                || reason.Contains("连接频率超过限制", StringComparison.Ordinal)))
        {
            return ControlLoginFailureAction.Backoff;
        }
        return ControlLoginFailureAction.Stop;
    }
}

internal enum ControlLoginFailureAction
{
    Backoff,
    RefreshImmediately,
    Stop,
}

internal sealed class ControlLoginRejectedException : Exception
{
    private ControlLoginRejectedException(string? reason, ControlLoginFailureAction action)
        : base($"control login failed: {ReasonOrDefaultValue(reason)}")
    {
        Reason = reason;
        Action = action;
    }

    public string? Reason { get; }

    public ControlLoginFailureAction Action { get; }

    public string ReasonOrDefault => ReasonOrDefaultValue(Reason);

    public static ControlLoginRejectedException FromReason(string? reason)
        => new(reason, TunnelControlClient.ClassifyControlLoginFailure(reason));

    private static string ReasonOrDefaultValue(string? reason)
        => string.IsNullOrWhiteSpace(reason) ? "login rejected" : reason;
}
