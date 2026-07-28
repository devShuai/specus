using System.IO.Pipelines;
using System.Net.Sockets;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using Specus.Client.Configuration;
using Specus.Client.DirectHttp;
using Specus.Client.Nat;
using Specus.Client.PeerMesh;
using Specus.Client.Runtime;
using Specus.Protocol;
using Specus.Protocol.Codec;
using Specus.Protocol.Packets;

namespace Specus.Client.Control;

/// <summary>
/// Drives the control-channel connection: dial, login, packet dispatch, heartbeat, and
/// reconnect with exponential backoff. The reconnect counter only resets on
/// LOGIN_RESPONSE.Success=true so wrong-credential loops still escalate. Mirrors the Java
/// <c>NettyClient</c>.
/// </summary>
public sealed class SpecusControlClient : IAsyncDisposable
{
    private const int MaxFrameSize = 32 * 1024 * 1024;
    private const int ConnectTimeoutMs = 5000;
    private const int BaseBackoffSeconds = 2;
    private const int MaxBackoffSeconds = 60;
    private static readonly TimeSpan TokenRefreshMaxLead = TimeSpan.FromMinutes(5);
    private static readonly TimeSpan TokenRefreshMinLead = TimeSpan.FromSeconds(30);
    private static readonly TimeSpan TokenRefreshMinDelay = TimeSpan.FromSeconds(5);
    private static readonly TimeSpan TokenRefreshRetryDelay = TimeSpan.FromSeconds(60);

    private readonly SpecusClientConfig _config;
    private readonly ClientAuthService _auth;
    private readonly DirectHttpForwarder _httpForwarder;
    private readonly PeerMeshClient _peerMesh;
    private readonly ILoggerFactory _loggerFactory;
    private readonly ILogger<SpecusControlClient> _logger;
    private readonly ISpecusClientObserver? _observer;
    private int _backoffAttempts;
    private bool _resetBackoffOnNextHttpLogin;
    private CancellationTokenSource? _sessionCts;
    private SpecusRuntimeState? _runtime;
    private FrameWriter? _activeWriter;
    private volatile bool _loggedIn;

    public SpecusControlClient(
        SpecusClientConfig config,
        ClientAuthService auth,
        DirectHttpForwarder httpForwarder,
        ILoggerFactory loggerFactory,
        ISpecusClientObserver? observer = null)
    {
        _config = config;
        _auth = auth;
        _httpForwarder = httpForwarder;
        _observer = observer;
        _peerMesh = new PeerMeshClient(config, loggerFactory.CreateLogger<PeerMeshClient>(), observer);
        _loggerFactory = loggerFactory;
        _logger = loggerFactory.CreateLogger<SpecusControlClient>();
    }

    public async Task<ClientMessageSendResult> SendClientMessageAsync(
        string toClientName,
        string message,
        CancellationToken cancellationToken = default,
        bool publishLocalEcho = true)
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
                if (publishLocalEcho)
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
                }
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

        if (publishLocalEcho)
        {
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
        }
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
        PublishRoutes(runtime.SpecusConfigList, runtime.HttpSpecusConfigList);

        _sessionCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        var sessionCts = _sessionCts;
        var session = sessionCts.Token;
        try
        {
        using var controlTcp = await ConnectAsync(runtime, ConnectionRole.Control, session).ConfigureAwait(false);
        await using var controlStream = controlTcp.GetStream();
        await using var controlWriter = new FrameWriter(controlStream);
        var controlReader = PipeReader.Create(controlStream);
        await using var controlWatchdog = CreateWatchdog(controlWriter, ConnectionRole.Control, session);

        await SendLoginAsync(controlWriter, ConnectionRole.Control, session).ConfigureAwait(false);
        var controlLogin = await ReadLoginResponseAsync(controlReader, controlWatchdog, session).ConfigureAwait(false);
        EnsureLoginSucceeded(controlLogin, ConnectionRole.Control);
        _activeWriter = controlWriter;
        await _peerMesh.StartAsync(runtime, controlWriter, session).ConfigureAwait(false);

        using var dataTcp = await ConnectAsync(runtime, ConnectionRole.Data, session).ConfigureAwait(false);
        await using var dataStream = dataTcp.GetStream();
        await using var dataWriter = new FrameWriter(dataStream);
        var dataReader = PipeReader.Create(dataStream);
        await using var dataWatchdog = CreateWatchdog(dataWriter, ConnectionRole.Data, session);
        var directHttp = new DirectHttpHandler(
            runtime.HttpSpecusConfigList, dataWriter, _httpForwarder, _loggerFactory.CreateLogger<DirectHttpHandler>());
        await using var nat = new NatClientHandler(
            runtime.SpecusConfigList, runtime.ClientName,
            dataWriter, directHttp, _loggerFactory.CreateLogger<NatClientHandler>());
        nat.Bind(session);
        dataWriter.WritabilityChanged += writable => nat.SetControlWritable(writable);

        await SendLoginAsync(dataWriter, ConnectionRole.Data, session).ConfigureAwait(false);
        var dataLogin = await ReadLoginResponseAsync(dataReader, dataWatchdog, session).ConfigureAwait(false);
        EnsureLoginSucceeded(dataLogin, ConnectionRole.Data);
        await nat.RegisterAllAsync().ConfigureAwait(false);
        _backoffAttempts = 0;
        _loggedIn = true;
        PublishStatus("RUNNING", $"控制与数据通道登录成功：{controlLogin.ClientName}",
            running: true, controlConnected: true, loggedIn: true);

        var refreshLoop = RefreshRuntimeLoopAsync(controlWriter, nat, directHttp, session);
        var controlLoop = ReadControlLoopAsync(controlReader, controlWatchdog, controlWriter, nat, directHttp, session);
        var dataLoop = ReadDataLoopAsync(dataReader, dataWatchdog, nat, session);
        try
        {
            var completed = await Task.WhenAny(controlLoop, dataLoop).ConfigureAwait(false);
            await completed.ConfigureAwait(false);
        }
        finally
        {
            sessionCts.Cancel();
            try
            {
                await refreshLoop.ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
            }
            try
            {
                await Task.WhenAll(controlLoop, dataLoop).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
            }
            catch
            {
                // The first loop failure is already propagated by the try block.
            }
            await controlReader.CompleteAsync().ConfigureAwait(false);
            await dataReader.CompleteAsync().ConfigureAwait(false);
        }
        }
        finally
        {
            _activeWriter = null;
            _loggedIn = false;
            sessionCts.Cancel();
            await _peerMesh.DisposeAsync().ConfigureAwait(false);
            PublishStatus("SESSION_CLOSED", "控制会话已关闭", running: true, controlConnected: false, loggedIn: false);
            sessionCts.Dispose();
            _sessionCts = null;
        }
    }

    private async Task<TcpClient> ConnectAsync(
        SpecusRuntimeState runtime, string role, CancellationToken cancellationToken)
    {
        var tcp = new TcpClient { NoDelay = true };
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
            tcp.Dispose();
            throw new TimeoutException(
                $"connect {role} to {runtime.NettyHost}:{runtime.NettyPort} timed out after {ConnectTimeoutMs} ms");
        }
        catch
        {
            tcp.Dispose();
            throw;
        }
        _logger.LogInformation("{role} connection established to {addr}:{port}",
            role, runtime.NettyHost, runtime.NettyPort);
        if (role == ConnectionRole.Control)
        {
            PublishStatus("CONTROL_CONNECTED", $"已连接控制端 {runtime.NettyHost}:{runtime.NettyPort}",
                running: true, controlConnected: true, loggedIn: false);
        }
        return tcp;
    }

    private HeartbeatWatchdog CreateWatchdog(
        FrameWriter writer, string role, CancellationToken cancellationToken)
    {
        var watchdog = new HeartbeatWatchdog(writer, _logger, reason =>
        {
            _logger.LogWarning("{role} channel closing: {reason}", role, reason);
            _sessionCts?.Cancel();
        });
        watchdog.Start(cancellationToken);
        return watchdog;
    }

    private static async Task<LoginResponsePacket> ReadLoginResponseAsync(
        PipeReader reader, HeartbeatWatchdog watchdog, CancellationToken cancellationToken)
    {
        var packet = await FrameReader.ReadFrameAsync(reader, PacketCodec.PreAuthMaxFrameSize, cancellationToken)
            .ConfigureAwait(false);
        if (packet is not LoginResponsePacket response)
        {
            throw new InvalidDataException("only LOGIN_RESPONSE is allowed before authentication");
        }
        watchdog.MarkRead();
        return response;
    }

    private static void EnsureLoginSucceeded(LoginResponsePacket response, string role)
    {
        if (!response.Success)
        {
            throw ControlLoginRejectedException.FromReason(response.Reason);
        }
        if (string.IsNullOrWhiteSpace(response.ClientName))
        {
            throw new InvalidDataException($"{role} login response omitted client name");
        }
    }

    private async Task SendLoginAsync(FrameWriter writer, string connectionRole,
        CancellationToken cancellationToken)
    {
        var runtime = _runtime ?? throw new InvalidOperationException("client runtime is not initialized");
        var packet = new LoginRequestPacket
        {
            ClientName = runtime.ClientName,
            ClientSessionId = runtime.ClientSessionId,
            AccessToken = runtime.AccessToken,
            ConnectionRole = connectionRole,
        };
        await writer.WriteAsync(packet, cancellationToken).ConfigureAwait(false);
        _logger.LogDebug("sent {role} login request for {client}, session={session}",
            connectionRole, runtime.ClientName, runtime.ClientSessionId);
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

            SpecusRuntimeState refreshed;
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
            await nat.ApplyConfigAsync(refreshed.SpecusConfigList).ConfigureAwait(false);
            directHttp.ApplyRoutes(refreshed.HttpSpecusConfigList);
            PublishRoutes(refreshed.SpecusConfigList, refreshed.HttpSpecusConfigList);
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

    private async Task ReadControlLoopAsync(
        PipeReader reader, HeartbeatWatchdog watchdog, FrameWriter writer,
        NatClientHandler nat, DirectHttpHandler directHttp, CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            var packet = await FrameReader.ReadFrameAsync(reader, MaxFrameSize, cancellationToken)
                .ConfigureAwait(false)
                ?? throw new IOException("server closed control connection");
            watchdog.MarkRead();
            await DispatchControlAsync(packet, writer, nat, directHttp, cancellationToken)
                .ConfigureAwait(false);
        }
    }

    private async Task ReadDataLoopAsync(
        PipeReader reader, HeartbeatWatchdog watchdog, NatClientHandler nat,
        CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            var packet = await FrameReader.ReadFrameAsync(reader, MaxFrameSize, cancellationToken)
                .ConfigureAwait(false)
                ?? throw new IOException("server closed data connection");
            watchdog.MarkRead();
            switch (packet)
            {
                case NatMessagePacket natMessage:
                    await nat.HandleAsync(natMessage).ConfigureAwait(false);
                    break;
                case HeartbeatResponsePacket:
                case HeartbeatRequestPacket:
                    break;
                case LogoutRequestPacket:
                    throw new IOException("server requested data connection logout");
                default:
                    throw new InvalidDataException(
                        $"packet {packet.Command} is not allowed on the data connection");
            }
        }
    }

    private async Task DispatchControlAsync(
        Packet packet, FrameWriter writer, NatClientHandler nat,
        DirectHttpHandler directHttp, CancellationToken cancellationToken)
    {
        switch (packet)
        {
            case LoginResponsePacket response:
                throw new InvalidDataException("duplicate LOGIN_RESPONSE on authenticated control connection");

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
                throw new InvalidDataException(
                    $"NAT packet {natMessage.NatMessageType} received on control connection");

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
        var from = FirstNonEmpty(message.ClientName, "server");
        var rawBody = message.Message ?? "";
        var bytes = System.Text.Encoding.UTF8.GetBytes(rawBody);
        if (PeerAppMessageCodec.LooksLike(bytes) && PeerAppMessageCodec.TryDecode(bytes, out var envelope))
        {
            from = FirstNonEmpty(envelope.FromClientName, from);
            rawBody = envelope.Attachment is null
                ? envelope.Message ?? ""
                : PeerAppMessageCodec.DisplayText(envelope);
        }
        if (_observer?.OnRawClientMessage(from, rawBody) == true)
        {
            return;
        }
        var body = DisplayClientMessage(message.Message ?? "");
        PublishClientMessage(new ClientMessageSnapshot
        {
            Id = Guid.NewGuid().ToString("N"),
            Direction = "IN",
            FromClientName = from,
            ToClientName = FirstNonEmpty(message.ToClientName, runtime?.ClientName),
            Message = body,
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
        SpecusConfigSnapshot? snapshot;
        try
        {
            snapshot = JsonSerializer.Deserialize<SpecusConfigSnapshot>(payload, SpecusClientConfigLoader.JsonOptions);
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
        await nat.ApplyConfigAsync(snapshot.SpecusConfigList).ConfigureAwait(false);
        directHttp.ApplyRoutes(snapshot.HttpSpecusConfigList);
        PublishRoutes(snapshot.SpecusConfigList, snapshot.HttpSpecusConfigList);
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
        _observer?.OnStatusChanged(SpecusClientStatusSnapshot.FromRuntime(
            _runtime, phase, detail, running, controlConnected, loggedIn));
    }

    private void PublishRoutes(
        IEnumerable<SpecusConfigEntry>? tcpRoutes,
        IEnumerable<HttpSpecusConfigEntry>? httpRoutes)
    {
        _observer?.OnRoutesChanged(SpecusClientRoutesSnapshot.FromRoutes(tcpRoutes, httpRoutes));
    }

    private void PublishClientMessage(ClientMessageSnapshot snapshot)
    {
        _observer?.OnClientMessage(snapshot);
    }

    private static string FirstNonEmpty(params string?[] values)
    {
        return values.FirstOrDefault(value => !string.IsNullOrWhiteSpace(value))?.Trim() ?? "";
    }

    private static string DisplayClientMessage(string body)
    {
        if (string.IsNullOrWhiteSpace(body))
        {
            return "";
        }
        var bytes = System.Text.Encoding.UTF8.GetBytes(body);
        return PeerAppMessageCodec.LooksLike(bytes) && PeerAppMessageCodec.TryDecode(bytes, out var message)
            ? PeerAppMessageCodec.DisplayText(message)
            : body;
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
        => new(reason, SpecusControlClient.ClassifyControlLoginFailure(reason));

    private static string ReasonOrDefaultValue(string? reason)
        => string.IsNullOrWhiteSpace(reason) ? "login rejected" : reason;
}
