using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.EntityFrameworkCore;
using Specus.Protocol;
using Specus.Protocol.Packets;
using Specus.Server.Authentication;
using Specus.Server.ControlChannel;
using Specus.Server.Data;
using Specus.Server.Data.Entities;
using Specus.Server.Nat;
using Specus.Server.PeerMesh;
using Specus.Server.ProductMetrics;
using Specus.Server.Sessions;
using Specus.Server.WebSockets;

namespace Specus.Server.Services;

/// <summary>
/// Routes inbound packets on one control connection: login, heartbeat, logout, NAT data, and
/// Direct HTTP responses. This mirrors Java's Netty pipeline ordering, but keeps the handlers as
/// one explicit async switch because the .NET port has a single framed stream abstraction instead
/// of mutable Netty pipeline stages.
///
/// <para>Threading: <see cref="DispatchAsync"/> runs on the connection's read loop. Login work
/// is offloaded to <see cref="LoginExecutor"/> so the read loop stays responsive — same shape
/// as Java's <c>ManagedLoginRequestHandler</c>.</para>
/// </summary>
public sealed class ControlChannelDispatcher : IControlChannelDispatcher
{
    private readonly IServiceProvider _services;
    private readonly LoginExecutor _loginExecutor;
    private readonly SessionRegistry _sessions;
    private readonly NatServerHandler _nat;
    private readonly ClientMessagesHub _clientMessages;
    private readonly ILogger<ControlChannelDispatcher> _logger;

    public ControlChannelDispatcher(IServiceProvider services, LoginExecutor loginExecutor,
        SessionRegistry sessions, NatServerHandler nat,
        ClientMessagesHub clientMessages,
        ILogger<ControlChannelDispatcher> logger)
    {
        _services = services;
        _loginExecutor = loginExecutor;
        _sessions = sessions;
        _nat = nat;
        _clientMessages = clientMessages;
        _logger = logger;
    }

    public Task OnConnectionOpenedAsync(SpecusConnectionContext context)
    {
        _logger.LogDebug("connection opened: channel={ChannelId} remote={Remote}",
            context.ChannelId, context.RemoteAddress);
        return Task.CompletedTask;
    }

    public async Task DispatchAsync(SpecusConnectionContext context, Packet packet)
    {
        // Auth gate: every packet other than LoginRequest requires the connection to be logged
        // in. The Java AuthHandler removes itself after first success; here we just check the
        // session registry on every dispatch, which is O(1) and avoids pipeline mutation.
        if (packet is LoginRequestPacket && context.ClientName is not null)
        {
            context.MarkDisconnectIfAbsent(DisconnectReason.ProtocolViolation);
            throw new InvalidOperationException("duplicate login on authenticated channel");
        }
        if (packet is not LoginRequestPacket && !_sessions.HasLogin(context))
        {
            context.MarkDisconnectIfAbsent(DisconnectReason.ProtocolViolation);
            _logger.LogWarning("[{ChannelId}] non-login packet on unauthenticated channel: {Cmd}",
                context.ChannelId, packet.Command);
            throw new InvalidOperationException("packet on unauthenticated channel");
        }
        if (context.ClientName is not null && !PacketAllowedForRole(context.ConnectionRole, packet))
        {
            context.MarkDisconnectIfAbsent(DisconnectReason.ProtocolViolation);
            throw new InvalidOperationException("packet is not allowed on this connection role");
        }

        switch (packet)
        {
            case LoginRequestPacket login:
                await HandleLoginAsync(context, login).ConfigureAwait(false);
                return;
            case HeartbeatRequestPacket:
                // Java's HeartbeatRequestHandler — answer with a fresh response packet. The
                // idle watchdog tracks our last-write timestamp.
                await context.Writer.WriteAsync(new HeartbeatResponsePacket(), context.Lifetime)
                    .ConfigureAwait(false);
                return;
            case LogoutRequestPacket:
                HandleLogout(context);
                return;
            case NatMessagePacket nat:
                await _nat.HandleAsync(context, nat).ConfigureAwait(false);
                return;
            case MessageRequestPacket message when message.MessageType == MessageType.ClientToClient:
                await HandleClientToClientAsync(context, message).ConfigureAwait(false);
                return;
            case MessageRequestPacket message when message.MessageType == MessageType.PeerControl:
                await using (var scope = _services.CreateAsyncScope())
                {
                    var peerMesh = scope.ServiceProvider.GetRequiredService<PeerMeshService>();
                    await RoutePeerSignalAsync(
                            () => peerMesh.HandleSignalAsync(message, context.ClientName!, context.Lifetime,
                                context.ClientSessionId),
                            _logger, context.ChannelId, message.ToClientName)
                        .ConfigureAwait(false);
                }
                return;
            default:
                // MESSAGE_* and future packet types are known on the wire but not meaningful to
                // the server dispatch path yet. Debug logging avoids alarming noise from benign
                // forward-compatible client builds.
                _logger.LogDebug("[{ChannelId}] dropped unhandled packet: {Cmd}",
                    context.ChannelId, packet.Command);
                return;
        }
    }

    /// <summary>
    /// Runs a client's peer signal through the mesh.
    /// </summary>
    /// <remarks>
    /// The read loop closes a connection on any exception the dispatcher lets through, which is right
    /// for a message that breaks the protocol and wrong for one that merely could not be delivered.
    /// A peer that has just gone offline is not the sender's doing, and every client still signalling
    /// it was being disconnected for it. So an undeliverable signal is dropped here, and everything
    /// else still closes, now with the reason in the log.
    /// </remarks>
    internal static async Task RoutePeerSignalAsync(Func<Task> handle, ILogger logger, string channelId,
        string? target)
    {
        try
        {
            await handle().ConfigureAwait(false);
        }
        catch (PeerSignalUndeliverableException ex)
        {
            logger.LogDebug("[{ChannelId}] dropped undeliverable peer signal to {Target}: {Reason}",
                channelId, target, ex.Message);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            logger.LogWarning("[{ChannelId}] peer signal rejected; closing the sender's connection: {Reason}",
                channelId, ex.Message);
            throw;
        }
    }

    internal static bool PacketAllowedForRole(string? role, Packet packet)
    {
        if (role == ConnectionRole.Control)
        {
            return packet is MessageRequestPacket or HeartbeatRequestPacket
                or HeartbeatResponsePacket or LogoutRequestPacket;
        }
        return role == ConnectionRole.Data
               && packet is NatMessagePacket or HeartbeatRequestPacket
                   or HeartbeatResponsePacket or LogoutRequestPacket;
    }

    private async Task HandleClientToClientAsync(SpecusConnectionContext context, MessageRequestPacket request)
    {
        if (string.IsNullOrWhiteSpace(context.ClientName)
            || string.IsNullOrWhiteSpace(request.ToClientName)
            || string.IsNullOrWhiteSpace(request.Message))
        {
            _logger.LogWarning("[{ChannelId}] client message rejected: invalid source/target/body",
                context.ChannelId);
            return;
        }

        await using var scope = _services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<SpecusDbContext>();
        var peerMesh = scope.ServiceProvider.GetRequiredService<PeerMeshService>();
        var source = await db.ClientAccounts.AsNoTracking()
            .FirstOrDefaultAsync(c => c.ClientName == context.ClientName, context.Lifetime)
            .ConfigureAwait(false);
        if (source is null || !source.Enabled)
        {
            _logger.LogWarning("[{ChannelId}] client message rejected: source account unavailable source={Source}",
                context.ChannelId, context.ClientName);
            return;
        }
        var targetName = request.ToClientName.Trim();
        if (targetName.StartsWith("admin:", StringComparison.OrdinalIgnoreCase))
        {
            var delivered = await _clientMessages.DeliverFromClientAsync(
                source, targetName, request.Message, context.Lifetime).ConfigureAwait(false);
            if (!delivered)
            {
                _logger.LogInformation(
                    "[{ChannelId}] client message admin target offline source={Source} target={Target}",
                    context.ChannelId, source.ClientName, targetName);
            }
            return;
        }
        var target = await db.ClientAccounts.AsNoTracking()
            .FirstOrDefaultAsync(c => c.ClientName == targetName, context.Lifetime)
            .ConfigureAwait(false);
        if (target is null || !target.Enabled)
        {
            _logger.LogWarning("[{ChannelId}] client message rejected: account unavailable source={Source} target={Target}",
                context.ChannelId, context.ClientName, targetName);
            return;
        }
        if (!await peerMesh.CanPeerAsync(source, target, context.Lifetime).ConfigureAwait(false))
        {
            _logger.LogWarning("[{ChannelId}] client message rejected: peer access denied source={Source} target={Target}",
                context.ChannelId, source.ClientName, target.ClientName);
            return;
        }

        var targetSession = _sessions.Find(target.ClientName);
        if (targetSession is null)
        {
            _logger.LogInformation("[{ChannelId}] client message target offline source={Source} target={Target}",
                context.ChannelId, source.ClientName, target.ClientName);
            return;
        }

        try
        {
            await targetSession.Writer.WriteAsync(new MessageResponsePacket
            {
                ClientName = source.ClientName,
                ToClientName = target.ClientName,
                MessageType = MessageType.ClientToClient,
                Message = request.Message,
            }, targetSession.Lifetime).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (targetSession.Lifetime.IsCancellationRequested)
        {
            _logger.LogInformation("[{ChannelId}] client message target closed during fallback source={Source} target={Target}",
                context.ChannelId, source.ClientName, target.ClientName);
            return;
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _logger.LogWarning(ex, "[{ChannelId}] client message fallback write failed source={Source} target={Target}",
                context.ChannelId, source.ClientName, target.ClientName);
            return;
        }
        _logger.LogInformation("[{ChannelId}] client message fallback delivered source={Source} target={Target}",
            context.ChannelId, source.ClientName, target.ClientName);
    }

    public async Task OnConnectionClosedAsync(SpecusConnectionContext context)
    {
        var dataConnection = context.ConnectionRole == ConnectionRole.Data;
        if (dataConnection)
        {
            await _nat.OnConnectionClosedAsync(context).ConfigureAwait(false);
        }

        if (context.ClientName is { } name)
        {
            _sessions.Unbind(name, context);
        }

        if (dataConnection)
        {
            return;
        }
        if (context.ClientName is { } controlName
            && _sessions.FindData(controlName) is { } data
            && data.ClientSessionId == context.ClientSessionId)
        {
            data.CloseAsync();
        }

        var reason = context.ReadDisconnectReason() ?? DisconnectReason.ClientClosed;

        // The connection is gone, but we want the row stamped. Run on a fresh DI scope so the
        // DbContext lifetime doesn't outlive the request.
        try
        {
            await using var scope = _services.CreateAsyncScope();
            var clientService = scope.ServiceProvider.GetRequiredService<ClientAccountService>();
            clientService.MarkNettyDisconnected(context.ClientSessionId);
            var peerMesh = scope.ServiceProvider.GetRequiredService<PeerMeshService>();
            if (context.ClientSessionId is { } disconnectedSessionId)
            {
                await peerMesh.OnClientDisconnectedAsync(disconnectedSessionId, CancellationToken.None)
                    .ConfigureAwait(false);
            }
            if (context.ClientName is { } departedName)
            {
                // After the unbind above, so the roster its peers are sent counts it as offline.
                await peerMesh.PushOnLogoutAsync(departedName, CancellationToken.None).ConfigureAwait(false);
            }
            if (context.ConnectionRecordId is not { } recordId)
            {
                return;
            }
            var records = scope.ServiceProvider.GetRequiredService<ConnectionRecordService>();
            await records.RecordDisconnectAsync(recordId, reason, CancellationToken.None)
                .ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "[{ChannelId}] failed to record disconnect", context.ChannelId);
        }
    }

    private async Task HandleLoginAsync(SpecusConnectionContext context, LoginRequestPacket packet)
    {
        context.ReadGate.Pause();
        if (!_loginExecutor.TryEnqueue(async () =>
            {
                try
                {
                    await ProcessLoginAsync(context, packet).ConfigureAwait(false);
                }
                finally
                {
                    context.ReadGate.Resume();
                }
            }))
        {
            _logger.LogWarning("[{ChannelId}] login executor full — rejecting client={ClientName}",
                context.ChannelId, packet.ClientName);
            context.MarkDisconnectIfAbsent(DisconnectReason.ServerBusy);
            await SendThenCloseAsync(context, busyResponse(packet)).ConfigureAwait(false);
        }

        static LoginResponsePacket busyResponse(LoginRequestPacket request) => new()
        {
            ClientName = request.ClientName,
            Success = false,
            Reason = "服务器繁忙，请稍后重试",
        };
    }

    private async Task ProcessLoginAsync(SpecusConnectionContext context, LoginRequestPacket packet)
    {
        await using var scope = _services.CreateAsyncScope();
        var clientService = scope.ServiceProvider.GetRequiredService<ClientAccountService>();
        if (!ConnectionRole.IsValid(packet.ConnectionRole))
        {
            await SendThenCloseAsync(context, new LoginResponsePacket
            {
                ClientName = packet.ClientName,
                Success = false,
                Reason = "登录包缺少有效 connectionRole",
            }).ConfigureAwait(false);
            return;
        }
        var dataConnection = packet.ConnectionRole == ConnectionRole.Data;

        AuthenticationResult result;
        try
        {
            result = dataConnection
                ? await clientService.AuthenticateDataAsync(
                        packet, context.ChannelId, context.RemoteAddress, context.Lifetime)
                    .ConfigureAwait(false)
                : await clientService.AuthenticateAsync(
                        packet, context.ChannelId, context.RemoteAddress, context.Lifetime)
                    .ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            return;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "[{ChannelId}] auth failed for client={ClientName}",
                context.ChannelId, packet.ClientName);
            context.MarkDisconnectIfAbsent(DisconnectReason.IoError);
            context.CloseAsync();
            return;
        }

        if (result.Success && dataConnection)
        {
            var control = _sessions.Find(packet.ClientName!);
            if (control is null || control.ClientSessionId != packet.ClientSessionId)
            {
                result = AuthenticationResult.Fail(result.Account, "数据连接未找到匹配的控制连接",
                    result.AuditTenantId);
            }
        }

        long? recordId = null;
        if (!dataConnection)
        {
            try
            {
                var records = scope.ServiceProvider.GetRequiredService<ConnectionRecordService>();
                recordId = await records.RecordConnectionAsync(
                        result, packet.ClientName ?? string.Empty, context.ChannelId,
                        context.RemoteAddress, context.Lifetime)
                    .ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "[{ChannelId}] failed to write connection record", context.ChannelId);
                context.MarkDisconnectIfAbsent(DisconnectReason.IoError);
                context.CloseAsync();
                return;
            }
        }

        var response = new LoginResponsePacket
        {
            ClientName = packet.ClientName,
            Success = result.Success,
            Reason = result.Reason,
        };

        SpecusConnectionContext? displaced = null;
        if (result.Success)
        {
            context.ConnectionRecordId = recordId;
            context.OnLoginSuccess(packet.ClientName!, DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                packet.ClientSessionId, packet.ConnectionRole!, result.Account!.TenantId);
            if (dataConnection)
            {
                displaced = _sessions.ReplaceData(packet.ClientName!, context);
                _nat.Attach(context);
            }
            else
            {
                displaced = _sessions.Replace(packet.ClientName!, context);
            }
        }

        try
        {
            await context.Writer.WriteAsync(response, context.Lifetime).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _logger.LogDebug(ex, "[{ChannelId}] login response write failed", context.ChannelId);
            context.MarkDisconnectIfAbsent(DisconnectReason.IoError);
            context.CloseAsync();
            return;
        }

        if (result.Success)
        {
            displaced?.CloseAsync();

            if (dataConnection)
            {
                _logger.LogInformation("[{ChannelId}] dedicated data connection ready for {ClientName}",
                    context.ChannelId, packet.ClientName);
                return;
            }

            if (result.Account is not null)
            {
                // Never throws: product metrics must not affect the login it observes.
                await scope.ServiceProvider.GetRequiredService<ProductMetricsService>()
                    .MilestoneAsync(result.Account.TenantId, result.Account.OwnerUsername,
                        ProductMetricsModel.StepClientOnline, context.Lifetime)
                    .ConfigureAwait(false);
            }

            // The NAT_CONTROL and the Peer Mesh login pushes each only log what goes wrong, as Java and
            // Go do: neither closes the connection nor stops the other. A NAT_CONTROL that does not fit
            // one MESSAGE, or a connection that cannot be written, is logged inside and does not throw;
            // a database error leaves a healthy connection, and closing it only had the client log in
            // again. A connection that cannot be written closed itself on the failed write, and the
            // pushes after it write nothing. See "NAT_CONTROL 写失败与数据库错误" and "帧写入失败" in
            // protocol/spec/control-protocol.md.
            try
            {
                var natControl = scope.ServiceProvider.GetRequiredService<NatControlService>();
                await natControl.PushOnLoginAsync(packet.ClientName!, context.Lifetime)
                    .ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (context.Lifetime.IsCancellationRequested)
            {
                return;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "[{ChannelId}] NAT_CONTROL push failed for {ClientName}; the connection is kept",
                    context.ChannelId, packet.ClientName);
            }

            try
            {
                var peerMesh = scope.ServiceProvider.GetRequiredService<PeerMeshService>();
                if (result.Account is not null)
                {
                    await peerMesh.PushOnLoginAsync(result.Account, context.Lifetime).ConfigureAwait(false);
                }
            }
            catch (OperationCanceledException) when (context.Lifetime.IsCancellationRequested)
            {
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "[{ChannelId}] Peer Mesh login push failed for {ClientName}; the connection is kept",
                    context.ChannelId, packet.ClientName);
            }
        }
        else
        {
            // Login failure: mark + close so the audit row gets stamped LOGIN_FAILURE.
            context.MarkDisconnectIfAbsent(DisconnectReason.LoginFailure);
            context.CloseAsync();
        }
    }

    private static async Task SendThenCloseAsync(SpecusConnectionContext context, Packet finalPacket)
    {
        try
        {
            await context.Writer.WriteAsync(finalPacket).ConfigureAwait(false);
        }
        catch
        {
            // Already going down — ignore.
        }
        context.CloseAsync();
    }

    private void HandleLogout(SpecusConnectionContext context)
    {
        if (context.ClientName is { } name)
        {
            _sessions.Unbind(name, context);
        }
        // Logout response goes on the same connection; socket close is driven by the client's
        // FIN immediately after.
        _ = context.Writer.WriteAsync(new LogoutResponsePacket { Success = true });
    }
}
