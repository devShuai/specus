using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using ShuaiTunnel.Protocol.Packets;
using ShuaiTunnel.Server.Authentication;
using ShuaiTunnel.Server.ControlChannel;
using ShuaiTunnel.Server.Data.Entities;
using ShuaiTunnel.Server.Http;
using ShuaiTunnel.Server.Nat;
using ShuaiTunnel.Server.Sessions;

namespace ShuaiTunnel.Server.Services;

/// <summary>
/// Routes inbound packets on a control connection to the right handler. Mirrors what Netty
/// pipelines do in Java — auth gate, login, heartbeat reply, logout — but expressed as plain
/// async dispatch in one place because we have far fewer handlers than the Java version (no
/// Phase 3+ NAT/HTTP yet).
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
    private readonly DirectHttpDispatcher _directHttp;
    private readonly ILogger<ControlChannelDispatcher> _logger;

    public ControlChannelDispatcher(IServiceProvider services, LoginExecutor loginExecutor,
        SessionRegistry sessions, NatServerHandler nat, DirectHttpDispatcher directHttp,
        ILogger<ControlChannelDispatcher> logger)
    {
        _services = services;
        _loginExecutor = loginExecutor;
        _sessions = sessions;
        _nat = nat;
        _directHttp = directHttp;
        _logger = logger;
    }

    public Task OnConnectionOpenedAsync(TunnelConnectionContext context)
    {
        _logger.LogDebug("connection opened: channel={ChannelId} remote={Remote}",
            context.ChannelId, context.RemoteAddress);
        return Task.CompletedTask;
    }

    public async Task DispatchAsync(TunnelConnectionContext context, Packet packet)
    {
        // Auth gate: every packet other than LoginRequest requires the connection to be logged
        // in. The Java AuthHandler removes itself after first success; here we just check the
        // session registry on every dispatch, which is O(1) and avoids pipeline mutation.
        if (packet is not LoginRequestPacket && !_sessions.HasLogin(context))
        {
            context.MarkDisconnectIfAbsent(DisconnectReason.ProtocolViolation);
            _logger.LogWarning("[{ChannelId}] non-login packet on unauthenticated channel: {Cmd}",
                context.ChannelId, packet.Command);
            throw new InvalidOperationException("packet on unauthenticated channel");
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
            case DirectHttpResponsePacket response:
                _directHttp.Ack(response);
                return;
            default:
                // Phase 4+ packets (DIRECT_HTTP_*, MESSAGE_*) — known on the wire
                // but not yet wired up. Logging at debug avoids alarming nooses on benign
                // forward-compat client builds.
                _logger.LogDebug("[{ChannelId}] dropped unhandled packet: {Cmd}",
                    context.ChannelId, packet.Command);
                return;
        }
    }

    public async Task OnConnectionClosedAsync(TunnelConnectionContext context)
    {
        await _nat.OnConnectionClosedAsync(context).ConfigureAwait(false);

        if (context.ClientName is { } name)
        {
            _sessions.Unbind(name, context);
        }

        if (context.ConnectionRecordId is not { } recordId)
        {
            return;
        }
        var reason = context.ReadDisconnectReason() ?? DisconnectReason.ClientClosed;

        // The connection is gone, but we want the row stamped. Run on a fresh DI scope so the
        // DbContext lifetime doesn't outlive the request.
        try
        {
            await using var scope = _services.CreateAsyncScope();
            var records = scope.ServiceProvider.GetRequiredService<ConnectionRecordService>();
            await records.RecordDisconnectAsync(recordId, reason, CancellationToken.None)
                .ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "[{ChannelId}] failed to record disconnect", context.ChannelId);
        }
    }

    private async Task HandleLoginAsync(TunnelConnectionContext context, LoginRequestPacket packet)
    {
        if (!_loginExecutor.TryEnqueue(() => ProcessLoginAsync(context, packet)))
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

    private async Task ProcessLoginAsync(TunnelConnectionContext context, LoginRequestPacket packet)
    {
        await using var scope = _services.CreateAsyncScope();
        var clientService = scope.ServiceProvider.GetRequiredService<ClientAccountService>();
        var records = scope.ServiceProvider.GetRequiredService<ConnectionRecordService>();

        AuthenticationResult result;
        try
        {
            result = await clientService.AuthenticateAsync(packet, context.Lifetime).ConfigureAwait(false);
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

        long recordId;
        try
        {
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

        var response = new LoginResponsePacket
        {
            ClientName = packet.ClientName,
            Success = result.Success,
            Reason = result.Reason,
        };

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
            context.ConnectionRecordId = recordId;
            context.OnLoginSuccess(packet.ClientName!, DateTimeOffset.UtcNow.ToUnixTimeMilliseconds());

            // Active replacement: if a prior session exists, close its socket so the new login
            // takes its place. Mirrors Java's <c>SessionUtil.bindSession</c>.
            var displaced = _sessions.Replace(packet.ClientName!, context);
            displaced?.CloseAsync();

            try
            {
                var natControl = scope.ServiceProvider.GetRequiredService<NatControlService>();
                await natControl.PushOnLoginAsync(packet.ClientName!, context.Lifetime)
                    .ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                return;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "[{ChannelId}] NAT_CONTROL push failed", context.ChannelId);
                context.MarkDisconnectIfAbsent(DisconnectReason.IoError);
                context.CloseAsync();
            }
        }
        else
        {
            // Login failure: mark + close so the audit row gets stamped LOGIN_FAILURE.
            context.MarkDisconnectIfAbsent(DisconnectReason.LoginFailure);
            context.CloseAsync();
        }
    }

    private static async Task SendThenCloseAsync(TunnelConnectionContext context, Packet finalPacket)
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

    private void HandleLogout(TunnelConnectionContext context)
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
