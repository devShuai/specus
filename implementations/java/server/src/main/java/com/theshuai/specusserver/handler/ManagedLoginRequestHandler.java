package com.theshuai.specusserver.handler;

import com.theshuai.common.protocol.request.LoginRequestPacket;
import com.theshuai.common.protocol.response.LoginResponsePacket;
import com.theshuai.common.protocol.ConnectionRole;
import com.theshuai.common.codec.Spliter;
import com.theshuai.common.session.Session;
import com.theshuai.specusserver.session.SessionUtil;
import com.theshuai.specusserver.session.ControlLifecycle;
import com.theshuai.specusserver.attribute.ServerAttributes;
import com.theshuai.specusserver.management.model.DisconnectReason;
import com.theshuai.specusserver.management.service.AuthenticationResult;
import com.theshuai.specusserver.management.service.ClientAuthService;
import com.theshuai.specusserver.management.service.ConnectionRecordService;
import com.theshuai.specusserver.management.service.NatControlService;
import com.theshuai.specusserver.management.service.PeerSignalService;
import com.theshuai.specusserver.config.NettyServerProperties;
import com.theshuai.specusserver.productmetrics.ProductMetricsService;
import io.netty.channel.ChannelHandler;
import io.netty.channel.Channel;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.SimpleChannelInboundHandler;
import io.netty.util.AttributeKey;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.atomic.AtomicInteger;

@Component
@ChannelHandler.Sharable
@Slf4j
public class ManagedLoginRequestHandler extends SimpleChannelInboundHandler<LoginRequestPacket> {
    private static final AttributeKey<Long> CONNECTION_RECORD_ID = AttributeKey.valueOf("connectionRecordId");
    private static final AttributeKey<Boolean> LOGIN_STARTED = AttributeKey.valueOf("loginStarted");

    private final ClientAuthService clientAuthService;
    private final ConnectionRecordService connectionRecordService;
    private final NatControlService natControlService;
    private final PeerSignalService peerSignalService;
    private final ExecutorService loginExecutor;
    private final NettyServerProperties nettyProperties;
    private final ProductMetricsService productMetrics;

    public ManagedLoginRequestHandler(ClientAuthService clientAuthService,
                                      ConnectionRecordService connectionRecordService,
                                      NatControlService natControlService,
                                      PeerSignalService peerSignalService,
                                      NettyServerProperties nettyProperties,
                                      @Qualifier("loginExecutor") ExecutorService loginExecutor,
                                      ProductMetricsService productMetrics) {
        this.clientAuthService = clientAuthService;
        this.connectionRecordService = connectionRecordService;
        this.natControlService = natControlService;
        this.peerSignalService = peerSignalService;
        this.nettyProperties = nettyProperties;
        this.loginExecutor = loginExecutor;
        this.productMetrics = productMetrics;
    }

    @Override
    protected void channelRead0(ChannelHandlerContext ctx, LoginRequestPacket packet) {
        if (ctx.channel().attr(LOGIN_STARTED).setIfAbsent(Boolean.TRUE) != null) {
            log.warn("duplicate login rejected: channel={} client={}",
                    ctx.channel().id().asLongText(), packet.getClientName());
            DisconnectReason.markIfAbsent(ctx.channel(), DisconnectReason.PROTOCOL_VIOLATION);
            ctx.close();
            return;
        }
        // The decoded packet is a plain POJO (not reference-counted), so it stays valid after this
        // method returns and is safe to hand to a worker thread. Keep the event loop free of DB work.
        try {
            loginExecutor.execute(() -> handleLogin(ctx, packet));
        } catch (RejectedExecutionException e) {
            log.warn("login rejected, server busy: client={}", packet.getClientName());
            // 同样：拒绝服务的回执发出后立即关闭，避免僵尸连接。
            DisconnectReason.markIfAbsent(ctx.channel(), DisconnectReason.SERVER_BUSY);
            ctx.writeAndFlush(busyResponse(packet))
                    .addListener(io.netty.channel.ChannelFutureListener.CLOSE);
        }
    }

    private void handleLogin(ChannelHandlerContext ctx, LoginRequestPacket packet) {
        try {
            boolean control = ConnectionRole.CONTROL.equals(packet.getConnectionRole());
            Long clientId = control ? clientAuthService.controlClientId(packet.getAccessToken()) : null;
            try (var ignored = clientId == null ? null : ControlLifecycle.acquire(clientId, ctx.channel());
                 var pending = clientId == null ? null : ControlLifecycle.beginPublication(clientId, ctx.channel())) {
                handleLoginUnderLease(ctx, packet, clientId);
            }
        } catch (Exception failure) {
            if (failure instanceof InterruptedException) Thread.currentThread().interrupt();
            log.warn("CONTROL admission stopped for client={}: {}", packet.getClientName(), failure.getClass().getSimpleName());
            if (failure instanceof RejectedExecutionException) {
                DisconnectReason.markIfAbsent(ctx.channel(), DisconnectReason.SERVER_BUSY);
                ctx.writeAndFlush(busyResponse(packet)).addListener(io.netty.channel.ChannelFutureListener.CLOSE);
            } else ctx.close();
        }
    }

    private void handleLoginUnderLease(ChannelHandlerContext ctx, LoginRequestPacket packet, Long clientId) {
        AuthenticationResult admitted = null;
        long recorded = 0;
        boolean dataConnection = ConnectionRole.DATA.equals(packet.getConnectionRole());
        var publication = new CompletableFuture<Boolean>();
        // 0 queued/not started, 1 owned by the I/O callback, 2 cancelled before that callback.
        var publicationState = new AtomicInteger();
        try {
            boolean validRole = ConnectionRole.isValid(packet.getConnectionRole());
            AuthenticationResult authentication;
            if (!validRole || !StringUtils.hasText(packet.getAccessToken())) {
                authentication = AuthenticationResult.failure(null, validRole
                        ? "客户端必须先通过 HTTP 登录获取访问令牌" : "登录包缺少有效 connectionRole");
            } else if (dataConnection) {
                authentication = clientAuthService.authenticateNetty(packet, ctx.channel().id().asLongText(),
                        String.valueOf(ctx.channel().remoteAddress()), true);
            } else if (clientId == null) {
                authentication = AuthenticationResult.failure(null, "客户端访问令牌无效");
            } else {
                authentication = clientAuthService.authenticateNetty(packet, ctx.channel().id().asLongText(),
                        String.valueOf(ctx.channel().remoteAddress()), false, clientId);
            }
            Channel authenticatedControl = authentication.success() && dataConnection
                    ? SessionUtil.getMatchingControl(packet.getClientName(), authentication.clientSessionId()) : null;
            if (authentication.success() && dataConnection && authenticatedControl == null) {
                authentication = AuthenticationResult.failure(authentication.account(), "数据连接要求控制连接先登录：未找到匹配的控制连接");
            }
            AuthenticationResult finalAuthentication = authentication;
            admitted = authentication;
            long connectionRecordId = dataConnection ? 0L : connectionRecordService.recordConnection(
                    finalAuthentication, packet, ctx.channel().id().asLongText(),
                    String.valueOf(ctx.channel().remoteAddress()));
            recorded = connectionRecordId;
            if (authentication.success() && !dataConnection) {
                peerSignalService.onControlConnected(authentication.account(), authentication.clientSessionId());
            }

            LoginResponsePacket response = new LoginResponsePacket();
            response.setVersion(packet.getVersion());
            response.setClientName(packet.getClientName());
            response.setSuccess(finalAuthentication.success());
            response.setReason(finalAuthentication.reason());

            // Channel-affecting work (attribute, session bind, write) must run on the channel's
            // event loop so it stays ordered relative to other I/O on this connection.
            Runnable publish = () -> {
                if (!publicationState.compareAndSet(0,1)) return;
                try {
                if (!ctx.channel().isActive()) {publication.complete(false);return;}
                if (finalAuthentication.success()) {
                    if (connectionRecordId > 0) {
                        ctx.channel().attr(CONNECTION_RECORD_ID).set(connectionRecordId);
                    }
                    ctx.channel().attr(com.theshuai.specusserver.attribute.ServerAttributes.LOGIN_TIME_MS).set(System.currentTimeMillis());
                    ctx.channel().attr(com.theshuai.specusserver.attribute.ServerAttributes.TENANT_ID).set(
                            finalAuthentication.account().getTenantId());
                    ctx.channel().attr(ServerAttributes.CLIENT_ID).set(finalAuthentication.account().getId());
                    ctx.channel().attr(com.theshuai.specusserver.attribute.ServerAttributes.CONNECTION_ROLE).set(
                            packet.getConnectionRole());
                    if (finalAuthentication.clientSessionId() != null) {
                        ctx.channel().attr(com.theshuai.specusserver.attribute.ServerAttributes.CLIENT_SESSION_ID).set(
                                finalAuthentication.clientSessionId());
                    }
                    if (dataConnection) {
                        if (!SessionUtil.bindDataSession(new Session(packet.getClientName()), ctx.channel(),
                                authenticatedControl, finalAuthentication.clientSessionId())) {
                            // Authentication ran on a worker. Its CONTROL may have gone away or
                            // been replaced while this event-loop callback was queued.
                            response.setSuccess(false);
                            response.setReason("数据连接要求控制连接先登录：原控制连接已改变，请重新建立数据连接");
                            ctx.channel().attr(ServerAttributes.TENANT_ID).set(null);
                            ctx.channel().attr(ServerAttributes.CONNECTION_ROLE).set(null);
                            ctx.channel().attr(ServerAttributes.CLIENT_SESSION_ID).set(null);
                            ctx.channel().attr(ServerAttributes.CLIENT_ID).set(null);
                            ctx.channel().attr(ServerAttributes.LOGIN_TIME_MS).set(null);
                        }
                    } else {
                        SessionUtil.bindControlSession(new Session(packet.getClientName()), ctx.channel());
                    }
                    if (response.isSuccess() && ctx.pipeline().context(Spliter.PRE_AUTH_HANDLER_NAME) != null) {
                        ctx.pipeline().replace(
                                Spliter.PRE_AUTH_HANDLER_NAME,
                                Spliter.AUTHENTICATED_HANDLER_NAME,
                                new Spliter(nettyProperties.getMaxFrameSize()));
                    }
                }
                io.netty.channel.ChannelFuture writeFuture = ctx.writeAndFlush(response);
                if (response.isSuccess()) {
                    if (!dataConnection) {
                        // pushOnLogin reads the DB; run it off the event loop, after the session is bound.
                        submit(() -> pushNatControlOnLogin(packet.getClientName()));
                        submit(() -> peerSignalService.pushOnLogin(finalAuthentication.account()));
                        submit(() -> productMetrics.clientOnline(finalAuthentication.account()));
                    }
                } else {
                    // 登录失败必须主动关连接，否则客户端心跳会让 server 端 reader idle 一直不超时，
                    // 形成"无 session 但保活"的僵尸连接，浪费资源也阻塞合法重连。
                    // 这条登录失败的 DB 行 disconnectedAt 在 recordConnection 里已经写过，
                    // 这里关 channel 也无需再调 recordDisconnect（CONNECTION_RECORD_ID 没 set）。
                    DisconnectReason.markIfAbsent(ctx.channel(), DisconnectReason.LOGIN_FAILURE);
                    writeFuture.addListener(io.netty.channel.ChannelFutureListener.CLOSE);
                }
                publication.complete(response.isSuccess());
                } catch (Throwable failure) {
                    publication.completeExceptionally(failure);ctx.close();
                }
            };
            if (ctx.channel().eventLoop().inEventLoop()) publish.run();
            else ctx.channel().eventLoop().execute(publish);
            // Only CONTROL owns a lifecycle lease. Keep it until native ONLINE and the binding/raw
            // cursor publication agree; the event loop itself never waits on this lease or the DB.
            if (!dataConnection && !publication.get() && admitted.success()) {
                retireUnpublished(ctx, admitted, recorded);
            }
        } catch (Exception e) {
            if (publicationState.compareAndSet(0,2)) publication.complete(false);
            else publication.handle((accepted, failure) -> null).join();
            if (!dataConnection && admitted != null && admitted.success()) retireUnpublished(ctx, admitted, recorded);
            if (e instanceof InterruptedException) {
                Thread.currentThread().interrupt();
                log.debug("login admission interrupted for client={}",packet.getClientName());
            } else log.error("login handling failed for client={}", packet.getClientName(), e);
            DisconnectReason.markIfAbsent(ctx.channel(), DisconnectReason.IO_ERROR);
            ctx.close();
        }
    }

    private void retireUnpublished(ChannelHandlerContext ctx, AuthenticationResult authentication, long recordId) {
        try {
            if (clientAuthService.markNettyDisconnected(authentication.clientSessionId(), ctx.channel().id().asLongText())
                    || clientAuthService.isSessionDisconnected(authentication.clientSessionId(), authentication.account().getId())) {
                Channel obsolete = SessionUtil.getChannel(authentication.account().getClientName());
                if (obsolete != null && obsolete != ctx.channel()
                        && java.util.Objects.equals(obsolete.attr(ServerAttributes.CLIENT_SESSION_ID).get(), authentication.clientSessionId())) {
                    obsolete.close();
                }
                peerSignalService.onClientDisconnected(authentication.clientSessionId());
            }
        } catch (RuntimeException failure) {log.warn("unpublished CONTROL cleanup failed", failure);}
        if (recordId > 0 && ctx.channel().attr(CONNECTION_RECORD_ID).get() == null) {
            try {connectionRecordService.recordDisconnect(recordId, DisconnectReason.LOGIN_FAILURE);}
            catch (RuntimeException failure) {log.warn("unpublished CONTROL audit failed", failure);}
        }
    }

    @Override
    public void channelInactive(ChannelHandlerContext ctx) throws Exception {
        String role = ctx.channel().attr(com.theshuai.specusserver.attribute.ServerAttributes.CONNECTION_ROLE)
                .getAndSet(null);
        boolean dataConnection = ConnectionRole.DATA.equals(role);
        Long connectionRecordId = ctx.channel().attr(CONNECTION_RECORD_ID).getAndSet(null);
        Long clientSessionId = ctx.channel().attr(com.theshuai.specusserver.attribute.ServerAttributes.CLIENT_SESSION_ID)
                .getAndSet(null);
        Long clientId = ctx.channel().attr(ServerAttributes.CLIENT_ID).getAndSet(null);
        if (connectionRecordId != null) {
            long recordId = connectionRecordId;
            // 读通道属性还原 reason；缺省视为客户端主动 FIN。
            DisconnectReason marked = DisconnectReason.readFrom(ctx.channel());
            DisconnectReason reason = marked == null ? DisconnectReason.CLIENT_CLOSED : marked;
            submit(() -> connectionRecordService.recordDisconnect(recordId, reason));
        }
        if (clientSessionId != null && clientId != null && !dataConnection) {
            long sessionId = clientSessionId;
            submit(() -> {
                try (var ignored = ControlLifecycle.acquire(clientId, null)) {
                    if (clientAuthService.markNettyDisconnected(sessionId, ctx.channel().id().asLongText())
                            || clientAuthService.isSessionDisconnected(sessionId, clientId)) {
                        peerSignalService.onClientDisconnected(sessionId);
                    }
                } catch (InterruptedException interrupted) {
                    Thread.currentThread().interrupt();log.warn("CONTROL disconnect cleanup interrupted");
                }
            });
        }
        // The close-future listener has normally unbound the session already, closing the data
        // connection with it, so the departed client is read from what that unbind left behind.
        SessionUtil.unBindSession(ctx.channel());
        String departed = ctx.channel().attr(com.theshuai.specusserver.attribute.ServerAttributes.DEPARTED_CLIENT)
                .getAndSet(null);
        if (StringUtils.hasText(departed)) {
            // Submitted after the unbind, not with the tasks above: the executor can run before this
            // thread reaches the unbind, and a roster built then would still count it as online.
            submit(() -> peerSignalService.pushOnLogout(departed));
        }
        super.channelInactive(ctx);
    }

    @Override
    public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) throws Exception {
        // IO / 解码 / TLS 异常 —— 在 channelInactive 之前打标；不再 fire 给后续 handler，
        // 让 Netty 默认行为关 channel。
        DisconnectReason.markIfAbsent(ctx.channel(), DisconnectReason.IO_ERROR);
        log.debug("exceptionCaught on channel {}: {}", ctx.channel().id().asLongText(),
                cause == null ? "null" : cause.toString());
        super.exceptionCaught(ctx, cause);
    }

    /**
     * The NAT_CONTROL login push. Whatever keeps it from being sent, a database error included, is
     * only logged: the connection stays and the Peer Mesh login push, a task of its own, still runs.
     * See "NAT_CONTROL 写失败与数据库错误" in protocol/spec/control-protocol.md.
     */
    private void pushNatControlOnLogin(String clientName) {
        try {
            natControlService.pushOnLogin(clientName);
        } catch (RuntimeException failure) {
            log.error("[nat-control] push to {} on login failed; the connection is kept", clientName, failure);
        }
    }

    private void submit(Runnable task) {
        try {
            loginExecutor.execute(task);
        } catch (RejectedExecutionException e) {
            log.warn("server busy, dropped background login task");
        }
    }

    private LoginResponsePacket busyResponse(LoginRequestPacket packet) {
        LoginResponsePacket response = new LoginResponsePacket();
        response.setVersion(packet.getVersion());
        response.setClientName(packet.getClientName());
        response.setSuccess(false);
        response.setReason("服务器繁忙，请稍后重试");
        return response;
    }
}
