package com.theshuai.tunnelserver.handler;

import com.theshuai.common.protocol.request.LoginRequestPacket;
import com.theshuai.common.protocol.response.LoginResponsePacket;
import com.theshuai.common.protocol.ConnectionRole;
import com.theshuai.common.codec.Spliter;
import com.theshuai.common.session.Session;
import com.theshuai.tunnelserver.session.SessionUtil;
import com.theshuai.tunnelserver.management.model.DisconnectReason;
import com.theshuai.tunnelserver.management.service.AuthenticationResult;
import com.theshuai.tunnelserver.management.service.ClientAuthService;
import com.theshuai.tunnelserver.management.service.ConnectionRecordService;
import com.theshuai.tunnelserver.management.service.NatControlService;
import com.theshuai.tunnelserver.management.service.PeerSignalService;
import com.theshuai.tunnelserver.config.NettyServerProperties;
import io.netty.channel.ChannelHandler;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.SimpleChannelInboundHandler;
import io.netty.util.AttributeKey;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.RejectedExecutionException;

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

    public ManagedLoginRequestHandler(ClientAuthService clientAuthService,
                                      ConnectionRecordService connectionRecordService,
                                      NatControlService natControlService,
                                      PeerSignalService peerSignalService,
                                      NettyServerProperties nettyProperties,
                                      @Qualifier("loginExecutor") ExecutorService loginExecutor) {
        this.clientAuthService = clientAuthService;
        this.connectionRecordService = connectionRecordService;
        this.natControlService = natControlService;
        this.peerSignalService = peerSignalService;
        this.nettyProperties = nettyProperties;
        this.loginExecutor = loginExecutor;
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
            boolean validRole = ConnectionRole.isValid(packet.getConnectionRole());
            boolean dataConnection = ConnectionRole.DATA.equals(packet.getConnectionRole());
            AuthenticationResult authentication = validRole && StringUtils.hasText(packet.getAccessToken())
                    ? clientAuthService.authenticateNetty(
                    packet,
                    ctx.channel().id().asLongText(),
                    String.valueOf(ctx.channel().remoteAddress()),
                    dataConnection)
                    : AuthenticationResult.failure(null, validRole
                    ? "客户端必须先通过 HTTP 登录获取访问令牌"
                    : "登录包缺少有效 connectionRole");
            if (authentication.success() && dataConnection
                    && !SessionUtil.hasMatchingControl(packet.getClientName(), authentication.clientSessionId())) {
                authentication = AuthenticationResult.failure(authentication.account(), "数据连接未找到匹配的控制连接");
            }
            AuthenticationResult finalAuthentication = authentication;
            long connectionRecordId = dataConnection ? 0L : connectionRecordService.recordConnection(
                    finalAuthentication, packet, ctx.channel().id().asLongText(),
                    String.valueOf(ctx.channel().remoteAddress()));

            LoginResponsePacket response = new LoginResponsePacket();
            response.setVersion(packet.getVersion());
            response.setClientName(packet.getClientName());
            response.setSuccess(finalAuthentication.success());
            response.setReason(finalAuthentication.reason());

            // Channel-affecting work (attribute, session bind, write) must run on the channel's
            // event loop so it stays ordered relative to other I/O on this connection.
            ctx.channel().eventLoop().execute(() -> {
                if (finalAuthentication.success()) {
                    if (ctx.pipeline().context(Spliter.PRE_AUTH_HANDLER_NAME) != null) {
                        ctx.pipeline().replace(
                                Spliter.PRE_AUTH_HANDLER_NAME,
                                Spliter.AUTHENTICATED_HANDLER_NAME,
                                new Spliter(nettyProperties.getMaxFrameSize()));
                    }
                    if (connectionRecordId > 0) {
                        ctx.channel().attr(CONNECTION_RECORD_ID).set(connectionRecordId);
                    }
                    ctx.channel().attr(com.theshuai.tunnelserver.attribute.ServerAttributes.LOGIN_TIME_MS).set(System.currentTimeMillis());
                    ctx.channel().attr(com.theshuai.tunnelserver.attribute.ServerAttributes.TENANT_ID).set(
                            finalAuthentication.account().getTenantId());
                    ctx.channel().attr(com.theshuai.tunnelserver.attribute.ServerAttributes.CONNECTION_ROLE).set(
                            packet.getConnectionRole());
                    if (finalAuthentication.clientSessionId() != null) {
                        ctx.channel().attr(com.theshuai.tunnelserver.attribute.ServerAttributes.CLIENT_SESSION_ID).set(
                                finalAuthentication.clientSessionId());
                    }
                    if (dataConnection) {
                        SessionUtil.bindDataSession(new Session(packet.getClientName()), ctx.channel());
                    } else {
                        SessionUtil.bindControlSession(new Session(packet.getClientName()), ctx.channel());
                    }
                }
                io.netty.channel.ChannelFuture writeFuture = ctx.writeAndFlush(response);
                if (finalAuthentication.success()) {
                    if (!dataConnection) {
                        // pushOnLogin reads the DB; run it off the event loop, after the session is bound.
                        submit(() -> natControlService.pushOnLogin(packet.getClientName()));
                        submit(() -> peerSignalService.pushOnLogin(finalAuthentication.account()));
                    }
                } else {
                    // 登录失败必须主动关连接，否则客户端心跳会让 server 端 reader idle 一直不超时，
                    // 形成"无 session 但保活"的僵尸连接，浪费资源也阻塞合法重连。
                    // 这条登录失败的 DB 行 disconnectedAt 在 recordConnection 里已经写过，
                    // 这里关 channel 也无需再调 recordDisconnect（CONNECTION_RECORD_ID 没 set）。
                    DisconnectReason.markIfAbsent(ctx.channel(), DisconnectReason.LOGIN_FAILURE);
                    writeFuture.addListener(io.netty.channel.ChannelFutureListener.CLOSE);
                }
            });
        } catch (Exception e) {
            log.error("login handling failed for client={}", packet.getClientName(), e);
            DisconnectReason.markIfAbsent(ctx.channel(), DisconnectReason.IO_ERROR);
            ctx.close();
        }
    }

    @Override
    public void channelInactive(ChannelHandlerContext ctx) throws Exception {
        String role = ctx.channel().attr(com.theshuai.tunnelserver.attribute.ServerAttributes.CONNECTION_ROLE)
                .getAndSet(null);
        boolean dataConnection = ConnectionRole.DATA.equals(role);
        Long connectionRecordId = ctx.channel().attr(CONNECTION_RECORD_ID).getAndSet(null);
        Long clientSessionId = ctx.channel().attr(com.theshuai.tunnelserver.attribute.ServerAttributes.CLIENT_SESSION_ID)
                .getAndSet(null);
        if (connectionRecordId != null) {
            long recordId = connectionRecordId;
            // 读通道属性还原 reason；缺省视为客户端主动 FIN。
            DisconnectReason marked = DisconnectReason.readFrom(ctx.channel());
            DisconnectReason reason = marked == null ? DisconnectReason.CLIENT_CLOSED : marked;
            submit(() -> connectionRecordService.recordDisconnect(recordId, reason));
        }
        if (clientSessionId != null && !dataConnection) {
            submit(() -> clientAuthService.markNettyDisconnected(clientSessionId));
        }
        Session session = SessionUtil.getSession(ctx.channel());
        if (!dataConnection && session != null) {
            SessionUtil.closeDataSession(session.getClientName());
        }
        SessionUtil.unBindSession(ctx.channel());
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
