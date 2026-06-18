package com.theshuai.tunnelserver.handler;

import com.theshuai.common.protocol.request.LoginRequestPacket;
import com.theshuai.common.protocol.response.LoginResponsePacket;
import com.theshuai.common.session.Session;
import com.theshuai.tunnelserver.session.SessionUtil;
import com.theshuai.tunnelserver.management.service.AuthenticationResult;
import com.theshuai.tunnelserver.management.service.ClientAccountService;
import com.theshuai.tunnelserver.management.service.ConnectionRecordService;
import com.theshuai.tunnelserver.management.service.NatControlService;
import io.netty.channel.ChannelHandler;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.SimpleChannelInboundHandler;
import io.netty.util.AttributeKey;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Component;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.RejectedExecutionException;

@Component
@ChannelHandler.Sharable
@Slf4j
public class ManagedLoginRequestHandler extends SimpleChannelInboundHandler<LoginRequestPacket> {
    private static final AttributeKey<Long> CONNECTION_RECORD_ID = AttributeKey.valueOf("connectionRecordId");

    private final ClientAccountService clientAccountService;
    private final ConnectionRecordService connectionRecordService;
    private final NatControlService natControlService;
    private final ExecutorService loginExecutor;

    public ManagedLoginRequestHandler(ClientAccountService clientAccountService,
                                      ConnectionRecordService connectionRecordService,
                                      NatControlService natControlService,
                                      @Qualifier("loginExecutor") ExecutorService loginExecutor) {
        this.clientAccountService = clientAccountService;
        this.connectionRecordService = connectionRecordService;
        this.natControlService = natControlService;
        this.loginExecutor = loginExecutor;
    }

    @Override
    protected void channelRead0(ChannelHandlerContext ctx, LoginRequestPacket packet) {
        // The decoded packet is a plain POJO (not reference-counted), so it stays valid after this
        // method returns and is safe to hand to a worker thread. Keep the event loop free of DB work.
        try {
            loginExecutor.execute(() -> handleLogin(ctx, packet));
        } catch (RejectedExecutionException e) {
            log.warn("login rejected, server busy: client={}", packet.getClientName());
            // 同样：拒绝服务的回执发出后立即关闭，避免僵尸连接。
            ctx.writeAndFlush(busyResponse(packet))
                    .addListener(io.netty.channel.ChannelFutureListener.CLOSE);
        }
    }

    private void handleLogin(ChannelHandlerContext ctx, LoginRequestPacket packet) {
        try {
            AuthenticationResult authentication = clientAccountService.authenticate(packet);
            long connectionRecordId = connectionRecordService.recordConnection(
                    authentication,
                    packet,
                    ctx.channel().id().asLongText(),
                    String.valueOf(ctx.channel().remoteAddress())
            );

            LoginResponsePacket response = new LoginResponsePacket();
            response.setVersion(packet.getVersion());
            response.setClientName(packet.getClientName());
            response.setSuccess(authentication.success());
            response.setReason(authentication.reason());

            // Channel-affecting work (attribute, session bind, write) must run on the channel's
            // event loop so it stays ordered relative to other I/O on this connection.
            ctx.channel().eventLoop().execute(() -> {
                if (authentication.success()) {
                    ctx.channel().attr(CONNECTION_RECORD_ID).set(connectionRecordId);
                    ctx.channel().attr(com.theshuai.tunnelserver.attribute.ServerAttributes.LOGIN_TIME_MS).set(System.currentTimeMillis());
                    SessionUtil.bindSession(new Session(packet.getClientName()), ctx.channel());
                }
                io.netty.channel.ChannelFuture writeFuture = ctx.writeAndFlush(response);
                if (authentication.success()) {
                    // pushOnLogin reads the DB; run it off the event loop, after the session is bound.
                    submit(() -> natControlService.pushOnLogin(packet.getClientName()));
                } else {
                    // 登录失败必须主动关连接，否则客户端心跳会让 server 端 reader idle 一直不超时，
                    // 形成"无 session 但保活"的僵尸连接，浪费资源也阻塞合法重连。
                    writeFuture.addListener(io.netty.channel.ChannelFutureListener.CLOSE);
                }
            });
        } catch (Exception e) {
            log.error("login handling failed for client={}", packet.getClientName(), e);
            ctx.close();
        }
    }

    @Override
    public void channelInactive(ChannelHandlerContext ctx) throws Exception {
        Long connectionRecordId = ctx.channel().attr(CONNECTION_RECORD_ID).getAndSet(null);
        if (connectionRecordId != null) {
            long recordId = connectionRecordId;
            submit(() -> connectionRecordService.recordDisconnect(recordId));
        }
        SessionUtil.unBindSession(ctx.channel());
        super.channelInactive(ctx);
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
