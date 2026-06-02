package com.theshuai.tunnelserver.handler;

import com.theshuai.common.protocol.request.LoginRequestPacket;
import com.theshuai.common.protocol.response.LoginResponsePacket;
import com.theshuai.common.session.Session;
import com.theshuai.common.util.SessionUtil;
import com.theshuai.tunnelserver.management.service.ClientManagementService;
import com.theshuai.tunnelserver.management.service.ClientManagementService.AuthenticationResult;
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

    private final ClientManagementService clientManagementService;
    private final NatControlService natControlService;
    private final ExecutorService loginExecutor;

    public ManagedLoginRequestHandler(ClientManagementService clientManagementService,
                                      NatControlService natControlService,
                                      @Qualifier("loginExecutor") ExecutorService loginExecutor) {
        this.clientManagementService = clientManagementService;
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
            ctx.writeAndFlush(busyResponse(packet));
        }
    }

    private void handleLogin(ChannelHandlerContext ctx, LoginRequestPacket packet) {
        try {
            AuthenticationResult authentication = clientManagementService.authenticate(packet);
            long connectionRecordId = clientManagementService.recordConnection(
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
                    SessionUtil.bindSession(new Session(packet.getClientName()), ctx.channel());
                }
                ctx.writeAndFlush(response);
                if (authentication.success()) {
                    // pushOnLogin reads the DB; run it off the event loop, after the session is bound.
                    submit(() -> natControlService.pushOnLogin(packet.getClientName()));
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
            submit(() -> clientManagementService.recordDisconnect(recordId));
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
