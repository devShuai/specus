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
import org.springframework.stereotype.Component;

@Component
@ChannelHandler.Sharable
public class ManagedLoginRequestHandler extends SimpleChannelInboundHandler<LoginRequestPacket> {
    private static final AttributeKey<Long> CONNECTION_RECORD_ID = AttributeKey.valueOf("connectionRecordId");

    private final ClientManagementService clientManagementService;
    private final NatControlService natControlService;

    public ManagedLoginRequestHandler(ClientManagementService clientManagementService,
                                      NatControlService natControlService) {
        this.clientManagementService = clientManagementService;
        this.natControlService = natControlService;
    }

    @Override
    protected void channelRead0(ChannelHandlerContext ctx, LoginRequestPacket packet) {
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

        if (authentication.success()) {
            ctx.channel().attr(CONNECTION_RECORD_ID).set(connectionRecordId);
            SessionUtil.bindSession(new Session(packet.getClientName()), ctx.channel());
        }
        ctx.writeAndFlush(response);

        if (authentication.success()) {
            natControlService.pushOnLogin(packet.getClientName());
        }
    }

    @Override
    public void channelInactive(ChannelHandlerContext ctx) throws Exception {
        Long connectionRecordId = ctx.channel().attr(CONNECTION_RECORD_ID).getAndSet(null);
        if (connectionRecordId != null) {
            clientManagementService.recordDisconnect(connectionRecordId);
        }
        SessionUtil.unBindSession(ctx.channel());
        super.channelInactive(ctx);
    }
}
