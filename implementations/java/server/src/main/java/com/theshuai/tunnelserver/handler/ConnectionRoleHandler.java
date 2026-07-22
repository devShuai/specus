package com.theshuai.tunnelserver.handler;

import com.theshuai.common.protocol.ConnectionRole;
import com.theshuai.common.protocol.NatMessagePacket;
import com.theshuai.common.protocol.request.HeartBeatRequestPacket;
import com.theshuai.common.protocol.request.LogoutRequestPacket;
import com.theshuai.tunnelserver.attribute.ServerAttributes;
import com.theshuai.tunnelserver.management.model.DisconnectReason;
import io.netty.channel.ChannelHandler;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;

/** Enforces the mandatory v2 control/data connection split after authentication. */
@ChannelHandler.Sharable
public final class ConnectionRoleHandler extends ChannelInboundHandlerAdapter {
    public static final ConnectionRoleHandler INSTANCE = new ConnectionRoleHandler();

    private ConnectionRoleHandler() {
    }

    @Override
    public void channelRead(ChannelHandlerContext ctx, Object msg) throws Exception {
        String role = ctx.channel().attr(ServerAttributes.CONNECTION_ROLE).get();
        boolean allowed = ConnectionRole.CONTROL.equals(role)
                ? !(msg instanceof NatMessagePacket)
                : ConnectionRole.DATA.equals(role)
                && (msg instanceof NatMessagePacket
                || msg instanceof HeartBeatRequestPacket
                || msg instanceof LogoutRequestPacket);
        if (!allowed) {
            DisconnectReason.markIfAbsent(ctx.channel(), DisconnectReason.PROTOCOL_VIOLATION);
            ctx.close();
            return;
        }
        super.channelRead(ctx, msg);
    }
}
