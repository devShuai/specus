package com.theshuai.tunnelclient.handler;

import com.theshuai.common.protocol.response.MessageResponsePacket;
import com.theshuai.common.util.JsonUtil;
import com.theshuai.tunnelclient.bean.TunnelBean;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.SimpleChannelInboundHandler;

public class MessageResponseHandler extends SimpleChannelInboundHandler<MessageResponsePacket> {

    @Override
    protected void channelRead0(ChannelHandlerContext ctx, MessageResponsePacket messageResponsePacket) throws Exception {

        switch (messageResponsePacket.getMessageType()) {

            case CLIENT_TO_CLIENT: {
                String clientName = messageResponsePacket.getClientName();
                String toClientName = messageResponsePacket.getToClientName();
                System.out.println("clientName:" + clientName + " -> " + "toClientName:" + toClientName +
                        " message: " + messageResponsePacket.getMessage());
                break;
            }
            case SERVER_TO_CLIENT: {
                System.out.println("server->client: " + messageResponsePacket.getMessage());
                break;
            }

            case NAT_CONTROL: {
                TunnelBean tunnelBean = JsonUtil.stringToObject(messageResponsePacket.getMessage(), TunnelBean.class);
                NatClientHandler natClientHandler = ctx.pipeline().get(NatClientHandler.class);
                if (natClientHandler == null) {
                    ctx.pipeline().addLast(new NatClientHandler(tunnelBean));
                } else {
                    natClientHandler.applyConfig(tunnelBean);
                }
                break;
            }

            default:
                System.out.println("客户端接收到未知消息类型");
        }


    }
}
