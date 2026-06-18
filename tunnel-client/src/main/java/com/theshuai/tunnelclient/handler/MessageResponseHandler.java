package com.theshuai.tunnelclient.handler;

import com.theshuai.common.protocol.response.MessageResponsePacket;
import com.theshuai.common.util.JsonUtil;
import com.theshuai.tunnelclient.bean.TunnelBean;
import com.theshuai.tunnelclient.client.TcpConnection;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.SimpleChannelInboundHandler;
import lombok.extern.slf4j.Slf4j;

@Slf4j
public class MessageResponseHandler extends SimpleChannelInboundHandler<MessageResponsePacket> {
    private final TcpConnection localConnection;

    public MessageResponseHandler() {
        this(new TcpConnection());
    }

    public MessageResponseHandler(TcpConnection localConnection) {
        this.localConnection = localConnection;
    }

    @Override
    protected void channelRead0(ChannelHandlerContext ctx, MessageResponsePacket messageResponsePacket) throws Exception {

        switch (messageResponsePacket.getMessageType()) {

            case CLIENT_TO_CLIENT: {
                String clientName = messageResponsePacket.getClientName();
                String toClientName = messageResponsePacket.getToClientName();
                log.info("clientName:" + clientName + " -> " + "toClientName:" + toClientName +
                        " message: " + messageResponsePacket.getMessage());
                break;
            }
            case SERVER_TO_CLIENT: {
                log.info("server->client: " + messageResponsePacket.getMessage());
                break;
            }

            case NAT_CONTROL: {
                TunnelBean tunnelBean = JsonUtil.stringToObject(messageResponsePacket.getMessage(), TunnelBean.class);
                NatClientHandler natClientHandler = ctx.pipeline().get(NatClientHandler.class);
                if (natClientHandler == null) {
                    ctx.pipeline().addLast(new NatClientHandler(tunnelBean, localConnection));
                } else {
                    natClientHandler.applyConfig(tunnelBean);
                }
                // HTTP 路由热更新：服务端权威全集（接管态时才下发该字段）。null 表示"未接管"，
                // 此时客户端继续使用启动时从 tunnelClientConfig.json 读出的 fallback 表，不要
                // 误把它清空。详见 server NatControlService.assembleHttpRoutesIfManaged 的语义说明。
                if (tunnelBean.getHttpTunnelConfigList() != null) {
                    DirectHttpRequestHandler directHttp = ctx.pipeline().get(DirectHttpRequestHandler.class);
                    if (directHttp != null) {
                        directHttp.applyRoutes(tunnelBean.getHttpTunnelConfigList());
                    } else {
                        log.warn("NAT_CONTROL carried httpTunnelConfigList but DirectHttpRequestHandler not in pipeline");
                    }
                }
                break;
            }

            default:
                log.info("客户端接收到未知消息类型");
        }


    }
}
