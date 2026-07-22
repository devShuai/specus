package com.theshuai.tunnelclient.handler;

import com.theshuai.common.protocol.response.MessageResponsePacket;
import com.theshuai.common.util.JsonUtil;
import com.theshuai.tunnelclient.bean.TunnelBean;
import com.theshuai.tunnelclient.client.TcpConnection;
import com.theshuai.tunnelclient.client.NettyClient;
import com.theshuai.tunnelclient.peer.PeerMeshClient;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.SimpleChannelInboundHandler;
import lombok.extern.slf4j.Slf4j;

@Slf4j
public class MessageResponseHandler extends SimpleChannelInboundHandler<MessageResponsePacket> {
    private final TcpConnection localConnection;
    private final PeerMeshClient peerMeshClient;
    private final NettyClient nettyClient;

    public MessageResponseHandler() {
        this(new TcpConnection());
    }

    public MessageResponseHandler(TcpConnection localConnection) {
        this(localConnection, null, null);
    }

    public MessageResponseHandler(TcpConnection localConnection, PeerMeshClient peerMeshClient) {
        this(localConnection, peerMeshClient, null);
    }

    public MessageResponseHandler(TcpConnection localConnection, PeerMeshClient peerMeshClient,
                                  NettyClient nettyClient) {
        this.localConnection = localConnection;
        this.peerMeshClient = peerMeshClient;
        this.nettyClient = nettyClient;
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
                if (nettyClient != null) {
                    nettyClient.applyNatControl(tunnelBean);
                    break;
                }
                NatClientHandler natClientHandler = ctx.pipeline().get(NatClientHandler.class);
                if (natClientHandler == null) {
                    ctx.pipeline().addLast(new NatClientHandler(tunnelBean, localConnection));
                } else {
                    natClientHandler.applyConfig(tunnelBean);
                }
                // HTTP 路由热更新：服务端权威全集（管理态时才下发该字段）。null 表示本次
                // NAT_CONTROL 不更新 HTTP 路由，此时客户端继续使用 HTTP 登录时拿到的初始快照。
                if (tunnelBean.getHttpTunnelConfigList() != null) {
                    NatClientHandler nat = ctx.pipeline().get(NatClientHandler.class);
                    if (nat != null) {
                        nat.applyHttpRoutes(tunnelBean.getHttpTunnelConfigList());
                    }
                }
                break;
            }

            case PEER_CONTROL: {
                if (peerMeshClient != null) {
                    peerMeshClient.handleControlMessage(messageResponsePacket.getMessage());
                } else {
                    log.debug("收到 peer mesh 信令但客户端未启用 peer mesh");
                }
                break;
            }

            default:
                log.info("客户端接收到未知消息类型");
        }


    }
}
