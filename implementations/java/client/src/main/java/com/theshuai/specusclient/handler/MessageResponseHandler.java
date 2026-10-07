package com.theshuai.specusclient.handler;

import com.theshuai.common.protocol.response.MessageResponsePacket;
import com.theshuai.common.util.JsonUtil;
import com.theshuai.specusclient.bean.SpecusBean;
import com.theshuai.specusclient.client.TcpConnection;
import com.theshuai.specusclient.client.NettyClient;
import com.theshuai.specusclient.peer.PeerMeshClient;
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
                SpecusBean specusBean = JsonUtil.stringToObject(messageResponsePacket.getMessage(), SpecusBean.class);
                if (nettyClient != null) {
                    nettyClient.applyNatControl(specusBean);
                    break;
                }
                NatClientHandler natClientHandler = ctx.pipeline().get(NatClientHandler.class);
                if (natClientHandler == null) {
                    ctx.pipeline().addLast(new NatClientHandler(specusBean, localConnection));
                } else {
                    natClientHandler.applyConfig(specusBean);
                }
                // Every NAT_CONTROL is the client's full snapshot: routes only ever come from the
                // HTTP login and NAT_CONTROL, so a missing or null list means "no routes", never
                // "keep the old ones" (an older server left the field out after the last delete).
                NatClientHandler nat = ctx.pipeline().get(NatClientHandler.class);
                if (nat != null) {
                    nat.applyHttpRoutes(specusBean.getHttpSpecusConfigList());
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
