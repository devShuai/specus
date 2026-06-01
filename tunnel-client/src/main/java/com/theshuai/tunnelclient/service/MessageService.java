package com.theshuai.tunnelclient.service;

import com.theshuai.common.protocol.MessageType;
import com.theshuai.common.protocol.request.MessageRequestPacket;
import com.theshuai.common.util.SessionUtil;
import io.netty.channel.Channel;
import lombok.extern.slf4j.Slf4j;

/**
 * Send a message to the server over the active control channel for {@code clientName}.
 * Pass the client name explicitly so multiple {@link com.theshuai.tunnelclient.client.NettyClient}
 * instances can coexist (no shared static state).
 */
@Slf4j
public class MessageService {

    public String sendMessage(String clientName, String message) {
        if (clientName == null) {
            return "missing clientName";
        }
        Channel channel = SessionUtil.getChannel(clientName);
        if (channel != null) {
            MessageRequestPacket messageRequestPacket = new MessageRequestPacket();
            messageRequestPacket.setClientName(clientName);
            messageRequestPacket.setMessageType(MessageType.CLIENT_TO_SERVER);
            messageRequestPacket.setToClientName("server");
            messageRequestPacket.setMessage(message);
            channel.writeAndFlush(messageRequestPacket);
            return "发送成功";
        }
        return "找不到对应的channel [" + clientName + "]";
    }
}
