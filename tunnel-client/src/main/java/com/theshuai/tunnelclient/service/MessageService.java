package com.theshuai.tunnelclient.service;

import com.theshuai.common.protocol.MessageType;
import com.theshuai.common.protocol.request.MessageRequestPacket;
import com.theshuai.common.util.SessionUtil;
import com.theshuai.tunnelclient.client.NettyClient;
import io.netty.channel.Channel;
import lombok.extern.slf4j.Slf4j;

@Slf4j
public class MessageService {

    public static String sendMessage(String message) {
        Channel channel = SessionUtil.getChannel(NettyClient.CLIENT_NAME);
        if (channel != null) {
            MessageRequestPacket messageRequestPacket = new MessageRequestPacket();
            messageRequestPacket.setClientName(NettyClient.CLIENT_NAME);
            messageRequestPacket.setMessageType(MessageType.CLIENT_TO_SERVER);
            messageRequestPacket.setToClientName("server");
            messageRequestPacket.setMessage(message);
            channel.writeAndFlush(messageRequestPacket);
            return "发送成功";
        }

        return "找不到对应的channel [" + NettyClient.CLIENT_NAME + "]";
    }
}
