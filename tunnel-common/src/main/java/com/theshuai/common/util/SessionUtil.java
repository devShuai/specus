package com.theshuai.common.util;


import com.theshuai.common.attribute.Attributes;
import com.theshuai.common.session.Session;
import io.netty.channel.Channel;
import io.netty.channel.group.ChannelGroup;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import lombok.extern.slf4j.Slf4j;

@Slf4j
public class SessionUtil {

    private static final Map<String, Channel> clientChannelMap = new ConcurrentHashMap<>();

    private static final Map<String, ChannelGroup> groupIdChannelGroupMap = new ConcurrentHashMap<>();

    public static void bindSession(Session session, Channel channel) {
        Channel oldChannel = clientChannelMap.put(session.getClientName(), channel);
        if (oldChannel != null && oldChannel != channel) {
            oldChannel.attr(Attributes.SESSION).set(null);
            oldChannel.close();
            log.info(session.getClientName() + " 旧连接已替换");
        }
        channel.attr(Attributes.SESSION).set(session);
        channel.closeFuture().addListener(future -> {
            unBindSession(channel);
        });
    }

    public static void unBindSession(Channel channel) {
        if (hasLogin(channel)) {
            Session session = getSession(channel);
            clientChannelMap.remove(session.getClientName(), channel);
            channel.attr(Attributes.SESSION).set(null);
            log.info(session + "退出登录！");
        }
    }

    public static Channel getChannel(String clientName) {
        return clientChannelMap.get(clientName);
    }

    public static boolean hasLogin(Channel channel) {
        return getSession(channel) != null;
    }

    public static Session getSession(Channel channel) {
        return channel.attr(Attributes.SESSION).get();
    }

    public static boolean hasSession(Channel channel) {
        return clientChannelMap.containsValue(channel);
    }

}
