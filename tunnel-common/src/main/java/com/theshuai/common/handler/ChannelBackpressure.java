package com.theshuai.common.handler;

import io.netty.channel.Channel;

import java.util.Collection;

public final class ChannelBackpressure {
    private ChannelBackpressure() {
    }

    public static void setAutoRead(Channel channel, boolean autoRead) {
        if (channel == null) {
            return;
        }
        Runnable update = () -> {
            if (channel.isOpen() && channel.config().isAutoRead() != autoRead) {
                channel.config().setAutoRead(autoRead);
            }
        };
        if (channel.eventLoop().inEventLoop()) {
            update.run();
        } else {
            channel.eventLoop().execute(update);
        }
    }

    public static boolean allWritable(Collection<Channel> channels) {
        for (Channel channel : channels) {
            if (channel != null && channel.isActive() && !channel.isWritable()) {
                return false;
            }
        }
        return true;
    }
}
