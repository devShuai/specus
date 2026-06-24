package com.theshuai.common.handler;

import io.netty.channel.embedded.EmbeddedChannel;
import org.junit.jupiter.api.Test;

import java.net.SocketException;

import static org.junit.jupiter.api.Assertions.assertFalse;

class NatCommonHandlerTests {

    @Test
    void connectionResetShouldCloseChannel() {
        EmbeddedChannel channel = new EmbeddedChannel(new NatCommonHandler());

        channel.pipeline().fireExceptionCaught(new SocketException("Connection reset"));

        assertFalse(channel.isOpen());
        channel.finishAndReleaseAll();
    }
}
