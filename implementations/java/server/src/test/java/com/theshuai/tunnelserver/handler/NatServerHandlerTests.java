package com.theshuai.tunnelserver.handler;

import com.theshuai.common.protocol.NatMessagePacket;
import com.theshuai.common.protocol.NatMessageType;
import io.netty.channel.embedded.EmbeddedChannel;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class NatServerHandlerTests {

    @Test
    void shouldAcceptInboundKeepaliveWithoutClosingChannel() {
        NatServerHandler handler = new NatServerHandler(null, null, null, null, null, null);
        EmbeddedChannel channel = new EmbeddedChannel(handler);
        try {
            NatMessagePacket keepalive = new NatMessagePacket();
            keepalive.setNatMessageType(NatMessageType.KEEPALIVE);

            channel.writeInbound(keepalive);

            assertTrue(channel.isActive());
            assertNull(channel.readInbound());
        } finally {
            channel.finishAndReleaseAll();
        }
    }
}
