package com.theshuai.tunnelserver.handler;

import com.theshuai.common.protocol.NatMessagePacket;
import com.theshuai.common.protocol.NatMessageType;
import com.theshuai.common.session.Session;
import com.theshuai.tunnelserver.attribute.ServerAttributes;
import com.theshuai.tunnelserver.http.WebSocketStreamRegistry;
import com.theshuai.tunnelserver.http.WebSocketTunnelHandler;
import io.netty.channel.embedded.EmbeddedChannel;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

class NatServerHandlerTests {

    @Test
    void shouldAcceptInboundKeepaliveWithoutClosingChannel() {
        NatServerHandler handler = new NatServerHandler(
                null, null, null, null, mock(WebSocketStreamRegistry.class),
                mock(WebSocketTunnelHandler.class));
        EmbeddedChannel channel = new EmbeddedChannel(handler);
        channel.attr(ServerAttributes.SESSION).set(new Session("client-a"));
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

    @Test
    void shouldIgnoreLateFramesForClosedStreamWithoutClosingDataConnection() {
        WebSocketTunnelHandler webSocketHandler = mock(WebSocketTunnelHandler.class);
        NatServerHandler handler = new NatServerHandler(
                null, null, null, null, mock(WebSocketStreamRegistry.class), webSocketHandler);
        EmbeddedChannel channel = new EmbeddedChannel(handler);
        channel.attr(ServerAttributes.SESSION).set(new Session("client-a"));
        channel.attr(ServerAttributes.TENANT_ID).set("tenant-a");
        try {
            NatMessagePacket data = new NatMessagePacket();
            data.setNatMessageType(NatMessageType.DATA);
            data.setStreamId(42);
            data.setData(new byte[]{1, 2, 3});
            channel.writeInbound(data);

            NatMessagePacket fin = new NatMessagePacket();
            fin.setNatMessageType(NatMessageType.FIN);
            fin.setStreamId(42);
            channel.writeInbound(fin);

            assertTrue(channel.isActive());
            assertNull(channel.readInbound());
        } finally {
            channel.finishAndReleaseAll();
        }
        verify(webSocketHandler).onControlChannelInactive("client-a");
    }
}
