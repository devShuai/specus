package com.theshuai.tunnelserver.handler;

import com.theshuai.common.protocol.NatMessagePacket;
import com.theshuai.common.protocol.NatMessageType;
import com.theshuai.common.session.Session;
import com.theshuai.tunnelserver.attribute.ServerAttributes;
import com.theshuai.tunnelserver.http.WebSocketStreamRegistry;
import com.theshuai.tunnelserver.http.WebSocketTunnelHandler;
import com.theshuai.tunnelserver.server.RemotePortServerManager;
import io.netty.channel.embedded.EmbeddedChannel;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

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

    @Test
    void shouldKeepDataConnectionWhenOnePublicPortCannotBind() throws Exception {
        RemotePortServerManager remotePorts = mock(RemotePortServerManager.class);
        when(remotePorts.bind(eq(19090), any()))
                .thenThrow(new InterruptedException("address already in use"));
        NatServerHandler handler = new NatServerHandler(
                null, null, remotePorts, null, mock(WebSocketStreamRegistry.class),
                mock(WebSocketTunnelHandler.class));
        EmbeddedChannel channel = new EmbeddedChannel(handler);
        channel.attr(ServerAttributes.SESSION).set(new Session("client-a"));
        channel.attr(ServerAttributes.TENANT_ID).set("tenant-a");
        try {
            NatMessagePacket register = new NatMessagePacket();
            register.setNatMessageType(NatMessageType.REGISTER);
            register.setMetaData(Map.of(
                    "port", 19090,
                    "tunnelPort", 8080,
                    "tunnelAddress", "127.0.0.1",
                    "clientName", "client-a"));

            channel.writeInbound(register);

            assertTrue(channel.isActive());
            NatMessagePacket result = channel.readOutbound();
            assertNotNull(result);
            assertEquals(NatMessageType.REGISTER_RESULT, result.getNatMessageType());
            assertEquals(19090, result.getMetaData().get("port"));
            assertFalse((Boolean) result.getMetaData().get("success"));
            assertNull(channel.readOutbound());
        } finally {
            channel.finishAndReleaseAll();
        }
    }
}
