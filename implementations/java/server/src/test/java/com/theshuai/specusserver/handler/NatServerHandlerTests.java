package com.theshuai.specusserver.handler;

import com.theshuai.common.protocol.NatMessagePacket;
import com.theshuai.common.protocol.NatMessageType;
import com.theshuai.common.session.Session;
import com.theshuai.specusserver.attribute.ServerAttributes;
import com.theshuai.specusserver.http.HttpStreamExchange;
import com.theshuai.specusserver.http.WebSocketStreamRegistry;
import com.theshuai.specusserver.http.WebSocketSpecusHandler;
import com.theshuai.specusserver.management.model.DisconnectReason;
import com.theshuai.specusserver.server.RemotePortServerManager;
import io.netty.channel.embedded.EmbeddedChannel;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
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
                mock(WebSocketSpecusHandler.class));
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
    void shouldResetUnknownTcpStreamWithoutClosingDataConnection() {
        WebSocketSpecusHandler webSocketHandler = mock(WebSocketSpecusHandler.class);
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
            channel.writeInbound(rst(42));

            assertTrue(channel.isActive());
            NatMessagePacket dataReset = channel.readOutbound();
            assertNotNull(dataReset);
            assertEquals(NatMessageType.RST, dataReset.getNatMessageType());
            assertEquals(42, dataReset.getStreamId());
            NatMessagePacket finReset = channel.readOutbound();
            assertNotNull(finReset);
            assertEquals(NatMessageType.RST, finReset.getNatMessageType());
            assertEquals(42, finReset.getStreamId());
            assertNull(channel.readOutbound());
            assertNull(channel.readInbound());
        } finally {
            channel.finishAndReleaseAll();
        }
        verify(webSocketHandler).onControlChannelInactive("client-a");
    }

    @Test
    void shouldCloseDataConnectionForRstOnNeverOpenedStream() {
        NatServerHandler handler = new NatServerHandler(
                null, null, null, null, mock(WebSocketStreamRegistry.class),
                mock(WebSocketSpecusHandler.class));
        EmbeddedChannel channel = new EmbeddedChannel(handler);
        channel.attr(ServerAttributes.SESSION).set(new Session("client-a"));
        channel.attr(ServerAttributes.TENANT_ID).set("tenant-a");
        try {
            channel.writeInbound(rst(43));

            assertFalse(channel.isActive());
            assertEquals(DisconnectReason.PROTOCOL_VIOLATION, DisconnectReason.readFrom(channel));
            assertNull(channel.readOutbound());
        } finally {
            channel.finishAndReleaseAll();
        }
    }

    @Test
    void shouldIgnoreLateRstForRecentlyClosedStream() {
        NatServerHandler handler = new NatServerHandler(
                null, null, null, null, mock(WebSocketStreamRegistry.class),
                mock(WebSocketSpecusHandler.class));
        EmbeddedChannel channel = new EmbeddedChannel(handler);
        channel.attr(ServerAttributes.SESSION).set(new Session("client-a"));
        channel.attr(ServerAttributes.TENANT_ID).set("tenant-a");
        HttpStreamExchange exchange = new HttpStreamExchange(44);
        try {
            assertTrue(handler.openHttpStream(exchange, Map.of("source", "http", "phase", "request")));
            assertNotNull(channel.readOutbound());
            handler.unregisterHttpStream(44);

            channel.writeInbound(rst(44));

            assertTrue(channel.isActive());
            assertNull(DisconnectReason.readFrom(channel));
            assertNull(channel.readOutbound());
        } finally {
            channel.finishAndReleaseAll();
        }
    }

    @Test
    void shouldKeepDataConnectionWhenOnePublicPortCannotBind() throws Exception {
        RemotePortServerManager remotePorts = mock(RemotePortServerManager.class);
        when(remotePorts.bind(eq(19090), any()))
                .thenThrow(new InterruptedException("address already in use"));
        NatServerHandler handler = new NatServerHandler(
                null, null, remotePorts, null, mock(WebSocketStreamRegistry.class),
                mock(WebSocketSpecusHandler.class));
        EmbeddedChannel channel = new EmbeddedChannel(handler);
        channel.attr(ServerAttributes.SESSION).set(new Session("client-a"));
        channel.attr(ServerAttributes.TENANT_ID).set("tenant-a");
        try {
            NatMessagePacket register = new NatMessagePacket();
            register.setNatMessageType(NatMessageType.REGISTER);
            register.setMetaData(Map.of(
                    "port", 19090,
                    "specusPort", 8080,
                    "specusAddress", "127.0.0.1",
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

    @Test
    void shouldQueueHttpDataBeforeEndStreamFlagFinishesResponse() throws Exception {
        NatServerHandler handler = new NatServerHandler(
                null, null, null, null, mock(WebSocketStreamRegistry.class),
                mock(WebSocketSpecusHandler.class));
        EmbeddedChannel channel = new EmbeddedChannel(handler);
        channel.attr(ServerAttributes.SESSION).set(new Session("client-a"));
        channel.attr(ServerAttributes.TENANT_ID).set("tenant-a");
        HttpStreamExchange exchange = new HttpStreamExchange(73);
        try {
            assertTrue(handler.openHttpStream(exchange, Map.of("source", "http", "phase", "request")));
            assertNotNull(channel.readOutbound());

            NatMessagePacket responseHead = new NatMessagePacket();
            responseHead.setNatMessageType(NatMessageType.OPEN);
            responseHead.setStreamId(73);
            responseHead.setMetaData(Map.of(
                    "source", "http",
                    "phase", "response",
                    "statusCode", 200));
            channel.writeInbound(responseHead);

            byte[] payload = new byte[]{4, 5, 6};
            NatMessagePacket dataAndFin = new NatMessagePacket();
            dataAndFin.setNatMessageType(NatMessageType.DATA);
            dataAndFin.setStreamId(73);
            dataAndFin.setData(payload);
            dataAndFin.setFlags(NatMessagePacket.FLAG_END_STREAM);
            channel.writeInbound(dataAndFin);

            HttpStreamExchange.Data data = assertInstanceOf(HttpStreamExchange.Data.class, exchange.take());
            assertArrayEquals(payload, data.bytes());
            assertInstanceOf(HttpStreamExchange.End.class, exchange.take());
        } finally {
            channel.finishAndReleaseAll();
        }
    }

    private NatMessagePacket rst(int streamId) {
        NatMessagePacket packet = new NatMessagePacket();
        packet.setNatMessageType(NatMessageType.RST);
        packet.setStreamId(streamId);
        return packet;
    }
}
