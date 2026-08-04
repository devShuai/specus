package com.theshuai.specusclient.handler;

import com.theshuai.common.protocol.NatMessagePacket;
import com.theshuai.common.protocol.NatMessageType;
import com.theshuai.specusclient.bean.SpecusBean;
import com.theshuai.specusclient.bean.SpecusConfig;
import com.theshuai.specusclient.client.NettyClient;
import io.netty.channel.embedded.EmbeddedChannel;
import org.junit.jupiter.api.Test;

import java.io.InputStream;
import java.lang.reflect.Field;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class NatClientHandlerTests {

    @Test
    void shouldAcceptInboundKeepaliveWithoutClosingChannel() {
        NatClientHandler handler = new NatClientHandler(specusBean());
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

    @Test
    void shouldSynchronizeSpecusSnapshotAfterHandlerWasAdded() {
        NatClientHandler handler = new NatClientHandler(specusBean(specus(9000, 8080)));
        EmbeddedChannel channel = new EmbeddedChannel(handler);
        try {
            assertNotNull(handler.getCtx());
            assertNatMessage(channel.readOutbound(), NatMessageType.REGISTER, 9000);
            assertNull(channel.readOutbound());

            handler.applyConfig(specusBean(specus(9001, 8081)));

            assertNatMessage(channel.readOutbound(), NatMessageType.UNREGISTER, 9000);
            assertNatMessage(channel.readOutbound(), NatMessageType.REGISTER, 9001);
            assertNull(channel.readOutbound());
        } finally {
            channel.finishAndReleaseAll();
        }
    }

    @Test
    void shouldKeepSessionAndRetryPortAfterRegisterFailure() {
        SpecusConfig mapping = specus(9000, 8080);
        NatClientHandler handler = new NatClientHandler(specusBean(mapping));
        EmbeddedChannel channel = new EmbeddedChannel(handler);
        try {
            assertNatMessage(channel.readOutbound(), NatMessageType.REGISTER, 9000);

            NatMessagePacket failed = new NatMessagePacket();
            failed.setNatMessageType(NatMessageType.REGISTER_RESULT);
            failed.setMetaData(Map.of(
                    "port", 9000,
                    "success", false,
                    "reason", "address already in use"));
            channel.writeInbound(failed);

            assertTrue(channel.isActive());
            handler.applyConfig(specusBean(mapping));
            assertNatMessage(channel.readOutbound(), NatMessageType.REGISTER, 9000);
            assertNull(channel.readOutbound());
        } finally {
            channel.finishAndReleaseAll();
        }
    }

    @Test
    void shouldResetUnknownTcpDataAndFinWithoutClosingDataConnection() {
        NatClientHandler handler = new NatClientHandler(specusBean());
        EmbeddedChannel channel = new EmbeddedChannel(handler);
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
            assertReset(channel.readOutbound(), 42);
            assertReset(channel.readOutbound(), 42);
            assertNull(channel.readOutbound());
        } finally {
            channel.finishAndReleaseAll();
        }
    }

    @Test
    void shouldCloseDataConnectionForRstOnNeverOpenedStream() {
        NatClientHandler handler = new NatClientHandler(specusBean());
        EmbeddedChannel channel = new EmbeddedChannel(handler);
        try {
            channel.writeInbound(rst(43));

            assertFalse(channel.isActive());
            assertNull(channel.readOutbound());
        } finally {
            channel.finishAndReleaseAll();
        }
    }

    @Test
    @SuppressWarnings("unchecked")
    void shouldIgnoreLateRstForRecentlyClosedStream() throws Exception {
        NatClientHandler handler = new NatClientHandler(specusBean());
        EmbeddedChannel channel = new EmbeddedChannel(handler);
        HttpStreamForwarder forwarder = new HttpStreamForwarder(
                handler, 44, Map.of(), Map.of(), null);
        Field streamsField = NatClientHandler.class.getDeclaredField("httpStreams");
        streamsField.setAccessible(true);
        ((Map<Integer, HttpStreamForwarder>) streamsField.get(handler)).put(44, forwarder);
        try {
            handler.httpForwarderDone(44, forwarder);
            channel.writeInbound(rst(44));

            assertTrue(channel.isActive());
            assertNull(channel.readOutbound());
        } finally {
            channel.finishAndReleaseAll();
        }
    }

    @Test
    @SuppressWarnings("unchecked")
    void shouldDeliverHttpDataBeforeEndStreamFlagFinishesRequest() throws Exception {
        NatClientHandler handler = new NatClientHandler(specusBean());
        EmbeddedChannel channel = new EmbeddedChannel(handler);
        HttpStreamForwarder forwarder = new HttpStreamForwarder(
                handler, 77, Map.of(), Map.of(), null);
        Field streamsField = NatClientHandler.class.getDeclaredField("httpStreams");
        streamsField.setAccessible(true);
        ((Map<Integer, HttpStreamForwarder>) streamsField.get(handler)).put(77, forwarder);
        Field requestBodyField = HttpStreamForwarder.class.getDeclaredField("requestBody");
        requestBodyField.setAccessible(true);
        InputStream requestBody = (InputStream) requestBodyField.get(forwarder);
        try {
            byte[] payload = new byte[]{1, 2, 3};
            NatMessagePacket dataAndFin = new NatMessagePacket();
            dataAndFin.setNatMessageType(NatMessageType.DATA);
            dataAndFin.setStreamId(77);
            dataAndFin.setData(payload);
            dataAndFin.setFlags(NatMessagePacket.FLAG_END_STREAM);

            channel.writeInbound(dataAndFin);

            assertArrayEquals(payload, requestBody.readNBytes(payload.length));
            assertEquals(-1, requestBody.read());
            assertFalse(forwarder.onRequestFin(null));
        } finally {
            channel.finishAndReleaseAll();
        }
    }

    private SpecusBean specusBean(SpecusConfig... specusMappings) {
        SpecusBean bean = new SpecusBean();
        bean.setRemoteAddress("127.0.0.1");
        bean.setSpecusConfigList(List.of(specusMappings));
        return bean;
    }

    private SpecusConfig specus(int port, int targetPort) {
        SpecusConfig config = new SpecusConfig();
        config.setPort(port);
        config.setSpecusAddress("127.0.0.1");
        config.setSpecusPort(targetPort);
        return config;
    }

    private void assertNatMessage(NatMessagePacket message, NatMessageType type, int port) {
        assertNotNull(message);
        assertEquals(type, message.getNatMessageType());
        assertEquals(port, message.getMetaData().get("port"));
    }

    private void assertReset(NatMessagePacket message, int streamId) {
        assertNotNull(message);
        assertEquals(NatMessageType.RST, message.getNatMessageType());
        assertEquals(streamId, message.getStreamId());
    }

    private NatMessagePacket rst(int streamId) {
        NatMessagePacket packet = new NatMessagePacket();
        packet.setNatMessageType(NatMessageType.RST);
        packet.setStreamId(streamId);
        return packet;
    }

}
