package com.theshuai.specusclient.handler;

import com.theshuai.common.protocol.NatMessagePacket;
import com.theshuai.common.protocol.NatMessageType;
import com.theshuai.specusclient.bean.SpecusBean;
import com.theshuai.specusclient.bean.SpecusConfig;
import com.theshuai.specusclient.client.NettyClient;
import io.netty.channel.embedded.EmbeddedChannel;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
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

}
