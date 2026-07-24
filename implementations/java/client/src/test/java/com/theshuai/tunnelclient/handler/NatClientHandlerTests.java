package com.theshuai.tunnelclient.handler;

import com.theshuai.common.protocol.NatMessagePacket;
import com.theshuai.common.protocol.NatMessageType;
import com.theshuai.tunnelclient.bean.TunnelBean;
import com.theshuai.tunnelclient.bean.TunnelConfig;
import com.theshuai.tunnelclient.client.NettyClient;
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
        NatClientHandler handler = new NatClientHandler(tunnelBean());
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
    void shouldSynchronizeTunnelSnapshotAfterHandlerWasAdded() {
        NatClientHandler handler = new NatClientHandler(tunnelBean(tunnel(9000, 8080)));
        EmbeddedChannel channel = new EmbeddedChannel(handler);
        try {
            assertNotNull(handler.getCtx());
            assertNatMessage(channel.readOutbound(), NatMessageType.REGISTER, 9000);
            assertNull(channel.readOutbound());

            handler.applyConfig(tunnelBean(tunnel(9001, 8081)));

            assertNatMessage(channel.readOutbound(), NatMessageType.UNREGISTER, 9000);
            assertNatMessage(channel.readOutbound(), NatMessageType.REGISTER, 9001);
            assertNull(channel.readOutbound());
        } finally {
            channel.finishAndReleaseAll();
        }
    }

    @Test
    void shouldKeepSessionAndRetryPortAfterRegisterFailure() {
        TunnelConfig mapping = tunnel(9000, 8080);
        NatClientHandler handler = new NatClientHandler(tunnelBean(mapping));
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
            handler.applyConfig(tunnelBean(mapping));
            assertNatMessage(channel.readOutbound(), NatMessageType.REGISTER, 9000);
            assertNull(channel.readOutbound());
        } finally {
            channel.finishAndReleaseAll();
        }
    }

    private TunnelBean tunnelBean(TunnelConfig... tunnels) {
        TunnelBean bean = new TunnelBean();
        bean.setRemoteAddress("127.0.0.1");
        bean.setTunnelConfigList(List.of(tunnels));
        return bean;
    }

    private TunnelConfig tunnel(int port, int targetPort) {
        TunnelConfig config = new TunnelConfig();
        config.setPort(port);
        config.setTunnelAddress("127.0.0.1");
        config.setTunnelPort(targetPort);
        return config;
    }

    private void assertNatMessage(NatMessagePacket message, NatMessageType type, int port) {
        assertNotNull(message);
        assertEquals(type, message.getNatMessageType());
        assertEquals(port, message.getMetaData().get("port"));
    }

}
