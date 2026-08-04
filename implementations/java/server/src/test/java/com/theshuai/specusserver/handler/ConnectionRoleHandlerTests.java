package com.theshuai.specusserver.handler;

import com.theshuai.common.protocol.ConnectionRole;
import com.theshuai.common.protocol.NatMessagePacket;
import com.theshuai.common.protocol.Packet;
import com.theshuai.common.protocol.request.HeartBeatRequestPacket;
import com.theshuai.common.protocol.request.LogoutRequestPacket;
import com.theshuai.common.protocol.request.MessageRequestPacket;
import com.theshuai.common.protocol.response.HeartBeatResponsePacket;
import com.theshuai.common.protocol.response.LoginResponsePacket;
import com.theshuai.common.protocol.response.LogoutResponsePacket;
import com.theshuai.common.protocol.response.MessageResponsePacket;
import com.theshuai.specusserver.attribute.ServerAttributes;
import com.theshuai.specusserver.management.model.DisconnectReason;
import io.netty.channel.embedded.EmbeddedChannel;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class ConnectionRoleHandlerTests {

    @Test
    void controlRoleAcceptsOnlyClientControlFrames() {
        for (Packet packet : List.of(
                new MessageRequestPacket(),
                new HeartBeatRequestPacket(),
                new HeartBeatResponsePacket(),
                new LogoutRequestPacket())) {
            assertAccepted(ConnectionRole.CONTROL, packet);
        }

        for (Packet packet : serverResponsePackets()) {
            assertRejected(ConnectionRole.CONTROL, packet);
        }
        assertRejected(ConnectionRole.CONTROL, new NatMessagePacket());
    }

    @Test
    void dataRoleAcceptsOnlyNatHeartbeatAndLogoutRequest() {
        for (Packet packet : List.of(
                new NatMessagePacket(),
                new HeartBeatRequestPacket(),
                new HeartBeatResponsePacket(),
                new LogoutRequestPacket())) {
            assertAccepted(ConnectionRole.DATA, packet);
        }

        assertRejected(ConnectionRole.DATA, new MessageRequestPacket());
        for (Packet packet : serverResponsePackets()) {
            assertRejected(ConnectionRole.DATA, packet);
        }
    }

    private static List<Packet> serverResponsePackets() {
        return List.of(new LoginResponsePacket(), new MessageResponsePacket(), new LogoutResponsePacket());
    }

    private static void assertAccepted(String role, Packet packet) {
        EmbeddedChannel channel = channel(role);
        assertThat(channel.writeInbound(packet)).isTrue();
        Packet inbound = channel.readInbound();
        assertThat(inbound).isSameAs(packet);
        assertThat(channel.isActive()).isTrue();
        channel.finishAndReleaseAll();
    }

    private static void assertRejected(String role, Packet packet) {
        EmbeddedChannel channel = channel(role);
        assertThat(channel.writeInbound(packet)).isFalse();
        channel.runPendingTasks();
        assertThat(channel.isActive()).isFalse();
        assertThat(DisconnectReason.readFrom(channel)).isEqualTo(DisconnectReason.PROTOCOL_VIOLATION);
        channel.finishAndReleaseAll();
    }

    private static EmbeddedChannel channel(String role) {
        EmbeddedChannel channel = new EmbeddedChannel(ConnectionRoleHandler.INSTANCE);
        channel.attr(ServerAttributes.CONNECTION_ROLE).set(role);
        return channel;
    }
}
