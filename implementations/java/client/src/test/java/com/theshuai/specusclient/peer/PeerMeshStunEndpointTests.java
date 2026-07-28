package com.theshuai.specusclient.peer;

import com.theshuai.common.clientauth.ClientAuthLoginResponse;
import com.theshuai.common.stun.StunMessage;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.file.Path;
import java.util.Arrays;

import static org.assertj.core.api.Assertions.assertThat;

class PeerMeshStunEndpointTests {
    @TempDir
    Path tempDir;

    @Test
    void usesStandaloneStunAndStartsRfc5780FilteringProbe() throws Exception {
        String previousHome = System.getProperty("user.home");
        System.setProperty("user.home", tempDir.toString());
        PeerMeshClient client = null;
        InetAddress loopback = InetAddress.getLoopbackAddress();
        try (DatagramSocket stunServer = socket(loopback);
             DatagramSocket turnServer = socket(loopback);
             DatagramSocket clientSocket = socket(loopback)) {
            ClientAuthLoginResponse.PeerMeshConfig disabled = new ClientAuthLoginResponse.PeerMeshConfig();
            client = new PeerMeshClient(disabled, (target, payload) -> {
            });

            ClientAuthLoginResponse.PeerMeshConfig config = new ClientAuthLoginResponse.PeerMeshConfig();
            config.setEnabled(true);
            config.setClientId(1L);
            config.setClientName("client-a");
            config.setStunHost(loopback.getHostAddress());
            config.setStunPort(stunServer.getLocalPort());
            config.setTurnHost(loopback.getHostAddress());
            config.setTurnPort(turnServer.getLocalPort());
            setField(client, "config", config);
            setField(client, "running", true);
            setField(client, "udpSocket", clientSocket);

            invoke(client, "requestPeerServerCandidates");

            CapturedStun binding = receive(stunServer);
            CapturedStun allocate = receive(turnServer);
            assertThat(binding.message().type()).isEqualTo(StunMessage.BINDING_REQUEST);
            assertThat(allocate.message().type()).isEqualTo(StunMessage.ALLOCATE_REQUEST);

            InetSocketAddress stunEndpoint =
                    new InetSocketAddress(loopback, stunServer.getLocalPort());
            InetSocketAddress mapped = new InetSocketAddress("198.51.100.20", 52000);
            int otherPort = stunServer.getLocalPort() == 65_535
                    ? stunServer.getLocalPort() - 1
                    : stunServer.getLocalPort() + 1;
            InetSocketAddress other = new InetSocketAddress("127.0.0.2", otherPort);
            StunMessage success = StunMessage.of(
                    StunMessage.BINDING_SUCCESS,
                    binding.message().transactionId(),
                    StunMessage.xorMappedAddress(mapped, binding.message().transactionId()),
                    StunMessage.responseOrigin(stunEndpoint),
                    StunMessage.otherAddress(other));
            invoke(
                    client,
                    "handleStunTurnMessage",
                    new Class<?>[]{StunMessage.class, InetSocketAddress.class},
                    success,
                    stunEndpoint);

            CapturedStun filteringProbe = receive(stunServer);
            assertThat(filteringProbe.message().type()).isEqualTo(StunMessage.BINDING_REQUEST);
            assertThat(filteringProbe.message().changeRequest()).hasValueSatisfying(change -> {
                assertThat(change.changeIp()).isTrue();
                assertThat(change.changePort()).isTrue();
            });
        } finally {
            if (client != null) {
                client.close();
            }
            if (previousHome == null) {
                System.clearProperty("user.home");
            } else {
                System.setProperty("user.home", previousHome);
            }
        }
    }

    private DatagramSocket socket(InetAddress address) throws Exception {
        DatagramSocket socket = new DatagramSocket(new InetSocketAddress(address, 0));
        socket.setSoTimeout(1_000);
        return socket;
    }

    private CapturedStun receive(DatagramSocket socket) throws Exception {
        DatagramPacket packet = new DatagramPacket(new byte[2_048], 2_048);
        socket.receive(packet);
        byte[] bytes = Arrays.copyOfRange(
                packet.getData(),
                packet.getOffset(),
                packet.getOffset() + packet.getLength());
        return new CapturedStun(StunMessage.parse(bytes, 0, bytes.length));
    }

    private void setField(PeerMeshClient client, String fieldName, Object value) throws Exception {
        Field field = PeerMeshClient.class.getDeclaredField(fieldName);
        field.setAccessible(true);
        field.set(client, value);
    }

    private void invoke(PeerMeshClient client, String methodName) throws Exception {
        invoke(client, methodName, new Class<?>[0]);
    }

    private void invoke(PeerMeshClient client,
                        String methodName,
                        Class<?>[] parameterTypes,
                        Object... arguments) throws Exception {
        Method method = PeerMeshClient.class.getDeclaredMethod(methodName, parameterTypes);
        method.setAccessible(true);
        method.invoke(client, arguments);
    }

    private record CapturedStun(StunMessage message) {
    }
}
