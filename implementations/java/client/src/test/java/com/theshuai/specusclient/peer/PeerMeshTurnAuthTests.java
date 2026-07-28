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
import java.net.SocketTimeoutException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.MessageDigest;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PeerMeshTurnAuthTests {
    private static final String USERNAME = "1900000000:client-a:01020304";
    private static final String CREDENTIAL = "turn-credential";

    @TempDir
    Path tempDir;

    @Test
    void staleNonceChallengeRetriesOnceWithNewTransactionAndIntegrity() throws Exception {
        String previousHome = System.getProperty("user.home");
        System.setProperty("user.home", tempDir.toString());
        PeerMeshClient client = null;
        try (DatagramSocket turnServer = new DatagramSocket(
                new InetSocketAddress(InetAddress.getLoopbackAddress(), 0));
             DatagramSocket clientSocket = new DatagramSocket(
                     new InetSocketAddress(InetAddress.getLoopbackAddress(), 0))) {
            turnServer.setSoTimeout(1_000);
            ClientAuthLoginResponse.PeerMeshConfig config = config("old-realm", "old-nonce");
            client = new PeerMeshClient(config, (target, payload) -> {
            });
            setUdpSocket(client, clientSocket);

            InetSocketAddress turnEndpoint = new InetSocketAddress(
                    InetAddress.getLoopbackAddress(), turnServer.getLocalPort());
            StunMessage allocate = StunMessage.of(
                    StunMessage.ALLOCATE_REQUEST,
                    transactionId(1),
                    StunMessage.requestedUdpTransportAttribute());
            sendStunRequest(client, allocate, turnEndpoint);

            CapturedStun first = receive(turnServer);
            assertEquals("old-nonce", first.message().nonce().orElseThrow());
            assertTrue(StunMessage.verifyMessageIntegrity(
                    first.bytes(),
                    0,
                    first.bytes().length,
                    longTermKey("old-realm")));

            StunMessage staleNonce = StunMessage.of(
                    StunMessage.ALLOCATE_ERROR,
                    first.message().transactionId(),
                    StunMessage.errorCode(438, "stale-nonce"),
                    StunMessage.realm("new-realm"),
                    StunMessage.nonce("new-nonce"));
            handleStunTurnMessage(client, staleNonce, turnEndpoint);

            CapturedStun retry = receive(turnServer);
            assertNotEquals(first.message().transactionIdHex(), retry.message().transactionIdHex());
            assertEquals(USERNAME, retry.message().username().orElseThrow());
            assertEquals("new-realm", retry.message().realm().orElseThrow());
            assertEquals("new-nonce", retry.message().nonce().orElseThrow());
            assertTrue(StunMessage.verifyMessageIntegrity(
                    retry.bytes(),
                    0,
                    retry.bytes().length,
                    longTermKey("new-realm")));

            StunMessage repeatedChallenge = StunMessage.of(
                    StunMessage.ALLOCATE_ERROR,
                    retry.message().transactionId(),
                    StunMessage.errorCode(438, "stale-nonce"),
                    StunMessage.realm("newer-realm"),
                    StunMessage.nonce("newer-nonce"));
            handleStunTurnMessage(client, repeatedChallenge, turnEndpoint);
            DatagramPacket unexpected = new DatagramPacket(new byte[2_048], 2_048);
            assertThrows(SocketTimeoutException.class, () -> turnServer.receive(unexpected));
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

    private CapturedStun receive(DatagramSocket socket) throws Exception {
        DatagramPacket packet = new DatagramPacket(new byte[2_048], 2_048);
        socket.receive(packet);
        byte[] bytes = java.util.Arrays.copyOfRange(
                packet.getData(), packet.getOffset(), packet.getOffset() + packet.getLength());
        return new CapturedStun(bytes, StunMessage.parse(bytes, 0, bytes.length));
    }

    private ClientAuthLoginResponse.PeerMeshConfig config(String realm, String nonce) {
        ClientAuthLoginResponse.PeerMeshConfig config = new ClientAuthLoginResponse.PeerMeshConfig();
        config.setIceUsername(USERNAME);
        config.setIceCredential(CREDENTIAL);
        config.setIceRealm(realm);
        config.setIceNonce(nonce);
        return config;
    }

    private byte[] longTermKey(String realm) throws Exception {
        return MessageDigest.getInstance("MD5").digest(
                (USERNAME + ":" + realm + ":" + CREDENTIAL).getBytes(StandardCharsets.UTF_8));
    }

    private byte[] transactionId(int seed) {
        byte[] value = new byte[StunMessage.TRANSACTION_ID_BYTES];
        for (int i = 0; i < value.length; i++) {
            value[i] = (byte) (seed + i);
        }
        return value;
    }

    private void setUdpSocket(PeerMeshClient client, DatagramSocket socket) throws Exception {
        Field field = PeerMeshClient.class.getDeclaredField("udpSocket");
        field.setAccessible(true);
        field.set(client, socket);
    }

    private void sendStunRequest(PeerMeshClient client,
                                 StunMessage request,
                                 InetSocketAddress endpoint) throws Exception {
        Method method = PeerMeshClient.class.getDeclaredMethod(
                "sendStunRequest", StunMessage.class, InetSocketAddress.class);
        method.setAccessible(true);
        method.invoke(client, request, endpoint);
    }

    private void handleStunTurnMessage(PeerMeshClient client,
                                       StunMessage response,
                                       InetSocketAddress endpoint) throws Exception {
        Method method = PeerMeshClient.class.getDeclaredMethod(
                "handleStunTurnMessage", StunMessage.class, InetSocketAddress.class);
        method.setAccessible(true);
        method.invoke(client, response, endpoint);
    }

    private record CapturedStun(byte[] bytes, StunMessage message) {
    }
}
