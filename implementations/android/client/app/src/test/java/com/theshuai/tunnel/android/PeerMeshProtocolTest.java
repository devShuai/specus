package com.theshuai.tunnel.android;

import org.junit.Test;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

public class PeerMeshProtocolTest {
    @Test
    public void spm1FrameRoundTripsAndAuthenticatesHeaderAndCiphertext() throws Exception {
        byte[] key = new byte[32];
        for (int i = 0; i < key.length; i++) {
            key[i] = (byte) (i + 1);
        }
        byte[] plaintext = "hello peer mesh".getBytes(StandardCharsets.UTF_8);
        byte[] encoded = PeerMeshEngine.DataFrameCodec.encode(key, 91L, 10L, 20L, 7L, plaintext);

        assertTrue(PeerMeshEngine.DataFrameCodec.looksLike(encoded));
        assertEquals(Long.valueOf(91L), PeerMeshEngine.DataFrameCodec.sessionId(encoded));
        PeerMeshEngine.DataFrame decoded = PeerMeshEngine.DataFrameCodec.decode(key, encoded, 91L, 20L);
        assertEquals(91L, decoded.sessionId);
        assertEquals(10L, decoded.fromClientId);
        assertEquals(20L, decoded.toClientId);
        assertEquals(7L, decoded.sequence);
        assertArrayEquals(plaintext, decoded.plaintext);

        assertNull(PeerMeshEngine.DataFrameCodec.decode(key, encoded, 92L, 20L));
        assertNull(PeerMeshEngine.DataFrameCodec.decode(key, encoded, 91L, 21L));

        byte[] tampered = encoded.clone();
        tampered[tampered.length - 1] ^= 1;
        assertNull(PeerMeshEngine.DataFrameCodec.decode(key, tampered, 91L, 20L));

        byte[] withTrailingByte = Arrays.copyOf(encoded, encoded.length + 1);
        assertNull(PeerMeshEngine.DataFrameCodec.decode(key, withTrailingByte, 91L, 20L));
    }

    @Test
    public void replayWindowAcceptsUnseenInWindowSequencesOnlyOnce() {
        PeerMeshEngine.ReplayWindow replay = new PeerMeshEngine.ReplayWindow();
        assertFalse(replay.accept(0L));
        assertTrue(replay.accept(100L));
        assertTrue(replay.accept(99L));
        assertFalse(replay.accept(100L));
        assertTrue(replay.accept(164L));
        assertFalse(replay.accept(100L));
        assertTrue(replay.accept(101L));
        assertFalse(replay.accept(101L));
    }

    @Test
    public void copiedReplayWindowPreservesHistoryWithoutSharingFutureBits() {
        PeerMeshEngine.ReplayWindow original = new PeerMeshEngine.ReplayWindow();
        assertTrue(original.accept(7L));
        PeerMeshEngine.ReplayWindow copy = original.copy();
        assertFalse(copy.accept(7L));
        assertTrue(original.accept(6L));
        assertTrue(copy.accept(6L));
    }

    @Test
    public void sameSessionGrantPreservesSequencesButNewSessionResetsThem() {
        PeerMeshEngine.PeerSession previous =
                new PeerMeshEngine.PeerSession(2L, 100L, "token-a", "");
        previous.nextSequence();
        previous.nextSequence();
        assertTrue(previous.accept(9L));
        previous.remoteEndpoint = new InetSocketAddress("127.0.0.1", 5000);
        previous.pathReady = true;

        PeerMeshEngine.PeerSession same =
                new PeerMeshEngine.PeerSession(2L, 100L, "token-a", "");
        same.inheritTransportState(previous);
        assertEquals(3L, same.nextSequence());
        assertFalse(same.accept(9L));
        assertEquals(previous.remoteEndpoint, same.remoteEndpoint);
        assertTrue(same.pathReady);

        PeerMeshEngine.PeerSession renewed =
                new PeerMeshEngine.PeerSession(2L, 101L, "token-b", "");
        renewed.inheritTransportState(previous);
        assertEquals(1L, renewed.nextSequence());
        assertTrue(renewed.accept(9L));
        assertEquals(previous.remoteEndpoint, renewed.remoteEndpoint);
        assertTrue(renewed.pathReady);
    }

    @Test
    public void turnChallengeParsesAndUpdatesRealmAndNonce() {
        byte[] transactionId = transactionId(1);
        PeerMeshEngine.StunMessage challengeMessage = PeerMeshEngine.StunMessage.of(
                PeerMeshEngine.StunMessage.ALLOCATE_ERROR,
                transactionId,
                PeerMeshEngine.StunMessage.errorCode(401, "Unauthorized"),
                PeerMeshEngine.StunMessage.realm("fresh-realm"),
                PeerMeshEngine.StunMessage.nonce("fresh-nonce"));

        PeerMeshEngine.StunMessage parsed = PeerMeshEngine.StunMessage.parse(challengeMessage.toBytes());
        PeerMeshEngine.TurnChallenge challenge = PeerMeshEngine.TurnChallenge.from(parsed);
        assertNotNull(challenge);
        assertEquals(401, challenge.code);
        assertEquals("Unauthorized", challenge.reason);
        assertEquals("fresh-realm", challenge.realm);
        assertEquals("fresh-nonce", challenge.nonce);
        assertTrue(challenge.retryable());

        TunnelCore.PeerMeshConfig config = new TunnelCore.PeerMeshConfig();
        config.iceUsername = "client";
        config.iceCredential = "secret";
        config.iceRealm = "old-realm";
        config.iceNonce = "old-nonce";
        assertTrue(challenge.applyTo(config));
        assertEquals("fresh-realm", config.iceRealm);
        assertEquals("fresh-nonce", config.iceNonce);

        PeerMeshEngine.TurnChallenge staleNonce = PeerMeshEngine.TurnChallenge.from(
                PeerMeshEngine.StunMessage.parse(PeerMeshEngine.StunMessage.of(
                        PeerMeshEngine.StunMessage.REFRESH_ERROR,
                        transactionId(2),
                        PeerMeshEngine.StunMessage.errorCode(438, "Stale Nonce"),
                        PeerMeshEngine.StunMessage.realm("fresh-realm"),
                        PeerMeshEngine.StunMessage.nonce("newer-nonce")).toBytes()));
        assertNotNull(staleNonce);
        assertTrue(staleNonce.retryable());
        assertTrue(staleNonce.applyTo(config));
        assertEquals("newer-nonce", config.iceNonce);
    }

    @Test
    public void turnPendingRequestsPreserveOperationAndRetryOnlyOnce() throws Exception {
        InetSocketAddress peer = new InetSocketAddress(InetAddress.getByName("2001:db8::42"), 54321);
        PeerMeshEngine.PendingTurnRequest[] pending = new PeerMeshEngine.PendingTurnRequest[]{
                PeerMeshEngine.PendingTurnRequest.allocate(),
                PeerMeshEngine.PendingTurnRequest.refresh(240L),
                PeerMeshEngine.PendingTurnRequest.createPermission(peer)
        };

        assertEquals(PeerMeshEngine.TurnOperation.ALLOCATE, pending[0].operation);
        assertEquals(PeerMeshEngine.StunMessage.ATTR_REQUESTED_TRANSPORT,
                pending[0].operationAttributes(transactionId(3))[0].type);
        assertEquals(PeerMeshEngine.TurnOperation.REFRESH, pending[1].operation);
        assertEquals(240L, pending[1].lifetimeSeconds);
        assertEquals(PeerMeshEngine.StunMessage.ATTR_LIFETIME,
                pending[1].operationAttributes(transactionId(4))[0].type);
        assertEquals(PeerMeshEngine.TurnOperation.CREATE_PERMISSION, pending[2].operation);
        assertEquals(peer, pending[2].peer);

        for (PeerMeshEngine.PendingTurnRequest original : pending) {
            PeerMeshEngine.PendingTurnRequest retry = original.retryOnce();
            assertNotNull(retry);
            assertTrue(retry.retried);
            assertEquals(original.operation, retry.operation);
            assertEquals(original.lifetimeSeconds, retry.lifetimeSeconds);
            assertEquals(original.peer, retry.peer);
            assertNull(retry.retryOnce());
        }
    }

    @Test
    public void turnPendingRequestRequiresMatchingResponseEndpoint() throws Exception {
        InetSocketAddress endpoint = new InetSocketAddress(InetAddress.getByName("192.0.2.10"), 3478);
        InetSocketAddress same = new InetSocketAddress(InetAddress.getByName("192.0.2.10"), 3478);
        InetSocketAddress wrongHost = new InetSocketAddress(InetAddress.getByName("192.0.2.11"), 3478);
        InetSocketAddress wrongPort = new InetSocketAddress(InetAddress.getByName("192.0.2.10"), 3479);
        PeerMeshEngine.PendingTurnRequest tracked = PeerMeshEngine.PendingTurnRequest.allocate()
                .withEndpointAndCreatedAt(endpoint, 123L);

        assertEquals(endpoint, tracked.endpoint);
        assertTrue(PeerMeshEngine.sameEndpoint(tracked.endpoint, same));
        assertFalse(PeerMeshEngine.sameEndpoint(tracked.endpoint, wrongHost));
        assertFalse(PeerMeshEngine.sameEndpoint(tracked.endpoint, wrongPort));
        assertFalse(PeerMeshEngine.sameEndpoint(tracked.endpoint, null));
    }

    @Test
    public void trafficReportCounterContainsDirectBytesOnly() {
        PeerMeshEngine.PeerSession session = new PeerMeshEngine.PeerSession(2L, 101L, "token", "");
        session.addDirectBytes(123L);

        assertEquals(123L, session.drainDirectBytes());
        assertEquals(0L, session.drainDirectBytes());
    }

    @Test
    public void createPermissionRebuildsIpv6XorAttributeForNewTransactionId() throws Exception {
        InetSocketAddress peer = new InetSocketAddress(InetAddress.getByName("2001:db8::7"), 3479);
        PeerMeshEngine.PendingTurnRequest pending = PeerMeshEngine.PendingTurnRequest.createPermission(peer);
        byte[] firstTransactionId = transactionId(10);
        byte[] secondTransactionId = transactionId(30);

        PeerMeshEngine.StunMessage.Attribute first = pending.operationAttributes(firstTransactionId)[0];
        PeerMeshEngine.StunMessage.Attribute second = pending.operationAttributes(secondTransactionId)[0];
        assertEquals(PeerMeshEngine.StunMessage.ATTR_XOR_PEER_ADDRESS, first.type);
        assertFalse(Arrays.equals(first.value, second.value));

        PeerMeshEngine.StunMessage firstMessage = PeerMeshEngine.StunMessage.parse(
                PeerMeshEngine.StunMessage.of(
                        PeerMeshEngine.StunMessage.CREATE_PERMISSION_REQUEST,
                        firstTransactionId,
                        first).toBytes());
        PeerMeshEngine.StunMessage secondMessage = PeerMeshEngine.StunMessage.parse(
                PeerMeshEngine.StunMessage.of(
                        PeerMeshEngine.StunMessage.CREATE_PERMISSION_REQUEST,
                        secondTransactionId,
                        second).toBytes());
        assertNotNull(firstMessage);
        assertNotNull(secondMessage);
        assertEquals(peer, firstMessage.xorPeerAddress());
        assertEquals(peer, secondMessage.xorPeerAddress());
    }

    private static byte[] transactionId(int start) {
        byte[] result = new byte[PeerMeshEngine.StunMessage.TRANSACTION_ID_BYTES];
        for (int i = 0; i < result.length; i++) {
            result[i] = (byte) (start + i);
        }
        return result;
    }
}
