package com.theshuai.tunnel.android;

import org.json.JSONObject;
import org.junit.Test;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

public class PeerMeshProtocolTest {
    @Test
    public void spm2FrameRoundTripsAndAuthenticatesHeaderAndCiphertext() throws Exception {
        byte[] key = new byte[32];
        for (int i = 0; i < key.length; i++) {
            key[i] = (byte) (i + 1);
        }
        byte[] plaintext = "hello peer mesh".getBytes(StandardCharsets.UTF_8);
        byte[] encoded = PeerMeshEngine.DataFrameCodec.encode(key, 91L, 10L, 20L, "epoch-a", 7L, plaintext);

        assertTrue(PeerMeshEngine.DataFrameCodec.looksLike(encoded));
        assertEquals(Long.valueOf(91L), PeerMeshEngine.DataFrameCodec.sessionId(encoded));
        PeerMeshEngine.DataFrame decoded = PeerMeshEngine.DataFrameCodec.decode(key, encoded, 91L, 10L, 20L, "epoch-a");
        assertEquals(91L, decoded.sessionId);
        assertEquals(7L, decoded.sequence);
        assertArrayEquals(plaintext, decoded.plaintext);

        assertNull(PeerMeshEngine.DataFrameCodec.decode(key, encoded, 92L, 10L, 20L, "epoch-a"));
        assertNull(PeerMeshEngine.DataFrameCodec.decode(key, encoded, 91L, 20L, 10L, "epoch-a"));

        byte[] tampered = encoded.clone();
        tampered[tampered.length - 1] ^= 1;
        assertNull(PeerMeshEngine.DataFrameCodec.decode(key, tampered, 91L, 10L, 20L, "epoch-a"));

        byte[] withTrailingByte = Arrays.copyOf(encoded, encoded.length + 1);
        assertNull(PeerMeshEngine.DataFrameCodec.decode(key, withTrailingByte, 91L, 10L, 20L, "epoch-a"));
    }

    @Test
    public void spm2FrameMatchesSharedWireVector() throws Exception {
        JSONObject vector = ProtocolVectorTestSupport.read("peer-mesh-spm2.json");
        byte[] key = ProtocolVectorTestSupport.hex(vector.getString("sessionKeyHex"));
        long sessionId = vector.getLong("sessionId");
        long fromClientId = vector.getLong("fromClientId");
        long toClientId = vector.getLong("toClientId");
        String senderKeyEpoch = vector.getString("senderKeyEpoch");
        long sequence = vector.getLong("sequence");
        byte[] plaintext = vector.getString("plaintextUtf8").getBytes(StandardCharsets.UTF_8);

        byte[] encoded = PeerMeshEngine.DataFrameCodec.encode(
                key,
                sessionId,
                fromClientId,
                toClientId,
                senderKeyEpoch,
                sequence,
                plaintext);

        assertArrayEquals(ProtocolVectorTestSupport.hex(vector.getString("frameHex")), encoded);
        PeerMeshEngine.DataFrame decoded = PeerMeshEngine.DataFrameCodec.decode(
                key, encoded, sessionId, fromClientId, toClientId, senderKeyEpoch);
        assertNotNull(decoded);
        assertEquals(sequence, decoded.sequence);
        assertArrayEquals(plaintext, decoded.plaintext);

        assertNull(PeerMeshEngine.DataFrameCodec.decode(
                key, encoded, sessionId, toClientId, fromClientId, senderKeyEpoch));

        byte[] invalidSequence = encoded.clone();
        Arrays.fill(invalidSequence, 12, 20, (byte) 0);
        assertNull(PeerMeshEngine.DataFrameCodec.decode(
                key, invalidSequence, sessionId, fromClientId, toClientId, senderKeyEpoch));
    }

    @Test
    public void spm2KeyEpochIsolatesNonceSpaceAcrossRestarts() throws Exception {
        // 客户端重启后可能拿回同一 sessionId/token，而 sequence 从 1 重新开始。
        // epoch 必须改变 traffic key，否则同一 key 下会重放同一段 nonce 空间。
        byte[] key = new byte[32];
        for (int i = 0; i < key.length; i++) {
            key[i] = (byte) (i + 1);
        }
        byte[] plaintext = "payload".getBytes(StandardCharsets.UTF_8);
        byte[] before = PeerMeshEngine.DataFrameCodec.encode(
                key, 91L, 10L, 20L, "epoch-before-restart", 1L, plaintext);
        byte[] after = PeerMeshEngine.DataFrameCodec.encode(
                key, 91L, 10L, 20L, "epoch-after-restart", 1L, plaintext);

        assertFalse(Arrays.equals(before, after));
        assertNull(PeerMeshEngine.DataFrameCodec.decode(
                key, before, 91L, 10L, 20L, "epoch-after-restart"));
    }

    @Test
    public void replayWindowAcceptsUnseenInWindowSequencesOnlyOnce() {
        PeerMeshEngine.ReplayWindow replay = new PeerMeshEngine.ReplayWindow();
        assertFalse(replay.accept(0L));
        assertTrue(replay.accept(100L));
        assertTrue(replay.accept(99L));
        assertFalse(replay.accept(100L));
        assertTrue(replay.accept(101L));
        assertFalse(replay.accept(101L));
        assertTrue(replay.accept(5000L));
        assertFalse(replay.accept(100L));
    }

    @Test
    public void sessionReplayWindowRejectsDuplicates() {
        PeerMeshEngine.PeerSession session =
                new PeerMeshEngine.PeerSession(2L, 100L, "token", "");

        assertTrue(session.accept(new PeerMeshEngine.DataFrame(100L, 7L, new byte[0])));
        assertFalse(session.accept(new PeerMeshEngine.DataFrame(100L, 7L, new byte[0])));
        assertTrue(session.accept(new PeerMeshEngine.DataFrame(100L, 8L, new byte[0])));
        assertFalse(session.accept(new PeerMeshEngine.DataFrame(100L, 0L, new byte[0])));
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
				PeerMeshEngine.PendingTurnRequest.createPermission(peer),
				PeerMeshEngine.PendingTurnRequest.channelBind(peer, PeerMeshEngine.TurnChannelData.MIN_CHANNEL)
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
		assertEquals(PeerMeshEngine.TurnOperation.CHANNEL_BIND, pending[3].operation);
		assertEquals(PeerMeshEngine.StunMessage.ATTR_CHANNEL_NUMBER,
				pending[3].operationAttributes(transactionId(5))[0].type);
		assertEquals(PeerMeshEngine.StunMessage.ATTR_XOR_PEER_ADDRESS,
				pending[3].operationAttributes(transactionId(5))[1].type);

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
	public void turnChannelDataRoundTripsAndRejectsTrailingBytes() {
		byte[] encoded = PeerMeshEngine.TurnChannelData.encode(
				PeerMeshEngine.TurnChannelData.MIN_CHANNEL, new byte[]{1, 2, 3});
		PeerMeshEngine.TurnChannelData decoded = PeerMeshEngine.TurnChannelData.parse(encoded);
		assertNotNull(decoded);
		assertEquals(PeerMeshEngine.TurnChannelData.MIN_CHANNEL, decoded.channelNumber);
		assertArrayEquals(new byte[]{1, 2, 3}, decoded.payload);
		assertNull(PeerMeshEngine.TurnChannelData.parse(Arrays.copyOf(encoded, encoded.length + 3)));
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

    @Test
    public void stunRfc5780AttributesRoundTrip() throws Exception {
        byte[] transactionId = transactionId(50);
        InetSocketAddress mapped = new InetSocketAddress(
                InetAddress.getByName("198.51.100.20"), 52000);
        InetSocketAddress origin = new InetSocketAddress(
                InetAddress.getByName("203.0.113.10"), 3478);
        InetSocketAddress other = new InetSocketAddress(
                InetAddress.getByName("203.0.113.11"), 3479);
        PeerMeshEngine.StunMessage parsed = PeerMeshEngine.StunMessage.parse(
                PeerMeshEngine.StunMessage.of(
                        PeerMeshEngine.StunMessage.BINDING_SUCCESS,
                        transactionId,
                        PeerMeshEngine.StunMessage.xorMappedAddress(mapped, transactionId),
                        PeerMeshEngine.StunMessage.responseOrigin(origin),
                        PeerMeshEngine.StunMessage.otherAddress(other),
                        PeerMeshEngine.StunMessage.changeRequest(true, true),
                        PeerMeshEngine.StunMessage.unknownAttributes(
                                PeerMeshEngine.StunMessage.ATTR_CHANGE_REQUEST)).toBytes());

        assertNotNull(parsed);
        assertEquals(mapped, parsed.xorMappedAddress());
        assertEquals(origin, parsed.responseOrigin());
        assertEquals(other, parsed.otherAddress());
        PeerMeshEngine.StunMessage.ChangeRequest change = parsed.changeRequest();
        assertNotNull(change);
        assertTrue(change.changeIp);
        assertTrue(change.changePort);
        assertEquals(
                List.of(PeerMeshEngine.StunMessage.ATTR_CHANGE_REQUEST),
                parsed.unknownAttributes());
    }

    private static byte[] transactionId(int start) {
        byte[] result = new byte[PeerMeshEngine.StunMessage.TRANSACTION_ID_BYTES];
        for (int i = 0; i < result.length; i++) {
            result[i] = (byte) (start + i);
        }
        return result;
    }

    private static PeerMeshEngine.PeerCandidate candidate(String type, String transport,
                                                          String address, int port, long priority,
                                                          String foundation) {
        PeerMeshEngine.PeerCandidate candidate = new PeerMeshEngine.PeerCandidate();
        candidate.type = type;
        candidate.transport = transport;
        candidate.address = address;
        candidate.port = port;
        candidate.priority = priority;
        candidate.foundation = foundation;
        return candidate;
    }

    @Test
    public void sortedDirectCandidateEndpointsOrdersByPriorityDescending() {
        // H-3：连通性检查候选按 priority 降序排列，高优先级（host）排在前面先被探测。
        List<PeerMeshEngine.PeerCandidate> input = Arrays.asList(
                candidate("srflx", "udp", "203.0.113.10", 30001, 800, "standard-stun"),
                candidate("host", "udp", "192.168.1.5", 40000, 1000, "host"),
                candidate("srflx", "udp", "203.0.113.20", 30002, 900, "public-stun"));
        java.util.Set<String> noLocal = java.util.Collections.emptySet();
        List<InetSocketAddress> endpoints = PeerMeshEngine.sortedDirectCandidateEndpoints(input, noLocal);
        // 期望顺序：1000 (host:192.168.1.5) -> 900 (203.0.113.20) -> 800 (203.0.113.10)
        assertEquals(3, endpoints.size());
        assertEquals(new InetSocketAddress("192.168.1.5", 40000), endpoints.get(0));
        assertEquals(new InetSocketAddress("203.0.113.20", 30002), endpoints.get(1));
        assertEquals(new InetSocketAddress("203.0.113.10", 30001), endpoints.get(2));
    }

    @Test
    public void demoteSameNatReflexiveCandidatesLowersPriorityWithoutPruning() {
        // H-6：与本地 STUN 公网地址相同的 reflexive 候选被降到 priority=1（排到末尾），而非被剪除。
        String localAddr = "203.0.113.42";
        java.util.Set<String> localAddresses = new java.util.HashSet<>();
        localAddresses.add(localAddr);
        List<PeerMeshEngine.PeerCandidate> input = Arrays.asList(
                // 同 NAT 的 srflx：应被降权到 priority=1
                candidate("srflx", "udp", localAddr, 34567, 800, "standard-stun"),
                // 不同地址的 srflx：保持原 priority
                candidate("srflx", "udp", "203.0.113.99", 35000, 800, "public-stun"),
                // host 候选：不受影响
                candidate("host", "udp", "192.168.1.5", 40000, 1000, "host"));
        List<PeerMeshEngine.PeerCandidate> demoted =
                PeerMeshEngine.demoteSameNatReflexiveCandidates(input, localAddresses);
        // 降权不剪除：数量不变
        assertEquals(3, demoted.size());
        // 同 NAT 的 srflx 应被降到 priority=1
        PeerMeshEngine.PeerCandidate sameNat = demoted.get(0);
        assertEquals(localAddr, sameNat.address);
        assertEquals(1L, sameNat.priority);
        // 不同地址的 srflx 保持原 priority=800
        PeerMeshEngine.PeerCandidate remote = demoted.get(1);
        assertEquals("203.0.113.99", remote.address);
        assertEquals(800L, remote.priority);
        // host 候选保持原 priority=1000
        PeerMeshEngine.PeerCandidate host = demoted.get(2);
        assertEquals(1000L, host.priority);
    }

    @Test
    public void sortedDirectCandidateEndpointsDemotesSameNatReflexiveToEnd() {
        // H-3 + H-6 组合：降权后再排序，同 NAT reflexive 自然排到末尾。
        String localAddr = "203.0.113.42";
        java.util.Set<String> localAddresses = new java.util.HashSet<>();
        localAddresses.add(localAddr);
        List<PeerMeshEngine.PeerCandidate> input = Arrays.asList(
                candidate("srflx", "udp", localAddr, 34567, 800, "standard-stun"),
                candidate("srflx", "udp", "203.0.113.99", 35000, 800, "public-stun"),
                candidate("host", "udp", "192.168.1.5", 40000, 1000, "host"));
        List<InetSocketAddress> endpoints = PeerMeshEngine.sortedDirectCandidateEndpoints(input, localAddresses);
        assertEquals(3, endpoints.size());
        // 期望顺序：host (1000) -> 不同地址 srflx (800) -> 同 NAT 被降权 srflx (1)
        assertEquals(new InetSocketAddress("192.168.1.5", 40000), endpoints.get(0));
        assertEquals(new InetSocketAddress("203.0.113.99", 35000), endpoints.get(1));
        assertEquals(new InetSocketAddress(localAddr, 34567), endpoints.get(2));
    }

    @Test
    public void demoteSameNatReflexiveCandidatesCoversPortMapCandidates() {
        // H-6 也覆盖 port-map 候选（foundation 以 "port-map-" 开头）。
        String localAddr = "203.0.113.42";
        java.util.Set<String> localAddresses = new java.util.HashSet<>();
        localAddresses.add(localAddr);
        List<PeerMeshEngine.PeerCandidate> input = Arrays.asList(
                candidate("srflx", "udp", localAddr, 34567, 900, "port-map-1"),
                candidate("host", "udp", "192.168.1.5", 40000, 1000, "host"));
        List<PeerMeshEngine.PeerCandidate> demoted =
                PeerMeshEngine.demoteSameNatReflexiveCandidates(input, localAddresses);
        assertEquals(2, demoted.size());
        // port-map 候选与本地 srflx 同地址：应被降权到 priority=1
        PeerMeshEngine.PeerCandidate portMap = demoted.get(0);
        assertEquals("port-map-1", portMap.foundation);
        assertEquals(1L, portMap.priority);
        // host 候选不受影响
        assertEquals(1000L, demoted.get(1).priority);
    }

    @Test
    public void demoteSameNatReflexiveCandidatesKeepsCountWhenNoLocalSrflx() {
        // 无本地 srflx 观测时，不做任何降权，候选列表原样返回。
        List<PeerMeshEngine.PeerCandidate> input = Arrays.asList(
                candidate("srflx", "udp", "203.0.113.42", 34567, 800, "standard-stun"),
                candidate("host", "udp", "192.168.1.5", 40000, 1000, "host"));
        List<PeerMeshEngine.PeerCandidate> demoted =
                PeerMeshEngine.demoteSameNatReflexiveCandidates(input, java.util.Collections.emptySet());
        assertEquals(2, demoted.size());
        assertEquals(800L, demoted.get(0).priority);
        assertEquals(1000L, demoted.get(1).priority);
    }

}
