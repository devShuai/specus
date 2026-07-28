package com.theshuai.specusclient.peer;

import com.fasterxml.jackson.databind.JsonNode;
import com.theshuai.common.util.JsonUtil;
import org.junit.jupiter.api.Test;

import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.HexFormat;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PeerDataFrameCodecTests {
    @Test
    void shouldMatchCanonicalSpm2VectorAndUseDirectionalTrafficKey() throws IOException {
        JsonNode vector = readVector("peer-mesh-spm2.json");
        SecretKeySpec sessionKey = new SecretKeySpec(
                HexFormat.of().parseHex(vector.path("sessionKeyHex").asText()), "AES");
        long sessionId = vector.path("sessionId").asLong();
        long fromClientId = vector.path("fromClientId").asLong();
        long toClientId = vector.path("toClientId").asLong();
        long sequence = vector.path("sequence").asLong();
        String keyEpoch = vector.path("senderKeyEpoch").asText();
        PeerDataFrameCodec.TrafficKey trafficKey = PeerDataFrameCodec.trafficKey(
                sessionKey, sessionId, fromClientId, toClientId, keyEpoch);
        byte[] payload = vector.path("plaintextUtf8").asText().getBytes(StandardCharsets.UTF_8);
        byte[] wrappedPayload = new byte[payload.length + 9];
        System.arraycopy(payload, 0, wrappedPayload, 5, payload.length);

        byte[] packet = PeerDataFrameCodec.encode(
                trafficKey, sessionId, sequence, wrappedPayload, 5, payload.length);
        PeerDataFrame frame = PeerDataFrameCodec.decode(trafficKey, packet, sessionId);

        assertArrayEquals(HexFormat.of().parseHex(vector.path("trafficKeyHex").asText()),
                trafficKey.key().getEncoded());
        assertEquals(vector.path("noncePrefixHex").asText(),
                "%08x".formatted(trafficKey.noncePrefix()));
        assertArrayEquals(HexFormat.of().parseHex(vector.path("frameHex").asText()), packet);
        assertEquals(sessionId, PeerDataFrameCodec.sessionId(packet));
        assertNotNull(frame);
        assertArrayEquals(payload, frame.plaintext());
        assertNull(PeerDataFrameCodec.decode(
                PeerDataFrameCodec.trafficKey(sessionKey, sessionId, toClientId, fromClientId, keyEpoch),
                packet,
                sessionId));
    }

    @Test
    void shouldRejectWrongDirectionTrailingBytesAndInvalidSequence() {
        PeerDataFrameCodec.TrafficKey trafficKey = PeerDataFrameCodec.trafficKey(
                sessionKey(), 99L, 1L, 2L, "epoch-a");
        byte[] packet = PeerDataFrameCodec.encode(
                trafficKey, 99L, 7L, new byte[]{1, 2, 3});

        assertNull(PeerDataFrameCodec.decode(
                PeerDataFrameCodec.trafficKey(sessionKey(), 99L, 2L, 1L, "epoch-a"), packet, 99L));
        assertNull(PeerDataFrameCodec.decode(
                trafficKey, Arrays.copyOf(packet, packet.length + 1), 99L));

        byte[] invalidSequence = packet.clone();
        Arrays.fill(invalidSequence, 12, 20, (byte) 0);
        assertNull(PeerDataFrameCodec.decode(trafficKey, invalidSequence, 99L));
        assertThrows(IllegalArgumentException.class,
                () -> PeerDataFrameCodec.encode(trafficKey, 99L, 0L, packet));
    }

    @Test
    void shouldIsolateNonceSpaceAcrossKeyEpochs() {
        // 客户端重启后 sessionId/token 可能被服务端复用、X25519 密钥又持久化在磁盘，
        // sequence 却从 1 重新开始。epoch 必须让 traffic key 完全改变，否则同一 key 下
        // 会重放同一段 nonce 空间，直接摧毁 AES-GCM 的认证性。
        PeerDataFrameCodec.TrafficKey before = PeerDataFrameCodec.trafficKey(
                sessionKey(), 99L, 1L, 2L, "epoch-before-restart");
        PeerDataFrameCodec.TrafficKey after = PeerDataFrameCodec.trafficKey(
                sessionKey(), 99L, 1L, 2L, "epoch-after-restart");

        assertFalse(Arrays.equals(before.key().getEncoded(), after.key().getEncoded()),
                "key epoch must change the traffic key");
        assertNotEquals(before.noncePrefix(), after.noncePrefix(),
                "key epoch must change the nonce prefix");

        byte[] sequenceOne = PeerDataFrameCodec.encode(before, 99L, 1L, new byte[]{9, 9, 9});
        // 重启后用同一 sequence 发出的帧，旧 epoch 的 key 必须无法解密
        assertNull(PeerDataFrameCodec.decode(after, sequenceOne, 99L));
        assertThrows(IllegalArgumentException.class,
                () -> PeerDataFrameCodec.trafficKey(sessionKey(), 99L, 1L, 2L, " "));
    }

    @Test
    void shouldRejectRemovedSpm1Format() {
        byte[] oldFrame = ByteBuffer.allocate(70).putInt(0x53504D31).array();

        assertNull(PeerDataFrameCodec.sessionId(oldFrame));
        assertFalse(PeerDataFrameCodec.looksLikeDataFrame(oldFrame, 0, oldFrame.length));
    }

    @Test
    void shouldNotReadSessionIdFromMalformedFrame() {
        assertNull(PeerDataFrameCodec.sessionId(new byte[]{1, 2, 3}));
    }

    @Test
    void shouldExtractIpv4DestinationAddress() {
        byte[] packet = {0x45, 0, 0, 20, 0, 0, 0, 0, 64, 6, 0, 0, 100, 96, 0, 1, 100, 96, 0, 2};
        byte[] wrapped = new byte[packet.length + 8];
        System.arraycopy(packet, 0, wrapped, 4, packet.length);

        assertEquals("100.96.0.2", PeerIpPacket.destinationIpv4(packet));
        assertEquals(PeerIpPacket.ipv4ToInt("100.96.0.2"),
                PeerIpPacket.destinationIpv4Int(wrapped, 4, packet.length));
    }

    private static SecretKeySpec sessionKey() {
        byte[] key = new byte[32];
        for (int index = 0; index < key.length; index++) {
            key[index] = (byte) index;
        }
        return new SecretKeySpec(key, "AES");
    }

    private static JsonNode readVector(String name) throws IOException {
        Path current = Path.of("").toAbsolutePath();
        for (int depth = 0; current != null && depth < 8; depth++, current = current.getParent()) {
            Path candidate = current.resolve("protocol/test-vectors").resolve(name);
            if (Files.isRegularFile(candidate)) {
                return JsonUtil.readString(Files.readString(candidate));
            }
        }
        throw new IllegalStateException("cannot locate protocol vector: " + name);
    }
}
