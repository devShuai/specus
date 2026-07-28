package com.theshuai.specus.android;

import org.json.JSONArray;
import org.json.JSONObject;
import org.junit.Test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

public class SpecusCoreProtocolTest {
    @Test
    public void apiKeySignatureMatchesProtocolVector() throws Exception {
        String canonical = SpecusCore.Hmac.canonicalApiKeyMessage(
                "demo-client",
                "1780000000000",
                "e7b8f6f8b1bb4a4fb47d9f281fc0c3a2",
                "m_xxx",
                "shshi");

        assertEquals("demo-client\n1780000000000\ne7b8f6f8b1bb4a4fb47d9f281fc0c3a2\nm_xxx\nshshi",
                canonical);
        assertEquals("ff4f7206e76fc2a13e2aa2e835b7e7be14a7429ee6ebfb1f872d7f9758b857d6",
                SpecusCore.Hmac.signApiKey(
                        "demo-client",
                        "1780000000000",
                        "e7b8f6f8b1bb4a4fb47d9f281fc0c3a2",
                        "m_xxx",
                        "shshi",
                        "test1234"));
    }

    @Test
    public void secondStageLoginCarriesNameSessionAndAccessToken() throws Exception {
        ByteArrayOutputStream wire = new ByteArrayOutputStream();
        SpecusCore.PacketCodec.write(wire,
                SpecusCore.Packet.loginRequest("android-a", 1868708022931423400L, "cs_token",
                        SpecusCore.CONNECTION_ROLE_CONTROL));

        ByteBuffer frame = ByteBuffer.wrap(wire.toByteArray());
        assertEquals(SpecusCore.PacketCodec.MAGIC, frame.getInt());
        assertEquals(SpecusCore.PacketCodec.VERSION, frame.get() & 0xff);
        assertEquals(4, frame.get() & 0xff);
        assertEquals(1, frame.get());
        int bodyLength = frame.getInt();
        assertEquals(bodyLength, frame.remaining());
        byte[] body = new byte[bodyLength];
        frame.get(body);

        SpecusCore.CompactInput payload = new SpecusCore.CompactInput(body);
        assertEquals("android-a", payload.readString());
        assertEquals(Long.valueOf(1868708022931423400L), payload.readNullableLong());
        assertEquals("cs_token", payload.readString());
        assertEquals(SpecusCore.CONNECTION_ROLE_CONTROL, payload.readString());
        payload.requireFullyConsumed();
    }

    @Test
    public void proactiveTokenRefreshUsesJavaClientTimingRules() {
        long now = 1_000_000L;
        long eightHours = 8L * 60L * 60L * 1000L;
        assertEquals(eightHours - 5L * 60L * 1000L,
                SpecusCore.TokenRefresh.delayMillis(now + eightHours, now));
        assertEquals(70_000L,
                SpecusCore.TokenRefresh.delayMillis(now + 100_000L, now));
        assertEquals(20_000L,
                SpecusCore.TokenRefresh.delayMillis(now + 40_000L, now));
        assertEquals(5_000L,
                SpecusCore.TokenRefresh.delayMillis(now - 1L, now));
        assertEquals(now + 8_000L,
                SpecusCore.TokenRefresh.expiresAtMillis(now, 8L));
    }

    @Test
    public void heartbeatRequiresFiveSecondsWithoutAnyWrite() {
        assertEquals(60_000, SpecusCore.CONTROL_READ_IDLE_TIMEOUT_MILLIS);
        assertFalse(SpecusCore.HeartbeatPolicy.shouldSend(5_000L, 0L));
        assertFalse(SpecusCore.HeartbeatPolicy.shouldSend(5_999L, 1_000L));
        assertTrue(SpecusCore.HeartbeatPolicy.shouldSend(6_000L, 1_000L));
        assertFalse(SpecusCore.HeartbeatPolicy.shouldSend(10_000L, 9_999L));
    }

    @Test
    public void loginFailureClassificationMatchesJavaReconnectPolicyInChineseAndEnglish() {
        assertEquals(SpecusCore.LoginFailureAction.REFRESH_CREDENTIALS,
                SpecusCore.LoginFailureAction.classify("客户端访问令牌已过期"));
        assertEquals(SpecusCore.LoginFailureAction.REFRESH_CREDENTIALS,
                SpecusCore.LoginFailureAction.classify("Access token expired"));
        assertEquals(SpecusCore.LoginFailureAction.RETRY_WITH_BACKOFF,
                SpecusCore.LoginFailureAction.classify("服务器繁忙，请稍后重试"));
        assertEquals(SpecusCore.LoginFailureAction.RETRY_WITH_BACKOFF,
                SpecusCore.LoginFailureAction.classify("server busy, try again later"));
        assertEquals(SpecusCore.LoginFailureAction.RETRY_WITH_BACKOFF,
                SpecusCore.LoginFailureAction.classify("连接频率超过限制"));
        assertEquals(SpecusCore.LoginFailureAction.RETRY_WITH_BACKOFF,
                SpecusCore.LoginFailureAction.classify("connection rate limit exceeded"));
        assertEquals(SpecusCore.LoginFailureAction.STOP_RECONNECTING,
                SpecusCore.LoginFailureAction.classify("billing policy denied"));
        assertEquals(SpecusCore.LoginFailureAction.STOP_RECONNECTING,
                SpecusCore.LoginFailureAction.classify(null));
    }

    @Test
    public void logoutRequestIsDecodedAsAControlReloginCommand() throws Exception {
        ByteArrayOutputStream wire = new ByteArrayOutputStream();
        SpecusCore.PacketCodec.write(wire, SpecusCore.Packet.logoutRequest());

        SpecusCore.Packet decoded = SpecusCore.PacketCodec.read(
                new ByteArrayInputStream(wire.toByteArray()));

        assertEquals(SpecusCore.Packet.logoutRequest().command, decoded.command);
    }

    @Test
    public void malformedOrUnknownTcpConnectedFramesAreIgnored() {
        assertTrue(SpecusCore.TcpConnectedPolicy.shouldIgnore(null, "channel-1", false));
        assertTrue(SpecusCore.TcpConnectedPolicy.shouldIgnore(18080, null, true));
        assertTrue(SpecusCore.TcpConnectedPolicy.shouldIgnore(18080, "channel-1", false));
        assertFalse(SpecusCore.TcpConnectedPolicy.shouldIgnore(18080, "channel-1", true));
    }

    @Test
    public void failedNatRegistrationIsClearedForRetryWithoutClosingDataChannel() {
        Set<Integer> registeredPorts = new HashSet<>(List.of(19090, 19091));
        String failure = SpecusCore.NatRegisterResultPolicy.apply(
                registeredPorts,
                Map.of(
                        "port", 19090,
                        "success", false,
                        "reason", "address already in use"));

        assertEquals("port 19090: address already in use", failure);
        assertFalse(registeredPorts.contains(19090));
        assertTrue(registeredPorts.contains(19091));
        assertNull(SpecusCore.NatRegisterResultPolicy.apply(
                registeredPorts,
                Map.of("port", 19091, "success", true)));
        assertTrue(registeredPorts.contains(19091));
    }

    @Test
    public void webSocketRouteUsesHttpBasePathAndSws2Envelope() {
        URI clear = SpecusCore.WebSocketSupport.buildTarget(
                "http://127.0.0.1:8080/base", "/events", "room=1");
        assertEquals("ws", clear.getScheme());
        assertEquals("/base/events", clear.getPath());
        assertEquals("room=1", clear.getRawQuery());

        URI secure = SpecusCore.WebSocketSupport.buildTarget(
                "wss://internal.example/socket", "/feed", null);
        assertEquals("wss", secure.getScheme());
        assertEquals("/socket/feed", secure.getPath());

        byte[] encoded = SpecusCore.WebSocketSupport.encodeFrame(
                SpecusCore.WebSocketSupport.OPCODE_TEXT, true, 0, 0,
                "hi".getBytes(StandardCharsets.UTF_8));
        SpecusCore.WebSocketSupport.Frame decoded = SpecusCore.WebSocketSupport.decodeFrame(encoded);
        assertEquals(SpecusCore.WebSocketSupport.OPCODE_TEXT, decoded.opcode);
        assertTrue(decoded.fin);
        assertArrayEquals("hi".getBytes(StandardCharsets.UTF_8), decoded.payload);
        assertThrows(IllegalArgumentException.class,
                () -> SpecusCore.WebSocketSupport.decodeFrame(new byte[]{0x01, 'o', 'l', 'd'}));
        assertEquals(16 * 1024 * 1024, SpecusCore.WebSocketSupport.MAX_MESSAGE_BYTES);
    }

    @Test
    public void webSocketEnvelopeMatchesCentralSws2Vector() throws Exception {
        JSONObject vector = new JSONObject(new String(
                Files.readAllBytes(findApplicationVector()), StandardCharsets.UTF_8))
                .getJSONObject("webSocket");
        byte[] expected = HexFormat.of().parseHex(vector.getString("frameHex"));
        byte[] encoded = SpecusCore.WebSocketSupport.encodeFrame(
                vector.getInt("opcode"),
                vector.getBoolean("finalFragment"),
                vector.getInt("rsv"),
                vector.getInt("closeCode"),
                vector.getString("payloadUtf8").getBytes(StandardCharsets.UTF_8));
        assertArrayEquals(expected, encoded);
        SpecusCore.WebSocketSupport.Frame decoded = SpecusCore.WebSocketSupport.decodeFrame(expected);
        assertEquals(vector.getInt("opcode"), decoded.opcode);
        assertEquals(vector.getBoolean("finalFragment"), decoded.fin);
        assertEquals(vector.getInt("rsv"), decoded.rsv);
        assertEquals(vector.getInt("closeCode"), decoded.closeCode);
        assertEquals(vector.getString("payloadUtf8"),
                new String(decoded.payload, StandardCharsets.UTF_8));
        assertThrows(IllegalArgumentException.class, () -> SpecusCore.WebSocketSupport.decodeFrame(
                HexFormat.of().parseHex(vector.getString("invalidMagicHex"))));
        assertThrows(IllegalArgumentException.class, () -> SpecusCore.WebSocketSupport.decodeFrame(
                HexFormat.of().parseHex(vector.getString("truncatedHex"))));
        assertThrows(IllegalArgumentException.class, () -> SpecusCore.WebSocketSupport.decodeFrame(
                HexFormat.of().parseHex(vector.getString("trailingHex"))));
    }

    @Test
    public void peerMeshMtuUsesJavaClientBounds() {
        assertEquals(1280, SpecusCore.PeerMeshConfig.normalizeMtu(0));
        assertEquals(576, SpecusCore.PeerMeshConfig.normalizeMtu(100));
        assertEquals(1200, SpecusCore.PeerMeshConfig.normalizeMtu(1200));
        assertEquals(1280, SpecusCore.PeerMeshConfig.normalizeMtu(9000));
    }

    @Test
    public void peerMeshRoutesContainOnlyUniqueOnlineIpv4Hosts() {
        assertEquals(List.of("100.96.0.2", "100.96.0.3"),
                SpecusCore.PeerMeshConfig.normalizePeerRoutes(
                        Arrays.asList("100.96.0.3", "100.96.0.2", "100.96.0.2",
                                "100.96.0.1", "bad-host", "300.1.1.1", null),
                        "100.96.0.1"));
    }

    @Test
    public void frameLimitIncludesTheElevenByteHeader() throws Exception {
        assertEquals(32 * 1024 * 1024, SpecusCore.PacketCodec.MAX_FRAME_SIZE);
        assertEquals(SpecusCore.PacketCodec.MAX_FRAME_SIZE - SpecusCore.PacketCodec.HEADER_BYTES,
                SpecusCore.PacketCodec.MAX_BODY_SIZE);
        SpecusCore.PacketCodec.validateBodyLength(
                (byte) -4, SpecusCore.PacketCodec.MAX_BODY_SIZE, SpecusCore.PacketCodec.MAX_FRAME_SIZE);
        assertThrows(IOException.class,
                () -> SpecusCore.PacketCodec.validateBodyLength(
                        (byte) -4,
                        SpecusCore.PacketCodec.MAX_BODY_SIZE + 1,
                        SpecusCore.PacketCodec.MAX_FRAME_SIZE));

        ByteBuffer oversizedHeader = ByteBuffer.allocate(SpecusCore.PacketCodec.HEADER_BYTES);
        oversizedHeader.putInt(SpecusCore.PacketCodec.MAGIC);
        oversizedHeader.put((byte) SpecusCore.PacketCodec.VERSION);
        oversizedHeader.put((byte) 4);
        oversizedHeader.put((byte) -4);
        oversizedHeader.putInt(SpecusCore.PacketCodec.MAX_BODY_SIZE + 1);
        assertThrows(IOException.class,
                () -> SpecusCore.PacketCodec.read(new ByteArrayInputStream(oversizedHeader.array())));
    }

    @Test
    public void protocolV1IsRejectedBeforeBodyAllocation() {
        ByteBuffer header = ByteBuffer.allocate(SpecusCore.PacketCodec.HEADER_BYTES);
        header.putInt(SpecusCore.PacketCodec.MAGIC);
        header.put((byte) 1);
        header.put((byte) 4);
        header.put((byte) -4);
        header.putInt(0);
        assertThrows(IOException.class,
                () -> SpecusCore.PacketCodec.read(new ByteArrayInputStream(header.array())));
    }

    @Test
    public void compactInputRejectsTrailingFields() {
        SpecusCore.CompactInput input = new SpecusCore.CompactInput(new byte[]{0, 1});
        assertNull(input.readString());
        assertThrows(IllegalArgumentException.class, input::requireFullyConsumed);
    }

    @Test
    public void natControlHttpRoutesHaveMissingEmptyAndReplacementStates() throws Exception {
        JSONObject login = new JSONObject()
                .put("clientName", "android-a")
                .put("clientSessionId", 1L)
                .put("accessToken", "cs_token")
                .put("nettyHost", "127.0.0.1")
                .put("nettyPort", 7010)
                .put("httpSpecusConfigList", new JSONArray().put(route("initial", "http://127.0.0.1:8080")));
        SpecusCore.SpecusSession session = SpecusCore.SpecusSession.fromLoginJson(login);

        session.applyRuntimeJson(new JSONObject().put("specusConfigList", new JSONArray()).toString());
        assertEquals("http://127.0.0.1:8080", session.routeMap().get("initial"));

        session.applyRuntimeJson(new JSONObject().put("httpSpecusConfigList", new JSONArray()).toString());
        assertTrue(session.routeMap().isEmpty());

        session.applyRuntimeJson(new JSONObject()
                .put("httpSpecusConfigList", new JSONArray().put(route("next", "https://10.0.0.2/base")))
                .toString());
        assertEquals(1, session.routeMap().size());
        assertEquals("https://10.0.0.2/base", session.routeMap().get("next"));
        assertFalse(session.routeMap().containsKey("initial"));
    }

    @Test
    public void directHttpRangeIsBoundedToEightMiB() {
        assertEquals("bytes=0-8388607",
                SpecusCore.DirectHttpForwarder.boundedRange("bytes=0-999999999"));
        assertEquals("bytes=-8388608",
                SpecusCore.DirectHttpForwarder.boundedRange("bytes=-999999999"));
        assertEquals("bytes=10485760-18874367",
                SpecusCore.DirectHttpForwarder.boundedRange("bytes=10485760-"));
        assertEquals("bytes=9223372036854775807-9223372036854775807",
                SpecusCore.DirectHttpForwarder.boundedRange("bytes=9223372036854775807-"));
        assertNull(SpecusCore.DirectHttpForwarder.boundedRange("bytes=0-1,4-5"));
        assertNull(SpecusCore.DirectHttpForwarder.boundedRange("items=0-10"));
    }

    @Test
    public void directHttpTargetPreservesHostAndBasePath() {
        URI target = SpecusCore.DirectHttpForwarder.buildTarget(
                "https://internal.example/base", "/assets/app.js", "v=1");
        assertEquals("https", target.getScheme());
        assertEquals("internal.example", target.getHost());
        assertEquals("/base/assets/app.js", target.getPath());
        assertEquals("v=1", target.getRawQuery());

        assertThrows(IllegalArgumentException.class,
                () -> SpecusCore.DirectHttpForwarder.buildTarget(
                        "https://internal.example/base", "/../secret", null));
        assertThrows(IllegalArgumentException.class,
                () -> SpecusCore.DirectHttpForwarder.buildTarget(
                        "file:///tmp", "/x", null));
    }

    @Test
    public void directHttpResponseLimitIsSixtyFourMiBAndInclusive() throws Exception {
        assertEquals(64 * 1024 * 1024, SpecusCore.DirectHttpForwarder.MAX_RESPONSE_BODY_SIZE);
        assertEquals(1024,
                SpecusCore.readLimited(new SizedInputStream(1024), 1024).length);
        assertThrows(IOException.class,
                () -> SpecusCore.readLimited(new SizedInputStream(1025), 1024));
    }

    @Test
    public void androidAdvertisesOnlyCapabilitiesItFullyImplements() throws Exception {
        SpecusCore.ClientMessageCapabilities capabilities =
                SpecusCore.ClientMessageCapabilities.androidDefault();
        JSONObject json = capabilities.toJson();
        assertTrue(json.getBoolean("sendMessages"));
        assertTrue(json.getBoolean("receiveMessages"));
        assertFalse(json.getBoolean("attachments"));
        assertFalse(json.getBoolean("mediaPreview"));
        assertEquals(0L, json.getLong("maxAttachmentBytes"));
    }

    private static JSONObject route(String name, String target) throws Exception {
        return new JSONObject().put("route", name).put("targetBaseUrl", target);
    }

    private static Path findApplicationVector() {
        Path current = Path.of("").toAbsolutePath();
        for (int depth = 0; current != null && depth < 8; depth++, current = current.getParent()) {
            Path candidate = current.resolve("protocol/test-vectors/application-protocol-v2.json");
            if (Files.isRegularFile(candidate)) {
                return candidate;
            }
        }
        throw new IllegalStateException("cannot locate application protocol v2 vector");
    }

    private static final class SizedInputStream extends InputStream {
        private int remaining;

        private SizedInputStream(int remaining) {
            this.remaining = remaining;
        }

        @Override
        public int read() {
            if (remaining <= 0) {
                return -1;
            }
            remaining--;
            return 0;
        }

        @Override
        public int read(byte[] bytes, int offset, int length) {
            if (remaining <= 0) {
                return -1;
            }
            int count = Math.min(length, remaining);
            Arrays.fill(bytes, offset, offset + count, (byte) 0);
            remaining -= count;
            return count;
        }
    }
}
