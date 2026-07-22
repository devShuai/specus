package com.theshuai.tunnel.android;

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
import java.util.HexFormat;
import java.util.List;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

public class TunnelCoreProtocolTest {
    @Test
    public void apiKeySignatureMatchesProtocolVector() throws Exception {
        String canonical = TunnelCore.Hmac.canonicalApiKeyMessage(
                "demo-client",
                "1780000000000",
                "e7b8f6f8b1bb4a4fb47d9f281fc0c3a2",
                "m_xxx",
                "shshi");

        assertEquals("demo-client\n1780000000000\ne7b8f6f8b1bb4a4fb47d9f281fc0c3a2\nm_xxx\nshshi",
                canonical);
        assertEquals("ff4f7206e76fc2a13e2aa2e835b7e7be14a7429ee6ebfb1f872d7f9758b857d6",
                TunnelCore.Hmac.signApiKey(
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
        TunnelCore.PacketCodec.write(wire,
                TunnelCore.Packet.loginRequest("android-a", 1868708022931423400L, "cs_token",
                        TunnelCore.CONNECTION_ROLE_CONTROL));

        ByteBuffer frame = ByteBuffer.wrap(wire.toByteArray());
        assertEquals(TunnelCore.PacketCodec.MAGIC, frame.getInt());
        assertEquals(TunnelCore.PacketCodec.VERSION, frame.get() & 0xff);
        assertEquals(4, frame.get() & 0xff);
        assertEquals(1, frame.get());
        int bodyLength = frame.getInt();
        assertEquals(bodyLength, frame.remaining());
        byte[] body = new byte[bodyLength];
        frame.get(body);

        TunnelCore.CompactInput payload = new TunnelCore.CompactInput(body);
        assertEquals("android-a", payload.readString());
        assertEquals(Long.valueOf(1868708022931423400L), payload.readNullableLong());
        assertEquals("cs_token", payload.readString());
        assertEquals(TunnelCore.CONNECTION_ROLE_CONTROL, payload.readString());
        payload.requireFullyConsumed();
    }

    @Test
    public void proactiveTokenRefreshUsesJavaClientTimingRules() {
        long now = 1_000_000L;
        long eightHours = 8L * 60L * 60L * 1000L;
        assertEquals(eightHours - 5L * 60L * 1000L,
                TunnelCore.TokenRefresh.delayMillis(now + eightHours, now));
        assertEquals(70_000L,
                TunnelCore.TokenRefresh.delayMillis(now + 100_000L, now));
        assertEquals(20_000L,
                TunnelCore.TokenRefresh.delayMillis(now + 40_000L, now));
        assertEquals(5_000L,
                TunnelCore.TokenRefresh.delayMillis(now - 1L, now));
        assertEquals(now + 8_000L,
                TunnelCore.TokenRefresh.expiresAtMillis(now, 8L));
    }

    @Test
    public void heartbeatRequiresFiveSecondsWithoutAnyWrite() {
        assertEquals(60_000, TunnelCore.CONTROL_READ_IDLE_TIMEOUT_MILLIS);
        assertFalse(TunnelCore.HeartbeatPolicy.shouldSend(5_000L, 0L));
        assertFalse(TunnelCore.HeartbeatPolicy.shouldSend(5_999L, 1_000L));
        assertTrue(TunnelCore.HeartbeatPolicy.shouldSend(6_000L, 1_000L));
        assertFalse(TunnelCore.HeartbeatPolicy.shouldSend(10_000L, 9_999L));
    }

    @Test
    public void loginFailureClassificationMatchesJavaReconnectPolicyInChineseAndEnglish() {
        assertEquals(TunnelCore.LoginFailureAction.REFRESH_CREDENTIALS,
                TunnelCore.LoginFailureAction.classify("客户端访问令牌已过期"));
        assertEquals(TunnelCore.LoginFailureAction.REFRESH_CREDENTIALS,
                TunnelCore.LoginFailureAction.classify("Access token expired"));
        assertEquals(TunnelCore.LoginFailureAction.RETRY_WITH_BACKOFF,
                TunnelCore.LoginFailureAction.classify("服务器繁忙，请稍后重试"));
        assertEquals(TunnelCore.LoginFailureAction.RETRY_WITH_BACKOFF,
                TunnelCore.LoginFailureAction.classify("server busy, try again later"));
        assertEquals(TunnelCore.LoginFailureAction.RETRY_WITH_BACKOFF,
                TunnelCore.LoginFailureAction.classify("连接频率超过限制"));
        assertEquals(TunnelCore.LoginFailureAction.RETRY_WITH_BACKOFF,
                TunnelCore.LoginFailureAction.classify("connection rate limit exceeded"));
        assertEquals(TunnelCore.LoginFailureAction.STOP_RECONNECTING,
                TunnelCore.LoginFailureAction.classify("billing policy denied"));
        assertEquals(TunnelCore.LoginFailureAction.STOP_RECONNECTING,
                TunnelCore.LoginFailureAction.classify(null));
    }

    @Test
    public void logoutRequestIsDecodedAsAControlReloginCommand() throws Exception {
        ByteArrayOutputStream wire = new ByteArrayOutputStream();
        TunnelCore.PacketCodec.write(wire, TunnelCore.Packet.logoutRequest());

        TunnelCore.Packet decoded = TunnelCore.PacketCodec.read(
                new ByteArrayInputStream(wire.toByteArray()));

        assertEquals(TunnelCore.Packet.logoutRequest().command, decoded.command);
    }

    @Test
    public void malformedOrUnknownTcpConnectedFramesAreIgnored() {
        assertTrue(TunnelCore.TcpConnectedPolicy.shouldIgnore(null, "channel-1", false));
        assertTrue(TunnelCore.TcpConnectedPolicy.shouldIgnore(18080, null, true));
        assertTrue(TunnelCore.TcpConnectedPolicy.shouldIgnore(18080, "channel-1", false));
        assertFalse(TunnelCore.TcpConnectedPolicy.shouldIgnore(18080, "channel-1", true));
    }

    @Test
    public void webSocketRouteUsesHttpBasePathAndSws2Envelope() {
        URI clear = TunnelCore.WebSocketSupport.buildTarget(
                "http://127.0.0.1:8080/base", "/events", "room=1");
        assertEquals("ws", clear.getScheme());
        assertEquals("/base/events", clear.getPath());
        assertEquals("room=1", clear.getRawQuery());

        URI secure = TunnelCore.WebSocketSupport.buildTarget(
                "wss://internal.example/socket", "/feed", null);
        assertEquals("wss", secure.getScheme());
        assertEquals("/socket/feed", secure.getPath());

        byte[] encoded = TunnelCore.WebSocketSupport.encodeFrame(
                TunnelCore.WebSocketSupport.OPCODE_TEXT, true, 0, 0,
                "hi".getBytes(StandardCharsets.UTF_8));
        TunnelCore.WebSocketSupport.Frame decoded = TunnelCore.WebSocketSupport.decodeFrame(encoded);
        assertEquals(TunnelCore.WebSocketSupport.OPCODE_TEXT, decoded.opcode);
        assertTrue(decoded.fin);
        assertArrayEquals("hi".getBytes(StandardCharsets.UTF_8), decoded.payload);
        assertThrows(IllegalArgumentException.class,
                () -> TunnelCore.WebSocketSupport.decodeFrame(new byte[]{0x01, 'o', 'l', 'd'}));
        assertEquals(16 * 1024 * 1024, TunnelCore.WebSocketSupport.MAX_MESSAGE_BYTES);
    }

    @Test
    public void webSocketEnvelopeMatchesCentralSws2Vector() throws Exception {
        JSONObject vector = new JSONObject(new String(
                Files.readAllBytes(findApplicationVector()), StandardCharsets.UTF_8))
                .getJSONObject("webSocket");
        byte[] expected = HexFormat.of().parseHex(vector.getString("frameHex"));
        byte[] encoded = TunnelCore.WebSocketSupport.encodeFrame(
                vector.getInt("opcode"),
                vector.getBoolean("finalFragment"),
                vector.getInt("rsv"),
                vector.getInt("closeCode"),
                vector.getString("payloadUtf8").getBytes(StandardCharsets.UTF_8));
        assertArrayEquals(expected, encoded);
        TunnelCore.WebSocketSupport.Frame decoded = TunnelCore.WebSocketSupport.decodeFrame(expected);
        assertEquals(vector.getInt("opcode"), decoded.opcode);
        assertEquals(vector.getBoolean("finalFragment"), decoded.fin);
        assertEquals(vector.getInt("rsv"), decoded.rsv);
        assertEquals(vector.getInt("closeCode"), decoded.closeCode);
        assertEquals(vector.getString("payloadUtf8"),
                new String(decoded.payload, StandardCharsets.UTF_8));
        assertThrows(IllegalArgumentException.class, () -> TunnelCore.WebSocketSupport.decodeFrame(
                HexFormat.of().parseHex(vector.getString("invalidMagicHex"))));
        assertThrows(IllegalArgumentException.class, () -> TunnelCore.WebSocketSupport.decodeFrame(
                HexFormat.of().parseHex(vector.getString("truncatedHex"))));
        assertThrows(IllegalArgumentException.class, () -> TunnelCore.WebSocketSupport.decodeFrame(
                HexFormat.of().parseHex(vector.getString("trailingHex"))));
    }

    @Test
    public void peerMeshMtuUsesJavaClientBounds() {
        assertEquals(1280, TunnelCore.PeerMeshConfig.normalizeMtu(0));
        assertEquals(576, TunnelCore.PeerMeshConfig.normalizeMtu(100));
        assertEquals(1200, TunnelCore.PeerMeshConfig.normalizeMtu(1200));
        assertEquals(1280, TunnelCore.PeerMeshConfig.normalizeMtu(9000));
    }

    @Test
    public void peerMeshRoutesContainOnlyUniqueOnlineIpv4Hosts() {
        assertEquals(List.of("100.96.0.2", "100.96.0.3"),
                TunnelCore.PeerMeshConfig.normalizePeerRoutes(
                        Arrays.asList("100.96.0.3", "100.96.0.2", "100.96.0.2",
                                "100.96.0.1", "bad-host", "300.1.1.1", null),
                        "100.96.0.1"));
    }

    @Test
    public void frameLimitIncludesTheElevenByteHeader() throws Exception {
        assertEquals(32 * 1024 * 1024, TunnelCore.PacketCodec.MAX_FRAME_SIZE);
        assertEquals(TunnelCore.PacketCodec.MAX_FRAME_SIZE - TunnelCore.PacketCodec.HEADER_BYTES,
                TunnelCore.PacketCodec.MAX_BODY_SIZE);
        TunnelCore.PacketCodec.validateBodyLength(
                (byte) -4, TunnelCore.PacketCodec.MAX_BODY_SIZE, TunnelCore.PacketCodec.MAX_FRAME_SIZE);
        assertThrows(IOException.class,
                () -> TunnelCore.PacketCodec.validateBodyLength(
                        (byte) -4,
                        TunnelCore.PacketCodec.MAX_BODY_SIZE + 1,
                        TunnelCore.PacketCodec.MAX_FRAME_SIZE));

        ByteBuffer oversizedHeader = ByteBuffer.allocate(TunnelCore.PacketCodec.HEADER_BYTES);
        oversizedHeader.putInt(TunnelCore.PacketCodec.MAGIC);
        oversizedHeader.put((byte) TunnelCore.PacketCodec.VERSION);
        oversizedHeader.put((byte) 4);
        oversizedHeader.put((byte) -4);
        oversizedHeader.putInt(TunnelCore.PacketCodec.MAX_BODY_SIZE + 1);
        assertThrows(IOException.class,
                () -> TunnelCore.PacketCodec.read(new ByteArrayInputStream(oversizedHeader.array())));
    }

    @Test
    public void protocolV1IsRejectedBeforeBodyAllocation() {
        ByteBuffer header = ByteBuffer.allocate(TunnelCore.PacketCodec.HEADER_BYTES);
        header.putInt(TunnelCore.PacketCodec.MAGIC);
        header.put((byte) 1);
        header.put((byte) 4);
        header.put((byte) -4);
        header.putInt(0);
        assertThrows(IOException.class,
                () -> TunnelCore.PacketCodec.read(new ByteArrayInputStream(header.array())));
    }

    @Test
    public void compactInputRejectsTrailingFields() {
        TunnelCore.CompactInput input = new TunnelCore.CompactInput(new byte[]{0, 1});
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
                .put("httpTunnelConfigList", new JSONArray().put(route("initial", "http://127.0.0.1:8080")));
        TunnelCore.TunnelSession session = TunnelCore.TunnelSession.fromLoginJson(login);

        session.applyRuntimeJson(new JSONObject().put("tunnelConfigList", new JSONArray()).toString());
        assertEquals("http://127.0.0.1:8080", session.routeMap().get("initial"));

        session.applyRuntimeJson(new JSONObject().put("httpTunnelConfigList", new JSONArray()).toString());
        assertTrue(session.routeMap().isEmpty());

        session.applyRuntimeJson(new JSONObject()
                .put("httpTunnelConfigList", new JSONArray().put(route("next", "https://10.0.0.2/base")))
                .toString());
        assertEquals(1, session.routeMap().size());
        assertEquals("https://10.0.0.2/base", session.routeMap().get("next"));
        assertFalse(session.routeMap().containsKey("initial"));
    }

    @Test
    public void directHttpRangeIsBoundedToEightMiB() {
        assertEquals("bytes=0-8388607",
                TunnelCore.DirectHttpForwarder.boundedRange("bytes=0-999999999"));
        assertEquals("bytes=-8388608",
                TunnelCore.DirectHttpForwarder.boundedRange("bytes=-999999999"));
        assertEquals("bytes=10485760-18874367",
                TunnelCore.DirectHttpForwarder.boundedRange("bytes=10485760-"));
        assertEquals("bytes=9223372036854775807-9223372036854775807",
                TunnelCore.DirectHttpForwarder.boundedRange("bytes=9223372036854775807-"));
        assertNull(TunnelCore.DirectHttpForwarder.boundedRange("bytes=0-1,4-5"));
        assertNull(TunnelCore.DirectHttpForwarder.boundedRange("items=0-10"));
    }

    @Test
    public void directHttpTargetPreservesHostAndBasePath() {
        URI target = TunnelCore.DirectHttpForwarder.buildTarget(
                "https://internal.example/base", "/assets/app.js", "v=1");
        assertEquals("https", target.getScheme());
        assertEquals("internal.example", target.getHost());
        assertEquals("/base/assets/app.js", target.getPath());
        assertEquals("v=1", target.getRawQuery());

        assertThrows(IllegalArgumentException.class,
                () -> TunnelCore.DirectHttpForwarder.buildTarget(
                        "https://internal.example/base", "/../secret", null));
        assertThrows(IllegalArgumentException.class,
                () -> TunnelCore.DirectHttpForwarder.buildTarget(
                        "file:///tmp", "/x", null));
    }

    @Test
    public void directHttpResponseLimitIsSixtyFourMiBAndInclusive() throws Exception {
        assertEquals(64 * 1024 * 1024, TunnelCore.DirectHttpForwarder.MAX_RESPONSE_BODY_SIZE);
        assertEquals(1024,
                TunnelCore.readLimited(new SizedInputStream(1024), 1024).length);
        assertThrows(IOException.class,
                () -> TunnelCore.readLimited(new SizedInputStream(1025), 1024));
    }

    @Test
    public void androidAdvertisesOnlyCapabilitiesItFullyImplements() throws Exception {
        TunnelCore.ClientMessageCapabilities capabilities =
                TunnelCore.ClientMessageCapabilities.androidDefault();
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
