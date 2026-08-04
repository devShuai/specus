package com.theshuai.specus.android;

import org.json.JSONArray;
import org.json.JSONObject;
import org.junit.Test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.URI;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.FutureTask;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertNotNull;
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
    public void ordinaryReconnectRetainsRuntimeSessionButExpiredTokenReloginClearsIt() {
        SpecusCore.SpecusSession session = new SpecusCore.SpecusSession();

        assertTrue(session == SpecusCore.RuntimeSessionPolicy.retainOrClear(
                session, SpecusCore.ControlExitAction.RETRY_WITH_BACKOFF));
        assertTrue(session == SpecusCore.RuntimeSessionPolicy.retainOrClear(
                session, SpecusCore.ControlExitAction.STOP_RECONNECTING));
        assertNull(SpecusCore.RuntimeSessionPolicy.retainOrClear(
                session, SpecusCore.ControlExitAction.IMMEDIATE_HTTP_LOGIN));
    }

    @Test
    public void duplicateControlLoginResponseIsAProtocolViolation() throws Exception {
        SpecusCore.requireFirstLoginResponse(false);
        IOException error = assertThrows(IOException.class,
                () -> SpecusCore.requireFirstLoginResponse(true));
        assertTrue(error.getMessage().contains("duplicate LOGIN_RESPONSE"));
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
    public void malformedOrUnknownTcpOpenFramesAreRejected() {
        assertTrue(SpecusCore.TcpOpenPolicy.isInvalid(null, "channel-1", false));
        assertTrue(SpecusCore.TcpOpenPolicy.isInvalid(18080, null, true));
        assertTrue(SpecusCore.TcpOpenPolicy.isInvalid(18080, "channel-1", false));
        assertFalse(SpecusCore.TcpOpenPolicy.isInvalid(18080, "channel-1", true));
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

        assertNotNull(SpecusCore.NatRegisterResultPolicy.apply(
                registeredPorts, Map.of("port", 19091)));
        assertFalse(registeredPorts.contains(19091));
        registeredPorts.add(19091);
        assertNotNull(SpecusCore.NatRegisterResultPolicy.apply(
                registeredPorts, Map.of("port", 19091, "success", "true")));
        assertFalse(registeredPorts.contains(19091));
    }

    @Test
    public void streamLifecycleBoundsPendingAndKeepsRecentResetTombstones() {
        SpecusCore.StreamLifecycleRegistry lifecycle =
                new SpecusCore.StreamLifecycleRegistry(2, 2);

        assertTrue(lifecycle.beginPending(1));
        assertTrue(lifecycle.beginPending(2));
        assertFalse(lifecycle.beginPending(3));
        assertEquals(2, lifecycle.pendingCount());

        lifecycle.markOpened(1);
        assertEquals(1, lifecycle.pendingCount());
        assertTrue(lifecycle.beginPending(3));
        lifecycle.markClosed(2);
        lifecycle.markClosed(3);
        assertTrue(lifecycle.isRecentlyClosed(2));
        assertTrue(lifecycle.isRecentlyClosed(3));

        lifecycle.markClosed(4);
        assertFalse(lifecycle.isRecentlyClosed(2));
        assertTrue(lifecycle.isRecentlyClosed(4));
        assertTrue(lifecycle.beginPending(3));
        assertFalse(lifecycle.isRecentlyClosed(3));
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
        JSONArray forbiddenCodes = vector.getJSONArray("wireForbiddenCloseCodes");
        for (int index = 0; index < forbiddenCodes.length(); index++) {
            int closeCode = forbiddenCodes.getInt(index);
            assertThrows(IllegalArgumentException.class, () -> SpecusCore.WebSocketSupport.encodeFrame(
                    SpecusCore.WebSocketSupport.OPCODE_CLOSE, true, 0, closeCode, new byte[0]));
            ByteBuffer forbidden = ByteBuffer.allocate(SpecusCore.WebSocketSupport.HEADER_BYTES);
            forbidden.putInt(0x53575332);
            forbidden.put((byte) SpecusCore.WebSocketSupport.OPCODE_CLOSE);
            forbidden.put((byte) 1);
            forbidden.putShort((short) closeCode);
            forbidden.putInt(0);
            assertThrows(IllegalArgumentException.class,
                    () -> SpecusCore.WebSocketSupport.decodeFrame(forbidden.array()));
        }
    }

    @Test
    public void tcpHalfCloseKeepsDirectionsIndependentAndRejectsDuplicates() throws Exception {
        SpecusCore.TcpHalfCloseState state = new SpecusCore.TcpHalfCloseState();
        assertTrue(state.canSendLocalData());
        assertTrue(state.canReceiveRemoteData());

        assertEquals(SpecusCore.TcpHalfCloseState.Transition.ACCEPTED, state.receiveRemoteFin());
        assertFalse(state.canReceiveRemoteData());
        assertTrue(state.canSendLocalData());
        assertEquals(SpecusCore.TcpHalfCloseState.Transition.DUPLICATE, state.receiveRemoteFin());
        state.completeRemoteOutputShutdown();
        assertFalse(state.isGracefullyComplete());

        assertEquals(SpecusCore.TcpHalfCloseState.Transition.ACCEPTED,
                state.sendLocalFin(() -> { }));
        assertFalse(state.canSendLocalData());
        assertTrue(state.isGracefullyComplete());
        assertEquals(SpecusCore.TcpHalfCloseState.Transition.DUPLICATE,
                state.sendLocalFin(() -> { }));
    }

    @Test
    public void tcpResetIsTerminalForBothDirections() throws Exception {
        SpecusCore.TcpHalfCloseState state = new SpecusCore.TcpHalfCloseState();
        assertTrue(state.reset());
        assertFalse(state.reset());
        assertFalse(state.canSendLocalData());
        assertFalse(state.canReceiveRemoteData());
        assertEquals(SpecusCore.TcpHalfCloseState.Transition.RESET,
                state.sendLocalFin(() -> { }));
        assertEquals(SpecusCore.TcpHalfCloseState.Transition.RESET, state.receiveRemoteFin());
    }

    @Test
    public void tcpResetCannotPassAnInFlightFinSend() throws Exception {
        SpecusCore.TcpHalfCloseState state = new SpecusCore.TcpHalfCloseState();
        CountDownLatch senderEntered = new CountDownLatch(1);
        CountDownLatch releaseSender = new CountDownLatch(1);
        CountDownLatch resetStarted = new CountDownLatch(1);
        CountDownLatch resetFinished = new CountDownLatch(1);

        FutureTask<SpecusCore.TcpHalfCloseState.Transition> fin = new FutureTask<>(
                () -> state.sendLocalFin(() -> {
                    senderEntered.countDown();
                    assertTrue(releaseSender.await(2, TimeUnit.SECONDS));
                }));
        Thread finThread = new Thread(fin, "android-tcp-fin-test");
        finThread.start();
        assertTrue(senderEntered.await(1, TimeUnit.SECONDS));

        FutureTask<Boolean> reset = new FutureTask<>(() -> {
            try {
                resetStarted.countDown();
                return state.reset();
            } finally {
                resetFinished.countDown();
            }
        });
        Thread resetThread = new Thread(reset, "android-tcp-reset-test");
        resetThread.start();
        assertTrue(resetStarted.await(1, TimeUnit.SECONDS));
        assertFalse(resetFinished.await(100, TimeUnit.MILLISECONDS));

        releaseSender.countDown();
        assertEquals(SpecusCore.TcpHalfCloseState.Transition.ACCEPTED,
                fin.get(2, TimeUnit.SECONDS));
        assertTrue(reset.get(2, TimeUnit.SECONDS));
        assertTrue(state.isReset());
    }

    @Test
    public void tcpResetBeforeFinSuppressesTheWireSend() throws Exception {
        SpecusCore.TcpHalfCloseState state = new SpecusCore.TcpHalfCloseState();
        AtomicBoolean sent = new AtomicBoolean(false);
        assertTrue(state.reset());

        assertEquals(SpecusCore.TcpHalfCloseState.Transition.RESET,
                state.sendLocalFin(() -> sent.set(true)));
        assertFalse(sent.get());
    }

    @Test
    public void websocketIngressBuffersOnlyValidatedFramesWithinBounds() throws Exception {
        byte[] first = SpecusCore.WebSocketSupport.encodeFrame(
                SpecusCore.WebSocketSupport.OPCODE_TEXT, true, 0, 0,
                "one".getBytes(StandardCharsets.UTF_8));
        byte[] second = SpecusCore.WebSocketSupport.encodeFrame(
                SpecusCore.WebSocketSupport.OPCODE_BINARY, true, 0, 0,
                new byte[]{1, 2, 3});
        SpecusCore.WebSocketIngressState ingress =
                new SpecusCore.WebSocketIngressState(first.length + second.length, 2);

        SpecusCore.WebSocketIngressState.AcceptedFrame acceptedFirst = ingress.accept(first);
        ingress.cache(acceptedFirst);
        SpecusCore.WebSocketIngressState.AcceptedFrame acceptedSecond = ingress.accept(second);
        ingress.cache(acceptedSecond);
        assertEquals(first.length + second.length, ingress.pendingBytes());
        assertEquals(2, ingress.drain().size());
        assertEquals(0, ingress.pendingBytes());

        assertThrows(IOException.class, () -> ingress.accept(new byte[]{1, 2, 3}));
        byte[] orphan = SpecusCore.WebSocketSupport.encodeFrame(
                SpecusCore.WebSocketSupport.OPCODE_CONTINUATION, true, 0, 0,
                new byte[]{1});
        assertThrows(IOException.class, () -> ingress.accept(orphan));
    }

    @Test
    public void websocketIngressRejectsOverflowBeforeGrantingMoreCredit() throws Exception {
        byte[] encoded = SpecusCore.WebSocketSupport.encodeFrame(
                SpecusCore.WebSocketSupport.OPCODE_TEXT, true, 0, 0,
                "bounded".getBytes(StandardCharsets.UTF_8));
        SpecusCore.WebSocketIngressState ingress =
                new SpecusCore.WebSocketIngressState(encoded.length, 1);
        ingress.cache(ingress.accept(encoded));

        SpecusCore.WebSocketIngressState.AcceptedFrame overflow = ingress.accept(encoded);
        assertThrows(IOException.class, () -> ingress.cache(overflow));
        assertEquals(encoded.length, ingress.pendingBytes());
    }

    @Test
    public void websocketPingIsAnsweredLocallyAndPongIsIdempotentlyConsumed() throws Exception {
        SpecusCore.WebSocketIngressState ingress = new SpecusCore.WebSocketIngressState();
        byte[] payload = "health".getBytes(StandardCharsets.UTF_8);
        SpecusCore.WebSocketIngressState.AcceptedFrame ping = ingress.accept(
                SpecusCore.WebSocketSupport.encodeFrame(
                        SpecusCore.WebSocketSupport.OPCODE_PING, true, 0, 0, payload));
        assertTrue(SpecusCore.WebSocketSupport.isLocallyTerminatedControlFrame(ping.frame));
        SpecusCore.WebSocketSupport.Frame pong = SpecusCore.WebSocketSupport.decodeFrame(
                SpecusCore.WebSocketSupport.localControlResponse(ping.frame));
        assertEquals(SpecusCore.WebSocketSupport.OPCODE_PONG, pong.opcode);
        assertArrayEquals(payload, pong.payload);

        SpecusCore.WebSocketIngressState.AcceptedFrame receivedPong = ingress.accept(
                SpecusCore.WebSocketSupport.encodeFrame(
                        SpecusCore.WebSocketSupport.OPCODE_PONG, true, 0, 0, payload));
        assertTrue(SpecusCore.WebSocketSupport.isLocallyTerminatedControlFrame(receivedPong.frame));
        assertNull(SpecusCore.WebSocketSupport.localControlResponse(receivedPong.frame));
    }

    @Test
    public void httpDataEndStreamDeliversPayloadBeforeFin() {
        List<String> events = new ArrayList<>();
        SpecusCore.HttpRequestIngress ingress = new SpecusCore.HttpRequestIngress() {
            @Override
            public void onRequestData(byte[] data) {
                events.add("data:" + new String(data, StandardCharsets.UTF_8));
            }

            @Override
            public void onRequestEnd(Map<String, Object> metadata) {
                events.add("fin");
            }
        };

        SpecusCore.dispatchHttpData(ingress, "body".getBytes(StandardCharsets.UTF_8),
                true, Map.of());

        assertEquals(List.of("data:body", "fin"), events);
    }

    @Test
    public void httpTrailersAreSafeDeclaredIntersection() {
        assertEquals(List.of("Digest", "X-Trace"), SpecusCore.HttpTrailerPolicy.validNames(
                List.of(" Digest ", "content-length", "X-Trace", "digest", "bad name")));
        assertEquals(List.of("Digest:sha-256=ok"), SpecusCore.HttpTrailerPolicy.validLines(
                List.of("Digest:sha-256=ok", "X-Injected:no", "Content-Length:4",
                        "X-Trace:bad\r\nInjected:yes"),
                List.of("Digest", "X-Trace", "Content-Length")));
    }

    @Test
    public void requestTrailersAreExplicitlyRejectedByHttpUrlConnectionTransport() throws Exception {
        SpecusCore.HttpTrailerPolicy.requireNoRequestTrailers(List.of());
        IOException error = assertThrows(IOException.class,
                () -> SpecusCore.HttpTrailerPolicy.requireNoRequestTrailers(List.of("Digest")));
        assertTrue(error.getMessage().contains("HttpURLConnection"));
        assertThrows(IOException.class,
                () -> SpecusCore.HttpTrailerPolicy.requireNoRequestTrailers("Digest"));
    }

    @Test
    public void httpUrlConnectionDoesNotSilentlyRewriteGetOrHeadBodies() {
        assertFalse(SpecusCore.HttpUrlConnectionRequestPolicy.opensRequestBody("GET", 1));
        assertFalse(SpecusCore.HttpUrlConnectionRequestPolicy.opensRequestBody("HEAD", -1));
        assertFalse(SpecusCore.HttpUrlConnectionRequestPolicy.opensRequestBody("POST", 0));
        assertTrue(SpecusCore.HttpUrlConnectionRequestPolicy.opensRequestBody("POST", 1));
    }

    @Test
    public void controlTlsUsesRuntimeSignalWithoutInferringManagementHttps() throws Exception {
        SpecusCore.StartupConfig defaults = SpecusCore.StartupConfig.parse("""
                {
                  "serverBaseUrl": "https://login.specus.test",
                  "apiKey": "key",
                  "secret": "secret"
                }
                """);
        assertFalse(defaults.controlTls.resolveEnabled(false));
        assertTrue(defaults.controlTls.resolveEnabled(true));

        SpecusCore.StartupConfig disabled = SpecusCore.StartupConfig.parse("""
                {
                  "serverBaseUrl": "https://login.specus.test",
                  "apiKey": "key",
                  "secret": "secret",
                  "controlTls": { "enabled": false }
                }
                """);
        assertFalse(disabled.controlTls.resolveEnabled(true));

        SpecusCore.StartupConfig optionEnabled = SpecusCore.StartupConfig.parse("""
                {
                  "serverBaseUrl": "http://login.specus.test",
                  "apiKey": "key",
                  "secret": "secret",
                  "controlTls": { "serverName": "control.specus.test" }
                }
                """);
        assertTrue(optionEnabled.controlTls.resolveEnabled(false));
        assertEquals("control.specus.test",
                optionEnabled.controlTls.resolveServerName("10.0.0.1"));
    }

    @Test
    public void noopPeerMeshDoesNotRequireOrStartAnAndroidVpnDevice() throws Exception {
        SpecusCore.StartupConfig noop = SpecusCore.StartupConfig.parse("""
                {
                  "serverBaseUrl": "https://login.specus.test",
                  "apiKey": "key",
                  "secret": "secret",
                  "peerMeshDevice": "noop"
                }
                """);
        SpecusCore.StartupConfig automatic = SpecusCore.StartupConfig.parse("""
                {
                  "serverBaseUrl": "https://login.specus.test",
                  "apiKey": "key",
                  "secret": "secret",
                  "peerMeshDevice": "auto"
                }
                """);
        assertFalse(noop.requiresVpnPermission());
        assertTrue(automatic.requiresVpnPermission());

        SpecusCore.SpecusSession session = new SpecusCore.SpecusSession();
        session.applyStartup(noop);
        assertFalse(session.usesVpnDevice());
        session.applyStartup(automatic);
        assertTrue(session.usesVpnDevice());
    }

    @Test
    public void invalidControlTlsCombinationsAreRejected() {
        assertInvalidControlTls("{ \"enabled\": false, \"caCertificatePath\": \"ca.pem\" }");
        assertInvalidControlTls("{ \"caCertificatePath\": \"ca.pem\", \"insecureSkipVerify\": true }");
        assertInvalidControlTls("{ \"serverName\": \"control.specus.test:443\" }");
        assertInvalidControlTls("{ \"serverName\": \"https://control.specus.test\" }");
    }

    @Test
    public void loginNettyTlsDefaultsFalseAndRefreshSynchronizesIt() throws Exception {
        SpecusCore.SpecusSession session = SpecusCore.SpecusSession.fromLoginJson(loginJson(false, false));
        assertFalse(session.nettyTls);

        SpecusCore.SpecusSession refreshed = SpecusCore.SpecusSession.fromLoginJson(loginJson(true, true));
        refreshed.applyStartup(SpecusCore.StartupConfig.parse("""
                {
                  "serverBaseUrl": "http://login.specus.test",
                  "apiKey": "key",
                  "secret": "secret"
                }
                """));
        session.applyRefresh(refreshed);
        assertTrue(session.nettyTls);
    }

    @Test
    public void vpnProtectFailureClosesSocketAndAbortsConnection() throws Exception {
        Socket socket = new Socket();
        SpecusCore.VpnPlatform rejectingVpn = vpnPlatform(false);

        IOException error = assertThrows(IOException.class,
                () -> SpecusCore.protectSocket(rejectingVpn, socket));

        assertTrue(error.getMessage().contains("protect"));
        assertTrue(socket.isClosed());
    }

    @Test
    public void tlsHandshakeHasFiniteReadTimeout() throws Exception {
        try (ServerSocket listener = new ServerSocket(0);
             Socket raw = new Socket("127.0.0.1", listener.getLocalPort());
             Socket silentPeer = listener.accept()) {
            SpecusCore.ControlTlsConfig tls = SpecusCore.ControlTlsConfig.parse(
                    new JSONObject().put("enabled", true).put("insecureSkipVerify", true));
            long started = System.nanoTime();

            assertThrows(IOException.class, () -> SpecusCore.ControlTlsSockets.wrapConnected(
                    raw, "127.0.0.1", listener.getLocalPort(), false, tls, 150));

            long elapsedMillis = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - started);
            assertTrue("TLS handshake should be bounded, elapsed=" + elapsedMillis,
                    elapsedMillis < 2_000);
        }
    }

    @Test
    public void closingConnectingSocketTrackerInterruptsTlsHandshake() throws Exception {
        try (ServerSocket listener = new ServerSocket(0);
             Socket raw = new Socket("127.0.0.1", listener.getLocalPort());
             Socket silentPeer = listener.accept()) {
            SpecusCore.ConnectingSocketTracker tracker = new SpecusCore.ConnectingSocketTracker();
            tracker.track(raw);
            SpecusCore.ControlTlsConfig tls = SpecusCore.ControlTlsConfig.parse(
                    new JSONObject().put("enabled", true).put("insecureSkipVerify", true));
            FutureTask<Throwable> handshake = new FutureTask<>(() -> {
                try {
                    SpecusCore.ControlTlsSockets.wrapConnected(
                            raw, "127.0.0.1", listener.getLocalPort(), false, tls, 5_000);
                    return null;
                } catch (Throwable error) {
                    return error;
                }
            });
            Thread thread = new Thread(handshake, "android-tls-handshake-test");
            thread.start();
            assertTrue(waitForClientHello(silentPeer));

            tracker.close();

            assertNotNull(handshake.get(2, TimeUnit.SECONDS));
            assertTrue(raw.isClosed());
        }
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

    private static void assertInvalidControlTls(String controlTls) {
        String config = """
                {
                  "serverBaseUrl": "http://login.specus.test",
                  "apiKey": "key",
                  "secret": "secret",
                  "controlTls": %s
                }
                """.formatted(controlTls);
        assertThrows(IllegalArgumentException.class,
                () -> SpecusCore.StartupConfig.parse(config));
    }

    private static JSONObject loginJson(boolean includeNettyTls, boolean nettyTls) throws Exception {
        JSONObject json = new JSONObject()
                .put("clientName", "android-a")
                .put("clientSessionId", 1L)
                .put("accessToken", "token")
                .put("nettyHost", "127.0.0.1")
                .put("nettyPort", 7010);
        if (includeNettyTls) {
            json.put("nettyTls", nettyTls);
        }
        return json;
    }

    private static SpecusCore.VpnPlatform vpnPlatform(boolean protectResult) {
        return new SpecusCore.VpnPlatform() {
            @Override
            public void startVpn(SpecusCore.PeerMeshConfig config,
                                 SpecusCore.VpnPacketHandler packetHandler) {
            }

            @Override
            public void stopVpn() {
            }

            @Override
            public boolean protectSocket(Socket socket) {
                return protectResult;
            }

            @Override
            public boolean protectDatagramSocket(java.net.DatagramSocket socket) {
                return protectResult;
            }

            @Override
            public void writeVpnPacket(byte[] packet) {
            }
        };
    }

    private static boolean waitForClientHello(Socket peer) throws Exception {
        peer.setSoTimeout(1_000);
        return peer.getInputStream().read() >= 0;
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
