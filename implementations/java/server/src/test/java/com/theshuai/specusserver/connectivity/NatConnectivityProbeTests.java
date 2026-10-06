package com.theshuai.specusserver.connectivity;

import com.fasterxml.jackson.databind.JsonNode;
import com.theshuai.common.protocol.NatMessagePacket;
import com.theshuai.common.protocol.NatMessageType;
import com.theshuai.common.session.Session;
import com.theshuai.specusserver.attribute.ServerAttributes;
import com.theshuai.specusserver.connectivity.ConnectivityCheckFakes.FakeTargets;
import com.theshuai.specusserver.handler.NatServerHandler;
import com.theshuai.specusserver.http.WebSocketSpecusHandler;
import com.theshuai.specusserver.http.WebSocketStreamRegistry;
import com.theshuai.specusserver.session.ClientHttpRouteCapabilities;
import com.theshuai.specusserver.session.SessionUtil;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelOutboundHandlerAdapter;
import io.netty.channel.ChannelPromise;
import io.netty.channel.embedded.EmbeddedChannel;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicLong;

import static com.theshuai.specusserver.connectivity.ConnectivityCheckFakes.JSON;
import static com.theshuai.specusserver.connectivity.ConnectivityCheckFakes.caller;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

/**
 * The probe over a real {@link NatServerHandler} on an embedded data connection, the client played
 * by a script: what the device's RST metadata, response head or silence turns into, which frames
 * the server sends, and that the RST reason never reaches the answer.
 */
class NatConnectivityProbeTests {
    private static final String LEAKY_REASON =
            "dial tcp 10.20.30.40:8080: connect: connection refused (GET /admin?token=s3cret)";
    private static final AtomicLong SESSION_IDS = new AtomicLong(90_000);

    private final ClientHttpRouteCapabilities capabilities = new ClientHttpRouteCapabilities();
    private final List<EmbeddedChannel> channels = new ArrayList<>();
    private String clientName;
    private EmbeddedChannel data;

    @AfterEach
    void disconnect() {
        channels.forEach(EmbeddedChannel::finishAndReleaseAll);
    }

    @Test
    void everyClassifiedResetOfACapableSessionReachesTheCheck() throws Exception {
        JsonNode failures = ConnectivityCheckFakes.readVector().path("rstFailures");
        assertThat(failures.size()).isEqualTo(com.theshuai.common.protocol.HttpRouteFailure.values().length);
        for (Iterator<String> names = failures.fieldNames(); names.hasNext(); ) {
            String failure = names.next();
            String stage = failures.get(failure).path("stage").asText();
            String code = failures.get(failure).path("code").asText();
            connect(1, new ScriptedClient().then(reset(failure)));

            JsonNode body = check(200);

            assertThat(body.path("code").asText()).as(failure).isEqualTo(code);
            assertThat(body.path("stoppedAt").asText()).as(failure).isEqualTo(stage);
            assertThat(body.path("outcome").asText()).as(failure).isEqualTo("failed");
            assertThat(body.path("requests").toString()).isEqualTo("[\"HEAD\"]");
            if (!stage.equals("device-online")) {
                assertThat(body.path("stages").get(1).path("code").asText()).isEqualTo("DEVICE_ONLINE");
            }
            // The client reset the stream itself: OPEN and FIN went out, and no RST of ours follows.
            assertThat(types(drainOutbound())).as(failure)
                    .containsExactly(NatMessageType.OPEN, NatMessageType.FIN);
        }
    }

    @Test
    void aResetIsUnverifiedWithoutTheCapabilityOrWithAnUnknownFailure() throws Exception {
        connect(0, new ScriptedClient().then(reset("connect-refused")));
        assertThat(check(200).path("code").asText()).isEqualTo("TARGET_UNVERIFIED");

        connect(1, new ScriptedClient().then(reset("something-newer")));
        assertThat(check(200).path("code").asText()).isEqualTo("TARGET_UNVERIFIED");

        connect(1, new ScriptedClient().then(reset(null)));
        JsonNode body = check(200);
        assertThat(body.path("outcome").asText()).isEqualTo("unverified");
        assertThat(body.path("stoppedAt").asText()).isEqualTo("target-reachable");
        assertThat(body.path("code").asText()).isEqualTo("TARGET_UNVERIFIED");
    }

    @Test
    void theProbeOpensAFixedRequestAndTheHeadEndsIt() throws Exception {
        // HEAD refused by method, no FIN yet: the server resets it. The GET head comes with its FIN.
        connect(1, new ScriptedClient().then(respond(405, false)).then(respond(204, true)));

        JsonNode body = check(200);

        assertThat(body.path("outcome").asText()).isEqualTo("succeeded");
        assertThat(body.path("code").asText()).isEqualTo("ACCESS_OK");
        assertThat(body.path("statusClass").asText()).isEqualTo("2xx");
        assertThat(body.path("requests").toString()).isEqualTo("[\"HEAD\",\"GET\"]");
        List<NatMessagePacket> frames = drainOutbound();
        assertThat(types(frames)).containsExactly(
                NatMessageType.OPEN, NatMessageType.FIN, NatMessageType.RST,
                NatMessageType.OPEN, NatMessageType.FIN);
        int headStream = frames.get(0).getStreamId();
        assertThat(frames.get(2).getStreamId()).isEqualTo(headStream);
        assertThat(frames.get(3).getStreamId()).isNotEqualTo(headStream);
        for (int index : new int[]{0, 3}) {
            Map<String, Object> open = frames.get(index).getMetaData();
            assertThat(new ArrayList<>(open.keySet())).containsExactly(
                    "source", "phase", "requestId", "method", "route", "relativePath", "rawQuery", "headers");
            assertThat(open.get("method")).isEqualTo(index == 0 ? "HEAD" : "GET");
            assertThat(open.get("route")).isEqualTo(ConnectivityCheckFakes.ROUTE_NAME);
            assertThat(open.get("relativePath")).isEqualTo("/");
            assertThat(open.get("rawQuery")).isEqualTo("");
            assertThat(open.get("headers")).isEqualTo(List.of("Accept:*/*", "User-Agent:specus-connectivity-check/1"));
            assertThat((String) open.get("requestId")).matches("[0-9a-f]{32}");
        }
        assertThat(frames.get(1).getMetaData()).isNull();

        // Body bytes and the FIN of the reset HEAD still in flight: dropped, no WINDOW_UPDATE, no RST.
        data.writeInbound(packet(NatMessageType.DATA, headStream, 0, null, new byte[]{1, 2, 3}));
        data.writeInbound(packet(NatMessageType.FIN, headStream, 0, null, null));
        data.writeInbound(packet(NatMessageType.RST, headStream, 8, Map.of("reason", "cancelled"), null));
        assertThat(drainOutbound()).isEmpty();
        assertThat(data.isActive()).isTrue();
    }

    @Test
    void aSilentDeviceIsResetWhenTheTimeIsUp() {
        connect(1, new ScriptedClient());
        ConnectivityProbe.Online online = (ConnectivityProbe.Online) new NatConnectivityProbe(capabilities).link(clientName);
        assertThat(online.channel().httpRouteCapability()).isEqualTo(1);

        ConnectivityProbe.Answer answer = online.channel().exchange(request("HEAD"), 30);

        assertThat(answer).isInstanceOf(ConnectivityProbe.NoAnswer.class);
        List<NatMessagePacket> frames = drainOutbound();
        assertThat(types(frames)).containsExactly(NatMessageType.OPEN, NatMessageType.FIN, NatMessageType.RST);
        // A head that shows up after the reset is dropped silently.
        data.writeInbound(responseHead(frames.get(0).getStreamId(), 200));
        assertThat(drainOutbound()).isEmpty();
        assertThat(data.isActive()).isTrue();
    }

    @Test
    void aDataConnectionThatClosesIsALostLink() throws Exception {
        connect(1, new ScriptedClient().then((ctx, streamId) -> ctx.close()));

        JsonNode body = check(200);

        assertThat(body.path("stoppedAt").asText()).isEqualTo("device-online");
        assertThat(body.path("code").asText()).isEqualTo("DEVICE_LINK_LOST");
    }

    @Test
    void aHeadOutsideTheStatusRangeIsAProtocolError() throws Exception {
        // 1xx passes the stream's own validation; 600 does not and is refused with an RST.
        for (int status : new int[]{103, 600}) {
            connect(1, new ScriptedClient().then(respond(status, true)));

            JsonNode body = check(200);

            assertThat(body.path("code").asText()).as("status " + status).isEqualTo("TARGET_PROTOCOL_ERROR");
            assertThat(body.path("stages").get(1).path("code").asText()).isEqualTo("DEVICE_ONLINE");
            assertThat(body.has("statusClass")).isFalse();
        }
    }

    @Test
    void theLinkFollowsTheSessionTable() {
        clientName = "probe-" + UUID.randomUUID();
        NatConnectivityProbe probe = new NatConnectivityProbe(capabilities);
        assertThat(probe.link(clientName)).isInstanceOf(ConnectivityProbe.Offline.class);

        EmbeddedChannel control = new EmbeddedChannel();
        channels.add(control);
        SessionUtil.bindControlSession(new Session(clientName), control);
        assertThat(probe.link(clientName)).isInstanceOf(ConnectivityProbe.DataChannelDown.class);

        data = new EmbeddedChannel(newHandler());
        channels.add(data);
        long sessionId = SESSION_IDS.incrementAndGet();
        data.attr(ServerAttributes.CLIENT_SESSION_ID).set(sessionId);
        SessionUtil.bindDataSession(new Session(clientName), data);
        assertThat(probe.link(clientName)).isInstanceOf(ConnectivityProbe.Online.class);
        assertThat(((ConnectivityProbe.Online) probe.link(clientName)).channel().httpRouteCapability()).isZero();
        capabilities.remember(sessionId, 1, Instant.now().plusSeconds(60));
        assertThat(((ConnectivityProbe.Online) probe.link(clientName)).channel().httpRouteCapability()).isEqualTo(1);

        data.close();
        assertThat(probe.link(clientName)).isInstanceOf(ConnectivityProbe.DataChannelDown.class);
        control.close();
        assertThat(probe.link(clientName)).isInstanceOf(ConnectivityProbe.Offline.class);
    }

    /** Binds a fresh control and data connection for a fresh client name. */
    private void connect(int capability, ScriptedClient client) {
        clientName = "probe-" + UUID.randomUUID();
        EmbeddedChannel control = new EmbeddedChannel();
        channels.add(control);
        SessionUtil.bindControlSession(new Session(clientName), control);
        data = new EmbeddedChannel(client, newHandler());
        channels.add(data);
        long sessionId = SESSION_IDS.incrementAndGet();
        data.attr(ServerAttributes.TENANT_ID).set(ConnectivityCheckFakes.TENANT);
        data.attr(ServerAttributes.CLIENT_SESSION_ID).set(sessionId);
        SessionUtil.bindDataSession(new Session(clientName), data);
        capabilities.remember(sessionId, capability, Instant.now().plusSeconds(60));
    }

    private JsonNode check(int expectedStatus) throws Exception {
        FakeTargets targets = new FakeTargets();
        targets.clientName = clientName;
        HttpRouteConnectivityCheckService service =
                new HttpRouteConnectivityCheckService(targets, new NatConnectivityProbe(capabilities));
        HttpRouteConnectivityCheckService.Response response =
                service.check(() -> caller("alice", false), "42", InputStream.nullInputStream());
        assertThat(response.status()).isEqualTo(expectedStatus);
        String text = new String(response.body(), StandardCharsets.UTF_8);
        assertThat(text).doesNotContain("10.20.30.40", "s3cret", "connection refused", "Server", "10.9.9.9");
        return JSON.readTree(text);
    }

    private List<NatMessagePacket> drainOutbound() {
        List<NatMessagePacket> frames = new ArrayList<>();
        for (Object frame; (frame = data.readOutbound()) != null; ) {
            frames.add((NatMessagePacket) frame);
        }
        return frames;
    }

    private static List<NatMessageType> types(List<NatMessagePacket> frames) {
        return frames.stream().map(NatMessagePacket::getNatMessageType).toList();
    }

    private static NatServerHandler newHandler() {
        return new NatServerHandler(null, null, null, null,
                mock(WebSocketStreamRegistry.class), mock(WebSocketSpecusHandler.class));
    }

    private static Map<String, Object> request(String method) {
        Map<String, Object> metadata = new LinkedHashMap<>();
        metadata.put("source", "http");
        metadata.put("phase", "request");
        metadata.put("requestId", "0".repeat(32));
        metadata.put("method", method);
        metadata.put("route", ConnectivityCheckFakes.ROUTE_NAME);
        metadata.put("relativePath", "/");
        metadata.put("rawQuery", "");
        metadata.put("headers", List.of("Accept:*/*"));
        return metadata;
    }

    private static Reaction reset(String failure) {
        return (ctx, streamId) -> {
            Map<String, Object> metadata = new HashMap<>();
            metadata.put("reason", LEAKY_REASON);
            if (failure != null) {
                metadata.put("failure", failure);
            }
            ctx.fireChannelRead(packet(NatMessageType.RST, streamId, 26, metadata, null));
        };
    }

    private static Reaction respond(int status, boolean fin) {
        return (ctx, streamId) -> {
            ctx.fireChannelRead(responseHead(streamId, status));
            if (fin) {
                ctx.fireChannelRead(packet(NatMessageType.FIN, streamId, 0, null, null));
            }
        };
    }

    private static NatMessagePacket responseHead(int streamId, int status) {
        return packet(NatMessageType.OPEN, streamId, 0, Map.of(
                "source", "http",
                "phase", "response",
                "statusCode", status,
                "headers", List.of("Server:secret-server", "Location:http://10.9.9.9/")), null);
    }

    private static NatMessagePacket packet(NatMessageType type, int streamId, long value,
                                           Map<String, Object> metadata, byte[] payload) {
        NatMessagePacket packet = new NatMessagePacket();
        packet.setNatMessageType(type);
        packet.setStreamId(streamId);
        packet.setValue(value);
        packet.setMetaData(metadata);
        packet.setData(payload);
        return packet;
    }

    @FunctionalInterface
    private interface Reaction {
        void react(ChannelHandlerContext ctx, int streamId);
    }

    /** Plays the client: reacts to each request FIN in turn, in the write that carries it. */
    private static final class ScriptedClient extends ChannelOutboundHandlerAdapter {
        private final Deque<Reaction> reactions = new ArrayDeque<>();

        private ScriptedClient then(Reaction reaction) {
            reactions.add(reaction);
            return this;
        }

        @Override
        public void write(ChannelHandlerContext ctx, Object msg, ChannelPromise promise) {
            ctx.write(msg, promise);
            if (msg instanceof NatMessagePacket packet && packet.getNatMessageType() == NatMessageType.FIN
                    && !reactions.isEmpty()) {
                reactions.removeFirst().react(ctx, packet.getStreamId());
            }
        }
    }
}
