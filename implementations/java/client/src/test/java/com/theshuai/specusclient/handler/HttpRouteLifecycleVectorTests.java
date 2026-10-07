package com.theshuai.specusclient.handler;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.theshuai.common.protocol.MessageType;
import com.theshuai.common.protocol.response.MessageResponsePacket;
import com.theshuai.specusclient.bean.HttpSpecusConfig;
import com.theshuai.specusclient.bean.SpecusBean;
import com.theshuai.specusclient.client.NettyClient;
import com.theshuai.specusclient.client.TcpConnection;
import io.netty.channel.Channel;
import io.netty.channel.embedded.EmbeddedChannel;
import org.junit.jupiter.api.DynamicContainer;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.TestFactory;

import java.io.IOException;
import java.lang.reflect.Field;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Stream;
import java.util.stream.StreamSupport;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Replays {@code client.cases} of {@code protocol/test-vectors/http-route-lifecycle-v1.json}: the
 * route table starts as the HTTP login snapshot, and every NAT_CONTROL, fed as its raw JSON, replaces
 * the whole table; an empty, null or missing {@code httpSpecusConfigList} leaves no route.
 *
 * <p>Each case runs through both NAT_CONTROL paths: {@link MessageResponseHandler} applying the push
 * to the {@link NatClientHandler} in its own pipeline, and the production path through
 * {@link NettyClient#applyNatControl}, which updates both the live data connection's handler and the
 * bean the next data connection is built from.
 */
class HttpRouteLifecycleVectorTests {
    private static final ObjectMapper JSON = new ObjectMapper();
    private static final JsonNode VECTOR = readVector();

    @TestFactory
    Stream<DynamicContainer> clientCases() {
        return elements(VECTOR.path("client").path("cases")).map(testCase -> DynamicContainer.dynamicContainer(
                testCase.get("id").asText(), Stream.of(
                        DynamicTest.dynamicTest("message handler", () -> replayThroughMessageHandler(testCase)),
                        DynamicTest.dynamicTest("netty client", () -> replayThroughNettyClient(testCase)))));
    }

    private static void replayThroughMessageHandler(JsonNode testCase) {
        NatClientHandler nat = new NatClientHandler(loginBean(testCase), new TcpConnection());
        EmbeddedChannel channel = new EmbeddedChannel(nat, new MessageResponseHandler(new TcpConnection()));
        try {
            assertThat(nat.getCurrentHttpRoutes()).as("login snapshot").isEqualTo(routes(testCase.get("loginSnapshot")));
            int index = 0;
            for (JsonNode step : testCase.get("steps")) {
                channel.writeInbound(natControl(step.get("natControl").asText()));
                assertThat(nat.getCurrentHttpRoutes()).as("routes after step #" + index++)
                        .isEqualTo(expectedRoutes(step));
            }
        } finally {
            channel.finishAndReleaseAll();
        }
    }

    private static void replayThroughNettyClient(JsonNode testCase) throws Exception {
        SpecusBean bean = loginBean(testCase);
        NettyClient client = new NettyClient(bean);
        // The data connection's handler as NettyClient builds it after the data login.
        NatClientHandler live = new NatClientHandler(bean, new TcpConnection());
        EmbeddedChannel data = new EmbeddedChannel(live);
        EmbeddedChannel control = new EmbeddedChannel(new MessageResponseHandler(new TcpConnection(), null, client));
        try {
            useDataChannel(client, data);
            int index = 0;
            for (JsonNode step : testCase.get("steps")) {
                control.writeInbound(natControl(step.get("natControl").asText()));
                data.runPendingTasks();
                Map<String, String> expected = expectedRoutes(step);
                assertThat(live.getCurrentHttpRoutes()).as("live data connection after step #" + index)
                        .isEqualTo(expected);
                assertThat(new NatClientHandler(bean, new TcpConnection()).getCurrentHttpRoutes())
                        .as("next data connection after step #" + index)
                        .isEqualTo(expected);
                index++;
            }
        } finally {
            useDataChannel(client, null);
            client.shutdown();
            control.finishAndReleaseAll();
            data.finishAndReleaseAll();
        }
    }

    private static SpecusBean loginBean(JsonNode testCase) {
        SpecusBean bean = new SpecusBean();
        bean.setClientName("route-lifecycle");
        bean.setClientSessionId(1L);
        bean.setAccessToken("cs_route_lifecycle");
        bean.setRemoteAddress("127.0.0.1");
        bean.setRemotePort(7010);
        bean.setSpecusConfigList(List.of());
        bean.setHttpSpecusConfigList(JSON.convertValue(testCase.get("loginSnapshot"),
                new TypeReference<List<HttpSpecusConfig>>() { }));
        return bean;
    }

    private static Map<String, String> routes(JsonNode snapshot) {
        Map<String, String> routes = new LinkedHashMap<>();
        snapshot.forEach(route -> routes.put(route.get("route").asText(), route.get("targetBaseUrl").asText()));
        return routes;
    }

    private static Map<String, String> expectedRoutes(JsonNode step) {
        Map<String, String> routes = new LinkedHashMap<>();
        step.get("expectRoutes").properties().forEach(entry -> routes.put(entry.getKey(), entry.getValue().asText()));
        return routes;
    }

    private static MessageResponsePacket natControl(String json) {
        MessageResponsePacket packet = new MessageResponsePacket();
        packet.setMessageType(MessageType.NAT_CONTROL);
        packet.setMessage(json);
        return packet;
    }

    /**
     * Stands {@code channel} in as the client's data connection. Reflection, because the field is
     * private and a setter only for tests would widen the production API.
     */
    @SuppressWarnings("unchecked")
    private static void useDataChannel(NettyClient client, Channel channel) throws ReflectiveOperationException {
        Field field = NettyClient.class.getDeclaredField("dataChannel");
        field.setAccessible(true);
        ((AtomicReference<Channel>) field.get(client)).set(channel);
    }

    private static Stream<JsonNode> elements(JsonNode array) {
        return StreamSupport.stream(array.spliterator(), false);
    }

    private static JsonNode readVector() {
        Path current = Path.of("").toAbsolutePath();
        for (int depth = 0; current != null && depth < 8; depth++, current = current.getParent()) {
            Path candidate = current.resolve("protocol/test-vectors/http-route-lifecycle-v1.json");
            if (Files.isRegularFile(candidate)) {
                try {
                    return JSON.readTree(Files.readString(candidate, StandardCharsets.UTF_8));
                } catch (IOException e) {
                    throw new IllegalStateException(e);
                }
            }
        }
        throw new IllegalStateException("cannot locate http-route-lifecycle-v1.json");
    }
}
