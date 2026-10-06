package com.theshuai.specusserver.connectivity;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.theshuai.specusserver.connectivity.ConnectivityCheckFakes.FakeClock;
import com.theshuai.specusserver.connectivity.ConnectivityCheckFakes.FakeTargets;
import com.theshuai.specusserver.connectivity.ConnectivityCheckFakes.ScriptedProbe;
import com.theshuai.specusserver.management.security.ManagementContextResolver;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.TestFactory;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.web.server.ResponseStatusException;

import java.io.InputStream;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.stream.Stream;
import java.util.stream.StreamSupport;

import static com.theshuai.specusserver.connectivity.ConnectivityCheckFakes.JSON;
import static com.theshuai.specusserver.connectivity.ConnectivityCheckFakes.ROUTE_NAME;
import static com.theshuai.specusserver.connectivity.ConnectivityCheckFakes.TENANT;
import static com.theshuai.specusserver.connectivity.ConnectivityCheckFakes.caller;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

/**
 * Replays every case of {@code protocol/test-vectors/service-connectivity-check-v1.json} through the
 * real endpoint and the real check service; only the route records, the device and the clocks are
 * scripted. The answer must equal the vector field by field, {@code routeId} and {@code checkedAt}
 * aside, which are checked for their run-time values instead.
 */
class HttpRouteConnectivityCheckVectorTests {
    private static final long ROUTE_ID = 42;
    private static final String PROBE_PATH = "/healthz";
    private static final long CHECK_START_MS = 7_000_000L;
    private static final Instant WALL_CLOCK = Instant.parse("2026-10-06T08:00:00.789Z");
    private static final String CHECKED_AT = "2026-10-06T08:00:00Z";
    private static final List<String> BODY_KEYS = List.of(
            "schemaVersion", "kind", "routeId", "checkedAt", "outcome", "stoppedAt", "code", "totalMs",
            "requests", "stages");
    private static final List<String> METADATA_KEYS = List.of(
            "source", "phase", "requestId", "method", "route", "relativePath", "rawQuery", "headers");

    @TestFactory
    Stream<DynamicTest> everyCaseOfTheSharedVector() throws Exception {
        JsonNode vector = ConnectivityCheckFakes.readVector();
        assertThat(vector.path("checkBudgetMs").asLong()).isEqualTo(HttpRouteConnectivityCheckService.BUDGET_MS);
        assertThat(vector.path("rate").path("maxConcurrentPerServer").asInt())
                .isEqualTo(HttpRouteConnectivityCheckService.MAX_CONCURRENT_CHECKS);
        assertThat(vector.path("rate").path("maxConcurrentPerRoute").asInt()).isEqualTo(1);
        JsonNode cases = vector.path("cases");
        assertThat(cases.size()).isPositive();
        return StreamSupport.stream(cases.spliterator(), false)
                .map(node -> DynamicTest.dynamicTest(node.path("name").asText(), () -> replay(node)));
    }

    private void replay(JsonNode node) throws Exception {
        String name = node.path("name").asText();
        JsonNode input = node.path("input");
        JsonNode expect = node.path("expect");

        FakeClock clock = new FakeClock(CHECK_START_MS, WALL_CLOCK);
        FakeTargets targets = new FakeTargets();
        targets.readable = input.path("configReadable").asBoolean(true);
        targets.visible = input.path("routeVisible").asBoolean(true);
        targets.routeEnabled = input.path("route").path("enabled").asBoolean(true);
        targets.targetValid = input.path("route").path("targetValid").asBoolean(true);
        targets.clientEnabled = input.path("device").path("enabled").asBoolean(true);
        ScriptedProbe probe = new ScriptedProbe(clock, CHECK_START_MS);
        probe.controlOnline = input.path("device").path("controlOnline").asBoolean(true);
        probe.dataOnline = input.path("device").path("dataOnline").asBoolean(true);
        probe.capability = input.path("device").path("httpRouteCapability").asInt(0);
        input.path("answers").forEach(probe.answers::add);
        int scriptedAnswers = probe.answers.size();

        HttpRouteConnectivityCheckService service = new HttpRouteConnectivityCheckService(targets, probe, clock);
        ManagementContextResolver resolver = mock(ManagementContextResolver.class);
        if (input.path("authenticated").asBoolean(true)) {
            when(resolver.resolve(any())).thenReturn(caller("alice", false));
        } else {
            when(resolver.resolve(any())).thenThrow(new ResponseStatusException(HttpStatus.UNAUTHORIZED, "缺少认证身份"));
        }
        MockMvc mvc = ConnectivityCheckFakes.endpoint(service, resolver);
        String body = input.path("requestValid").asBoolean(true)
                ? "{\"path\":\"" + PROBE_PATH + "\"}"
                : "{\"path\":\"/status/../admin\"}";

        Logger logger = (Logger) LoggerFactory.getLogger(HttpRouteConnectivityCheckService.class);
        ListAppender<ILoggingEvent> logs = new ListAppender<>();
        logs.start();
        logger.addAppender(logs);
        MockHttpServletResponse response;
        ExecutorService occupants = Executors.newFixedThreadPool(HttpRouteConnectivityCheckService.MAX_CONCURRENT_CHECKS);
        List<Future<HttpRouteConnectivityCheckService.Response>> held = new ArrayList<>();
        try {
            occupy(input.path("admission").asText("admitted"), service, probe, occupants, held);
            response = mvc.perform(post("/api/admin/http-routes/" + ROUTE_ID + "/connectivity-check")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(body))
                    .andReturn().getResponse();
        } finally {
            // The occupants log their own checks once released; only the case's lines are captured.
            logger.detachAppender(logs);
            probe.release.countDown();
            for (Future<HttpRouteConnectivityCheckService.Response> occupant : held) {
                assertThat(occupant.get(10, TimeUnit.SECONDS).status()).as(name + " occupant").isEqualTo(200);
            }
            occupants.shutdownNow();
        }

        int status = expect.path("httpStatus").asInt();
        assertThat(response.getStatus()).as(name + " httpStatus").isEqualTo(status);
        assertThat(response.getHeader("Cache-Control")).as(name + " Cache-Control").isEqualTo("private, no-store");
        JsonNode answer = JSON.readTree(response.getContentAsByteArray());
        List<String> lines = logs.list.stream().map(ILoggingEvent::getFormattedMessage).toList();
        assertThat(lines).as(name + " log").noneMatch(line -> line.contains(PROBE_PATH));

        if (status != 200) {
            if (expect.has("code")) {
                assertThat(answer).as(name + " body").isEqualTo(JSON.createObjectNode()
                        .put("code", expect.get("code").asText()));
            } else {
                assertThat(answer.has("code")).as(name + " body has no code").isFalse();
            }
            assertThat(response.getHeader("Retry-After")).as(name + " Retry-After")
                    .isEqualTo(expectedRetryAfter(expect));
            assertThat(probe.sent).as(name + " probes sent").isEmpty();
            assertThat(lines).as(name + " log").noneMatch(line -> line.contains("route=" + ROUTE_ID + " outcome="));
            return;
        }

        JsonNode expected = expect.path("body");
        assertThat(response.getContentType()).as(name + " Content-Type").startsWith(MediaType.APPLICATION_JSON_VALUE);
        assertThat(response.getHeader("Retry-After")).as(name + " Retry-After").isNull();
        List<String> keys = new ArrayList<>(BODY_KEYS);
        if (expected.has("statusClass")) {
            keys.add("statusClass");
        }
        assertThat(fieldNames(answer)).as(name + " body keys in order").isEqualTo(keys);
        assertThat(answer.get("routeId").isIntegralNumber()).as(name + " routeId is a number").isTrue();
        assertThat(answer.get("routeId").asLong()).as(name + " routeId").isEqualTo(ROUTE_ID);
        assertThat(answer.get("checkedAt").asText()).as(name + " checkedAt")
                .matches("\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}Z")
                .isEqualTo(CHECKED_AT);
        ObjectNode rest = ((ObjectNode) answer).deepCopy();
        rest.remove("routeId");
        rest.remove("checkedAt");
        for (Iterator<String> fields = expected.fieldNames(); fields.hasNext(); ) {
            String field = fields.next();
            assertThat(rest.get(field)).as(name + " body." + field).isEqualTo(expected.get(field));
        }
        assertThat(rest).as(name + " body").isEqualTo(expected);
        for (JsonNode stage : answer.get("stages")) {
            assertThat(fieldNames(stage)).as(name + " stage keys in order").isEqualTo(
                    "skipped".equals(stage.path("result").asText())
                            ? List.of("stage", "result") : List.of("stage", "result", "code", "atMs"));
        }

        // What reached the device: one probe per listed request, nothing left of the script.
        assertThat(probe.answers).as(name + " unused answers").isEmpty();
        assertThat(probe.sent).as(name + " probes sent").hasSize(expected.path("requests").size());
        assertThat(scriptedAnswers).as(name + " scripted answers").isEqualTo(expected.path("requests").size());
        for (int index = 0; index < probe.sent.size(); index++) {
            assertProbe(name, probe.sent.get(index), expected.path("requests").get(index).asText());
        }
        if (!probe.timeouts.isEmpty()) {
            assertThat(probe.timeouts.get(0)).as(name + " HEAD budget").isEqualTo(HttpRouteConnectivityCheckService.BUDGET_MS);
        }
        if (probe.timeouts.size() == 2) {
            long headAt = input.path("answers").get(0).path("atMs").asLong();
            assertThat(probe.timeouts.get(1)).as(name + " GET budget")
                    .isEqualTo(HttpRouteConnectivityCheckService.BUDGET_MS - headAt);
        }

        String stoppedAt = expected.path("stoppedAt").isNull() ? "-" : expected.path("stoppedAt").asText();
        String line = "[connectivity-check] tenant=" + TENANT + " user=alice route=" + ROUTE_ID
                + " outcome=" + expected.path("outcome").asText() + " stage=" + stoppedAt
                + " code=" + expected.path("code").asText() + " totalMs=" + expected.path("totalMs").asLong();
        assertThat(logs.list).as(name + " log").filteredOn(event -> event.getLevel() == Level.INFO)
                .extracting(ILoggingEvent::getFormattedMessage).containsExactly(line);
    }

    /**
     * Holds the slots a case needs taken: the route itself for {@code route-in-progress}, every
     * process slot (on other routes, by other users) for {@code server-busy}.
     */
    private static void occupy(String admission, HttpRouteConnectivityCheckService service, ScriptedProbe probe,
                               ExecutorService executor,
                               List<Future<HttpRouteConnectivityCheckService.Response>> held) throws Exception {
        List<Long> routes = switch (admission) {
            case "admitted" -> List.of();
            case "route-in-progress" -> List.of(ROUTE_ID);
            case "server-busy" -> {
                List<Long> others = new ArrayList<>();
                for (int index = 1; index <= HttpRouteConnectivityCheckService.MAX_CONCURRENT_CHECKS; index++) {
                    others.add(1000L + index);
                }
                yield others;
            }
            default -> throw new AssertionError("unknown admission " + admission);
        };
        probe.blocked = new CountDownLatch(routes.size());
        for (long route : routes) {
            probe.blocking.add("device-" + route);
            String user = "occupant-" + route;
            held.add(executor.submit(() -> service.check(() -> caller(user, true), Long.toString(route),
                    InputStream.nullInputStream())));
        }
        assertThat(probe.blocked.await(10, TimeUnit.SECONDS)).as("occupants running").isTrue();
    }

    /**
     * The vector's Retry-After where it gives one. It gives none for {@code 503 CHECK_UNAVAILABLE},
     * which every server sends with {@code Retry-After: 1} (spec 3.2: every 429 and 503 carries one).
     */
    private static String expectedRetryAfter(JsonNode expect) {
        if (expect.has("retryAfterSeconds")) {
            return expect.get("retryAfterSeconds").asText();
        }
        return HttpRouteConnectivityCheckService.UNAVAILABLE.equals(expect.path("code").asText()) ? "1" : null;
    }

    private static void assertProbe(String name, Map<String, Object> metadata, String method) {
        assertThat(new ArrayList<>(metadata.keySet())).as(name + " OPEN metadata keys").isEqualTo(METADATA_KEYS);
        assertThat(metadata.get("source")).isEqualTo("http");
        assertThat(metadata.get("phase")).isEqualTo("request");
        assertThat((String) metadata.get("requestId")).as(name + " requestId").matches("[0-9a-f]{32}");
        assertThat(metadata.get("method")).as(name + " method").isEqualTo(method);
        assertThat(metadata.get("route")).isEqualTo(ROUTE_NAME);
        assertThat(metadata.get("relativePath")).isEqualTo(PROBE_PATH);
        assertThat(metadata.get("rawQuery")).isEqualTo("");
        assertThat(metadata.get("headers")).isEqualTo(List.of("Accept:*/*", "User-Agent:specus-connectivity-check/1"));
    }

    private static List<String> fieldNames(JsonNode node) {
        List<String> names = new ArrayList<>();
        node.fieldNames().forEachRemaining(names::add);
        return names;
    }
}
