package com.theshuai.specusserver.connectivity;

import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.fasterxml.jackson.databind.JsonNode;
import com.theshuai.specusserver.connectivity.ConnectivityCheckFakes.FakeClock;
import com.theshuai.specusserver.connectivity.ConnectivityCheckFakes.FakeTargets;
import com.theshuai.specusserver.connectivity.ConnectivityCheckFakes.ScriptedProbe;
import com.theshuai.specusserver.connectivity.ConnectivityCheckRateLimiter.Admission;
import com.theshuai.specusserver.connectivity.ConnectivityCheckRateLimiter.Outcome;
import com.theshuai.specusserver.management.security.ManagementContextResolver;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.test.web.servlet.MockMvc;

import java.time.Instant;
import java.util.List;

import static com.theshuai.specusserver.connectivity.ConnectivityCheckFakes.JSON;
import static com.theshuai.specusserver.connectivity.ConnectivityCheckFakes.TENANT;
import static com.theshuai.specusserver.connectivity.ConnectivityCheckFakes.caller;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

/**
 * The shared vector's {@code rate.events}, replayed in order through one limiter with a fake
 * clock, and then through the whole endpoint, where a refusal is a 429 with Retry-After and a
 * throttled log line.
 */
class HttpRouteConnectivityCheckRateTests {
    private static final long CLOCK_ORIGIN_MS = 123_456_789L;

    @Test
    void rateEventsReplayThroughTheLimiter() throws Exception {
        JsonNode rate = ConnectivityCheckFakes.readVector().path("rate");
        assertThat(rate.path("algorithm").asText()).isEqualTo("gcra");
        assertThat(rate.path("perRoute").path("intervalMs").asLong()).isEqualTo(ConnectivityCheckRateLimiter.ROUTE_INTERVAL_MS);
        assertThat(rate.path("perRoute").path("burst").asInt()).isEqualTo(ConnectivityCheckRateLimiter.ROUTE_BURST);
        assertThat(rate.path("perUser").path("intervalMs").asLong()).isEqualTo(ConnectivityCheckRateLimiter.USER_INTERVAL_MS);
        assertThat(rate.path("perUser").path("burst").asInt()).isEqualTo(ConnectivityCheckRateLimiter.USER_BURST);
        JsonNode events = rate.path("events");
        assertThat(events.size()).isPositive();

        ConnectivityCheckRateLimiter limiter = new ConnectivityCheckRateLimiter();
        int index = 0;
        for (JsonNode event : events) {
            String label = "event " + index++ + " " + event;
            Admission admission = limiter.tryAcquire(
                    TENANT + '\n' + event.path("routeId").asLong(),
                    TENANT + '\n' + event.path("username").asText(),
                    CLOCK_ORIGIN_MS + event.path("atMs").asLong());
            if (event.path("admitted").asBoolean()) {
                assertThat(admission.outcome()).as(label).isEqualTo(Outcome.ADMITTED);
            } else {
                assertThat(admission.outcome()).as(label).isEqualTo(Outcome.LIMITED);
                assertThat(event.path("code").asText()).isEqualTo(HttpRouteConnectivityCheckService.RATE_LIMITED);
                assertThat(admission.limitedBy()).as(label + " limitedBy").isEqualTo(event.path("limitedBy").asText());
                assertThat(admission.retryAfterSeconds()).as(label + " Retry-After")
                        .isEqualTo(event.path("retryAfterSeconds").asLong());
            }
        }
    }

    @Test
    void rateEventsReplayThroughTheEndpoint() throws Exception {
        JsonNode events = ConnectivityCheckFakes.readVector().path("rate").path("events");
        FakeClock clock = new FakeClock(CLOCK_ORIGIN_MS, Instant.parse("2026-10-06T08:00:00Z"));
        ScriptedProbe probe = new ScriptedProbe(clock, CLOCK_ORIGIN_MS);
        // An offline device: every admitted check runs, quickly, and still counts.
        probe.controlOnline = false;
        HttpRouteConnectivityCheckService service = new HttpRouteConnectivityCheckService(new FakeTargets(), probe, clock);
        ManagementContextResolver resolver = mock(ManagementContextResolver.class);
        MockMvc mvc = ConnectivityCheckFakes.endpoint(service, resolver);

        Logger logger = (Logger) LoggerFactory.getLogger(HttpRouteConnectivityCheckService.class);
        ListAppender<ILoggingEvent> logs = new ListAppender<>();
        logs.start();
        logger.addAppender(logs);
        try {
            int index = 0;
            for (JsonNode event : events) {
                String label = "event " + index++ + " " + event;
                String username = event.path("username").asText();
                when(resolver.resolve(any())).thenReturn(caller(username, "admin".equals(username)));
                clock.set(CLOCK_ORIGIN_MS + event.path("atMs").asLong());

                MockHttpServletResponse response = mvc.perform(
                                post("/api/admin/http-routes/" + event.path("routeId").asLong() + "/connectivity-check"))
                        .andReturn().getResponse();

                assertThat(response.getHeader("Cache-Control")).as(label).isEqualTo("private, no-store");
                JsonNode body = JSON.readTree(response.getContentAsByteArray());
                if (event.path("admitted").asBoolean()) {
                    assertThat(response.getStatus()).as(label).isEqualTo(200);
                    assertThat(body.path("code").asText()).as(label).isEqualTo("DEVICE_OFFLINE");
                } else {
                    assertThat(response.getStatus()).as(label).isEqualTo(event.path("httpStatus").asInt());
                    assertThat(body).as(label).isEqualTo(JSON.createObjectNode().put("code", event.path("code").asText()));
                    assertThat(response.getHeader("Retry-After")).as(label)
                            .isEqualTo(event.path("retryAfterSeconds").asText());
                }
            }
        } finally {
            logger.detachAppender(logs);
        }

        // At most one refusal line per caller per minute: alice's later refusals stay quiet.
        assertThat(logs.list).extracting(ILoggingEvent::getFormattedMessage)
                .filteredOn(line -> line.contains(" refused "))
                .containsExactly(
                        "[connectivity-check] tenant=t1 user=alice route=1 refused code=CHECK_RATE_LIMITED retryAfter=10",
                        "[connectivity-check] tenant=t1 user=admin route=1 refused code=CHECK_RATE_LIMITED retryAfter=10");
    }

    /** A refused check takes nothing: the next check of another route by another user still runs. */
    @Test
    void aRefusalConsumesNeitherKey() {
        ConnectivityCheckRateLimiter limiter = new ConnectivityCheckRateLimiter();
        assertThat(limiter.tryAcquire("r1", "u1", 0).outcome()).isEqualTo(Outcome.ADMITTED);
        // Route 1 is limited; u2's burst must not shrink for it.
        for (int attempt = 0; attempt < 20; attempt++) {
            assertThat(limiter.tryAcquire("r1", "u2", 1 + attempt).outcome()).isEqualTo(Outcome.LIMITED);
        }
        for (int route = 2; route <= ConnectivityCheckRateLimiter.USER_BURST + 1; route++) {
            assertThat(limiter.tryAcquire("r" + route, "u2", 100).outcome()).as("route " + route)
                    .isEqualTo(Outcome.ADMITTED);
        }
        assertThat(limiter.tryAcquire("r99", "u2", 100).outcome()).isEqualTo(Outcome.LIMITED);
    }

    /**
     * 10 000 keys per table: a new key finds no room while every entry is live, and nothing is
     * evicted to make some; entries whose TAT has passed make room.
     */
    @Test
    void aFullKeyTableRefusesNewKeysWithoutEvictingLiveOnes() {
        ConnectivityCheckRateLimiter limiter = new ConnectivityCheckRateLimiter();
        for (int key = 0; key < ConnectivityCheckRateLimiter.MAX_KEYS; key++) {
            assertThat(limiter.tryAcquire("route-" + key, "user-" + key, 0).outcome()).isEqualTo(Outcome.ADMITTED);
        }
        assertThat(limiter.tryAcquire("route-new", "user-new", 1).outcome()).isEqualTo(Outcome.FULL);
        // Nothing was evicted: route-0 is still limited.
        assertThat(limiter.tryAcquire("route-0", "user-0", 1).outcome()).isEqualTo(Outcome.LIMITED);
        // The route entries are dead at 10 s, the user entries are not until 30 s.
        assertThat(limiter.tryAcquire("route-new", "user-new", 10_000).outcome()).isEqualTo(Outcome.FULL);
        assertThat(limiter.tryAcquire("route-new", "user-new", 30_000).outcome()).isEqualTo(Outcome.ADMITTED);
    }

    /** The endpoint answers a full table as busy, with Retry-After, and runs nothing. */
    @Test
    void aFullKeyTableIsCheckBusy() throws Exception {
        FakeClock clock = new FakeClock(CLOCK_ORIGIN_MS, Instant.parse("2026-10-06T08:00:00Z"));
        ScriptedProbe probe = new ScriptedProbe(clock, CLOCK_ORIGIN_MS);
        probe.controlOnline = false;
        HttpRouteConnectivityCheckService service = new HttpRouteConnectivityCheckService(
                new FakeTargets(), probe, clock, new ConnectivityCheckRateLimiter(2));
        ManagementContextResolver resolver = mock(ManagementContextResolver.class);
        MockMvc mvc = ConnectivityCheckFakes.endpoint(service, resolver);

        for (String user : List.of("u1", "u2")) {
            when(resolver.resolve(any())).thenReturn(caller(user, true));
            int route = user.equals("u1") ? 1 : 2;
            assertThat(mvc.perform(post("/api/admin/http-routes/" + route + "/connectivity-check"))
                    .andReturn().getResponse().getStatus()).isEqualTo(200);
        }
        when(resolver.resolve(any())).thenReturn(caller("u3", true));
        MockHttpServletResponse busy = mvc.perform(post("/api/admin/http-routes/3/connectivity-check"))
                .andReturn().getResponse();

        assertThat(busy.getStatus()).isEqualTo(503);
        assertThat(JSON.readTree(busy.getContentAsByteArray()))
                .isEqualTo(JSON.createObjectNode().put("code", HttpRouteConnectivityCheckService.BUSY));
        assertThat(busy.getHeader("Retry-After")).isEqualTo("1");
        assertThat(busy.getHeader("Cache-Control")).isEqualTo("private, no-store");
    }
}
