package com.theshuai.specusserver.connectivity;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.theshuai.specusserver.management.controller.HttpRouteResource;
import com.theshuai.specusserver.management.security.ManagementContext;
import com.theshuai.specusserver.management.security.ManagementContextResolver;
import com.theshuai.specusserver.management.service.HttpRouteService;
import com.theshuai.specusserver.management.service.HttpShareService;
import com.theshuai.specusserver.productmetrics.ProductMetricsService;
import com.theshuai.specusserver.management.tenant.TenantContext;
import org.springframework.dao.DataAccessResourceFailureException;
import org.springframework.security.web.method.annotation.AuthenticationPrincipalArgumentResolver;
import org.springframework.test.web.servlet.MockMvc;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Deque;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

import static org.mockito.Mockito.mock;
import static org.springframework.test.web.servlet.setup.MockMvcBuilders.standaloneSetup;

/**
 * Stand-ins for what a connectivity check reads around itself: the clocks, the route records and
 * the device. The check service and the endpoint under test are the real ones.
 */
final class ConnectivityCheckFakes {
    static final ObjectMapper JSON = new ObjectMapper();
    static final String TENANT = "t1";
    static final String ROUTE_NAME = "api";

    private ConnectivityCheckFakes() {
    }

    static ManagementContext caller(String username, boolean admin) {
        return new ManagementContext(new TenantContext(TENANT), username, admin);
    }

    /** The endpoint as the management API serves it, minus Spring Security. */
    static MockMvc endpoint(HttpRouteConnectivityCheckService service, ManagementContextResolver resolver) {
        return standaloneSetup(new HttpRouteResource(mock(HttpRouteService.class), mock(HttpShareService.class),
                        resolver, service, mock(ProductMetricsService.class)))
                .setCustomArgumentResolvers(new AuthenticationPrincipalArgumentResolver())
                .build();
    }

    static JsonNode readVector() throws IOException {
        Path current = Path.of("").toAbsolutePath();
        for (int depth = 0; current != null && depth < 8; depth++, current = current.getParent()) {
            Path candidate = current.resolve("protocol/test-vectors/service-connectivity-check-v1.json");
            if (Files.isRegularFile(candidate)) {
                return JSON.readTree(Files.readString(candidate));
            }
        }
        throw new IOException("protocol/test-vectors/service-connectivity-check-v1.json not found");
    }

    /** Both clocks under the test's hand; the monotonic one moves only when told to. */
    static final class FakeClock implements ConnectivityCheckClock {
        private final AtomicLong millis;
        private final Instant wall;

        FakeClock(long startMillis, Instant wall) {
            this.millis = new AtomicLong(startMillis);
            this.wall = wall;
        }

        @Override
        public long monotonicMillis() {
            return millis.get();
        }

        @Override
        public Instant now() {
            return wall;
        }

        void set(long value) {
            millis.set(value);
        }

        void advance(long delta) {
            millis.addAndGet(delta);
        }
    }

    /**
     * Every route is visible and called {@value #ROUTE_NAME}; its client is {@link #clientName}, or
     * {@code device-<routeId>} when that is not set.
     */
    static final class FakeTargets implements ConnectivityCheckTargets {
        volatile String clientName;
        volatile boolean readable = true;
        volatile boolean visible = true;
        volatile boolean routeEnabled = true;
        volatile boolean clientEnabled = true;
        volatile boolean targetValid = true;

        @Override
        public Optional<Target> findVisible(ManagementContext caller, long routeId) {
            if (!readable) {
                throw new DataAccessResourceFailureException("database unavailable");
            }
            if (!visible) {
                return Optional.empty();
            }
            return Optional.of(new Target(routeId, caller.tenant().tenantId(), ROUTE_NAME,
                    clientName == null ? "device-" + routeId : clientName, routeEnabled, clientEnabled, targetValid));
        }
    }

    /**
     * A device answering from a script: each answer moves the monotonic clock to the check start
     * plus its {@code atMs}, and an answer of kind {@code none} moves it by the time the check gave.
     * Clients listed in {@link #blocking} instead hold their probe until {@link #release} opens.
     */
    static final class ScriptedProbe implements ConnectivityProbe {
        final FakeClock clock;
        final long checkStart;
        volatile boolean controlOnline = true;
        volatile boolean dataOnline = true;
        volatile int capability;
        final Deque<JsonNode> answers = new ArrayDeque<>();
        final List<Map<String, Object>> sent = Collections.synchronizedList(new ArrayList<>());
        final List<Long> timeouts = Collections.synchronizedList(new ArrayList<>());
        final Set<String> blocking = ConcurrentHashMap.newKeySet();
        volatile CountDownLatch blocked = new CountDownLatch(0);
        final CountDownLatch release = new CountDownLatch(1);

        ScriptedProbe(FakeClock clock, long checkStart) {
            this.clock = clock;
            this.checkStart = checkStart;
        }

        @Override
        public DeviceLink link(String clientName) {
            if (blocking.contains(clientName)) {
                return new Online(new HoldingChannel());
            }
            if (!controlOnline) {
                return new Offline();
            }
            if (!dataOnline) {
                return new DataChannelDown();
            }
            return new Online(new ScriptedChannel());
        }

        private final class ScriptedChannel implements ProbeChannel {
            @Override
            public int httpRouteCapability() {
                return capability;
            }

            @Override
            public Answer exchange(Map<String, Object> metadata, long timeoutMillis) {
                sent.add(metadata);
                timeouts.add(timeoutMillis);
                JsonNode answer = answers.removeFirst();
                String kind = answer.path("kind").asText();
                if (kind.equals("none")) {
                    clock.advance(timeoutMillis);
                    return new NoAnswer();
                }
                clock.set(checkStart + answer.path("atMs").asLong());
                return switch (kind) {
                    case "response" -> new Head(answer.path("status").asInt());
                    case "rst" -> new Reset(answer.hasNonNull("failure") ? answer.get("failure").asText() : null);
                    case "link-lost" -> new LinkLost();
                    case "open-failed" -> new OpenFailed("stream-limit".equals(answer.path("cause").asText()));
                    default -> throw new AssertionError("unknown answer kind " + kind);
                };
            }
        }

        private final class HoldingChannel implements ProbeChannel {
            @Override
            public int httpRouteCapability() {
                return 1;
            }

            @Override
            public Answer exchange(Map<String, Object> metadata, long timeoutMillis) {
                blocked.countDown();
                try {
                    if (!release.await(10, TimeUnit.SECONDS)) {
                        throw new AssertionError("held probe was never released");
                    }
                } catch (InterruptedException interrupted) {
                    Thread.currentThread().interrupt();
                    throw new AssertionError(interrupted);
                }
                return new Head(200);
            }
        }
    }
}
