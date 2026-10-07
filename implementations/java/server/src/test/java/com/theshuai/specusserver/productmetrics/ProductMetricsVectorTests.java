package com.theshuai.specusserver.productmetrics;

import com.fasterxml.jackson.databind.JsonNode;
import com.theshuai.specusserver.productmetrics.ProductMetricsStore.OnboardingCount;
import com.theshuai.specusserver.productmetrics.ProductMetricsStore.ProgressRow;
import com.theshuai.specusserver.productmetrics.ProductMetricsStore.SwitchRow;
import com.theshuai.specusserver.productmetrics.ProductMetricsStore.TransferCount;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.net.URLEncoder;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.StringJoiner;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Replays protocol/test-vectors/product-metrics-v1.json: every bucket and rate case, the 44 ingest
 * validation bodies and the five scenarios, through the real HTTP stack (security filter chain,
 * token decoding, context resolution, the resource, the service and the SQLite store) with the
 * product metrics clock pinned at each op's time. Milestone, user-deletion and sweep ops call the
 * server-internal hooks directly, as the vector prescribes.
 */
class ProductMetricsVectorTests extends ProductMetricsHttpTestSupport {
    private static final String SETTINGS = "/api/admin/product-metrics/settings";
    private static final String DATA = "/api/admin/product-metrics/data";
    private static final String INGEST = "/api/admin/product-metrics/transfer-outcomes";
    private static final String SUMMARY = "/api/admin/product-metrics/summary";

    static JsonNode vector() throws IOException {
        Path current = Path.of("").toAbsolutePath();
        for (int depth = 0; current != null && depth < 8; depth++, current = current.getParent()) {
            Path candidate = current.resolve("protocol/test-vectors/product-metrics-v1.json");
            if (Files.exists(candidate)) {
                return JSON.readTree(Files.readAllBytes(candidate));
            }
        }
        throw new IllegalStateException("cannot locate protocol/test-vectors/product-metrics-v1.json");
    }

    @Test
    void bucketsAndRatesMatchTheVector() throws IOException {
        JsonNode vector = vector();
        for (JsonNode item : vector.get("sizeBuckets")) {
            Optional<String> bucket = ProductMetricsModel.sizeBucket(item.get("sizeBytes").asLong());
            assertThat(bucket.orElse(null)).as("size %s", item).isEqualTo(item.get("bucket").textValue());
        }
        for (JsonNode item : vector.get("durationBuckets")) {
            Optional<String> bucket = ProductMetricsModel.durationBucket(item.get("seconds").asLong());
            assertThat(bucket.orElse(null)).as("duration %s", item).isEqualTo(item.get("bucket").textValue());
        }
        for (JsonNode item : vector.get("rates")) {
            Long rate = ProductMetricsModel.rateBp(item.get("numerator").asLong(), item.get("denominator").asLong());
            JsonNode expected = item.get("rateBp");
            assertThat(rate).as("rate %s", item).isEqualTo(expected.isNull() ? null : expected.asLong());
        }
        assertThat(vector.get("sizeBuckets").size() + vector.get("durationBuckets").size()
                + vector.get("rates").size()).isPositive();
    }

    @Test
    void ingestValidationCasesMatchTheVector() throws IOException {
        JsonNode validation = vector().get("ingestValidation");
        JsonNode actor = validation.get("context").get("actor");
        String tenant = actor.get("tenantId").textValue();
        String username = actor.get("username").textValue();
        createUser(tenant, username, "ADMIN".equals(actor.get("role").textValue()));
        long at = Instant.parse(validation.get("context").get("at").textValue()).toEpochMilli();
        at(at);
        store.saveSwitch(new SwitchRow(tenant, true, "root", at, null));
        int replayed = 0;
        for (JsonNode item : validation.get("cases")) {
            String name = item.get("name").textValue();
            byte[] body = item.get("bodyText").textValue().getBytes(StandardCharsets.UTF_8);
            assertThat(body.length).as(name).isEqualTo(item.get("bodyBytes").asInt());
            rateLimiter.clear();
            long before = transferTotal();
            HttpResponse<String> response = send("POST", INGEST, token(tenant, username), body);
            JsonNode expect = item.get("expect");
            compare(name, expect, response);
            long accepted = expect.get("status").asInt() == 200 ? expect.get("body").get("accepted").asLong() : 0;
            assertThat(transferTotal() - before).as(name + " counted events").isEqualTo(accepted);
            replayed++;
        }
        assertThat(replayed).isEqualTo(validation.get("cases").size()).isEqualTo(44);
    }

    @Test
    void scenariosMatchTheVector() throws IOException {
        int scenarios = 0;
        int ops = 0;
        for (JsonNode scenario : vector().get("scenarios")) {
            freshState();
            ops += replay(scenario);
            scenarios++;
        }
        assertThat(scenarios).isEqualTo(5);
        assertThat(ops).isEqualTo(112);
    }

    private int replay(JsonNode scenario) {
        String name = scenario.get("name").textValue();
        JsonNode limits = scenario.get("limits");
        limits(limits.get("perUserEventsPerMinute").asInt(), limits.get("perTenantEventsPerMinute").asInt());
        Map<String, String> actors = new HashMap<>();
        for (JsonNode op : scenario.get("ops")) {
            JsonNode actor = op.get("actor");
            if (actor != null && !actor.isNull() && actors.putIfAbsent(actor.get("username").textValue(),
                    actor.get("tenantId").textValue() + "/" + actor.get("role").textValue()) == null) {
                createUser(actor.get("tenantId").textValue(), actor.get("username").textValue(),
                        "ADMIN".equals(actor.get("role").textValue()));
            }
        }
        load(scenario.get("initialState"));
        int index = 0;
        for (JsonNode op : scenario.get("ops")) {
            String label = name + " op " + index++ + " (" + op.get("op").textValue() + " at " + op.get("at").textValue()
                    + ")";
            at(Instant.parse(op.get("at").textValue()).toEpochMilli());
            JsonNode expect = op.get("expect");
            switch (op.get("op").textValue()) {
                case "milestone" -> assertThat(service.milestone(op.get("tenantId").textValue(),
                        op.get("username").textValue(), op.get("step").textValue()))
                        .as(label).isEqualTo(expect.get("effect").textValue());
                case "userDeleted" -> assertThat(service.userDeleted(op.get("tenantId").textValue(),
                        op.get("username").textValue())).as(label).isEqualTo(expect.get("effect").textValue());
                case "sweep" -> service.sweep();
                case "checkpoint" -> compareState(label, expect.get("state"));
                case "getSettings" -> compare(label, expect, send("GET", SETTINGS, tokenOf(op), (byte[]) null));
                case "putSettings" -> compare(label, expect, send("PUT", SETTINGS, tokenOf(op),
                        op.get("body").toString()));
                case "purge" -> compare(label, expect, send("DELETE", DATA, tokenOf(op), (byte[]) null));
                case "ingest" -> compare(label, expect, send("POST", INGEST, tokenOf(op),
                        op.get("bodyText").textValue()));
                case "summary" -> compare(label, expect, send("GET", SUMMARY + query(op.get("query")), tokenOf(op),
                        (byte[]) null));
                default -> throw new AssertionError(label + ": unknown op");
            }
        }
        return index;
    }

    private String tokenOf(JsonNode op) {
        JsonNode actor = op.get("actor");
        if (actor == null || actor.isNull()) {
            return null;
        }
        return token(actor.get("tenantId").textValue(), actor.get("username").textValue());
    }

    private static String query(JsonNode query) {
        if (query == null || query.isEmpty()) {
            return "";
        }
        StringJoiner joiner = new StringJoiner("&", "?", "");
        for (Iterator<Map.Entry<String, JsonNode>> fields = query.fields(); fields.hasNext(); ) {
            Map.Entry<String, JsonNode> field = fields.next();
            joiner.add(field.getKey() + "=" + URLEncoder.encode(field.getValue().textValue(), StandardCharsets.UTF_8));
        }
        return joiner.toString();
    }

    private void compare(String label, JsonNode expect, HttpResponse<String> response) {
        assertThat(response.statusCode()).as(label + ": " + response.body()).isEqualTo(expect.get("status").asInt());
        if (response.statusCode() != 401) {
            assertThat(response.headers().firstValue("Cache-Control")).as(label).hasValue("private, no-store");
        }
        JsonNode body = expect.get("body");
        if (body != null) {
            assertThat(json(response)).as(label).isEqualTo(body);
        }
    }

    // -- store contents -----------------------------------------------------------------------------

    private static Long millis(JsonNode value) {
        return value == null || value.isNull() ? null : Instant.parse(value.textValue()).toEpochMilli();
    }

    private static String text(JsonNode value) {
        return value == null || value.isNull() ? null : value.textValue();
    }

    private void load(JsonNode state) {
        for (JsonNode row : state.path("switches")) {
            store.saveSwitch(new SwitchRow(row.get("tenantId").textValue(), row.get("enabled").booleanValue(),
                    text(row.get("updatedBy")), millis(row.get("updatedAt")), millis(row.get("purgedAt"))));
        }
        for (JsonNode row : state.path("progress")) {
            store.insertProgressIfAbsent(progress(row));
        }
        for (JsonNode row : state.path("onboardingDaily")) {
            store.addOnboardingCount(onboarding(row));
        }
        for (JsonNode row : state.path("transferDaily")) {
            store.addTransferCount(transfer(row));
        }
    }

    private static ProgressRow progress(JsonNode row) {
        return new ProgressRow(row.get("tenantId").textValue(), row.get("username").textValue(),
                millis(row.get("startedAt")), millis(row.get("signedInAt")), millis(row.get("credentialCreatedAt")),
                millis(row.get("clientOnlineAt")));
    }

    private static OnboardingCount onboarding(JsonNode row) {
        return new OnboardingCount(row.get("tenantId").textValue(), row.get("cohortDay").textValue(),
                row.get("reachedStep").textValue(), row.get("durationBucket").textValue(), row.get("users").asLong());
    }

    private static TransferCount transfer(JsonNode row) {
        return new TransferCount(row.get("tenantId").textValue(), row.get("day").textValue(),
                row.get("mode").textValue(), row.get("path").textValue(), row.get("sizeBucket").textValue(),
                row.get("attempt").textValue(), row.get("outcome").textValue(), row.get("count").asLong());
    }

    private long transferTotal() {
        return store.transferCounts(null, null, null).stream().mapToLong(TransferCount::count).sum();
    }

    /** Compares the four tables with a checkpoint; times compare as instants. */
    private void compareState(String label, JsonNode state) {
        List<SwitchRow> wantSwitches = new ArrayList<>();
        for (JsonNode row : state.get("switches")) {
            wantSwitches.add(new SwitchRow(row.get("tenantId").textValue(), row.get("enabled").booleanValue(),
                    text(row.get("updatedBy")), millis(row.get("updatedAt")), millis(row.get("purgedAt"))));
        }
        List<ProgressRow> wantProgress = new ArrayList<>();
        state.get("progress").forEach(row -> wantProgress.add(progress(row)));
        List<OnboardingCount> wantOnboarding = new ArrayList<>();
        state.get("onboardingDaily").forEach(row -> wantOnboarding.add(onboarding(row)));
        List<TransferCount> wantTransfers = new ArrayList<>();
        state.get("transferDaily").forEach(row -> wantTransfers.add(transfer(row)));

        assertThat(store.switches()).as(label + " product_metrics_switch")
                .containsExactlyInAnyOrderElementsOf(wantSwitches);
        assertThat(store.progressRows(null)).as(label + " product_metrics_onboarding_progress")
                .containsExactlyInAnyOrderElementsOf(wantProgress);
        assertThat(store.onboardingCounts(null, null, null)).as(label + " product_metrics_onboarding_daily")
                .containsExactlyInAnyOrderElementsOf(wantOnboarding);
        assertThat(store.transferCounts(null, null, null)).as(label + " product_metrics_transfer_daily")
                .containsExactlyInAnyOrderElementsOf(wantTransfers);
    }
}
