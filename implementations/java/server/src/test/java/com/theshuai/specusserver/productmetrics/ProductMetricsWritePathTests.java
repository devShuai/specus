package com.theshuai.specusserver.productmetrics;

import com.fasterxml.jackson.databind.JsonNode;
import com.theshuai.specusserver.management.model.ClientAccount;
import com.theshuai.specusserver.management.repository.ClientAccountRepository;
import com.theshuai.specusserver.management.repository.ClientCredentialRepository;
import com.theshuai.specusserver.management.repository.HttpRouteMappingRepository;
import com.theshuai.specusserver.productmetrics.ProductMetricsStore.OnboardingCount;
import com.theshuai.specusserver.productmetrics.ProductMetricsStore.ProgressRow;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import java.net.http.HttpResponse;
import java.time.Instant;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The real write paths fire the onboarding milestones: an admin creating the account, its password
 * sign-in, its first credential and the first HTTP route on its client. Deleting another account
 * drops its progress row and switching off drops the rest. A member's transfer outcomes are counted
 * and only the tenant's ADMIN reads the summary.
 */
class ProductMetricsWritePathTests extends ProductMetricsHttpTestSupport {
    private static final String TENANT = "default";

    @Autowired ClientAccountRepository clientAccountRepository;
    @Autowired ClientCredentialRepository clientCredentialRepository;
    @Autowired HttpRouteMappingRepository httpRouteMappingRepository;

    @AfterEach
    void removeClients() {
        httpRouteMappingRepository.deleteAllInBatch();
        clientCredentialRepository.deleteAllInBatch();
        clientAccountRepository.deleteAllInBatch();
    }

    private Optional<ProgressRow> progress(String username) {
        return store.findProgress(TENANT, username);
    }

    private String login(String username) {
        HttpResponse<String> response = send("POST", "/auth/login", null,
                "{\"username\":\"" + username + "\",\"password\":\"" + PASSWORD + "\"}");
        assertThat(response.statusCode()).as(response.body()).isEqualTo(200);
        return json(response).get("accessToken").textValue();
    }

    @Test
    void writePathsRecordTheOnboardingMilestones() {
        at(Instant.parse("2026-09-01T08:00:00Z").toEpochMilli());
        createUser(TENANT, "pm-admin", true);
        String admin = token(TENANT, "pm-admin");
        HttpResponse<String> early = send("POST", "/api/admin/users", admin,
                "{\"username\":\"pm-early\",\"password\":\"" + PASSWORD + "\",\"role\":\"USER\"}");
        assertThat(early.statusCode()).isEqualTo(201);
        assertThat(progress("pm-early")).as("created before opt-in").isEmpty();

        HttpResponse<String> enabled = send("PUT", "/api/admin/product-metrics/settings", admin,
                "{\"enabled\":true,\"disclosureVersion\":1}");
        assertThat(enabled.statusCode()).as(enabled.body()).isEqualTo(200);
        assertThat(json(enabled).get("updatedBy").textValue()).isEqualTo("pm-admin");

        HttpResponse<String> created = send("POST", "/api/admin/users", admin,
                "{\"username\":\"pm-alice\",\"password\":\"" + PASSWORD + "\",\"role\":\"USER\"}");
        assertThat(created.statusCode()).isEqualTo(201);
        assertThat(progress("pm-alice")).hasValueSatisfying(row -> assertThat(row.signedInAt()).isNull());

        at(Instant.parse("2026-09-01T08:01:00Z").toEpochMilli());
        String alice = login("pm-alice");
        assertThat(progress("pm-alice")).hasValueSatisfying(row -> assertThat(row.signedInAt()).isNotNull());

        HttpResponse<String> credential = send("POST", "/api/admin/client-credentials", alice, "{}");
        assertThat(credential.statusCode()).as(credential.body()).isEqualTo(201);
        assertThat(progress("pm-alice"))
                .hasValueSatisfying(row -> assertThat(row.credentialCreatedAt()).isNotNull());

        ClientAccount client = new ClientAccount();
        client.setId(7_700_001L);
        client.setTenantId(TENANT);
        client.setOwnerUsername("pm-alice");
        client.setClientName("pm-client");
        client.setPasswordHash("0".repeat(64));
        client.setCreatedAt(Instant.now().toString());
        client.setUpdatedAt(Instant.now().toString());
        clientAccountRepository.saveAndFlush(client);
        at(Instant.parse("2026-09-01T08:05:00Z").toEpochMilli());
        assertThat(service.milestone(TENANT, "pm-alice", ProductMetricsModel.STEP_CLIENT_ONLINE)).isEqualTo("recorded");

        at(Instant.parse("2026-09-01T08:20:00Z").toEpochMilli());
        HttpResponse<String> route = send("POST", "/api/admin/clients/7700001/http-routes", alice,
                "{\"route\":\"metrics\",\"targetBaseUrl\":\"http://127.0.0.1:18080\",\"enabled\":true}");
        assertThat(route.statusCode()).as(route.body()).isEqualTo(201);
        assertThat(progress("pm-alice")).as("completion closes the row").isEmpty();
        assertThat(store.onboardingCounts(TENANT, null, null)).containsExactly(
                new OnboardingCount(TENANT, "2026-09-01", "service_published", "10m-30m", 1));

        HttpResponse<String> bob = send("POST", "/api/admin/users", admin,
                "{\"username\":\"pm-bob\",\"password\":\"" + PASSWORD + "\",\"role\":\"USER\"}");
        assertThat(bob.statusCode()).isEqualTo(201);
        assertThat(progress("pm-bob")).isPresent();
        assertThat(send("DELETE", "/api/admin/users/pm-bob", admin, (byte[]) null).statusCode()).isEqualTo(204);
        assertThat(progress("pm-bob")).as("a deleted account keeps no progress").isEmpty();

        String event = "{\"mode\":\"device\",\"path\":\"turn\",\"sizeBucket\":\"1m-16m\","
                + "\"attempt\":\"retry_after_failure\",\"outcome\":\"success\"}";
        HttpResponse<String> ingest = send("POST", "/api/admin/product-metrics/transfer-outcomes", alice,
                "{\"schemaVersion\":1,\"events\":[" + event + "]}");
        assertThat(ingest.statusCode()).isEqualTo(200);
        assertThat(json(ingest).get("accepted").asInt()).isEqualTo(1);
        HttpResponse<String> member = send("GET", "/api/admin/product-metrics/settings", alice, (byte[]) null);
        assertThat(json(member).has("updatedBy")).as("a member never sees updatedBy").isFalse();
        assertThat(send("GET", "/api/admin/product-metrics/summary", alice, (byte[]) null).statusCode())
                .isEqualTo(403);
        HttpResponse<String> summary = send("GET", "/api/admin/product-metrics/summary", admin, (byte[]) null);
        assertThat(summary.statusCode()).isEqualTo(200);
        JsonNode body = json(summary);
        assertThat(body.get("onboarding").get("completed").asInt()).isEqualTo(1);
        assertThat(body.get("onboarding").get("medianDurationBucket").textValue()).isEqualTo("10m-30m");
        assertThat(body.get("transfers").get("byAttempt").get(1).get("successRateBp").asInt()).isEqualTo(10000);

        HttpResponse<String> carol = send("POST", "/api/admin/users", admin,
                "{\"username\":\"pm-carol\",\"password\":\"" + PASSWORD + "\",\"role\":\"USER\"}");
        assertThat(carol.statusCode()).isEqualTo(201);
        assertThat(send("PUT", "/api/admin/product-metrics/settings", admin, "{\"enabled\":false}").statusCode())
                .isEqualTo(200);
        assertThat(store.progressRows(TENANT)).as("switching off drops progress").isEmpty();
        HttpResponse<String> stopped = send("POST", "/api/admin/product-metrics/transfer-outcomes", alice,
                "{\"schemaVersion\":1,\"events\":[" + event + "]}");
        assertThat(json(stopped).get("collecting").booleanValue()).isFalse();
    }

    @Test
    void theDeploymentSwitchKeepsEveryTenantOff() {
        at(Instant.parse("2026-09-01T08:00:00Z").toEpochMilli());
        properties.setAllowed(false);
        createUser(TENANT, "pm-admin", true);
        String admin = token(TENANT, "pm-admin");
        HttpResponse<String> enable = send("PUT", "/api/admin/product-metrics/settings", admin,
                "{\"enabled\":true,\"disclosureVersion\":1}");
        assertThat(enable.statusCode()).isEqualTo(409);
        assertThat(json(enable).get("code").textValue()).isEqualTo("PRODUCT_METRICS_NOT_ALLOWED");
        assertThat(json(send("GET", "/api/admin/product-metrics/settings", admin, (byte[]) null))
                .get("enabled").booleanValue()).isFalse();
        HttpResponse<String> oversize = send("POST", "/api/admin/product-metrics/transfer-outcomes", admin,
                " ".repeat(4097));
        assertThat(oversize.statusCode()).isEqualTo(413);
        assertThat(List.of(store.switches().size())).containsExactly(0);
    }
}
