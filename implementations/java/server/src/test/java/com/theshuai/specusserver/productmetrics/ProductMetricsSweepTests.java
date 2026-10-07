package com.theshuai.specusserver.productmetrics;

import com.theshuai.specusserver.management.security.ManagementContext;
import com.theshuai.specusserver.productmetrics.ProductMetricsStore.OnboardingCount;
import com.theshuai.specusserver.productmetrics.ProductMetricsStore.ProgressRow;
import com.theshuai.specusserver.productmetrics.ProductMetricsStore.SwitchRow;
import com.theshuai.specusserver.productmetrics.ProductMetricsStore.TransferCount;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Section 9: sweep steps 1 and 4 decide on the switch when they delete, not on the switches the
 * sweep read first. A tenant that is off and purged in that snapshot but switched back on before
 * the deletes keeps the progress and counts it collected since.
 */
class ProductMetricsSweepTests extends ProductMetricsHttpTestSupport {
    private static final String TENANT = "t1";

    private static byte[] utf8(String text) {
        return text.getBytes(StandardCharsets.UTF_8);
    }

    @Test
    void aTenantSwitchedBackOnBeforeTheDeletesKeepsWhatItCollects() {
        at(Instant.parse("2026-09-01T08:00:00Z").toEpochMilli());
        ManagementContext admin = tenantAdmin(TENANT);
        byte[] on = utf8("{\"enabled\":true,\"disclosureVersion\":1}");
        assertThat(service.putSettings(admin, on).status()).isEqualTo(200);
        assertThat(service.putSettings(admin, utf8("{\"enabled\":false}")).status()).isEqualTo(200);
        assertThat(service.purge(admin).status()).isEqualTo(200);
        List<SwitchRow> switches = store.switches();
        assertThat(switches).singleElement().satisfies(row -> {
            assertThat(row.enabled()).isFalse();
            assertThat(row.purgedAt()).isNotNull();
        });

        // Between the snapshot and the deletes: switched back on, then a transfer, a started account
        // and a completed one.
        assertThat(service.putSettings(admin, on).status()).isEqualTo(200);
        String event = "{\"mode\":\"device\",\"path\":\"direct\",\"sizeBucket\":\"lt1m\",\"attempt\":\"first\","
                + "\"outcome\":\"success\"}";
        assertThat(service.ingest(admin, utf8("{\"schemaVersion\":1,\"events\":[" + event + "]}")).status())
                .isEqualTo(200);
        assertThat(service.milestone(TENANT, "bob", ProductMetricsModel.STEP_ACCOUNT_CREATED)).isEqualTo("started");
        assertThat(service.milestone(TENANT, "carol", ProductMetricsModel.STEP_ACCOUNT_CREATED)).isEqualTo("started");
        assertThat(service.milestone(TENANT, "carol", ProductMetricsModel.STEP_SERVICE_PUBLISHED))
                .isEqualTo("completed");

        service.sweep(switches);
        assertThat(store.progressRows(TENANT)).extracting(ProgressRow::username).containsExactly("bob");
        assertThat(store.onboardingCounts(TENANT, null, null)).extracting(OnboardingCount::users)
                .containsExactly(1L);
        assertThat(store.transferCounts(TENANT, null, null)).extracting(TransferCount::count).containsExactly(1L);

        // When the deployment does not allow metrics no tenant collects: step 1 drops the row although
        // the tenant's switch is on.
        properties.setAllowed(false);
        service.sweep();
        assertThat(store.progressRows(TENANT)).isEmpty();
    }
}
