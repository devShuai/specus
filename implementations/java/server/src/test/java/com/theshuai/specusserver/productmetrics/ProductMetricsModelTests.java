package com.theshuai.specusserver.productmetrics;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/** Cases beyond the shared vector: duplicated keys, non-integer spellings of 1, trailing content. */
class ProductMetricsModelTests {
    private static final String EVENT =
            "{\"mode\":\"device\",\"path\":\"direct\",\"sizeBucket\":\"lt1m\",\"attempt\":\"first\",\"outcome\":\"success\"}";

    private static byte[] bytes(String text) {
        return text.getBytes(StandardCharsets.UTF_8);
    }

    @Test
    void ingestRefusesWhatTheClosedSchemaDoesNotAllow() {
        for (String body : List.of(
                "{\"schemaVersion\":1,\"schemaVersion\":1,\"events\":[" + EVENT + "]}",
                "{\"schemaVersion\":1,\"events\":[{\"mode\":\"device\",\"mode\":\"device\",\"path\":\"direct\","
                        + "\"sizeBucket\":\"lt1m\",\"attempt\":\"first\",\"outcome\":\"success\"}]}",
                "{\"schemaVersion\":1.0,\"events\":[" + EVENT + "]}",
                "{\"schemaVersion\":1e0,\"events\":[" + EVENT + "]}",
                "{\"schemaVersion\":1,\"events\":[" + EVENT + "]} {}",
                "",
                "{\"schemaVersion\":1,\"events\":[" + EVENT)) {
            assertThat(ProductMetricsModel.parseIngest(bytes(body)).refusal()).as(body)
                    .isEqualTo(ProductMetricsModel.CODE_INVALID);
        }
        byte[] invalidUtf8 = {'{', '"', 'a', '"', ':', '"', (byte) 0xff, '"', '}'};
        assertThat(ProductMetricsModel.parseIngest(invalidUtf8).refusal()).isEqualTo(ProductMetricsModel.CODE_INVALID);
        ProductMetricsModel.Ingest spaced = ProductMetricsModel.parseIngest(
                bytes(" \n{\"events\":[" + EVENT + "],\"schemaVersion\":1}\n"));
        assertThat(spaced.refusal()).isNull();
        assertThat(spaced.events()).hasSize(1);
    }

    @Test
    void settingsBodyIsClosed() {
        for (String body : List.of("{\"disclosureVersion\":1}", "{\"enabled\":\"true\"}",
                "{\"enabled\":true,\"disclosureVersion\":true}", "{\"enabled\":true,\"disclosureVersion\":1.5}",
                "{\"enabled\":false,\"tenantId\":\"t2\"}", "{\"enabled\":false,\"enabled\":true}", "[true]",
                "{\"enabled\":false}x", "{\"enabled\":true,\"disclosureVersion\":null}", "{}",
                "{\"enabled\":true,\"disclosureVersion\":\"1\"}")) {
            assertThat(ProductMetricsModel.parseSettingsUpdate(bytes(body))).as(body).isEmpty();
        }
        assertThat(ProductMetricsModel.parseSettingsUpdate(bytes("{\"disclosureVersion\":2,\"enabled\":true}")))
                .contains(new ProductMetricsModel.SettingsUpdate(true, "2"));
        assertThat(ProductMetricsModel.parseSettingsUpdate(bytes("{\"enabled\":false}")))
                .contains(new ProductMetricsModel.SettingsUpdate(false, null));
    }
}
