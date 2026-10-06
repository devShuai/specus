package com.theshuai.specusclient;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The login environment announces that HTTP route resets say why they failed
 * (protocol/spec/service-connectivity-check.md section 6.1). A server trusts {@code failure} on an
 * RST only from a session that announced version 1, so without this every classified reset would
 * still be reported as unverified.
 */
class HttpRouteCapabilityLoginTests {

    @Test
    void theLoginEnvironmentAnnouncesHttpRouteCapabilities() {
        JsonNode environment = new ObjectMapper().valueToTree(SpecusClientApplication.collectEnvironment());
        JsonNode capabilities = environment.path("clientHttpRouteCapabilities");

        assertThat(capabilities.isObject()).as("clientHttpRouteCapabilities is present").isTrue();
        assertThat(capabilities.path("version").isInt()).isTrue();
        assertThat(capabilities.path("version").asInt()).isEqualTo(1);
    }
}
