package com.theshuai.specusclient;

import static org.assertj.core.api.Assertions.assertThat;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.theshuai.common.peeregress.PeerEgressProtocol;
import com.theshuai.common.peeregress.PeerEgressRule;
import com.theshuai.specusclient.bean.ClientStartupConfig;
import com.theshuai.specusclient.bean.SpecusBean;
import com.theshuai.specusclient.cli.ClientCli;
import com.theshuai.specusclient.peer.PeerEgressRouteCommanders;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;

/**
 * What has to happen before the egress feature can do anything on a Java client: its rules have to
 * reach the running client, and its login has to tell the server it can take part.
 *
 * <p>Both were missing. The rules were read by the Go and .NET clients and warned about as an
 * unknown field here, then dropped; and the login announced egress version 0, which every server
 * reads as "never push this client a policy". Every existing test handed the mesh its rules and its
 * policy directly, which is how neither was seen.
 */
class EgressStartupTests {

    private static final String CONFIG = """
            {
              // Comments stay legal in the shared JSONC schema.
              "serverBaseUrl": "https://example.invalid",
              "apiKey": "key",
              "secret": "secret",
              "peerEgressRules": [
                {"match": "203.0.113.0/24", "action": "egress", "egressClientId": 42},
                {"match": "198.51.100.0/24", "action": "direct"},
              ]
            }
            """;

    /** The shared field is read, and read without an unknown-field warning. */
    @Test
    void egressRulesAreReadFromTheSharedConfigurationField() throws Exception {
        List<String> warnings = new ArrayList<>();
        ClientStartupConfig config = ClientCli.parse(CONFIG, warnings::add);

        assertThat(config.getPeerEgressRules()).hasSize(2);
        PeerEgressRule first = config.getPeerEgressRules().get(0);
        assertThat(first.getMatch()).isEqualTo("203.0.113.0/24");
        assertThat(first.getAction()).isEqualTo(PeerEgressRule.ACTION_EGRESS);
        assertThat(first.getEgressClientId()).isEqualTo(42L);
        assertThat(warnings).as("peerEgressRules is a known field now")
                .noneMatch(warning -> warning.contains("peerEgressRules"));
    }

    /** And the rules make it from the file to the bean the mesh is built from. */
    @Test
    void egressRulesReachTheRunningClient() throws Exception {
        ClientStartupConfig config = ClientCli.parse(CONFIG, ignored -> { });
        SpecusBean bean = new SpecusBean();

        SpecusClientApplication.copyLocalSettings(config, bean);

        assertThat(bean.getPeerEgressRules()).hasSize(2);
        assertThat(bean.getPeerEgressRules().get(0).getMatch()).isEqualTo("203.0.113.0/24");
    }

    /** A configuration that leaves the field out, or sets it to null, yields no rules rather than a failure. */
    @Test
    void anAbsentOrNullRuleListIsEmpty() throws Exception {
        for (String text : List.of(
                "{\"serverBaseUrl\":\"https://example.invalid\",\"apiKey\":\"k\",\"secret\":\"s\"}",
                "{\"serverBaseUrl\":\"https://example.invalid\",\"apiKey\":\"k\",\"secret\":\"s\","
                        + "\"peerEgressRules\":null}")) {
            ClientStartupConfig config = ClientCli.parse(text, ignored -> { });
            SpecusBean bean = new SpecusBean();
            SpecusClientApplication.copyLocalSettings(config, bean);
            assertThat(bean.getPeerEgressRules()).isNotNull().isEmpty();
        }
    }

    /**
     * The login environment announces egress, in the field all four servers read.
     *
     * <p>Asserted on the serialised JSON rather than on the bean, because the wire names are what
     * the servers read and the default of 0 is what went wrong.
     */
    @Test
    void theLoginEnvironmentAnnouncesEgressCapabilities() {
        JsonNode environment = new ObjectMapper().valueToTree(SpecusClientApplication.collectEnvironment());
        JsonNode capabilities = environment.path("clientEgressCapabilities");

        assertThat(capabilities.isObject()).as("clientEgressCapabilities is present").isTrue();
        assertThat(capabilities.path("version").asInt())
                .as("every server skips egress-config below 1")
                .isGreaterThanOrEqualTo(1)
                .isEqualTo(PeerEgressProtocol.PROTOCOL_VERSION);
        assertThat(capabilities.path("egressCapable").asBoolean()).isTrue();
        assertThat(capabilities.path("consumerCapable").asBoolean())
                .isEqualTo(PeerEgressRouteCommanders.takeoverSupported());
        // Phase one carries address targets only.
        assertThat(capabilities.path("domainTargetCapable").isBoolean()).isTrue();
        assertThat(capabilities.path("domainTargetCapable").asBoolean()).isFalse();
        assertThat(capabilities.path("ipv6TargetCapable").isBoolean()).isTrue();
        assertThat(capabilities.path("ipv6TargetCapable").asBoolean()).isFalse();
    }
}
