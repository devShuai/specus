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
              "peerEgressEnabled": true,
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
        assertThat(bean.isPeerEgressEnabled()).isTrue();
    }

    /**
     * Rules kept with the master switch off are warned about once, by count, in the words the Go and
     * .NET clients use; a rule the user switched off is not warned about.
     */
    @Test
    void rulesKeptWithTheSwitchOffAreWarnedAboutOnce() throws Exception {
        List<String> warnings = new ArrayList<>();
        ClientStartupConfig config = ClientCli.parse("""
                {
                  "serverBaseUrl": "https://example.invalid",
                  "apiKey": "key",
                  "secret": "secret",
                  "peerEgressRules": [
                    {"match": "203.0.113.0/24", "action": "egress", "egressClientId": 42},
                    {"match": "198.51.100.0/24", "action": "block", "enabled": false}
                  ]
                }
                """, warnings::add);

        assertThat(config.isPeerEgressEnabled()).isFalse();
        assertThat(warnings).containsExactly(
                "peerEgressRules has 2 rule(s) but peerEgressEnabled is false: none is in force");
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
     * Phase two's switch and pool are known fields that reach the running client, off and on the
     * default pool when the file says nothing. With the switch on, a domain rule is judged as the
     * running client would judge it rather than warned about as unsupported, and an address rule
     * inside the pool is refused.
     */
    @Test
    void phaseTwoSettingsAreReadAndJudgeTheRules() throws Exception {
        ClientStartupConfig defaults = ClientCli.parse(CONFIG, ignored -> { });
        assertThat(defaults.isPeerEgressDnsTakeover()).isFalse();
        assertThat(defaults.getPeerEgressFakeIpCidr()).isEqualTo("198.18.0.0/15");

        List<String> warnings = new ArrayList<>();
        ClientStartupConfig config = ClientCli.parse("""
                {
                  "serverBaseUrl": "https://example.invalid",
                  "apiKey": "key",
                  "secret": "secret",
                  "peerEgressEnabled": true,
                  "peerEgressDnsTakeover": true,
                  "peerEgressFakeIpCidr": "10.64.0.0/16",
                  "peerEgressRules": [
                    {"match": "*.example.com", "action": "egress", "egressClientId": 42},
                    {"match": "10.64.1.0/24", "action": "block"}
                  ]
                }
                """, warnings::add);
        assertThat(warnings).containsExactly("peerEgressRules[1] is not in force: EGRESS_RULE_FAKE_IP_OVERLAP");
        SpecusBean bean = new SpecusBean();
        SpecusClientApplication.copyLocalSettings(config, bean);
        assertThat(bean.isPeerEgressDnsTakeover()).isTrue();
        assertThat(bean.getPeerEgressFakeIpCidr()).isEqualTo("10.64.0.0/16");

        warnings.clear();
        ClientCli.parse("""
                {
                  "serverBaseUrl": "https://example.invalid",
                  "apiKey": "key",
                  "secret": "secret",
                  "peerEgressEnabled": true,
                  "peerEgressDnsTakeover": true,
                  "peerEgressFakeIpCidr": "198.18.0.0/25",
                  "peerEgressRules": [{"match": "example.com", "action": "direct"}]
                }
                """, warnings::add);
        // An unusable pool stops phase two alone, and the domain rule reads as it does in phase one.
        assertThat(warnings).containsExactly(
                "peerEgressFakeIpCidr is not usable: EGRESS_FAKE_IP_POOL_INVALID; domain rules are not in force",
                "peerEgressRules[0] is not in force: EGRESS_RULE_DOMAIN_UNSUPPORTED");
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
        // The egress honours name-bind; IPv6 targets are not claimed.
        assertThat(capabilities.path("domainTargetCapable").isBoolean()).isTrue();
        assertThat(capabilities.path("domainTargetCapable").asBoolean()).isTrue();
        assertThat(capabilities.path("ipv6TargetCapable").isBoolean()).isTrue();
        assertThat(capabilities.path("ipv6TargetCapable").asBoolean()).isFalse();
    }
}
