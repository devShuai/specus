package com.theshuai.specusclient.cli;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.fasterxml.jackson.databind.JsonNode;
import com.theshuai.specusclient.bean.ClientStartupConfig;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * egress test with a domain name (protocol/spec/peer-egress-dns.md, 预演一个域名): the five lines,
 * the JSON, the refusals, and the local page answering through the same preview. Phase two is
 * judged offline, as config validate judges it, so the master switch does not decide whether the
 * responder would answer; it only decides whether the rule is in force.
 */
class EgressTestPreviewTests {

    private static final Path PATH = Path.of("client.jsonc");
    private static final String FIRST = "Preview for example.com from the configuration (no connection is made)";
    private static final String SYSTEM = "  result: resolved by the system's DNS; egress test <that address> previews where it goes";
    private static final String FORWARD = "  dns: forwarded to the system's DNS; the address it returns is then decided by the IPv4 rules";
    private static final String THROUGH = "through egress 42, which resolves the name itself";

    @TempDir
    Path temporary;

    private static ClientStartupConfig config(String extra) throws Exception {
        return ClientCli.parse("{\"serverBaseUrl\":\"https://example.invalid\",\"apiKey\":\"k\",\"secret\":\"s\""
                + extra + "}", ignored -> { });
    }

    private record Preview(List<String> lines, Map<String, Object> data) { }

    private static Preview preview(String extra, String address) throws Exception {
        var lines = new ArrayList<String>();
        Map<String, Object> data = EgressEdit.preview(PATH, config(extra), address, lines);
        return new Preview(lines, data);
    }

    private static final String RULES = ",\"peerEgressRules\":["
            + "{\"match\":\"example.com\",\"action\":\"egress\",\"egressClientId\":42},"
            + "{\"match\":\"*.Blocked.example\",\"action\":\"block\"},"
            + "{\"match\":\"direct.example\",\"action\":\"direct\"}]";
    private static final String RUNNING = ",\"peerEgressEnabled\":true,\"peerEgressDnsTakeover\":true" + RULES;

    @Test
    void tellsAnAddressFromANameAndRefusesWhatNoDomainRuleCouldMatch() {
        assertThat(EgressEdit.addressProblem("203.0.113.9")).isNull();
        assertThat(EgressEdit.addressProblem("example.com")).isNull();
        assertThat(EgressEdit.addressProblem("Example.COM.")).isNull();
        assertThat(EgressEdit.addressProblem("xn--bcher-kva.example")).isNull();
        // Written the way section two refuses a rule's match: Unicode, an underscore, one label, a
        // wildcard (a rule's pattern, not a name), and a Kelvin sign that lower-cases to ASCII.
        for (String name : List.of("bad_name.example", "bücher.example", "例子.测试", "localhost", "*.example.com",
                "Kexample.com", "-a.example", "a..example")) {
            assertThat(EgressEdit.addressProblem(name)).as(name).isEqualTo(
                    "ADDRESS is not a name a domain rule can match: use labels of a-z, 0-9 and -, with punycode (xn--)"
                            + " for international names.");
        }
        // Neither a name nor an IPv4 address.
        for (String value : List.of("1.2.3", "300.1.1.1", "203.0.113.0/24", "fe80::1", "example.com:443", "", "1-2.3")) {
            assertThat(EgressEdit.addressProblem(value)).as(value).isEqualTo("ADDRESS must be an IPv4 address.");
        }
    }

    @Test
    void aNameWithDnsTakeoverOffIsResolvedByTheSystem() throws Exception {
        var preview = preview(",\"peerEgressEnabled\":true", "example.com");
        assertThat(preview.lines()).containsExactly(FIRST, "  takeover: on | dns takeover: off", "  rule: none",
                "  dns: not taken over (peerEgressDnsTakeover is off), so the name is resolved by the system's DNS", SYSTEM);
        assertThat(preview.data()).containsExactly(Map.entry("configPath", PATH.toString()), Map.entry("address", "example.com"),
                Map.entry("kind", "domain"), Map.entry("takeover", true), Map.entry("dnsTakeover", false),
                Map.entry("matchedRuleIndex", -1), Map.entry("dns", "local"), Map.entry("result", "direct"));
    }

    @Test
    void anEgressRuleInForceIsAnsweredWithAFakeIpAndResolvedByTheEgress() throws Exception {
        var preview = preview(RUNNING, "Example.COM.");
        assertThat(preview.lines()).containsExactly(FIRST, "  takeover: on | dns takeover: on",
                "  rule: [0] example.com egress 42",
                "  dns: answered with a fake IP from 198.18.0.0/15; the egress resolves the name",
                "  result: " + THROUGH);
        // The fields in the spec's order, the name as normalised.
        assertThat(preview.data()).containsExactly(Map.entry("configPath", PATH.toString()), Map.entry("address", "example.com"),
                Map.entry("kind", "domain"), Map.entry("takeover", true), Map.entry("dnsTakeover", true),
                Map.entry("matchedRuleIndex", 0), Map.entry("ruleAction", "egress"), Map.entry("egressClientId", 42L),
                Map.entry("dns", "fake"), Map.entry("result", "egress"));
    }

    @Test
    void aBlockRuleIsAnsweredWithAFakeIpAndBlocked() throws Exception {
        var preview = preview(RUNNING, "a.b.blocked.example");
        assertThat(preview.lines()).containsExactly("Preview for a.b.blocked.example from the configuration (no connection is made)",
                "  takeover: on | dns takeover: on", "  rule: [1] *.Blocked.example block",
                "  dns: answered with a fake IP from 198.18.0.0/15", "  result: blocked");
        assertThat(preview.data()).containsEntry("ruleAction", "block").containsEntry("dns", "fake")
                .containsEntry("result", "block").doesNotContainKeys("egressClientId", "resultWithTakeover");
        // A suffix never covers its own apex.
        assertThat(preview(RUNNING, "blocked.example").data()).containsEntry("matchedRuleIndex", -1);
    }

    @Test
    void aDirectRuleOrNoRuleIsForwardedToTheSystemsDns() throws Exception {
        var direct = preview(RUNNING, "direct.example");
        assertThat(direct.lines().subList(2, 5)).containsExactly("  rule: [2] direct.example direct", FORWARD, SYSTEM);
        assertThat(direct.data()).containsEntry("matchedRuleIndex", 2).containsEntry("ruleAction", "direct")
                .containsEntry("dns", "forward").containsEntry("result", "direct")
                .doesNotContainKeys("egressClientId", "resultWithTakeover");

        var none = preview(RUNNING, "www.example.com");
        assertThat(none.lines().subList(2, 5)).containsExactly("  rule: none", FORWARD, SYSTEM);
        assertThat(none.data()).containsEntry("matchedRuleIndex", -1).containsEntry("dns", "forward")
                .doesNotContainKeys("ruleAction", "egressClientId", "resultWithTakeover");

        // Direct is direct whichever switch is off: nothing to say about turning them on.
        var off = preview(",\"peerEgressDnsTakeover\":true" + RULES, "direct.example");
        assertThat(off.lines().get(4)).isEqualTo(SYSTEM);
        assertThat(off.data()).containsEntry("result", "direct").doesNotContainKey("resultWithTakeover");
    }

    @Test
    void theRuleIsTheOneTheResponderWouldSelect() throws Exception {
        String rules = ",\"peerEgressEnabled\":true,\"peerEgressDnsTakeover\":true,\"peerEgressRules\":["
                + "{\"match\":\"*.example.com\",\"action\":\"block\"},"
                + "{\"match\":\"*.cdn.example.com\",\"action\":\"egress\",\"egressClientId\":7},"
                + "{\"match\":\"img.cdn.example.com\",\"action\":\"direct\"},"
                + "{\"match\":\"off.example.com\",\"action\":\"egress\",\"egressClientId\":9,\"enabled\":false},"
                + "{\"match\":\"port.example.com\",\"action\":\"egress\",\"egressClientId\":9,\"port\":443}]";
        // Exact beats suffix, and the suffix with more labels beats the one with fewer.
        assertThat(preview(rules, "img.cdn.example.com").data()).containsEntry("matchedRuleIndex", 2);
        assertThat(preview(rules, "a.cdn.example.com").data()).containsEntry("matchedRuleIndex", 1)
                .containsEntry("egressClientId", 7L);
        // A rule switched off or refused takes no part.
        assertThat(preview(rules, "off.example.com").data()).containsEntry("matchedRuleIndex", 0);
        assertThat(preview(rules, "port.example.com").data()).containsEntry("matchedRuleIndex", 0);
    }

    @Test
    void anEgressRuleOutOfForceSaysWhyAndWhatTurningItOnWouldDo() throws Exception {
        // Only the master switch off: the responder is judged offline, so it would still answer.
        var master = preview(",\"peerEgressDnsTakeover\":true" + RULES, "example.com");
        assertThat(master.lines()).containsExactly(FIRST, "  takeover: off | dns takeover: on",
                "  rule: [0] example.com egress 42",
                "  dns: answered with a fake IP from 198.18.0.0/15; the egress resolves the name",
                "  result: domain rules are not in force (takeover is off); with them on: " + THROUGH);
        assertThat(master.data()).containsEntry("dns", "fake").containsEntry("result", "direct")
                .containsEntry("resultWithTakeover", "egress").containsEntry("egressClientId", 42L);

        // DNS takeover off: the rule is still selected, to say what turning it on would do.
        var dns = preview(",\"peerEgressEnabled\":true" + RULES, "example.com");
        assertThat(dns.lines().subList(1, 5)).containsExactly("  takeover: on | dns takeover: off",
                "  rule: [0] example.com egress 42",
                "  dns: not taken over (peerEgressDnsTakeover is off), so the name is resolved by the system's DNS",
                "  result: domain rules are not in force (dns takeover is off); with them on: " + THROUGH);
        assertThat(dns.data()).containsEntry("dns", "local").containsEntry("result", "direct")
                .containsEntry("resultWithTakeover", "egress");

        // A pool phase two cannot run with, here one inside the default mesh.
        var pool = preview(RUNNING + ",\"peerEgressFakeIpCidr\":\"100.100.0.0/16\"", "x.blocked.example");
        assertThat(pool.lines().subList(2, 5)).containsExactly("  rule: [1] *.Blocked.example block",
                "  dns: not taken over (peerEgressFakeIpCidr is not usable), so the name is resolved by the system's DNS",
                "  result: domain rules are not in force (peerEgressFakeIpCidr is not usable); with them on: blocked");
        assertThat(pool.data()).containsEntry("dns", "local").containsEntry("result", "direct")
                .containsEntry("resultWithTakeover", "block");
    }

    @Test
    void theFirstReasonThatHoldsIsGiven() throws Exception {
        String unusable = ",\"peerEgressFakeIpCidr\":\"10.0.0.0/25\"";
        assertThat(preview(RULES + unusable, "example.com").lines().get(4))
                .isEqualTo("  result: domain rules are not in force (takeover is off); with them on: " + THROUGH);
        var dnsOff = preview(",\"peerEgressEnabled\":true" + RULES + unusable, "example.com");
        assertThat(dnsOff.lines().get(3))
                .isEqualTo("  dns: not taken over (peerEgressDnsTakeover is off), so the name is resolved by the system's DNS");
        assertThat(dnsOff.lines().get(4))
                .isEqualTo("  result: domain rules are not in force (dns takeover is off); with them on: " + THROUGH);
        var masterOff = preview(",\"peerEgressDnsTakeover\":true" + RULES + unusable, "example.com");
        assertThat(masterOff.lines().get(3))
                .isEqualTo("  dns: not taken over (peerEgressFakeIpCidr is not usable), so the name is resolved by the system's DNS");
        assertThat(masterOff.lines().get(4))
                .isEqualTo("  result: domain rules are not in force (takeover is off); with them on: " + THROUGH);
    }

    @Test
    void theFakeIpComesFromTheConfiguredPool() throws Exception {
        var preview = preview(RUNNING + ",\"peerEgressFakeIpCidr\":\"10.64.0.0/16\"", "example.com");
        assertThat(preview.lines().get(3)).isEqualTo("  dns: answered with a fake IP from 10.64.0.0/16; the egress resolves the name");
    }

    @Test
    void anAddressPreviewSaysItIsAnAddress() throws Exception {
        var preview = preview(",\"peerEgressEnabled\":true,\"peerEgressRules\":[{\"match\":\"203.0.113.0/24\","
                + "\"action\":\"egress\",\"egressClientId\":42}]", "203.0.113.9");
        assertThat(preview.data()).containsExactly(Map.entry("configPath", PATH.toString()), Map.entry("address", "203.0.113.9"),
                Map.entry("kind", "address"), Map.entry("takeover", true), Map.entry("matchedRuleIndex", 0),
                Map.entry("ruleAction", "egress"), Map.entry("egressClientId", 42L), Map.entry("result", "egress"));
        assertThat(preview.lines()).containsExactly(
                "Preview for 203.0.113.9 from the configuration (no connection is made; --connect PORT tests one)",
                "  takeover: on", "  rule: [0] 203.0.113.0/24 egress 42", "  result: through egress 42");
    }

    private Path file(String extra) throws IOException {
        Path config = temporary.resolve("client.jsonc");
        Files.writeString(config, "{\n  \"serverBaseUrl\": \"http://127.0.0.1:1\",\n  \"apiKey\": \"test\",\n"
                + "  \"secret\": \"secret\"" + extra + "\n}\n");
        return config;
    }

    private static JsonNode body(String json) throws IOException {
        return CliOutput.JSON.readTree(json);
    }

    @Test
    void theLocalPagePreviewsANameThroughTheSamePreview() throws Exception {
        Path config = file(",\n  \"peerEgressDnsTakeover\": true" + RULES);
        Map<String, Object> named = EgressEdit.uiTest(config, body("{\"address\":\" Example.COM. \"}"));
        assertThat(named).containsEntry("kind", "domain").containsEntry("address", "example.com")
                .containsEntry("dns", "fake").containsEntry("result", "direct").containsEntry("resultWithTakeover", "egress")
                .containsEntry("configPath", config.toString()).containsEntry("schemaVersion", 1)
                .doesNotContainKey("connect");
        assertThat(EgressEdit.uiTest(config, body("{\"address\":\"203.0.113.9\"}"))).containsEntry("kind", "address");

        assertThatThrownBy(() -> EgressEdit.uiTest(config, body("{\"address\":\"bad_name.example\"}")))
                .isInstanceOfSatisfying(LocalUi.Failure.class, failure -> {
                    assertThat(failure.status).isEqualTo(422);
                    assertThat(failure.getMessage()).isEqualTo(EgressEdit.UNUSABLE_NAME);
                });
        assertThatThrownBy(() -> EgressEdit.uiTest(config, body("{\"address\":\"example.com\",\"connect\":443}")))
                .isInstanceOfSatisfying(LocalUi.Failure.class, failure -> {
                    assertThat(failure.status).isEqualTo(422);
                    assertThat(failure.getMessage())
                            .isEqualTo("--connect needs an IPv4 address: a name would be resolved here, not by the egress.");
                });
        assertThatThrownBy(() -> EgressEdit.uiTest(config, body("{\"address\":\"1.2.3\"}")))
                .isInstanceOfSatisfying(LocalUi.Failure.class, failure ->
                        assertThat(failure.getMessage()).isEqualTo("ADDRESS must be an IPv4 address."));
    }

    private record Run(int exit, String out, String err) { }

    private Run run(String... args) throws Exception {
        var command = new ArrayList<>(List.of(Path.of(System.getProperty("java.home"), "bin", "java").toString(),
                "-Duser.home=" + temporary, "-cp", System.getProperty("java.class.path"),
                "com.theshuai.specusclient.SpecusClientApplication"));
        command.addAll(List.of(args));
        Path out = Files.createTempFile(temporary, "out", ".txt");
        Path err = Files.createTempFile(temporary, "err", ".txt");
        ProcessBuilder builder = new ProcessBuilder(command).directory(temporary.toFile())
                .redirectOutput(out.toFile()).redirectError(err.toFile());
        builder.environment().put("SPECUS_CLI_STATE_DIR", temporary.resolve("state").toString());
        Process process = builder.start();
        try {
            assertThat(process.waitFor(20, TimeUnit.SECONDS)).as("hung: %s", List.of(args)).isTrue();
            return new Run(process.exitValue(), Files.readString(out), Files.readString(err));
        } finally {
            if (process.isAlive()) {
                process.destroyForcibly();
                process.waitFor();
            }
        }
    }

    @Test
    void theCommandPrintsTheFiveLinesAndRefusesWhatItCannotPreview() throws Exception {
        String config = file(",\n  \"peerEgressDnsTakeover\": true" + RULES).toString();
        Run text = run("egress", "test", "Example.COM.", "--config", config);
        assertThat(text.exit()).as(text.err()).isEqualTo(0);
        assertThat(text.out()).isEqualTo(String.join("\n", FIRST, "  takeover: off | dns takeover: on",
                "  rule: [0] example.com egress 42",
                "  dns: answered with a fake IP from 198.18.0.0/15; the egress resolves the name",
                "  result: domain rules are not in force (takeover is off); with them on: " + THROUGH)
                + System.lineSeparator());

        Run json = run("egress", "test", "example.com", "--config", config, "--json");
        assertThat(json.exit()).isEqualTo(0);
        JsonNode data = CliOutput.JSON.readTree(json.out()).path("data");
        assertThat(data.path("kind").asText()).isEqualTo("domain");
        assertThat(data.path("dnsTakeover").asBoolean()).isTrue();
        assertThat(data.path("resultWithTakeover").asText()).isEqualTo("egress");
        assertThat(data.path("egressClientId").asLong()).isEqualTo(42);

        Run name = run("egress", "test", "bad_name.example", "--config", config);
        assertThat(name.exit()).isEqualTo(2);
        assertThat(name.out()).isEmpty();
        assertThat(name.err()).isEqualTo(EgressEdit.UNUSABLE_NAME + System.lineSeparator());

        Run connect = run("egress", "test", "example.com", "--connect", "443", "--config", config, "--json");
        assertThat(connect.exit()).isEqualTo(2);
        JsonNode refused = CliOutput.JSON.readTree(connect.out());
        assertThat(refused.path("error").asText())
                .isEqualTo("--connect needs an IPv4 address: a name would be resolved here, not by the egress.");
        assertThat(refused.path("data").isNull()).isTrue();
    }
}
