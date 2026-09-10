package com.theshuai.common.peeregress;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;

/**
 * Replays {@code peer-egress-control-v1.json} against the Java {@code egress-config} decoder.
 *
 * <p>The push is produced by three server implementations and read by three clients. Its
 * expectations come from an independent reference decoder in the generator rather than from any
 * implementation, so agreeing with it is independent agreement.
 */
class PeerEgressControlVectorTests {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private static JsonNode readVector() throws IOException {
        Path directory = Path.of("").toAbsolutePath();
        for (int depth = 0; depth < 8 && directory != null; depth++) {
            Path candidate = directory.resolve("protocol").resolve("test-vectors")
                    .resolve("peer-egress-control-v1.json");
            if (Files.exists(candidate)) {
                return MAPPER.readTree(Files.readString(candidate));
            }
            directory = directory.getParent();
        }
        throw new IOException("cannot locate peer-egress-control-v1.json");
    }

    @Test
    void egressConfigDecodeMatchesSharedVector() throws IOException {
        JsonNode section = readVector().path("egressConfig");
        assertTrue(section.path("accept").size() > 0, "control vector carried no accept cases");
        assertTrue(section.path("reject").size() > 0, "control vector carried no reject cases");

        for (JsonNode testCase : section.path("accept")) {
            String name = testCase.path("name").asText();
            PeerEgressConfigMessage decoded =
                    PeerEgressConfigMessage.decode(testCase.path("message").asText());
            assertNotNull(decoded, name + ": the message was refused");

            JsonNode expect = testCase.path("expect");
            assertEquals(expect.path("revision").asLong(), decoded.revision(), name + ": revision");

            JsonNode want = expect.path("policy");
            PeerEgressPolicy policy = decoded.policy();
            assertEquals(want.path("enabled").asBoolean(), policy.isEnabled(), name + ": enabled");
            assertEquals(want.path("scope").asText(), policy.getScope(), name + ": scope");
            assertEquals(want.path("allowedConsumerClientIds").size(),
                    policy.getAllowedConsumerClientIds().size(), name + ": consumers");
            assertEquals(want.path("destinationRules").size(),
                    policy.getDestinationRules().size(), name + ": destination rules");

            for (int index = 0; index < want.path("destinationRules").size(); index++) {
                JsonNode expectedRule = want.path("destinationRules").get(index);
                PeerEgressPolicy.PeerEgressDestinationRule rule =
                        policy.getDestinationRules().get(index);
                assertEquals(expectedRule.path("cidr").asText(), rule.getCidr(),
                        name + ": rule " + index + " cidr");
                assertEquals(expectedRule.path("protocols").size(), rule.getProtocols().size(),
                        name + ": rule " + index + " protocols");
                assertEquals(expectedRule.path("portRanges").size(), rule.getPortRanges().size(),
                        name + ": rule " + index + " port ranges");
            }

            JsonNode limits = want.path("limits");
            assertEquals(limits.path("maxConcurrentFlows").asInt(),
                    policy.getLimits().getMaxConcurrentFlows(), name + ": maxConcurrentFlows");
            assertEquals(limits.path("maxFlowsPerConsumer").asInt(),
                    policy.getLimits().getMaxFlowsPerConsumer(), name + ": maxFlowsPerConsumer");
            assertEquals(limits.path("idleTimeoutSeconds").asInt(),
                    policy.getLimits().getIdleTimeoutSeconds(), name + ": idleTimeoutSeconds");
        }

        for (JsonNode testCase : section.path("reject")) {
            assertNull(PeerEgressConfigMessage.decode(testCase.path("message").asText()),
                    testCase.path("name").asText() + ": the message was accepted");
        }
    }
}
