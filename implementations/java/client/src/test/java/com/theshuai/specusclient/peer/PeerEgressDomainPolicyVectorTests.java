package com.theshuai.specusclient.peer;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.theshuai.common.peeregress.Ipv4Cidr;
import com.theshuai.common.peeregress.PeerEgressAuthorization;
import com.theshuai.common.peeregress.PeerEgressCodes;
import com.theshuai.common.peeregress.PeerEgressConfigMessage;
import com.theshuai.common.peeregress.PeerEgressFrame;
import com.theshuai.common.peeregress.PeerEgressPolicy;
import com.theshuai.common.peeregress.PeerEgressRequest;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import org.junit.jupiter.api.Test;

/**
 * Binds the egress side of an egress policy's domain rules to the {@code config} and
 * {@code authorize} sections of {@code peer-egress-domain-policy-v1.json}. The {@code management}
 * section is what a server stores and is not this client's to check.
 *
 * <p>Every case's policy goes through the real {@code egress-config} decoder, so what is checked is
 * what this egress keeps from the push as well as how it judges a flow. Each case is run twice:
 * straight through the judgment layer with the request as the vector writes it, name included, and
 * through the egress runtime, where a flow carrying a name is one the consumer bound with
 * name-bind and the name resolves to the case's address.
 */
class PeerEgressDomainPolicyVectorTests {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final long EPOCH = 1_800_000_000_000L;
    /** The consumer's fake address a name is bound to; the resolver answers with the case's address. */
    private static final String FAKE = "198.18.0.5";
    private static final String CONSUMER_IP = "100.96.0.1";

    private static JsonNode vector() throws IOException {
        Path directory = Path.of("").toAbsolutePath();
        for (int depth = 0; depth < 8 && directory != null; depth++) {
            Path candidate = directory.resolve("protocol").resolve("test-vectors")
                    .resolve("peer-egress-domain-policy-v1.json");
            if (Files.exists(candidate)) {
                return MAPPER.readTree(Files.readString(candidate));
            }
            directory = directory.getParent();
        }
        throw new IOException("cannot locate peer-egress-domain-policy-v1.json");
    }

    /** A case's own config when it has one, the top-level config otherwise, through the real decoder. */
    private static PeerEgressPolicy decode(JsonNode vector, JsonNode testCase) throws IOException {
        JsonNode config = testCase.has("config") ? testCase.path("config") : vector.path("config");
        PeerEgressConfigMessage message = PeerEgressConfigMessage.decode(MAPPER.writeValueAsString(config));
        assertNotNull(message, testCase.path("name").asText() + ": the egress-config was refused");
        return message.policy();
    }

    private static int address(String dotted) {
        Integer value = Ipv4Cidr.parseAddress(dotted);
        assertNotNull(value, dotted + " did not parse");
        return value;
    }

    @Test
    void authorizeCasesMatchTheSharedVector() throws IOException {
        JsonNode vector = vector();
        JsonNode cases = vector.path("authorize");
        assertFalse(cases.isEmpty(), "domain policy vector carried no authorize cases");
        for (JsonNode testCase : cases) {
            String name = testCase.path("name").asText();
            JsonNode raw = testCase.path("request");
            PeerEgressRequest request = new PeerEgressRequest();
            request.setConsumerClientId(raw.path("consumerClientId").asLong());
            request.setDestinationIp(raw.path("destinationIp").asText());
            request.setDestinationPort(raw.path("destinationPort").asInt());
            request.setProtocol(raw.path("protocol").asText());
            if (raw.has("name")) {
                request.setName(raw.path("name").asText());
            }
            PeerEgressAuthorization.Decision decision = PeerEgressAuthorization.evaluate(
                    request, decode(vector, testCase), true, PeerEgressAuthorization.Context.defaults());
            assertEquals(testCase.path("code").asText(), decision.code(), name);
            assertEquals(PeerEgressCodes.ALLOWED.equals(testCase.path("code").asText()), decision.allowed(), name);
        }
    }

    /**
     * What the decoder keeps of the domain rules: an absent or non-array field is none, an entry
     * that is not an object or whose match is not a valid name is skipped, and the match is stored
     * normalised.
     */
    @Test
    void decodesDomainRulesAsTheReferenceDoes() throws IOException {
        JsonNode vector = vector();
        Map<String, JsonNode> byName = new java.util.HashMap<>();
        vector.path("authorize").forEach(testCase -> byName.put(testCase.path("name").asText(), testCase));

        List<String> top = matches(decodeConfig(vector.path("config")));
        List<String> listed = new ArrayList<>();
        vector.path("config").path("domainRules").forEach(rule -> listed.add(rule.path("match").asText()));
        assertEquals(listed, top, "the top-level domain rules");

        Map<String, List<String>> expected = Map.of(
                "absent-domain-rules", List.of(),
                "domain-rules-not-an-array", List.of(),
                "unreadable-entries-skipped", List.of("example.com"),
                "wildcard-entry-grants-nothing", List.of());
        for (var entry : expected.entrySet()) {
            JsonNode testCase = byName.get(entry.getKey());
            assertNotNull(testCase, "the vector no longer has " + entry.getKey());
            assertEquals(entry.getValue(), matches(decode(vector, testCase)), entry.getKey());
        }

        PeerEgressPolicy.PeerEgressDomainRule kept =
                decode(vector, byName.get("unreadable-entries-skipped")).getDomainRules().get(0);
        assertEquals(List.of("tcp"), kept.getProtocols());
        assertEquals(List.of(List.of(443, 443)), kept.getPortRanges());
    }

    private static PeerEgressPolicy decodeConfig(JsonNode config) throws IOException {
        PeerEgressConfigMessage message = PeerEgressConfigMessage.decode(MAPPER.writeValueAsString(config));
        assertNotNull(message);
        return message.policy();
    }

    private static List<String> matches(PeerEgressPolicy policy) {
        return policy.getDomainRules().stream()
                .map(PeerEgressPolicy.PeerEgressDomainRule::getMatch)
                .collect(Collectors.toList());
    }

    /**
     * The same cases through the egress runtime. A case with a name is a flow to the consumer's
     * fake address after a name-bind, resolved here to the case's address; one without is a flow to
     * the address itself. Allowed means that address is dialled and nothing refused; otherwise
     * nothing is dialled and the consumer is told the case's code.
     */
    @Test
    void authorizeCasesHoldThroughTheEgressRuntime() throws IOException {
        JsonNode vector = vector();
        for (JsonNode testCase : vector.path("authorize")) {
            String name = testCase.path("name").asText();
            JsonNode raw = testCase.path("request");
            long consumer = raw.path("consumerClientId").asLong();
            String destination = raw.path("destinationIp").asText();
            int port = raw.path("destinationPort").asInt();
            String protocol = raw.path("protocol").asText();

            Plane plane = new Plane(destination);
            plane.runtime.applyPolicy(decode(vector, testCase), PeerEgressAuthorization.Context.defaults(), EPOCH);
            String target = destination;
            if (raw.has("name")) {
                plane.runtime.handleFrame(consumer, PeerEgressFrame.encode(PeerEgressFrame.TYPE_CONTROL, false,
                        PeerEgressFrame.encodeControl(PeerEgressFrame.Control.nameBind(FAKE, raw.path("name").asText()))),
                        EPOCH);
                target = FAKE;
            }
            if ("tcp".equals(protocol)) {
                plane.runtime.handleFrame(consumer, PeerEgressFrame.encode(PeerEgressFrame.TYPE_IP_PACKET, false,
                        PeerEgressSegment.build(new PeerEgressSegment.Segment(address(CONSUMER_IP), address(target),
                                40000, port, 1000, 0, PeerEgressSegment.FLAG_SYN, 65535, 1360, new byte[0]))), EPOCH);
            } else {
                plane.runtime.handleFrame(consumer, PeerEgressFrame.encode(PeerEgressFrame.TYPE_IP_PACKET, false,
                        PeerEgressDatagram.build(new PeerEgressDatagram.Datagram(address(CONSUMER_IP), address(target),
                                40000, port, "query".getBytes(StandardCharsets.US_ASCII)))), EPOCH);
            }

            String code = testCase.path("code").asText();
            if (PeerEgressCodes.ALLOWED.equals(code)) {
                assertEquals(List.of(protocol + " " + destination + ":" + port), plane.dialed, name + ": dialled");
                assertEquals(List.of(), plane.rejectCodes(), name + ": refused");
            } else {
                assertEquals(List.of(), plane.dialed, name + ": a refused flow was dialled");
                assertEquals(List.of(code), plane.rejectCodes(), name + ": refusal");
            }
            plane.runtime.shutdown(EPOCH);
        }
    }

    /** A runtime with no network: the dialler records, readers never run, frames are kept. */
    private static final class Plane {
        final List<String> dialed = new ArrayList<>();
        final List<byte[]> frames = new ArrayList<>();
        final PeerEgressRuntime runtime;

        Plane(String resolvesTo) {
            runtime = new PeerEgressRuntime(
                    (consumer, frame) -> frames.add(frame.clone()),
                    (protocol, host, port, timeoutMs) -> {
                        dialed.add(protocol + " " + host + ":" + port);
                        return new IdleSocket();
                    },
                    reader -> {
                    },
                    () -> EPOCH);
            runtime.resolve = name -> List.of(address(resolvesTo));
        }

        List<String> rejectCodes() {
            List<String> codes = new ArrayList<>();
            for (byte[] raw : frames) {
                PeerEgressFrame.Decoded frame = PeerEgressFrame.parse(raw);
                if (!frame.accepted() || frame.type() != PeerEgressFrame.TYPE_CONTROL) {
                    continue;
                }
                PeerEgressFrame.Control control = PeerEgressFrame.decodeControl(frame.body());
                if (control != null && PeerEgressFrame.CONTROL_FLOW_REJECT.equals(control.type())) {
                    codes.add(control.code());
                }
            }
            return codes;
        }
    }

    /** A socket nothing is read from: the runtime here never starts a reader. */
    private static final class IdleSocket implements PeerEgressRuntime.Socket {
        @Override
        public int read(byte[] buffer) {
            return -1;
        }

        @Override
        public void write(byte[] data) {
        }

        @Override
        public void close() {
        }
    }
}
