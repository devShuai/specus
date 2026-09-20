package com.theshuai.specusclient.peer;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.theshuai.common.peeregress.Ipv4Cidr;
import com.theshuai.common.peeregress.PeerEgressRule;
import com.theshuai.common.peeregress.PeerEgressRules;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import org.junit.jupiter.api.Test;

/**
 * Binds what the consumer writes back into the TUN to {@code peer-egress-failure-v1.json}.
 *
 * <p>Three runtimes that reset a flow at different sequence numbers would leave the application
 * hanging on one of them: a reset a stack does not accept is a reset that was not sent.
 */
class PeerEgressFailureVectorTests {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final long EPOCH = 1_800_000_000_000L;

    private static JsonNode vector() throws IOException {
        Path directory = Path.of("").toAbsolutePath();
        for (int depth = 0; depth < 8 && directory != null; depth++) {
            Path candidate = directory.resolve("protocol").resolve("test-vectors").resolve("peer-egress-failure-v1.json");
            if (Files.exists(candidate)) {
                return MAPPER.readTree(Files.readString(candidate));
            }
            directory = directory.getParent();
        }
        throw new IOException("cannot locate peer-egress-failure-v1.json");
    }

    private static int address(String dotted) {
        Integer value = Ipv4Cidr.parseAddress(dotted);
        assertFalse(value == null, dotted + " did not parse");
        return value;
    }

    /**
     * A flow the consumer closes is reset from what it remembered. Driven through the consumer:
     * the application's last segment carries the numbers, the egress goes offline, and the reset
     * that reaches the TUN has to be the vector's bytes.
     */
    @Test
    void resetsOnPurgeMatchTheSharedVector() throws IOException {
        JsonNode cases = vector().path("resetOnPurge").path("cases");
        assertFalse(cases.isEmpty(), "no purge cases");
        for (JsonNode testCase : cases) {
            List<byte[]> toTun = new ArrayList<>();
            PeerEgressConsumer consumer = new PeerEgressConsumer((egress, frame) -> true, toTun::add);
            PeerEgressRule rule = new PeerEgressRule();
            rule.setMatch("203.0.113.0/24");
            rule.setAction(PeerEgressRule.ACTION_EGRESS);
            rule.setEgressClientId(2L);
            consumer.configure(List.of(rule), PeerEgressRules.DEFAULT_MESH_CIDR, testCase.path("consumerIp").asText(), EPOCH);
            consumer.setEgressOnline(2L, true, EPOCH);
            // A segment with ACK and no payload leaves the application's next sequence at its
            // own sequence, and its acknowledgement where the case says.
            consumer.handleOutbound(PeerEgressSegment.build(new PeerEgressSegment.Segment(
                    address(testCase.path("consumerIp").asText()), address(testCase.path("remoteIp").asText()),
                    testCase.path("consumerPort").asInt(), testCase.path("remotePort").asInt(),
                    (int) testCase.path("appSeqNext").asLong(), (int) testCase.path("appAck").asLong(),
                    PeerEgressSegment.FLAG_ACK, 65535, 0, new byte[0])), EPOCH);
            toTun.clear();

            consumer.setEgressOnline(2L, false, EPOCH);

            assertEquals(1, toTun.size(), testCase.path("name").asText() + ": packets written");
            assertEquals(testCase.path("expect").path("packetHex").asText(), HexFormat.of().formatHex(toTun.get(0)),
                    testCase.path("name").asText());
        }
    }

    @Test
    void resetsOnPacketMatchTheSharedVector() throws IOException {
        JsonNode cases = vector().path("resetOnPacket").path("cases");
        assertFalse(cases.isEmpty(), "no packet cases");
        for (JsonNode testCase : cases) {
            byte[] packet = HexFormat.of().parseHex(testCase.path("packetHex").asText());
            byte[] answer = PeerEgressConsumer.failurePacket(packet, PeerEgressSegment.IPV4_PROTOCOL_TCP);
            assertEquals(testCase.path("expect").path("packetHex").asText(),
                    answer == null ? null : HexFormat.of().formatHex(answer), testCase.path("name").asText());
        }
    }

    @Test
    void unreachablesOnDatagramMatchTheSharedVector() throws IOException {
        JsonNode cases = vector().path("unreachableOnDatagram").path("cases");
        assertFalse(cases.isEmpty(), "no datagram cases");
        for (JsonNode testCase : cases) {
            byte[] packet = HexFormat.of().parseHex(testCase.path("packetHex").asText());
            byte[] answer = PeerEgressConsumer.failurePacket(packet, PeerEgressDatagram.IPV4_PROTOCOL_UDP);
            assertEquals(testCase.path("expect").path("packetHex").asText(),
                    answer == null ? null : HexFormat.of().formatHex(answer), testCase.path("name").asText());
        }
    }
}
