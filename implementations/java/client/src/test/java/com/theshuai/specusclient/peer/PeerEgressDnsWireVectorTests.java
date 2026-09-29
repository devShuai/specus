package com.theshuai.specusclient.peer;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.theshuai.common.peeregress.Ipv4Cidr;
import com.theshuai.common.peeregress.PeerEgressRule;
import com.theshuai.common.peeregress.PeerEgressRules;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * The responder's wire format, bound to the {@code wire} and {@code answers} sections of
 * {@code peer-egress-dns-v1.json}: every query in every case through {@link PeerEgressDnsMessage},
 * against the drop, the forward, or the answer the other clients build, byte for byte.
 */
class PeerEgressDnsWireVectorTests {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final long EPOCH = 1_800_000_000_000L;
    private static final HexFormat HEX = HexFormat.of();

    static List<PeerEgressRule> rules(JsonNode document) throws IOException {
        List<PeerEgressRule> rules = new ArrayList<>();
        for (JsonNode node : document.path("rules")) {
            rules.add(MAPPER.treeToValue(node, PeerEgressRule.class));
        }
        return rules;
    }

    @Test
    void constantsMatchTheSharedVector() throws IOException {
        JsonNode document = PeerEgressFakeIpPoolTests.vector();
        assertEquals(document.path("responderAnswerTtlSeconds").asInt(), PeerEgressDnsMessage.ANSWER_TTL);
        assertEquals(document.path("responderEdnsPayload").asInt(), PeerEgressDnsMessage.EDNS_PAYLOAD);
    }

    @Test
    void answersEveryWireQueryAsTheSharedVectorSays() throws IOException {
        JsonNode document = PeerEgressFakeIpPoolTests.vector();
        List<PeerEgressRule> rules = rules(document);
        JsonNode cases = document.path("wire");
        assertFalse(cases.isEmpty(), "no wire cases");
        int checked = 0;
        for (JsonNode testCase : cases) {
            PeerEgressFakeIpPool pool = new PeerEgressFakeIpPool(Ipv4Cidr.parse(testCase.path("cidr").asText()), () -> EPOCH);
            JsonNode events = testCase.path("events");
            JsonNode results = testCase.path("results");
            assertEquals(events.size(), results.size());
            for (int index = 0; index < events.size(); index++) {
                JsonNode event = events.get(index);
                JsonNode expected = results.get(index);
                String where = testCase.path("name").asText() + " " + event.path("name").asText();
                PeerEgressDnsMessage.Result result = PeerEgressDnsMessage.respond(rules,
                        PeerEgressRules.DEFAULT_MESH_CIDR, pool, HEX.parseHex(event.path("query").asText()),
                        EPOCH + event.path("at").asLong() * 1000);
                assertEquals(expected.path("result").asText(), result.kind().name().toLowerCase(), where);
                if (expected.has("response")) {
                    assertEquals(expected.path("response").asText(), HEX.formatHex(result.response()), where);
                } else {
                    assertNull(result.response(), where);
                }
                assertEquals(expected.path("exhausted").asBoolean(false), result.exhausted(), where);
                checked++;
            }
        }
        assertTrue(checked >= 25, "only " + checked + " wire events");
    }

    /** The answer each name and type gets, through the same code the wire goes through. */
    @Test
    void decidesEveryAnswerCaseAsTheSharedVectorSays() throws IOException {
        JsonNode document = PeerEgressFakeIpPoolTests.vector();
        List<PeerEgressRule> rules = rules(document);
        Map<String, Integer> types = Map.of("A", 1, "AAAA", 28, "HTTPS", 65, "SVCB", 64, "ANY", 255, "MX", 15);
        for (JsonNode testCase : document.path("answers")) {
            String where = testCase.path("name").asText();
            PeerEgressFakeIpPool pool = new PeerEgressFakeIpPool(Ipv4Cidr.parse(document.path("fakeIpCidr").asText()), () -> EPOCH);
            byte[] query = query(0x4242, testCase.path("query").asText(), types.get(testCase.path("type").asText()));
            PeerEgressDnsMessage.Result result = PeerEgressDnsMessage.respond(rules, PeerEgressRules.DEFAULT_MESH_CIDR,
                    pool, query, EPOCH);
            switch (testCase.path("answer").asText()) {
                case "forward" -> assertEquals(PeerEgressDnsMessage.Kind.FORWARD, result.kind(), where);
                case "nodata" -> {
                    assertEquals(PeerEgressDnsMessage.Kind.ANSWER, result.kind(), where);
                    assertEquals(0x8180, PeerEgressDnsMessage.u16(result.response(), 2), where);
                    assertEquals(0, PeerEgressDnsMessage.u16(result.response(), 6), where + ": NODATA has answers");
                }
                case "fake" -> {
                    assertEquals(PeerEgressDnsMessage.Kind.ANSWER, result.kind(), where);
                    assertEquals(1, PeerEgressDnsMessage.u16(result.response(), 6), where);
                    assertEquals(1, pool.mappings(), where + ": no mapping was made");
                }
                default -> throw new IllegalStateException(where);
            }
        }
    }

    /**
     * A forward that got no reply is answered SERVFAIL by the same rules as any built answer: one
     * readable question copied as asked and EDNS answered with EDNS; otherwise the header alone,
     * question count zero.
     */
    @Test
    void buildsServfailForAFailedForward() {
        // OPT: the root name, type 41, a payload of 4096, no extended RCODE or flags, no data.
        byte[] asked = HEX.parseHex("abcd0100000100000000000103577777076578616d706c6503636f6d00000f0001"
                + "00" + "0029" + "1000" + "00000000" + "0000");
        assertEquals("abcd8182000100000000000103577777076578616d706c6503636f6d00000f0001"
                + "000029" + "04d0" + "00000000" + "0000", HEX.formatHex(PeerEgressDnsMessage.servfail(asked)));

        // Another opcode is forwarded; its failure still copies the opcode and the one question.
        byte[] opcode = HEX.parseHex("beef1100000100000000000003777777076578616d706c6503636f6d0000010001");
        assertEquals("beef9182000100000000000003777777076578616d706c6503636f6d0000010001",
                HEX.formatHex(PeerEgressDnsMessage.servfail(opcode)));

        // Two questions, a pointer in the question, a question cut short, none at all: the header.
        String question = "03777777076578616d706c6503636f6d0000010001";
        for (String header : List.of(
                "000201000002000000000000" + question + question,
                "000301000001000000000001" + "c00c00010001" + "00002910000000000000",
                "000401000001000000000000" + "0377",
                "000501000000000000000000")) {
            byte[] failed = PeerEgressDnsMessage.servfail(HEX.parseHex(header));
            assertEquals(12, failed.length, header);
            assertArrayEquals(HEX.parseHex(header.substring(0, 4) + "8182" + "0000000000000000"), failed, header);
        }
    }

    /** A query as a stub resolver writes it: RD set, one question of class IN. */
    static byte[] query(int id, String name, int type) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(id >>> 8);
        out.write(id);
        out.writeBytes(new byte[] {1, 0, 0, 1, 0, 0, 0, 0, 0, 0});
        out.writeBytes(PeerEgressDnsMessage.encodeName(name));
        out.write(type >>> 8);
        out.write(type);
        out.writeBytes(new byte[] {0, 1});
        return out.toByteArray();
    }
}
