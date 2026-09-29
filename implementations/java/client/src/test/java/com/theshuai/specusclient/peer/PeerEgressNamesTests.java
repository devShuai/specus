package com.theshuai.specusclient.peer;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.theshuai.common.peeregress.Ipv4Cidr;
import com.theshuai.common.peeregress.PeerEgressCodes;
import com.theshuai.common.peeregress.PeerEgressFrame;
import com.theshuai.common.peeregress.PeerEgressNames;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * Phase two on the egress side, bound to {@code peer-egress-dns-v1.json}: the name-bind a consumer
 * sends, and the address an egress picks for a name.
 */
class PeerEgressNamesTests {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private static JsonNode vector() throws IOException {
        Path directory = Path.of("").toAbsolutePath();
        for (int depth = 0; depth < 8 && directory != null; depth++) {
            Path candidate = directory.resolve("protocol").resolve("test-vectors").resolve("peer-egress-dns-v1.json");
            if (Files.exists(candidate)) {
                return MAPPER.readTree(Files.readString(candidate));
            }
            directory = directory.getParent();
        }
        throw new IOException("cannot locate peer-egress-dns-v1.json");
    }

    /** name-bind is encoded byte for byte as the other runtimes encode it, with the name normalised. */
    @Test
    void nameBindMatchesTheSharedVector() throws IOException {
        for (JsonNode testCase : vector().get("nameBind")) {
            String name = testCase.get("name").asText();
            byte[] body = PeerEgressFrame.encodeControl(PeerEgressFrame.Control.nameBind(
                    testCase.get("address").asText(), testCase.get("domain").asText()));
            assertEquals(testCase.get("json").asText(), new String(body, StandardCharsets.UTF_8), name);
            PeerEgressFrame.Decoded frame = PeerEgressFrame.parse(
                    PeerEgressFrame.encode(PeerEgressFrame.TYPE_CONTROL, false, body));
            assertNull(frame.code(), name + ": the encoded binding does not validate");
        }
    }

    /**
     * The egress dials the first resolved address the policy allows. This build resolves IPv4 only
     * and does not announce IPv6 targets, so a case that expects an AAAA address is one it answers as
     * unresolved; every other case must match the vector exactly.
     */
    @Test
    void addressChoiceMatchesTheSharedVector() throws IOException {
        for (JsonNode testCase : vector().get("egressChoice")) {
            String name = testCase.get("name").asText();
            List<Integer> a = new ArrayList<>();
            for (JsonNode item : testCase.get("a")) {
                a.add(Ipv4Cidr.parseAddress(item.asText()));
            }
            JsonNode decisions = testCase.get("decisions");
            PeerEgressRuntime.Choice choice = PeerEgressRuntime.chooseAddress(a, address -> {
                String code = decisions.get(Ipv4Cidr.format(address)).asText();
                return PeerEgressCodes.ALLOWED.equals(code) ? null : code;
            });
            if (a.isEmpty() && testCase.get("aaaa").size() > 0 && testCase.get("ipv6TargetCapable").asBoolean()) {
                assertEquals(PeerEgressCodes.NAME_UNRESOLVED, choice.code(),
                        name + ": an IPv4-only egress should find nothing to dial");
                continue;
            }
            assertEquals(testCase.get("code").asText(),
                    choice.code() == null ? PeerEgressCodes.ALLOWED : choice.code(), name + ": code");
            JsonNode expected = testCase.get("address");
            if (expected.isTextual()) {
                assertEquals(expected.asText(), Ipv4Cidr.format(choice.address()), name + ": address");
            }
        }
    }

    @Test
    void validatesNames() {
        Map<String, Boolean> cases = Map.of(
                "example.com", true, "WWW.Example.COM.", true, "xn--fiqs8s.example", true,
                "localhost", false, "*.example.com", false, "a_b.example.com", false,
                "-a.example", false, "1.2.3.4", false, "", false, "\u4e2d\u56fd.example", false);
        cases.forEach((name, valid) -> assertEquals(valid, PeerEgressNames.valid(name), name));
    }

    @Test
    void refusesAMalformedNameBind() {
        for (String body : List.of(
                "{\"type\":\"name-bind\"}",
                "{\"type\":\"name-bind\",\"address\":\"198.18.0.5\"}",
                "{\"type\":\"name-bind\",\"address\":\"not-an-address\",\"name\":\"example.com\"}",
                "{\"type\":\"name-bind\",\"address\":\"198.18.0.5\",\"name\":\"*.example.com\"}")) {
            PeerEgressFrame.Decoded frame = PeerEgressFrame.parse(PeerEgressFrame.encode(
                    PeerEgressFrame.TYPE_CONTROL, false, body.getBytes(StandardCharsets.UTF_8)));
            assertEquals(PeerEgressCodes.FRAME_MALFORMED_CONTROL, frame.code(), body);
        }
    }

    @Test
    void keepsBindingsByRecentUseWithinTheCaps() {
        PeerEgressNameTable table = new PeerEgressNameTable();
        for (int address = 1; address <= PeerEgressNameTable.CAPACITY_PER_CONSUMER; address++) {
            table.bind(7, address, "example.com");
        }
        table.lookup(7, 1);
        table.bind(7, PeerEgressNameTable.CAPACITY_PER_CONSUMER + 1, "late.example");
        assertNotNull(table.lookup(7, 1), "the binding just used was evicted");
        assertNull(table.lookup(7, 2), "the least recently used binding survived a full table");

        table.bind(9, 1, "other.example");
        table.dropConsumer(7);
        assertEquals(1, table.size());
        assertEquals("other.example", table.lookup(9, 1));
        assertTrue(table.size() <= PeerEgressNameTable.CAPACITY);
    }
}
