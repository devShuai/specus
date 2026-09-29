package com.theshuai.specusclient.peer;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.theshuai.common.peeregress.Ipv4Cidr;
import com.theshuai.common.peeregress.PeerEgressDns;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicLong;
import org.junit.jupiter.api.Test;

/**
 * The fake-IP pool, bound to the {@code pool} section of {@code peer-egress-dns-v1.json}: every
 * query and every packet in each case, at its time, against the address, name, eviction or
 * exhaustion the other clients produce for it.
 */
class PeerEgressFakeIpPoolTests {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final long EPOCH = 1_800_000_000_000L;

    static JsonNode vector() throws IOException {
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

    private static List<String> texts(JsonNode array) {
        List<String> out = new ArrayList<>();
        for (JsonNode item : array) {
            out.add(item.asText());
        }
        return out;
    }

    @Test
    void allocatesRefreshesEvictsAndQuarantinesAsTheSharedVectorSays() throws IOException {
        JsonNode cases = vector().path("pool");
        assertFalse(cases.isEmpty(), "no pool cases");
        for (JsonNode testCase : cases) {
            String name = testCase.path("name").asText();
            AtomicLong clock = new AtomicLong(EPOCH);
            PeerEgressFakeIpPool pool = new PeerEgressFakeIpPool(Ipv4Cidr.parse(testCase.path("cidr").asText()), clock::get);
            JsonNode events = testCase.path("events");
            JsonNode results = testCase.path("results");
            assertEquals(events.size(), results.size(), name);
            for (int index = 0; index < events.size(); index++) {
                JsonNode event = events.get(index);
                JsonNode expected = results.get(index);
                String where = name + " event " + index + " " + event;
                // The clock is what the responder's entry point reads; queries go through it.
                clock.set(EPOCH + event.path("at").asLong() * 1000);
                if (event.has("query")) {
                    PeerEgressFakeIpPool.Answer answer = pool.query(event.path("query").asText());
                    if (expected.path("exhausted").asBoolean(false)) {
                        assertTrue(answer.exhausted(), where);
                        assertNull(answer.address(), where);
                    } else {
                        assertFalse(answer.exhausted(), where);
                        assertEquals(expected.path("address").asText(), answer.addressText(), where);
                    }
                    assertEquals(texts(expected.path("evicted")), answer.evicted(), where);
                } else {
                    String produced = pool.traffic(Ipv4Cidr.parseAddress(event.path("traffic").asText()), clock.get());
                    if (expected.has("blocked")) {
                        assertEquals("fake-ip-unmapped", expected.path("blocked").asText(), where);
                        assertNull(produced, where);
                    } else {
                        assertEquals(expected.path("name").asText(), produced, where);
                    }
                }
            }
        }
    }

    /** The status counts, taken at the moment asked: a quarantine that has run out is not counted. */
    @Test
    void countsMappingsAndQuarantineAtTheTimeAsked() {
        PeerEgressFakeIpPool pool = new PeerEgressFakeIpPool(Ipv4Cidr.parse("198.18.0.0/30"), () -> EPOCH);
        pool.query("only.example", EPOCH);
        assertEquals(1, pool.mappings());
        assertEquals(0, pool.quarantined(EPOCH));

        long later = EPOCH + PeerEgressDns.MIN_MAPPING_LIFETIME_MS;
        assertTrue(pool.query("next.example", later).exhausted());
        assertEquals(0, pool.mappings());
        assertEquals(1, pool.quarantined(later));
        assertEquals(0, pool.quarantined(later + PeerEgressDns.QUARANTINE_MS));
    }

    /**
     * The responder's address, the network and the broadcast address are never handed out, and a
     * lookup for the status or a purge does not keep a mapping alive the way traffic does.
     */
    @Test
    void neverHandsOutTheReservedAddressesAndOnlyTrafficRefreshes() {
        PeerEgressFakeIpPool pool = new PeerEgressFakeIpPool(Ipv4Cidr.parse("198.18.0.0/29"), () -> EPOCH);
        List<String> handed = new ArrayList<>();
        for (int index = 0; index < 5; index++) {
            handed.add(pool.query("n" + index + ".example", EPOCH).addressText());
        }
        assertEquals(List.of("198.18.0.2", "198.18.0.3", "198.18.0.4", "198.18.0.5", "198.18.0.6"), handed);
        assertEquals("198.18.0.1", Ipv4Cidr.format(pool.listenAddress()));
        assertNull(pool.nameOf(Ipv4Cidr.parseAddress("198.18.0.1")));

        long idle = EPOCH + PeerEgressDns.MIN_MAPPING_LIFETIME_MS;
        // Looked up without refreshing: still idle when the pool fills.
        assertEquals("n0.example", pool.nameOf(Ipv4Cidr.parseAddress("198.18.0.2")));
        // Refreshed by traffic just before: kept.
        assertEquals("n1.example", pool.traffic(Ipv4Cidr.parseAddress("198.18.0.3"), idle - 1));
        PeerEgressFakeIpPool.Answer answer = pool.query("late.example", idle);
        assertTrue(answer.exhausted(), "the evicted addresses are in quarantine");
        assertEquals(List.of("n0.example", "n2.example", "n3.example", "n4.example"), answer.evicted());
        assertEquals("n1.example", pool.nameOf(Ipv4Cidr.parseAddress("198.18.0.3")));
    }
}
