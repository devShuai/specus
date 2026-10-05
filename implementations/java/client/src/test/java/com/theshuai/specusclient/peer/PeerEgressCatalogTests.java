package com.theshuai.specusclient.peer;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import org.junit.jupiter.api.Test;

/**
 * What a consumer keeps from {@code egress-catalog}, bound to the {@code catalog} section of
 * {@code peer-egress-dns-v1.json}: one reader fed every message in order, with the control session
 * renewed where the vector says, holding the same capable egresses, the same listed egresses and
 * the same egressVersions after each step as the other clients do.
 */
class PeerEgressCatalogTests {

    private static final long EPOCH = 1_800_000_000_000L;

    private static List<Long> ids(JsonNode array) {
        List<Long> out = new ArrayList<>();
        for (JsonNode id : array) {
            out.add(id.asLong());
        }
        return out;
    }

    @Test
    void readsTheCatalogueAsTheSharedVectorSays() throws IOException {
        JsonNode cases = PeerEgressFakeIpPoolTests.vector().path("catalog");
        assertFalse(cases.isEmpty(), "no catalog cases");
        PeerEgressCatalog catalog = new PeerEgressCatalog();
        boolean sawVersions = false;
        for (JsonNode testCase : cases) {
            String name = testCase.path("name").asText();
            if (testCase.path("newSession").asBoolean(false)) {
                catalog.newSession(EPOCH);
                assertFalse(catalog.snapshot().received(), name + ": a new session still counts the old catalogue");
            } else {
                assertEquals(testCase.path("accepted").asBoolean(), catalog.read(testCase.path("json").asText()), name);
            }
            assertEquals(ids(testCase.path("domainTargetCapable")), catalog.domainCapableIds(), name);
            assertTrue(testCase.has("listed") && testCase.has("egressVersion"), name + ": the vector predates listed");
            assertEquals(ids(testCase.path("listed")), catalog.listedIds(), name + ": listed");
            Map<Long, Long> versions = new TreeMap<>();
            testCase.path("egressVersion").fields().forEachRemaining(
                    field -> versions.put(Long.parseLong(field.getKey()), field.getValue().asLong()));
            assertEquals(versions, new TreeMap<>(catalog.egressVersions()), name + ": egressVersion");
            sawVersions |= !versions.isEmpty();
            // The snapshot the consumer judges by says the same.
            PeerEgressCatalog.Snapshot snapshot = catalog.snapshot();
            assertEquals(ids(testCase.path("listed")), new ArrayList<>(new java.util.TreeSet<>(snapshot.listed())), name);
            assertEquals(versions, new TreeMap<>(snapshot.egressVersions()), name);
        }
        assertTrue(sawVersions, "no case carries an egressVersion");
    }

    /** A catalogue is not a policy, nor the other way round; neither reader takes the other's message. */
    @Test
    void takesOnlyItsOwnType() {
        PeerEgressCatalog catalog = new PeerEgressCatalog();
        assertTrue(catalog.read("{\"type\":\"egress-catalog\",\"revision\":1,\"egresses\":[{\"clientId\":2,\"domainTargetCapable\":true}]}"));
        assertFalse(catalog.read("{\"type\":\"egress-config\",\"revision\":2,\"enabled\":true}"));
        assertFalse(catalog.read(null));
        assertEquals(List.of(2L), catalog.domainCapableIds());
        assertEquals(1L, catalog.revision());
    }

    /**
     * A later entry for the same egress replaces an earlier one whole, version included; a version
     * too large for a long is still one of at least 1.
     */
    @Test
    void aLaterEntryReplacesAnEarlierOne() {
        PeerEgressCatalog catalog = new PeerEgressCatalog();
        assertTrue(catalog.read("{\"type\":\"egress-catalog\",\"revision\":1,\"egresses\":["
                + "{\"clientId\":2,\"egressVersion\":0},{\"clientId\":2},"
                + "{\"clientId\":3,\"egressVersion\":1},{\"clientId\":3,\"egressVersion\":0},"
                + "{\"clientId\":4,\"egressVersion\":1.0},{\"clientId\":5,\"egressVersion\":99999999999999999999}]}"));
        assertEquals(List.of(2L, 3L, 4L, 5L), catalog.listedIds());
        assertEquals(Map.of(3L, 0L, 5L, Long.MAX_VALUE), catalog.egressVersions());
        PeerEgressCatalog.Snapshot snapshot = catalog.snapshot();
        assertEquals(PeerEgressCatalog.Standing.OFFERED, snapshot.standing(2L));
        assertEquals(PeerEgressCatalog.Standing.UNSUPPORTED, snapshot.standing(3L));
        assertEquals(PeerEgressCatalog.Standing.OFFERED, snapshot.standing(4L));
        assertEquals(PeerEgressCatalog.Standing.OFFERED, snapshot.standing(5L));
        assertEquals(PeerEgressCatalog.Standing.NOT_OFFERED, snapshot.standing(6L));
    }

    /**
     * The status's catalog state on the reader's own clock: waiting before any control session and
     * for the vector's wait after one, none after that, received once a catalogue is accepted, and
     * waiting again in the next session. A clock that steps back keeps it waiting.
     */
    @Test
    void theStateWaitsThenSaysNone() throws IOException {
        long wait = PeerEgressStandingVectorTests.vector().path("catalogWaitSeconds").asLong() * 1000L;
        PeerEgressCatalog catalog = new PeerEgressCatalog();
        assertEquals("waiting", catalog.state(EPOCH));
        catalog.newSession(EPOCH);
        assertEquals("waiting", catalog.state(EPOCH + wait - 1));
        assertEquals("none", catalog.state(EPOCH + wait));
        assertEquals("waiting", catalog.state(EPOCH - 1));
        assertFalse(catalog.read("{\"type\":\"egress-catalog\",\"revision\":\"1\"}"));
        assertEquals("none", catalog.state(EPOCH + wait), "a refused catalogue counted as received");
        assertTrue(catalog.read("{\"type\":\"egress-catalog\",\"revision\":1}"));
        assertEquals("received", catalog.state(EPOCH + wait));
        assertTrue(catalog.snapshot().received());
        // An empty catalogue is a catalogue: it offers nothing.
        assertEquals(PeerEgressCatalog.Standing.NOT_OFFERED, catalog.snapshot().standing(2L));

        catalog.newSession(EPOCH + 2 * wait);
        assertEquals("waiting", catalog.state(EPOCH + 2 * wait));
        assertEquals(PeerEgressCatalog.Standing.UNKNOWN, catalog.snapshot().standing(2L));
        assertEquals("none", catalog.state(EPOCH + 3 * wait));
    }
}
