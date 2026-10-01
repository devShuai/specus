package com.theshuai.specusclient.peer;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;

/**
 * What a consumer keeps from {@code egress-catalog}, bound to the {@code catalog} section of
 * {@code peer-egress-dns-v1.json}: one reader fed every message in order, with the control session
 * renewed where the vector says, holding the same capable egresses after each step as the other
 * clients do.
 */
class PeerEgressCatalogTests {

    @Test
    void readsTheCatalogueAsTheSharedVectorSays() throws IOException {
        JsonNode cases = PeerEgressFakeIpPoolTests.vector().path("catalog");
        assertFalse(cases.isEmpty(), "no catalog cases");
        PeerEgressCatalog catalog = new PeerEgressCatalog();
        for (JsonNode testCase : cases) {
            String name = testCase.path("name").asText();
            if (testCase.path("newSession").asBoolean(false)) {
                catalog.newSession();
            } else {
                assertEquals(testCase.path("accepted").asBoolean(), catalog.read(testCase.path("json").asText()), name);
            }
            List<Long> expected = new ArrayList<>();
            for (JsonNode id : testCase.path("domainTargetCapable")) {
                expected.add(id.asLong());
            }
            assertEquals(expected, catalog.domainCapableIds(), name);
        }
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
}
