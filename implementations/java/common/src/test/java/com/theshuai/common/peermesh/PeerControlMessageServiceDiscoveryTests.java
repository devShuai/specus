package com.theshuai.common.peermesh;

import com.fasterxml.jackson.databind.JsonNode;
import com.theshuai.common.util.JsonUtil;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PeerControlMessageServiceDiscoveryTests {

    @Test
    void unknownCatalogTypeRoundTripsWithoutTargetHost() {
        PeerControlMessage catalog = new PeerControlMessage();
        catalog.setType(PeerControlMessage.TYPE_SERVICE_CATALOG);
        catalog.setPublisherClientId(1L);
        catalog.setPublisherClientName("client-a");
        catalog.setPublisherSessionId(9L);
        catalog.setRevision(3L);
        catalog.setExpiresAt("2026-08-19T09:05:00Z");
        PeerAdvertisedService service = new PeerAdvertisedService();
        service.setServiceId("svc-ssh001");
        service.setName("ssh");
        service.setTransport("tcp");
        service.setApplication("ssh");
        service.setPublishedPort(2222);
        catalog.setServices(List.of(service));

        String json = JsonUtil.objectToString(catalog);
        JsonNode node = JsonUtil.readString(json);
        assertEquals("service-catalog", node.path("type").asText());
        assertFalse(json.contains("targetHost"));
        assertFalse(node.path("services").get(0).has("targetHost"));
        assertFalse(node.has("mdnsCandidates") && !node.path("mdnsCandidates").isEmpty());

        PeerControlMessage parsed = JsonUtil.stringToObject(json, PeerControlMessage.class);
        assertEquals(PeerControlMessage.TYPE_SERVICE_CATALOG, parsed.getType());
        assertEquals(1, parsed.getServices().size());
        assertEquals("svc-ssh001", parsed.getServices().getFirst().getServiceId());
    }

    @Test
    void unknownTypeDoesNotFailDeserialization() {
        PeerControlMessage parsed = JsonUtil.stringToObject(
                "{\"type\":\"future-signal\",\"sourceClientName\":\"a\"}", PeerControlMessage.class);
        assertEquals("future-signal", parsed.getType());
        assertTrue(parsed.getServices() == null || parsed.getServices().isEmpty());
    }
}
