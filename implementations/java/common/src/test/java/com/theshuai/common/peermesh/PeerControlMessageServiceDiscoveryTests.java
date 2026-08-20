package com.theshuai.common.peermesh;

import com.fasterxml.jackson.databind.JsonNode;
import com.theshuai.common.util.JsonUtil;
import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Path;
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

    @Test
    void realClientServiceReportOmitsServerBoundSessionAndUsesV2Applications() {
        PeerControlMessage report = new PeerControlMessage();
        report.setType(PeerControlMessage.TYPE_SERVICE_REPORT);
        report.setEnabled(true);
        report.setRevision(1L);
        report.setInstanceId("fixture-java");
        report.setGeneratedAt("2026-08-20T02:00:00Z");
        report.setExpiresAt("2026-08-20T02:05:00Z");
        report.setCreatedAtMillis(1787191200000L);
        PeerAdvertisedService service = new PeerAdvertisedService();
        service.setServiceId("svc-wire01");
        service.setName("fixture-http");
        service.setDescription("wire fixture");
        service.setTransport("tcp");
        service.setApplication("http");
        service.setPublishedPort(18080);
        service.setPath("/health");
        report.setServices(List.of(service));

        JsonNode node = JsonUtil.readString(JsonUtil.objectToString(report));
        JsonNode vectors = readVector();

        assertEquals("service-report", node.path("type").asText());
        assertEquals(vectors.path("serviceReports").path("java"), node,
                "the shared fixture must be produced by the real Java wire DTO");
        for (String field : List.of(
                "sourceClientId", "sourceClientName", "sourceVirtualIp", "sourcePublicKey", "sourceKeyEpoch",
                "targetClientId", "targetClientName", "targetVirtualIp", "targetPublicKey",
                "sessionId", "token", "publisherClientId", "publisherClientName", "publisherSessionId")) {
            assertFalse(node.has(field), field);
        }
        assertEquals(2, PeerServiceDiscovery.PROTOCOL_VERSION);
        assertEquals(JsonUtil.stringToObject(vectors.path("applications").toString(), List.class),
                PeerServiceDiscovery.APPLICATIONS);
    }

    private static JsonNode readVector() {
        Path current = Path.of("").toAbsolutePath();
        for (int depth = 0; current != null && depth < 10; depth++, current = current.getParent()) {
            Path candidate = current.resolve("protocol/test-vectors/peer-service-discovery-v2.json");
            if (Files.isRegularFile(candidate)) {
                try {
                    return JsonUtil.readString(Files.readString(candidate));
                } catch (Exception exception) {
                    throw new IllegalStateException("cannot read peer service wire vector", exception);
                }
            }
        }
        throw new IllegalStateException("cannot locate peer service wire vector");
    }
}
