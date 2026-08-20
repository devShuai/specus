package com.theshuai.specusserver.management.service;

import com.theshuai.common.protocol.request.MessageRequestPacket;
import com.theshuai.common.peermesh.PeerControlMessage;
import com.theshuai.common.peermesh.PeerServiceStats;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;

class PeerSignalServiceEnvelopeTests {

    @Test
    void acceptsIdentityFreeServiceReport() {
        assertDoesNotThrow(() -> PeerSignalService.validateServiceReportEnvelope(
                request("", "{\"type\":\"service-report\",\"enabled\":true,\"revision\":1,\"services\":[]}")));
    }

    @Test
    void rejectsOuterTargetAndEveryClientControlledIdentityFieldEvenWhenNull() {
        assertThrows(IllegalArgumentException.class, () -> PeerSignalService.validateServiceReportEnvelope(
                request("peer-b", "{\"type\":\"service-report\",\"enabled\":true,\"revision\":1,\"services\":[]}")));
        for (String field : List.of(
                "sourceClientId", "sourceClientName", "sourceVirtualIp", "sourcePublicKey", "sourceKeyEpoch",
                "targetClientId", "targetClientName", "targetVirtualIp", "targetPublicKey",
                "sessionId", "token", "publisherClientId", "publisherClientName", "publisherSessionId")) {
            String body = "{\"type\":\"service-report\",\"enabled\":true,\"revision\":1,\"services\":[],\""
                    + field + "\":null}";
            assertThrows(IllegalArgumentException.class,
                    () -> PeerSignalService.validateServiceReportEnvelope(request("", body)), field);
        }
    }

    @Test
    void rejectsOversizedRawAndPostDeserializeCollections() {
        assertThrows(IllegalArgumentException.class, () -> PeerSignalService.validateServiceReportEnvelope(
                request("", "{\"type\":\"service-report\",\"padding\":\"" + "x".repeat(16 * 1024) + "\"}")));
        PeerControlMessage report = new PeerControlMessage();
        report.setStats(java.util.stream.IntStream.range(0, 33).mapToObj(index -> {
            PeerServiceStats stats = new PeerServiceStats();
            stats.setServiceId("svc-stat" + String.format("%02d", index));
            return stats;
        }).toList());
        assertThrows(IllegalArgumentException.class,
                () -> PeerServiceDiscoveryService.validateReportCollections(report));
        report.setInstanceId("bad/instance");
        assertThrows(IllegalArgumentException.class,
                () -> PeerServiceDiscoveryService.validateReportCollections(report));
        report.setStats(List.of());
        report.setInstanceId("x".repeat(65));
        assertThrows(IllegalArgumentException.class,
                () -> PeerServiceDiscoveryService.validateReportCollections(report));
    }

    private static MessageRequestPacket request(String target, String body) {
        MessageRequestPacket request = new MessageRequestPacket();
        request.setToClientName(target);
        request.setMessage(body);
        return request;
    }
}
