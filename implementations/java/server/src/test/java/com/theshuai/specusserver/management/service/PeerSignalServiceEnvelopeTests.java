package com.theshuai.specusserver.management.service;

import com.theshuai.common.protocol.request.MessageRequestPacket;
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

    private static MessageRequestPacket request(String target, String body) {
        MessageRequestPacket request = new MessageRequestPacket();
        request.setToClientName(target);
        request.setMessage(body);
        return request;
    }
}
