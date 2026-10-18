package com.theshuai.specusserver.management.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.theshuai.specusserver.management.model.ConnectionRecord;
import com.theshuai.specusserver.management.model.DisconnectReason;
import com.theshuai.specusserver.management.repository.ConnectionRecordRepository;
import com.theshuai.specusserver.websocket.ConnectionEvent;
import io.netty.channel.embedded.EmbeddedChannel;
import org.junit.jupiter.api.Test;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.jpa.domain.Specification;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

class DisconnectReasonsVectorTests {
    private static final ObjectMapper JSON = new ObjectMapper();

    @Test
    void sharedReasonsSurviveManagementAndWebSocketReadModels() throws Exception {
        Path root = Path.of("").toAbsolutePath();
        while (root != null && !Files.isRegularFile(root.resolve("protocol/test-vectors/disconnect-reasons-v1.json"))) {
            root = root.getParent();
        }
        assertNotNull(root, "shared vector must be present");
        JsonNode vector = JSON.readTree(Files.readString(root.resolve("protocol/test-vectors/disconnect-reasons-v1.json")));
        assertEquals(1, vector.path("version").asInt());
        assertEquals(17, vector.path("reasons").size());
        assertEquals(14, DisconnectReason.UNKNOWN.ordinal());
        var seen = new HashSet<String>();
        var repository = mock(ConnectionRecordRepository.class);
        var events = mock(ApplicationEventPublisher.class);
        var service = new ConnectionRecordService(repository, mock(ClientAccountService.class), events);
        var page = PageRequest.of(0, 100);
        for (JsonNode expected : vector.path("reasons")) {
            String code = expected.path("code").asText();
            assertTrue(seen.add(code), "duplicate code " + code);
            DisconnectReason reason = DisconnectReason.parse(code);
            assertEquals(code, reason.name(), "known code must not collapse to UNKNOWN");
            var record = record(code);
            when(repository.findAll(org.mockito.ArgumentMatchers.<Specification<ConnectionRecord>>any(), eq(page)))
                    .thenReturn(new PageImpl<>(List.of(record), page, 1));
            var view = service.listConnections(new ConnectionRecordService.ConnectionFilter(null, null, null, null), page)
                    .getContent().getFirst();
            assertReason(JSON.valueToTree(view), expected);
            // The same production mapper is also used for AFTER_COMMIT event payloads.
            when(repository.disconnectCurrent(eq(7L), anyString(), eq(code))).thenReturn(Optional.of(record));
            service.recordDisconnect(7L, reason);
            verify(events).publishEvent(argThat((Object event) -> event instanceof ConnectionEvent update
                    && JSON.valueToTree(update.connection()).path("disconnectReason").asText().equals(code)
                    && JSON.valueToTree(update.connection()).path("disconnectReasonText").asText()
                            .equals(expected.path("text").asText())));
        }
        assertEquals(new HashSet<>(Arrays.stream(DisconnectReason.values()).map(Enum::name).toList()), seen);
    }

    @Test
    void unsetUnknownAndFirstCloseCauseRetainTheirSemantics() {
        assertNull(DisconnectReason.parse(null));
        assertEquals(DisconnectReason.UNKNOWN, DisconnectReason.parse("FUTURE_REASON"));
        assertEquals(DisconnectReason.UNKNOWN, DisconnectReason.parse(""));
        var channel = new EmbeddedChannel();
        try {
            assertNull(DisconnectReason.readFrom(channel));
            DisconnectReason.markIfAbsent(channel, DisconnectReason.ADMIN_DISABLED);
            DisconnectReason.markIfAbsent(channel, DisconnectReason.AUTH_SOURCE_RETIRED);
            DisconnectReason.markIfAbsent(channel, DisconnectReason.SOURCE_PROCESS_GONE);
            assertEquals(DisconnectReason.ADMIN_DISABLED, DisconnectReason.readFrom(channel));
        } finally {
            channel.finishAndReleaseAll();
        }
    }

    private static ConnectionRecord record(String code) {
        var record = new ConnectionRecord();
        record.setId(7L);
        record.setClientName("vector-client");
        record.setConnectedAt("2026-10-16T00:00:00Z");
        record.setDisconnectedAt("2026-10-16T00:01:00Z");
        record.setSuccess(true);
        record.setDisconnectReason(code);
        return record;
    }

    private static void assertReason(JsonNode actual, JsonNode expected) {
        assertEquals(expected.path("code").asText(), actual.path("disconnectReason").asText());
        assertEquals(expected.path("text").asText(), actual.path("disconnectReasonText").asText());
    }
}
