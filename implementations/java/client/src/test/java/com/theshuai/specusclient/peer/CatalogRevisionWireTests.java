package com.theshuai.specusclient.peer;

import com.theshuai.common.clientauth.ClientAuthLoginResponse;
import com.theshuai.common.peermesh.PeerAdvertisedService;
import com.theshuai.common.peermesh.PeerControlMessage;
import com.theshuai.common.peermesh.PeerServiceSharingStatus;
import com.theshuai.common.util.JsonUtil;
import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class CatalogRevisionWireTests {
    @Test
    void publisherReconnectDoesNotResetConsumerHighWater() throws Exception {
        String directory = System.getenv("SPECUS_TEST_CATALOG_REVISION_WIRE_DIR");
        if (directory == null || directory.isBlank()) {
            replay("canonical", canonical());
        } else {
            // Require all four original producer outputs; never silently substitute fixtures.
            for (String producer : List.of("java", "go", "dotnet", "c")) {
                replay(producer, Files.readAllLines(Path.of(directory, producer + ".jsonl")));
            }
        }
    }

    private static void replay(String producer, List<String> wire) {
        assertEquals(5, wire.size(), producer);
        try (var runtime = new PeerServiceRuntime((name, message) -> {})) {
            var config = new ClientAuthLoginResponse.PeerMeshConfig();
            config.setServiceSharing(PeerServiceSharingStatus.of(true, true, true, false));
            runtime.applyConfig(config);
            runtime.setRosterLookup(id -> new PeerServiceRuntime.RosterHint("100.96.0.2", true));
            var messages = wire.stream().map(raw -> JsonUtil.stringToObject(raw, PeerControlMessage.class)).toList();
            var first = messages.getFirst();
            int[] counts = {1, 1, 0, 0, 1};
            for (int i = 0; i < messages.size(); i++) {
                var message = messages.get(i);
                assertEquals(PeerControlMessage.TYPE_SERVICE_CATALOG, message.getType());
                assertEquals(first.getPublisherClientId(), message.getPublisherClientId());
                assertEquals(first.getPublisherSessionId(), message.getPublisherSessionId());
                assertEquals((long) i + 1, message.getRevision());
                assertEquals(counts[i], message.getServices().size());
                if (counts[i] != 0) {
                    assertTrue(Instant.parse(message.getExpiresAt()).isAfter(Instant.now()),
                            "Captured catalogs expired: regenerate producers, do not rewrite wire timestamps");
                }
                runtime.applyCatalog(message);
                assertEquals(counts[i], runtime.remoteServices().size(), producer + " stage " + i);
            }
            // The same consumer remains live across withdrawal and publisher reconnect.
            runtime.applyCatalog(messages.get(1));
            runtime.applyCatalog(messages.get(3));
            assertEquals(1, runtime.remoteServices().size(), producer + " late data/withdrawal");
        }
        System.out.println("[catalog-revision-wire] " + producer + " -> java PASS (5 stages + 2 stale replays)");
    }

    private static List<String> canonical() {
        var service = new PeerAdvertisedService();
        service.setServiceId("svc-revision");
        service.setName("revision-service");
        service.setTransport("tcp");
        service.setApplication("http");
        service.setPublishedPort(18080);
        service.setPath("/");
        var wire = new ArrayList<String>();
        for (long revision = 1; revision <= 5; revision++) {
            var message = new PeerControlMessage();
            message.setType(PeerControlMessage.TYPE_SERVICE_CATALOG);
            message.setPublisherClientId(7301L);
            message.setPublisherSessionId(7381L);
            message.setRevision(revision);
            message.setExpiresAt(Instant.now().plusSeconds(300).toString());
            message.setServices(revision == 3 || revision == 4 ? List.of() : List.of(service));
            wire.add(JsonUtil.objectToString(message));
        }
        return wire;
    }
}
