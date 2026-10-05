package com.theshuai.specusclient.peer;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.theshuai.common.peeregress.PeerEgressReportMessage;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * Binds when this egress reports and what it says to {@code peer-egress-report-v1.json}.
 *
 * <p>The servers keep only the latest report and drop one whose revision is below the stored one,
 * so two runtimes that disagree here disagree on the admin page: one that counts revisions from 1
 * goes silent after a restart, one that reports intervals shows numbers nobody can read.
 */
class PeerEgressReportVectorTests {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private static JsonNode vector() throws IOException {
        Path directory = Path.of("").toAbsolutePath();
        for (int depth = 0; depth < 8 && directory != null; depth++) {
            Path candidate = directory.resolve("protocol").resolve("test-vectors").resolve("peer-egress-report-v1.json");
            if (Files.exists(candidate)) {
                return MAPPER.readTree(Files.readString(candidate));
            }
            directory = directory.getParent();
        }
        throw new IOException("cannot locate peer-egress-report-v1.json");
    }

    /** The egress section an event describes, as the runtime's snapshot would carry it. */
    private static PeerEgressStatus.RuntimeSnapshot snapshot(boolean active, JsonNode egress) {
        Map<String, Long> refused = new LinkedHashMap<>();
        for (Map.Entry<String, JsonNode> code : egress.path("refused").properties()) {
            refused.put(code.getKey(), code.getValue().asLong());
        }
        return new PeerEgressStatus.RuntimeSnapshot(active, 0L, egress.path("flows").asInt(),
                new PeerEgressRuntime.Stats(egress.path("totalFlows").asLong(), egress.path("bytesIn").asLong(),
                        egress.path("bytesOut").asLong()),
                refused);
    }

    @Test
    void checksAtTheVectorsInterval() throws IOException {
        assertEquals(vector().path("intervalSeconds").asLong() * 1000L, PeerEgressReporter.INTERVAL_MS);
    }

    /**
     * Every event in order through one reporter: a new session, or a check at a wall clock with
     * the egress switched on or off. A check sends exactly the vector's body, compared as parsed
     * JSON so no key is extra or missing, or sends nothing where the vector says null.
     */
    @Test
    void everyEventMatchesTheSharedVector() throws IOException {
        JsonNode events = vector().path("events");
        assertFalse(events.isEmpty(), "no events");
        PeerEgressReporter reporter = new PeerEgressReporter();
        int sent = 0;
        int quiet = 0;
        int sessions = 0;
        for (int index = 0; index < events.size(); index++) {
            JsonNode event = events.get(index);
            if (event.path("newSession").asBoolean(false)) {
                reporter.newSession();
                sessions++;
                continue;
            }
            PeerEgressReportMessage report = reporter.check(event.path("wallMs").asLong(),
                    snapshot(event.path("active").asBoolean(), event.path("egress")));
            JsonNode expected = event.path("report");
            if (expected.isNull()) {
                assertNull(report, "event " + index + " sent a report the vector does not");
                quiet++;
                continue;
            }
            assertNotNull(report, "event " + index + " sent nothing");
            assertEquals(expected, MAPPER.readTree(report.encode()), "event " + index + " body");
            sent++;
        }
        // The vector exercises both outcomes and a session change; a replay that skipped them would
        // prove nothing.
        assertTrue(sent > 0 && quiet > 0 && sessions > 0,
                "sent=" + sent + " quiet=" + quiet + " sessions=" + sessions);
    }

    /** The body is compact and in the spec's key order, as the vector writes it. */
    @Test
    void encodesInTheSpecsOrderWithoutWhitespace() {
        PeerEgressReportMessage report = new PeerEgressReportMessage(12, 18, 2140,
                Map.of("EGRESS_PORT_DENIED", 1L, "EGRESS_DEST_DENIED", 4L, "EGRESS_SCOPE_DENIED", 0L),
                10485760, 2097152);

        assertEquals("{\"type\":\"egress-report\",\"revision\":12,\"activeFlows\":18,\"totalFlows\":2140,"
                        + "\"rejectedFlows\":{\"EGRESS_DEST_DENIED\":4,\"EGRESS_PORT_DENIED\":1},"
                        + "\"bytesIn\":10485760,\"bytesOut\":2097152}",
                report.encode());
    }
}
