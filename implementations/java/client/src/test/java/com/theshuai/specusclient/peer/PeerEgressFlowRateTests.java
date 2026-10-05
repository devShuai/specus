package com.theshuai.specusclient.peer;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.theshuai.common.peeregress.PeerEgressCodes;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;

/**
 * Binds the per-consumer new-flow bucket to {@code peer-egress-rate-v1.json}. Every runtime counts
 * in the same integer thousandths, so a flow at the edge of a refill is admitted or refused alike
 * everywhere.
 */
class PeerEgressFlowRateTests {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private static JsonNode vector() throws IOException {
        Path directory = Path.of("").toAbsolutePath();
        for (int depth = 0; depth < 8 && directory != null; depth++) {
            Path candidate = directory.resolve("protocol").resolve("test-vectors").resolve("peer-egress-rate-v1.json");
            if (Files.exists(candidate)) {
                return MAPPER.readTree(Files.readString(candidate));
            }
            directory = directory.getParent();
        }
        throw new IOException("cannot locate peer-egress-rate-v1.json");
    }

    @Test
    void admitsAsTheSharedVectorSays() throws IOException {
        JsonNode vector = vector();
        assertEquals(PeerEgressFlowRate.CAPACITY, vector.path("capacity").asInt());
        assertEquals(PeerEgressFlowRate.REFILL_PER_SECOND, vector.path("refillPerSecond").asInt());
        assertEquals(PeerEgressCodes.LIMIT_EXCEEDED, vector.path("refusalCode").asText());

        JsonNode events = vector.path("events");
        assertFalse(events.isEmpty(), "no rate events");
        PeerEgressFlowRate rate = new PeerEgressFlowRate();
        for (JsonNode event : events) {
            long consumer = event.path("consumer").asLong();
            long atMs = event.path("atMs").asLong();
            int flows = event.path("flows").asInt();
            int admitted = 0;
            for (int flow = 0; flow < flows; flow++) {
                if (rate.tryTake(consumer, atMs)) {
                    admitted++;
                }
            }
            assertEquals(event.path("admitted").asInt(), admitted, "admitted at " + event);
            assertEquals(event.path("refused").asInt(), flows - admitted, "refused at " + event);
        }
    }

    /**
     * Buckets that filled again are forgotten, so the map does not grow with every consumer that
     * ever opened a flow; one still refilling is kept, or forgetting it would hand that consumer a
     * full bucket early.
     */
    @Test
    void forgetsOnlyBucketsThatFilledAgain() {
        PeerEgressFlowRate rate = new PeerEgressFlowRate();
        for (int flow = 0; flow < PeerEgressFlowRate.CAPACITY; flow++) {
            assertTrue(rate.tryTake(1, 0));
        }
        for (long consumer = 2; consumer < 1000; consumer++) {
            assertTrue(rate.tryTake(consumer, 0));
        }
        // A second later the one-token buckets are full again and consumer 1's is half full.
        for (long consumer = 1000; consumer < 2000; consumer++) {
            assertTrue(rate.tryTake(consumer, 1000));
        }
        assertEquals(1 + 1000, rate.size(), "the buckets that filled again were kept");

        int admitted = 0;
        while (rate.tryTake(1, 1000)) {
            admitted++;
        }
        assertEquals(PeerEgressFlowRate.REFILL_PER_SECOND, admitted,
                "consumer 1's bucket was forgotten while it was still refilling");
    }
}
