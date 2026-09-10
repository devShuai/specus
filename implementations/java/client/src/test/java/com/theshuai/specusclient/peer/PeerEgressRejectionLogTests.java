package com.theshuai.specusclient.peer;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.theshuai.common.peeregress.PeerEgressCodes;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * Refusal accounting.
 *
 * <p>No shared vector here. What leaves the node is an aggregate per error code, which the report
 * schema already pins; the rest is local rate limiting, where two runtimes disagreeing changes how
 * much an operator reads on their own machine and produces no interop failure.
 */
class PeerEgressRejectionLogTests {

    private static final long EPOCH = 1_800_000_000_000L;

    /**
     * Rate limiting governs what an operator reads. It must never govern what the report counts, or
     * a busy period would look like the refusals had stopped.
     */
    @Test
    void countsEveryRefusalRegardlessOfLimiting() {
        PeerEgressRejectionLog log = new PeerEgressRejectionLog();
        int emitted = 0;
        for (int attempt = 0; attempt < PeerEgressRejectionLog.PER_WINDOW * 3; attempt++) {
            if (log.record(7, PeerEgressCodes.DEST_DENIED, EPOCH).shouldLog()) {
                emitted++;
            }
        }
        assertEquals(PeerEgressRejectionLog.PER_WINDOW, emitted, "emitted lines");

        Map<String, Long> counts = log.drainCounts();
        assertEquals((long) PeerEgressRejectionLog.PER_WINDOW * 3, counts.get(PeerEgressCodes.DEST_DENIED),
                "the aggregate must count every refusal");
    }

    /**
     * The spec limits by subject and reason together. One consumer hammering one rule must not
     * silence a different rule, or a different consumer.
     */
    @Test
    void limitsPerSubjectAndReason() {
        PeerEgressRejectionLog log = new PeerEgressRejectionLog();
        for (int attempt = 0; attempt < PeerEgressRejectionLog.PER_WINDOW; attempt++) {
            log.record(7, PeerEgressCodes.DEST_DENIED, EPOCH);
        }
        assertFalse(log.record(7, PeerEgressCodes.DEST_DENIED, EPOCH).shouldLog(),
                "the exhausted subject and reason still emitted");
        assertTrue(log.record(7, PeerEgressCodes.PORT_DENIED, EPOCH).shouldLog(),
                "a different reason was silenced by an exhausted one");
        assertTrue(log.record(9, PeerEgressCodes.DEST_DENIED, EPOCH).shouldLog(),
                "a different consumer was silenced by another consumer's traffic");
    }

    /**
     * A gap in the log with no explanation reads as the problem having gone away, so the next line
     * that does get written says how many it stands for.
     */
    @Test
    void reportsWhatItSuppressed() {
        PeerEgressRejectionLog log = new PeerEgressRejectionLog();
        for (int attempt = 0; attempt < PeerEgressRejectionLog.PER_WINDOW; attempt++) {
            assertEquals(0, log.record(7, PeerEgressCodes.DEST_DENIED, EPOCH).suppressed(),
                    "reported a suppression before anything was dropped");
        }
        for (int attempt = 0; attempt < 5; attempt++) {
            log.record(7, PeerEgressCodes.DEST_DENIED, EPOCH);
        }

        PeerEgressRejectionLog.Decision rolled =
                log.record(7, PeerEgressCodes.DEST_DENIED, EPOCH + PeerEgressRejectionLog.WINDOW_MS);
        assertTrue(rolled.shouldLog(), "the window did not roll over");
        assertEquals(5, rolled.suppressed());

        // The count belongs to the line that carried it, so the line after starts clean.
        assertEquals(0,
                log.record(7, PeerEgressCodes.DEST_DENIED, EPOCH + PeerEgressRejectionLog.WINDOW_MS).suppressed(),
                "the suppression count was reported twice");
    }

    /**
     * A peer that varies its identity would otherwise turn the limiter into a memory leak, which is
     * a worse outcome than the flooding the limiter exists to prevent.
     */
    @Test
    void boundsItsSubjectTable() {
        PeerEgressRejectionLog log = new PeerEgressRejectionLog();
        long attempts = PeerEgressRejectionLog.MAX_SUBJECTS + 500L;
        for (long consumer = 0; consumer < attempts; consumer++) {
            log.record(consumer, PeerEgressCodes.CONSUMER_DENIED, EPOCH);
        }
        assertTrue(log.subjectCount() <= PeerEgressRejectionLog.MAX_SUBJECTS,
                "subject table held " + log.subjectCount() + " entries");
        assertTrue(log.limited(), "hitting the cap was not recorded");

        // Reaching the cap costs diagnostic lines, never accuracy.
        assertEquals(attempts, log.drainCounts().get(PeerEgressCodes.CONSUMER_DENIED),
                "the aggregate must count every refusal even at the cap");
    }

    /**
     * Once the windows behind those entries elapse, the cap must stop biting rather than leaving
     * the limiter permanently full.
     */
    @Test
    void recoversAfterTheWindowElapses() {
        PeerEgressRejectionLog log = new PeerEgressRejectionLog();
        for (long consumer = 0; consumer < PeerEgressRejectionLog.MAX_SUBJECTS; consumer++) {
            log.record(consumer, PeerEgressCodes.CONSUMER_DENIED, EPOCH);
        }
        long later = EPOCH + PeerEgressRejectionLog.WINDOW_MS + 1000;
        assertTrue(log.record(999_999, PeerEgressCodes.CONSUMER_DENIED, later).shouldLog(),
                "a new subject was refused a line after every stale window had elapsed");
    }

    /**
     * Consecutive reports have to describe consecutive intervals. A running total would leave the
     * server differencing values it was never told were cumulative.
     */
    @Test
    void drainResetsTheInterval() {
        PeerEgressRejectionLog log = new PeerEgressRejectionLog();
        log.record(7, PeerEgressCodes.DEST_DENIED, EPOCH);
        log.record(7, PeerEgressCodes.PORT_DENIED, EPOCH);

        Map<String, Long> first = log.drainCounts();
        assertEquals(1L, first.get(PeerEgressCodes.DEST_DENIED));
        assertEquals(1L, first.get(PeerEgressCodes.PORT_DENIED));
        assertTrue(log.drainCounts().isEmpty(), "an interval with no refusals had something to send");

        log.record(7, PeerEgressCodes.DEST_DENIED, EPOCH);
        Map<String, Long> third = log.drainCounts();
        assertEquals(1, third.size(), "the third interval carried more than its own refusal");
        assertEquals(1L, third.get(PeerEgressCodes.DEST_DENIED));
    }
}
