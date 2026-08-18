package com.theshuai.specus.android;

import org.junit.Test;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

/**
 * The non-blocking submission path.
 *
 * {@link StreamFlowScheduler#send} parks until credit arrives, which is correct on a thread that
 * serves one stream and fatal on a Netty event loop shared by all of them. These tests pin the
 * property that matters: submitting never waits, no matter how starved the stream is.
 */
public class StreamFlowSubmitTest {
    @Test
    public void submitDoesNotWaitForCreditTheWaySendDoes() throws Exception {
        try (StreamFlowScheduler scheduler = new StreamFlowScheduler()) {
            assertTrue(scheduler.open(21));
            exhaustCredit(scheduler, 21);

            AtomicInteger sent = new AtomicInteger();
            long start = System.nanoTime();
            StreamFlowScheduler.Submission submission =
                    scheduler.submit(21, 128, sent::incrementAndGet);
            long elapsedMillis = (System.nanoTime() - start) / 1_000_000L;

            assertTrue("submit blocked for " + elapsedMillis + "ms", elapsedMillis < 500L);
            assertFalse("nothing may be written without credit", submission.completion().isDone());
            assertEquals(0, sent.get());

            // Credit arriving is what releases it, and the future is how the caller finds out.
            assertTrue(scheduler.addCredit(21, 128));
            submission.completion().get(2, TimeUnit.SECONDS);
            assertEquals(1, sent.get());
        }
    }

    @Test
    public void submitReportsSaturationSoTheCallerCanStopReading() throws Exception {
        try (StreamFlowScheduler scheduler = new StreamFlowScheduler()) {
            assertTrue(scheduler.open(22));
            exhaustCredit(scheduler, 22);

            boolean sawSaturation = false;
            int queued = 0;
            while (queued * StreamFlowScheduler.MAX_CHUNK_BYTES
                    < StreamFlowScheduler.SATURATION_BYTES + StreamFlowScheduler.MAX_CHUNK_BYTES) {
                StreamFlowScheduler.Submission submission = scheduler.submit(
                        22, StreamFlowScheduler.MAX_CHUNK_BYTES, () -> { });
                queued++;
                if (submission.saturated()) {
                    sawSaturation = true;
                    break;
                }
            }
            assertTrue("the caller was never told to stop", sawSaturation);
            assertTrue(scheduler.saturated(22));
        }
    }

    @Test
    public void submitRefusesOnceThePerStreamQueueIsFull() throws Exception {
        try (StreamFlowScheduler scheduler = new StreamFlowScheduler()) {
            assertTrue(scheduler.open(23));
            exhaustCredit(scheduler, 23);

            int chunk = StreamFlowScheduler.MAX_CHUNK_BYTES;
            int accepted = 0;
            IOException refusal = null;
            for (int i = 0; i < StreamFlowScheduler.MAX_PENDING_BYTES / chunk + 4; i++) {
                try {
                    scheduler.submit(23, chunk, () -> { });
                    accepted++;
                } catch (IOException error) {
                    refusal = error;
                    break;
                }
            }
            assertTrue("the queue accepted nothing", accepted > 0);
            assertTrue("an unbounded queue would never refuse", refusal != null);
            assertTrue((long) accepted * chunk <= StreamFlowScheduler.MAX_PENDING_BYTES);
        }
    }

    /** Per-stream limits alone let N streams hold N times the limit; the total is capped too. */
    @Test
    public void submitRefusesOnceTheTotalBudgetIsSpent() throws Exception {
        try (StreamFlowScheduler scheduler = new StreamFlowScheduler()) {
            int chunk = StreamFlowScheduler.MAX_CHUNK_BYTES;
            int streams = StreamFlowScheduler.MAX_TOTAL_PENDING_BYTES
                    / StreamFlowScheduler.MAX_PENDING_BYTES + 4;
            boolean refusedForTotal = false;

            outer:
            for (int streamId = 100; streamId < 100 + streams; streamId++) {
                assertTrue(scheduler.open(streamId));
                // Credit is spent by submitting, so the refusal can land here as easily as in the
                // fill loop below; either way it is the process-wide budget talking.
                for (int i = 0; i < StreamFlowScheduler.MAX_PENDING_BYTES / chunk; i++) {
                    try {
                        scheduler.submit(streamId, chunk, () -> { });
                    } catch (IOException error) {
                        if (error.getMessage().contains("total")) {
                            refusedForTotal = true;
                            break outer;
                        }
                        break;
                    }
                }
            }

            assertTrue("streams could exceed the process-wide budget", refusedForTotal);
            assertTrue(scheduler.totalPendingBytes()
                    <= StreamFlowScheduler.MAX_TOTAL_PENDING_BYTES);
        }
    }

    /**
     * A FIN queued behind starved data still waits for that data, which is what keeps the FIN after
     * the bytes it terminates. The caller submitting it must not wait alongside it.
     */
    @Test
    public void submitFinishReturnsImmediatelyAndFiresOnceTheQueueDrains() throws Exception {
        try (StreamFlowScheduler scheduler = new StreamFlowScheduler()) {
            assertTrue(scheduler.open(24));
            exhaustCredit(scheduler, 24);
            scheduler.submit(24, 1024, () -> { });

            CountDownLatch finSent = new CountDownLatch(1);
            long start = System.nanoTime();
            CompletableFuture<Void> completion = scheduler.submitFinish(24, finSent::countDown);
            long elapsedMillis = (System.nanoTime() - start) / 1_000_000L;

            assertTrue("submitFinish blocked for " + elapsedMillis + "ms", elapsedMillis < 500L);
            assertFalse("the FIN must not overtake the data ahead of it", completion.isDone());
            assertFalse(finSent.await(200, TimeUnit.MILLISECONDS));

            // Credit for the queued chunk lets it drain, and the FIN follows.
            assertTrue(scheduler.addCredit(24, 1024));
            completion.get(5, TimeUnit.SECONDS);
            assertTrue(finSent.await(2, TimeUnit.SECONDS));
        }
    }

    @Test
    public void submitRejectsUnknownAndClosedStreams() throws Exception {
        try (StreamFlowScheduler scheduler = new StreamFlowScheduler()) {
            assertThrows(IOException.class, () -> scheduler.submit(99, 16, () -> { }));

            assertTrue(scheduler.open(25));
            assertThrows(IOException.class, () -> scheduler.submit(25, 0, () -> { }));
            assertThrows(IOException.class, () -> scheduler.submit(
                    25, StreamFlowScheduler.MAX_CHUNK_BYTES + 1, () -> { }));
            assertThrows(IOException.class, () -> scheduler.submit(25, 16, null));

            scheduler.closeStream(25);
            assertThrows(IOException.class, () -> scheduler.submit(25, 16, () -> { }));
            assertFalse(scheduler.saturated(25));
        }
    }

    /**
     * Spends the initial window using the non-blocking path.
     *
     * The blocking {@link StreamFlowScheduler#send} would park here as soon as an earlier stream in
     * the same test had spent the process-wide budget, since nothing ever drains a queue that has
     * no credit. Submitting cannot park, so the helper works no matter how starved the scheduler is.
     */
    private static void exhaustCredit(StreamFlowScheduler scheduler, int streamId)
            throws Exception {
        int chunk = StreamFlowScheduler.MAX_CHUNK_BYTES;
        long remaining = StreamFlowScheduler.INITIAL_BYTES;
        List<CompletableFuture<Void>> writes = new ArrayList<>();
        while (remaining > 0) {
            int bytes = (int) Math.min(chunk, remaining);
            writes.add(scheduler.submit(streamId, bytes, () -> { }).completion());
            remaining -= bytes;
        }
        // These have credit, so they all drain; waiting keeps the queue empty for the assertions.
        CompletableFuture.allOf(writes.toArray(new CompletableFuture[0])).get(10, TimeUnit.SECONDS);
    }
}
