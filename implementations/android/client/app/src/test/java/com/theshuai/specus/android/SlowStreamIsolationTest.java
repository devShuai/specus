package com.theshuai.specus.android;

import org.junit.Test;

import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

/**
 * One starved stream must not hold up the others.
 *
 * The scheduler is shared: a single worker drains every stream. If a stream without credit could
 * hold the head of the queue, or if a submitting thread parked waiting for it, the peer that simply
 * stops sending WINDOW_UPDATE would freeze the whole connection. These tests pin the isolation.
 */
public class SlowStreamIsolationTest {
    @Test
    public void aStarvedStreamDoesNotDelayAHealthyOne() throws Exception {
        try (StreamFlowScheduler scheduler = new StreamFlowScheduler()) {
            int starved = 31;
            int healthy = 32;
            assertTrue(scheduler.open(starved));
            assertTrue(scheduler.open(healthy));
            spendInitialWindow(scheduler, starved);

            // Queue behind the starved stream: nothing here can move until credit arrives.
            AtomicInteger starvedWrites = new AtomicInteger();
            StreamFlowScheduler.Submission blocked =
                    scheduler.submit(starved, 4096, starvedWrites::incrementAndGet);

            // The healthy stream still has its whole window.
            CountDownLatch healthyWrite = new CountDownLatch(1);
            StreamFlowScheduler.Submission moving =
                    scheduler.submit(healthy, 4096, healthyWrite::countDown);

            assertTrue("a healthy stream was blocked behind a starved one",
                    healthyWrite.await(5, TimeUnit.SECONDS));
            moving.completion().get(5, TimeUnit.SECONDS);
            assertEquals("the starved stream must not have moved", 0, starvedWrites.get());
            assertFalse(blocked.completion().isDone());

            // And it recovers on its own once the peer finally returns credit.
            assertTrue(scheduler.addCredit(starved, 4096));
            blocked.completion().get(5, TimeUnit.SECONDS);
            assertEquals(1, starvedWrites.get());
        }
    }

    /**
     * Terminal frames are what tear a stream down. A starved stream must still be resettable, or a
     * peer could pin resources simply by withholding credit.
     */
    @Test
    public void aStarvedStreamCanStillBeResetImmediately() throws Exception {
        try (StreamFlowScheduler scheduler = new StreamFlowScheduler()) {
            int starved = 33;
            assertTrue(scheduler.open(starved));
            spendInitialWindow(scheduler, starved);
            scheduler.submit(starved, 4096, () -> { });

            CountDownLatch resetSent = new CountDownLatch(1);
            long start = System.nanoTime();
            scheduler.reset(starved, resetSent::countDown);
            long elapsedMillis = (System.nanoTime() - start) / 1_000_000L;

            assertTrue("reset waited " + elapsedMillis + "ms on a starved stream",
                    elapsedMillis < 5_000L);
            assertTrue(resetSent.await(2, TimeUnit.SECONDS));
            assertFalse("the identity must be released after the reset",
                    scheduler.contains(starved));
        }
    }

    /** Many starved streams together must not consume more than the process-wide budget. */
    @Test
    public void manyStarvedStreamsShareOneBudget() throws Exception {
        try (StreamFlowScheduler scheduler = new StreamFlowScheduler()) {
            List<Integer> opened = new CopyOnWriteArrayList<>();
            int chunk = StreamFlowScheduler.MAX_CHUNK_BYTES;

            for (int streamId = 200; streamId < 260; streamId++) {
                assertTrue(scheduler.open(streamId));
                opened.add(streamId);
                for (int i = 0; i < 128; i++) {
                    try {
                        scheduler.submit(streamId, chunk, () -> { });
                    } catch (Exception refused) {
                        break;
                    }
                }
            }

            assertTrue(opened.size() > 1);
            assertTrue("the shared budget was exceeded: " + scheduler.totalPendingBytes(),
                    scheduler.totalPendingBytes() <= StreamFlowScheduler.MAX_TOTAL_PENDING_BYTES);
        }
    }

    /** Spends the initial window without blocking, so the stream is left with zero credit. */
    private static void spendInitialWindow(StreamFlowScheduler scheduler, int streamId)
            throws Exception {
        int chunk = StreamFlowScheduler.MAX_CHUNK_BYTES;
        long remaining = StreamFlowScheduler.INITIAL_BYTES;
        CompletableFuture<?> last = null;
        while (remaining > 0) {
            int bytes = (int) Math.min(chunk, remaining);
            last = scheduler.submit(streamId, bytes, () -> { }).completion();
            remaining -= bytes;
        }
        if (last != null) {
            last.get(10, TimeUnit.SECONDS);
        }
    }
}
