package com.theshuai.specus.android;

import org.junit.Test;

import java.io.IOException;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

public class StreamFlowFailureVisibilityTest {
    @Test
    public void failedWriteStateIsClosedBeforeItsFailureIsPublished() throws Exception {
        CountDownLatch writing = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        AtomicBoolean queuedWriteRan = new AtomicBoolean();
        try (StreamFlowScheduler scheduler = new StreamFlowScheduler()) {
            assertTrue(scheduler.open(14));
            StreamFlowScheduler.Submission failed = scheduler.submit(14, 8, () -> {
                writing.countDown();
                if (!release.await(5, TimeUnit.SECONDS)) throw new IOException("test release missing");
                throw new IOException("wire write failed");
            });
            assertTrue(writing.await(5, TimeUnit.SECONDS));
            StreamFlowScheduler.Submission queued = scheduler.submit(14, 8,
                    () -> queuedWriteRan.set(true));
            // Register while the write is held. This observer runs during publication of its
            // failure, deterministically exposing notify-before-cleanup without sleeps/retries.
            CompletableFuture<Boolean> observed = failed.completion().handle((ignored, error) ->
                    error instanceof IOException && !scheduler.contains(14)
                            && !scheduler.addCredit(14, 8)
                            && queued.completion().isCompletedExceptionally()
                            && scheduler.totalPendingBytes() == 0);
            release.countDown();
            assertTrue("failed stream and its queued work must be closed before failure publication",
                    observed.get(5, TimeUnit.SECONDS));
            assertThrows(ExecutionException.class, () -> queued.completion().get(5, TimeUnit.SECONDS));
            assertFalse(queuedWriteRan.get());
        } finally {
            release.countDown();
        }
    }
}
