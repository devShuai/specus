package com.theshuai.specus.android;

import org.junit.Test;

import java.io.IOException;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

public class StreamFlowSchedulerTest {
    @Test
    public void streamIdentityAndCreditValidationAreStrict() {
        try (StreamFlowScheduler scheduler = new StreamFlowScheduler()) {
            assertTrue(scheduler.open(7));
            assertFalse(scheduler.open(7));
            assertTrue(scheduler.contains(7));
            assertFalse(scheduler.addCredit(7, 0));
            assertFalse(scheduler.addCredit(7, StreamFlowScheduler.MAXIMUM_BYTES));

            scheduler.closeStream(7);
            assertFalse(scheduler.contains(7));
            assertFalse(scheduler.addCredit(7, 1));
        }
    }

    @Test
    public void senderStopsAtCreditAndResumesAfterWindowUpdate() throws Exception {
        try (StreamFlowScheduler scheduler = new StreamFlowScheduler()) {
            assertTrue(scheduler.open(11));
            exhaustInitialCredit(scheduler, 11);

            AtomicBoolean sent = new AtomicBoolean(false);
            AtomicReference<Throwable> failure = new AtomicReference<>();
            CountDownLatch entered = new CountDownLatch(1);
            Thread sender = new Thread(() -> {
                entered.countDown();
                try {
                    scheduler.send(11, 1, () -> sent.set(true));
                } catch (Throwable error) {
                    failure.set(error);
                }
            }, "stream-flow-credit-test");
            sender.start();

            assertTrue(entered.await(1, TimeUnit.SECONDS));
            Thread.sleep(50L);
            assertFalse(sent.get());
            assertTrue(sender.isAlive());

            assertTrue(scheduler.addCredit(11, 1));
            sender.join(2_000L);
            assertFalse(sender.isAlive());
            assertTrue(sent.get());
            assertNull(failure.get());
        }
    }

    @Test
    public void windowUpdateCannotExceedActuallySentOutstandingBytes() throws Exception {
        try (StreamFlowScheduler scheduler = new StreamFlowScheduler()) {
            assertTrue(scheduler.open(12));
            assertFalse("credit without outstanding DATA must be rejected",
                    scheduler.addCredit(12, 1));

            scheduler.send(12, 8, () -> { });
            assertFalse("credit above outstanding DATA must be rejected",
                    scheduler.addCredit(12, 9));
            assertTrue(scheduler.addCredit(12, 3));
            assertFalse("partial return leaves only five outstanding bytes",
                    scheduler.addCredit(12, 6));
            assertTrue("exact outstanding credit must be accepted",
                    scheduler.addCredit(12, 5));
            assertFalse(scheduler.addCredit(12, 1));
        }
    }

    @Test
    public void failedWriteClosesTheStreamInsteadOfRefundingCredit() {
        try (StreamFlowScheduler scheduler = new StreamFlowScheduler()) {
            assertTrue(scheduler.open(14));
            assertThrows(IOException.class,
                    () -> scheduler.send(14, 8, () -> {
                        throw new IOException("wire write failed");
                    }));
            assertFalse(scheduler.contains(14));
            assertFalse(scheduler.addCredit(14, 8));
        }
    }

    @Test
    public void closingAStreamReleasesCreditBlockedSender() throws Exception {
        try (StreamFlowScheduler scheduler = new StreamFlowScheduler()) {
            assertTrue(scheduler.open(13));
            exhaustInitialCredit(scheduler, 13);

            AtomicReference<Throwable> failure = new AtomicReference<>();
            CountDownLatch entered = new CountDownLatch(1);
            Thread sender = new Thread(() -> {
                entered.countDown();
                try {
                    scheduler.send(13, 1, () -> { });
                } catch (Throwable error) {
                    failure.set(error);
                }
            }, "stream-flow-close-test");
            sender.start();

            assertTrue(entered.await(1, TimeUnit.SECONDS));
            Thread.sleep(50L);
            assertTrue(sender.isAlive());
            scheduler.closeStream(13);

            sender.join(2_000L);
            assertFalse(sender.isAlive());
            assertTrue(failure.get() instanceof IOException);
        }
    }

    @Test
    public void finRunsAfterAlreadyQueuedDataAndClosesTheIdentity() throws Exception {
        try (StreamFlowScheduler scheduler = new StreamFlowScheduler()) {
            assertTrue(scheduler.open(17));
            List<String> events = new CopyOnWriteArrayList<>();
            CountDownLatch dataStarted = new CountDownLatch(1);
            CountDownLatch releaseData = new CountDownLatch(1);
            AtomicReference<Throwable> dataFailure = new AtomicReference<>();
            AtomicReference<Throwable> finFailure = new AtomicReference<>();

            Thread data = new Thread(() -> {
                try {
                    scheduler.send(17, 1, () -> {
                        events.add("data");
                        dataStarted.countDown();
                        assertTrue(releaseData.await(2, TimeUnit.SECONDS));
                    });
                } catch (Throwable error) {
                    dataFailure.set(error);
                }
            }, "stream-flow-fin-data");
            data.start();
            assertTrue(dataStarted.await(1, TimeUnit.SECONDS));

            Thread fin = new Thread(() -> {
                try {
                    scheduler.finish(17, () -> events.add("fin"));
                } catch (Throwable error) {
                    finFailure.set(error);
                }
            }, "stream-flow-fin");
            fin.start();
            Thread.sleep(50L);
            assertEquals(List.of("data"), events);
            assertTrue(fin.isAlive());

            releaseData.countDown();
            data.join(2_000L);
            fin.join(2_000L);
            assertFalse(data.isAlive());
            assertFalse(fin.isAlive());
            assertNull(dataFailure.get());
            assertNull(finFailure.get());
            assertEquals(List.of("data", "fin"), events);
            assertFalse(scheduler.contains(17));
        }
    }

    @Test
    public void resetDropsQueuedDataAndPreventsStreamReuseUntilTerminalRuns() throws Exception {
        try (StreamFlowScheduler scheduler = new StreamFlowScheduler()) {
            assertTrue(scheduler.open(19));
            List<String> events = new CopyOnWriteArrayList<>();
            CountDownLatch runningStarted = new CountDownLatch(1);
            CountDownLatch releaseRunning = new CountDownLatch(1);
            AtomicReference<Throwable> runningFailure = new AtomicReference<>();
            AtomicReference<Throwable> queuedFailure = new AtomicReference<>();
            AtomicReference<Throwable> resetFailure = new AtomicReference<>();

            Thread running = new Thread(() -> {
                try {
                    scheduler.send(19, 1, () -> {
                        events.add("running-data");
                        runningStarted.countDown();
                        assertTrue(releaseRunning.await(2, TimeUnit.SECONDS));
                    });
                } catch (Throwable error) {
                    runningFailure.set(error);
                }
            }, "stream-flow-reset-running");
            running.start();
            assertTrue(runningStarted.await(1, TimeUnit.SECONDS));

            Thread queued = new Thread(() -> {
                try {
                    scheduler.send(19, 1, () -> events.add("queued-data"));
                } catch (Throwable error) {
                    queuedFailure.set(error);
                }
            }, "stream-flow-reset-queued");
            queued.start();
            Thread.sleep(50L);

            Thread reset = new Thread(() -> {
                try {
                    scheduler.reset(19, () -> events.add("rst"));
                } catch (Throwable error) {
                    resetFailure.set(error);
                }
            }, "stream-flow-reset");
            reset.start();
            Thread.sleep(50L);
            assertTrue(reset.isAlive());
            assertFalse(scheduler.open(19));

            releaseRunning.countDown();
            running.join(2_000L);
            queued.join(2_000L);
            reset.join(2_000L);
            assertFalse(running.isAlive());
            assertFalse(queued.isAlive());
            assertFalse(reset.isAlive());
            assertNull(runningFailure.get());
            assertTrue(queuedFailure.get() instanceof IOException);
            assertNull(resetFailure.get());
            assertEquals(List.of("running-data", "rst"), events);

            assertTrue(scheduler.open(19));
            scheduler.send(19, 1, () -> events.add("reused-data"));
            assertEquals(List.of("running-data", "rst", "reused-data"), events);
        }
    }

    @Test
    public void resetSupersedesACreditBlockedGracefulFinish() throws Exception {
        try (StreamFlowScheduler scheduler = new StreamFlowScheduler()) {
            assertTrue(scheduler.open(21));
            exhaustInitialCredit(scheduler, 21);
            List<String> events = new CopyOnWriteArrayList<>();
            AtomicReference<Throwable> dataFailure = new AtomicReference<>();
            AtomicReference<Throwable> finFailure = new AtomicReference<>();

            Thread data = new Thread(() -> {
                try {
                    scheduler.send(21, 1, () -> events.add("data"));
                } catch (Throwable error) {
                    dataFailure.set(error);
                }
            }, "stream-flow-superseded-data");
            data.start();
            Thread.sleep(50L);

            Thread fin = new Thread(() -> {
                try {
                    scheduler.finish(21, () -> events.add("fin"));
                } catch (Throwable error) {
                    finFailure.set(error);
                }
            }, "stream-flow-superseded-fin");
            fin.start();
            Thread.sleep(50L);

            scheduler.reset(21, () -> events.add("rst"));
            data.join(2_000L);
            fin.join(2_000L);

            assertFalse(data.isAlive());
            assertFalse(fin.isAlive());
            assertTrue(dataFailure.get() instanceof IOException);
            assertTrue(finFailure.get() instanceof IOException);
            assertEquals(List.of("rst"), events);
            assertFalse(scheduler.contains(21));
        }
    }

    @Test
    public void resetFollowsGracefulTerminalAlreadyInFlight() throws Exception {
        try (StreamFlowScheduler scheduler = new StreamFlowScheduler()) {
            assertTrue(scheduler.open(22));
            List<String> events = new CopyOnWriteArrayList<>();
            CountDownLatch finStarted = new CountDownLatch(1);
            CountDownLatch releaseFin = new CountDownLatch(1);
            CountDownLatch resetEntered = new CountDownLatch(1);
            AtomicReference<Throwable> finFailure = new AtomicReference<>();
            AtomicReference<Throwable> resetFailure = new AtomicReference<>();

            Thread fin = new Thread(() -> {
                try {
                    scheduler.finish(22, () -> {
                        events.add("fin-start");
                        finStarted.countDown();
                        assertTrue(releaseFin.await(2, TimeUnit.SECONDS));
                        events.add("fin-end");
                    });
                } catch (Throwable error) {
                    finFailure.set(error);
                }
            }, "stream-flow-in-flight-fin");
            fin.start();
            assertTrue(finStarted.await(1, TimeUnit.SECONDS));

            Thread reset = new Thread(() -> {
                resetEntered.countDown();
                try {
                    scheduler.reset(22, () -> events.add("rst"));
                } catch (Throwable error) {
                    resetFailure.set(error);
                }
            }, "stream-flow-reset-after-fin");
            reset.start();
            assertTrue(resetEntered.await(1, TimeUnit.SECONDS));
            Thread.sleep(50L);

            assertTrue("RST must wait behind the physical FIN write", reset.isAlive());
            assertFalse("identity stays reserved until RST is sent", scheduler.open(22));
            releaseFin.countDown();
            fin.join(2_000L);
            reset.join(2_000L);

            assertFalse(fin.isAlive());
            assertFalse(reset.isAlive());
            assertTrue(finFailure.get() instanceof IOException);
            assertNull(resetFailure.get());
            assertEquals(List.of("fin-start", "fin-end", "rst"), events);
            assertFalse(scheduler.contains(22));
        }
    }

    @Test
    public void interruptedTerminalWaitCannotReuseIdentityBeforeActionCompletes() throws Exception {
        try (StreamFlowScheduler scheduler = new StreamFlowScheduler()) {
            assertTrue(scheduler.open(23));
            CountDownLatch terminalStarted = new CountDownLatch(1);
            CountDownLatch releaseTerminal = new CountDownLatch(1);
            AtomicReference<Throwable> finFailure = new AtomicReference<>();

            Thread fin = new Thread(() -> {
                try {
                    scheduler.finish(23, () -> {
                        terminalStarted.countDown();
                        assertTrue(releaseTerminal.await(2, TimeUnit.SECONDS));
                    });
                } catch (Throwable error) {
                    finFailure.set(error);
                }
            }, "stream-flow-interrupted-fin");
            fin.start();
            assertTrue(terminalStarted.await(1, TimeUnit.SECONDS));

            fin.interrupt();
            fin.join(1_000L);
            assertFalse(fin.isAlive());
            assertTrue(finFailure.get() instanceof IOException);
            assertFalse(scheduler.open(23));

            releaseTerminal.countDown();
            long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(1L);
            while (scheduler.contains(23) && System.nanoTime() < deadline) {
                Thread.yield();
            }
            assertFalse(scheduler.contains(23));
            assertTrue(scheduler.open(23));
        }
    }

    private static void exhaustInitialCredit(StreamFlowScheduler scheduler, int streamId)
            throws Exception {
        long remaining = StreamFlowScheduler.INITIAL_BYTES;
        while (remaining > 0) {
            int chunk = (int) Math.min(StreamFlowScheduler.MAX_CHUNK_BYTES, remaining);
            scheduler.send(streamId, chunk, () -> { });
            remaining -= chunk;
        }
    }
}
