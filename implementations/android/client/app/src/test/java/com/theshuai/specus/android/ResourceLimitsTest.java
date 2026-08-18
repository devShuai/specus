package com.theshuai.specus.android;

import org.junit.Test;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.ThreadPoolExecutor;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

/**
 * The ceilings that keep a misbehaving peer from exhausting the phone.
 *
 * Each of these was previously unbounded, and every one of them is reachable by a peer that simply
 * opens streams or sends faster than they complete.
 */
public class ResourceLimitsTest {
    /** A cached pool grows a thread per concurrent task; the tunnel pool must not. */
    @Test
    public void ioPoolIsBoundedInThreadsAndQueueDepth() {
        ExecutorService pool = SpecusCore.Runtime.newIoPool();
        try {
            assertTrue(pool instanceof ThreadPoolExecutor);
            ThreadPoolExecutor executor = (ThreadPoolExecutor) pool;

            assertTrue("threads must be capped",
                    executor.getMaximumPoolSize() <= SpecusCore.Runtime.MAX_IO_THREADS);
            assertTrue("the cap must leave room for real concurrency",
                    executor.getMaximumPoolSize() >= SpecusCore.Runtime.MAX_IO_THREADS_FLOOR);
            assertTrue("core threads must not exceed the maximum",
                    executor.getCorePoolSize() <= executor.getMaximumPoolSize());
            assertEquals("the queue must be bounded",
                    SpecusCore.Runtime.IO_QUEUE_CAPACITY,
                    executor.getQueue().remainingCapacity());
            assertTrue("a full pool must push back rather than discard work",
                    executor.getRejectedExecutionHandler()
                            instanceof ThreadPoolExecutor.CallerRunsPolicy);
        } finally {
            pool.shutdownNow();
        }
    }

    /** Admission is what stops a peer opening streams until the process runs out of descriptors. */
    @Test
    public void streamAdmissionStopsAtTheCeiling() {
        int limit = SpecusCore.MAX_ACTIVE_STREAMS;
        assertTrue("the ceiling must be a real number", limit > 0);

        assertFalse(SpecusCore.streamLimitReached(0, limit));
        assertFalse(SpecusCore.streamLimitReached(limit - 1, limit));
        assertTrue("the stream that would sit on the ceiling must be refused",
                SpecusCore.streamLimitReached(limit, limit));
        assertTrue(SpecusCore.streamLimitReached(limit + 1, limit));
    }

    /** Per-stream limits alone let N streams hold N times the limit, so the total is capped too. */
    @Test
    public void queueCeilingsAreOrderedSoTheTotalActuallyBinds() {
        assertTrue(StreamFlowScheduler.MAX_CHUNK_BYTES < StreamFlowScheduler.MAX_PENDING_BYTES);
        assertTrue(StreamFlowScheduler.SATURATION_BYTES < StreamFlowScheduler.MAX_PENDING_BYTES);
        assertTrue("a single stream must not be able to spend the whole budget alone",
                StreamFlowScheduler.MAX_PENDING_BYTES
                        < StreamFlowScheduler.MAX_TOTAL_PENDING_BYTES);
        assertTrue("saturation must trip before the hard limit, leaving room for the chunk "
                        + "that crosses it",
                StreamFlowScheduler.SATURATION_BYTES + StreamFlowScheduler.MAX_CHUNK_BYTES
                        <= StreamFlowScheduler.MAX_PENDING_BYTES);
    }
}
