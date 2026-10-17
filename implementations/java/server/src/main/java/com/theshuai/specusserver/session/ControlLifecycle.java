package com.theshuai.specusserver.session;

import io.netty.channel.Channel;
import java.util.concurrent.CancellationException;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Semaphore;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.ReentrantLock;

/** Process-local physical CONTROL lifecycle, keyed by an authenticated immutable client ID.
 * Acquire on a worker BEFORE opening a database transaction. Never use this for NAT/stream I/O.
 * Exact keys prevent unrelated clients from blocking each other. A bounded, reference-counted
 * registry retains a gate while either a holder or a waiter can still use it. Reentrancy permits
 * a cleanup service to defend its own entry point. */
public final class ControlLifecycle {
    private static final ConcurrentHashMap<Long,Gate> LOCKS = new ConcurrentHashMap<>();
    private static final Semaphore LIFECYCLE_SLOTS = new Semaphore(4096);
    private static final ConcurrentHashMap<Long,Channel> PUBLISHING = new ConcurrentHashMap<>();
    private static final Semaphore PUBLICATION_SLOTS = new Semaphore(4096);
    private ControlLifecycle() {}

    public static Lease acquire(long clientId, Channel cancellation) throws InterruptedException {
        if(clientId <= 0) throw new IllegalArgumentException("authenticated client ID is required");
        var gate=LOCKS.compute(clientId,(key,current) -> {
            if(current == null) {
                if(!LIFECYCLE_SLOTS.tryAcquire()) throw new RejectedExecutionException("CONTROL lifecycle capacity reached");
                current=new Gate();
            }
            current.users++;return current;
        });
        boolean acquired=false;
        try {
            for (;;) {
                if(cancellation != null && !cancellation.isActive()) throw new CancellationException("CONTROL is closed");
                if(gate.lock.tryLock(25, TimeUnit.MILLISECONDS)) {
                    if(cancellation != null && !cancellation.isActive()) {gate.lock.unlock();throw new CancellationException("CONTROL is closed");}
                    acquired=true;return new Lease(clientId,gate);
                }
            }
        } finally {
            if(!acquired) releaseReference(clientId,gate);
        }
    }

    private static final class Gate {
        final ReentrantLock lock=new ReentrantLock();
        int users; // Only read/written inside this key's ConcurrentHashMap.compute.
    }

    private static void releaseReference(long clientId,Gate gate) {
        LOCKS.compute(clientId,(key,current) -> {
            if(current != gate) throw new IllegalStateException("CONTROL lifecycle gate lost its owner");
            if(--current.users == 0) {LIFECYCLE_SLOTS.release();return null;}
            return current;
        });
    }

    public static final class Lease implements AutoCloseable {
        private final long clientId;
        private Gate gate;
        private Lease(long clientId,Gate gate) {this.clientId=clientId;this.gate=gate;}
        @Override public void close() {
            if(gate != null) {
                var held=gate;held.lock.unlock();gate=null;
                releaseReference(clientId,held);
            }
        }
    }

    /** Register BEFORE native ONLINE. Another identity sharing this credential can authenticate
     * under a different lifecycle stripe, and must not mistake this committed row for stale state. */
    public static Publication beginPublication(long clientId, Channel channel) {
        if (clientId <= 0 || channel == null) throw new IllegalArgumentException("authenticated publication identity is required");
        if (!channel.isActive()) throw new CancellationException("CONTROL is closed");
        if (!PUBLICATION_SLOTS.tryAcquire()) throw new RejectedExecutionException("CONTROL publication capacity reached");
        if (PUBLISHING.putIfAbsent(clientId,channel) != null) {
            PUBLICATION_SLOTS.release();throw new IllegalStateException("a CONTROL publication already owns this client");
        }
        return new Publication(clientId,channel);
    }

    public static boolean isPublishing(Long clientId, String channelId) {
        if (clientId == null || channelId == null) return false;
        var channel=PUBLISHING.get(clientId);
        return channel != null && channel.isActive() && channelId.equals(channel.id().asLongText());
    }

    public static final class Publication implements AutoCloseable {
        private final long clientId;private Channel channel;
        private Publication(long clientId, Channel channel) {this.clientId=clientId;this.channel=channel;}
        @Override public void close() {
            if(channel != null) {var previous=channel;channel=null;if(PUBLISHING.remove(clientId,previous)) PUBLICATION_SLOTS.release();}
        }
    }
}
