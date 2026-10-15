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
 * Fixed stripes bound memory; reentrancy permits a cleanup service to defend its own entry point. */
public final class ControlLifecycle {
    private static final ReentrantLock[] LOCKS = new ReentrantLock[256];
    private static final ConcurrentHashMap<Long,Channel> PUBLISHING = new ConcurrentHashMap<>();
    private static final Semaphore PUBLICATION_SLOTS = new Semaphore(4096);
    static {for (int i=0;i<LOCKS.length;i++) LOCKS[i]=new ReentrantLock();}
    private ControlLifecycle() {}

    public static Lease acquire(long clientId, Channel cancellation) throws InterruptedException {
        if(clientId <= 0) throw new IllegalArgumentException("authenticated client ID is required");
        int hash=Long.hashCode(clientId);var lock=LOCKS[(hash^(hash>>>16))&(LOCKS.length-1)];
        for (;;) {
            if(cancellation != null && !cancellation.isActive()) throw new CancellationException("CONTROL is closed");
            if(lock.tryLock(25, TimeUnit.MILLISECONDS)) {
                if(cancellation != null && !cancellation.isActive()) {lock.unlock();throw new CancellationException("CONTROL is closed");}
                return new Lease(lock);
            }
        }
    }

    public static final class Lease implements AutoCloseable {
        private ReentrantLock lock;
        private Lease(ReentrantLock lock) {this.lock=lock;}
        @Override public void close() {if(lock != null) {var held=lock;lock=null;held.unlock();}}
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
