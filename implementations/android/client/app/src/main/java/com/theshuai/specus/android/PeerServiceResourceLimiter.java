package com.theshuai.specus.android;

import java.net.InetAddress;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.Semaphore;
import java.util.concurrent.atomic.AtomicBoolean;

final class PeerServiceResourceLimiter {
    static final int MAX_TCP_GLOBAL = 256;
    static final int MAX_TCP_PER_SERVICE = 64;
    static final int MAX_TCP_PER_SOURCE = 8;
    static final int MAX_UDP_GLOBAL = 256;
    static final int MAX_UDP_PER_SERVICE = 64;
    static final int MAX_UDP_PER_SOURCE = 8;
    static final int CONNECT_TIMEOUT_MILLIS = 3_000;
    static final int IDLE_TIMEOUT_MILLIS = 60_000;

    private static final Object LOCK = new Object();
    private static final Semaphore TCP_GLOBAL = new Semaphore(MAX_TCP_GLOBAL);
    private static final Semaphore UDP_GLOBAL = new Semaphore(MAX_UDP_GLOBAL);
    private static final Map<InetAddress, Integer> TCP_SOURCES = new HashMap<>();
    private static final Map<InetAddress, Integer> UDP_SOURCES = new HashMap<>();

    private PeerServiceResourceLimiter() {
    }

    static Lease tryAcquireTcp(InetAddress source) {
        return acquire(source, TCP_GLOBAL, TCP_SOURCES, MAX_TCP_PER_SOURCE);
    }

    static Lease tryAcquireUdp(InetAddress source) {
        return acquire(source, UDP_GLOBAL, UDP_SOURCES, MAX_UDP_PER_SOURCE);
    }

    private static Lease acquire(InetAddress source, Semaphore global, Map<InetAddress, Integer> sources, int limit) {
        if (source == null || !global.tryAcquire()) {
            return null;
        }
        synchronized (LOCK) {
            int active = sources.getOrDefault(source, 0);
            if (active >= limit) {
                global.release();
                return null;
            }
            sources.put(source, active + 1);
        }
        return new Lease(source, global, sources);
    }

    static final class Lease implements AutoCloseable {
        private final InetAddress source;
        private final Semaphore global;
        private final Map<InetAddress, Integer> sources;
        private final AtomicBoolean closed = new AtomicBoolean();

        private Lease(InetAddress source, Semaphore global, Map<InetAddress, Integer> sources) {
            this.source = source;
            this.global = global;
            this.sources = sources;
        }

        @Override
        public void close() {
            if (!closed.compareAndSet(false, true)) {
                return;
            }
            synchronized (LOCK) {
                int remaining = sources.getOrDefault(source, 1) - 1;
                if (remaining <= 0) {
                    sources.remove(source);
                } else {
                    sources.put(source, remaining);
                }
            }
            global.release();
        }
    }
}
