package com.theshuai.specusclient.peer;

import com.theshuai.common.peermesh.PeerServiceDiscovery;

import java.net.InetAddress;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.Semaphore;
import java.util.concurrent.atomic.AtomicBoolean;

/** Process-wide Peer service data-plane budget shared by every published service. */
final class PeerServiceResourceLimiter {
    private static final Object LOCK = new Object();
    private static final Semaphore TCP_GLOBAL = new Semaphore(PeerServiceDiscovery.MAX_TCP_CONNECTIONS_GLOBAL);
    private static final Semaphore UDP_GLOBAL = new Semaphore(PeerServiceDiscovery.MAX_UDP_PEERS_GLOBAL);
    private static final Map<InetAddress, Integer> TCP_SOURCES = new HashMap<>();
    private static final Map<InetAddress, Integer> UDP_SOURCES = new HashMap<>();

    private PeerServiceResourceLimiter() {
    }

    static Lease tryAcquireTcp(InetAddress source) {
        return tryAcquire(source, TCP_GLOBAL, TCP_SOURCES, PeerServiceDiscovery.MAX_TCP_CONNECTIONS_PER_SOURCE);
    }

    static Lease tryAcquireUdp(InetAddress source) {
        return tryAcquire(source, UDP_GLOBAL, UDP_SOURCES, PeerServiceDiscovery.MAX_UDP_PEERS_PER_SOURCE);
    }

    private static Lease tryAcquire(InetAddress source, Semaphore global, Map<InetAddress, Integer> sources,
                                    int perSourceLimit) {
        if (source == null || !global.tryAcquire()) {
            return null;
        }
        synchronized (LOCK) {
            int active = sources.getOrDefault(source, 0);
            if (active >= perSourceLimit) {
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
