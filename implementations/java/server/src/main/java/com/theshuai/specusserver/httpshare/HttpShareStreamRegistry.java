package com.theshuai.specusserver.httpshare;

import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * This instance's in-flight streams per share (HTTP requests and WebSockets together). It caps
 * each share at {@link HttpShareRules#MAX_CONCURRENT_PER_SHARE} and lets a revocation, an expiry or
 * a database recheck cut every stream of a share at once: the cutter sends the NAT RST to the
 * device and aborts the public connection.
 */
@Component
@Slf4j
public class HttpShareStreamRegistry {
    private final Map<String, Set<InFlight>> byShare = new ConcurrentHashMap<>();

    /** Reserves a slot for one stream, or returns null when the share already has 64 here. */
    public InFlight tryAcquire(String shareId, long expiresAtSeconds) {
        InFlight[] acquired = new InFlight[1];
        byShare.compute(shareId, (key, streams) -> {
            Set<InFlight> current = streams == null ? ConcurrentHashMap.newKeySet() : streams;
            if (current.size() < HttpShareRules.MAX_CONCURRENT_PER_SHARE) {
                acquired[0] = new InFlight(this, shareId, expiresAtSeconds);
                current.add(acquired[0]);
            }
            return current.isEmpty() ? null : current;
        });
        return acquired[0];
    }

    public int count(String shareId) {
        Set<InFlight> streams = byShare.get(shareId);
        return streams == null ? 0 : streams.size();
    }

    /** Shares that currently have at least one stream on this instance. */
    public List<String> sharesInFlight() {
        return new ArrayList<>(byShare.keySet());
    }

    /** Cuts every stream of the share on this instance. */
    public void cut(String shareId) {
        Set<InFlight> streams = byShare.get(shareId);
        if (streams == null) {
            return;
        }
        for (InFlight stream : List.copyOf(streams)) {
            stream.cut();
        }
    }

    /** Cuts the streams whose share has reached its expiresAt. */
    public void cutExpired(long nowMillis) {
        for (Set<InFlight> streams : byShare.values()) {
            for (InFlight stream : List.copyOf(streams)) {
                if (stream.expiresAtSeconds() * 1000L <= nowMillis) {
                    stream.cut();
                }
            }
        }
    }

    /** Drops every reservation; only for tests that reuse one application context. */
    public void clear() {
        byShare.clear();
    }

    private void remove(InFlight stream) {
        byShare.computeIfPresent(stream.shareId(), (key, streams) -> {
            streams.remove(stream);
            return streams.isEmpty() ? null : streams;
        });
    }

    /** One reserved stream. The forwarding code attaches the action that tears it down. */
    public static final class InFlight {
        private final HttpShareStreamRegistry registry;
        private final String shareId;
        private final long expiresAtSeconds;
        private Runnable cutter;
        private boolean cut;
        private boolean released;

        private InFlight(HttpShareStreamRegistry registry, String shareId, long expiresAtSeconds) {
            this.registry = registry;
            this.shareId = shareId;
            this.expiresAtSeconds = expiresAtSeconds;
        }

        public String shareId() {
            return shareId;
        }

        public long expiresAtSeconds() {
            return expiresAtSeconds;
        }

        /** Binds the tear-down action; runs it at once when the share was cut in the meantime. */
        public void attach(Runnable action) {
            boolean runNow;
            synchronized (this) {
                cutter = action;
                runNow = cut;
            }
            if (runNow) {
                runQuietly(action);
            }
        }

        public synchronized boolean isCut() {
            return cut;
        }

        /** Tears the stream down and frees its slot; later calls do nothing. */
        public void cut() {
            Runnable action;
            synchronized (this) {
                if (cut) {
                    return;
                }
                cut = true;
                action = cutter;
            }
            registry.remove(this);
            if (action != null) {
                runQuietly(action);
            }
        }

        /** Frees the slot when the stream ends normally. */
        public void release() {
            synchronized (this) {
                if (released) {
                    return;
                }
                released = true;
            }
            registry.remove(this);
        }

        private void runQuietly(Runnable action) {
            try {
                action.run();
            } catch (RuntimeException error) {
                log.warn("[http-share] cutting a stream of share {} failed: {}", shareId, error.toString());
            }
        }
    }
}
