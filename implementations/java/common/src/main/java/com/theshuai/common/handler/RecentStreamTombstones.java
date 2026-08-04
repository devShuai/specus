package com.theshuai.common.handler;

import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.Set;

/**
 * Per-connection bounded history of recently closed stream IDs.
 *
 * <p>A late {@code RST} for a stream that was just closed is idempotent and must
 * not start a reset loop. Keeping only the most recent IDs also prevents an
 * untrusted peer from growing connection state without bound.</p>
 */
public final class RecentStreamTombstones {
    private final int capacity;
    private final Set<Integer> streamIds = new LinkedHashSet<>();

    public RecentStreamTombstones(int capacity) {
        if (capacity <= 0) {
            throw new IllegalArgumentException("capacity must be positive");
        }
        this.capacity = capacity;
    }

    public synchronized void add(int streamId) {
        streamIds.remove(streamId);
        streamIds.add(streamId);
        if (streamIds.size() > capacity) {
            Iterator<Integer> iterator = streamIds.iterator();
            iterator.next();
            iterator.remove();
        }
    }

    public synchronized boolean contains(int streamId) {
        return streamIds.contains(streamId);
    }

    public synchronized void remove(int streamId) {
        streamIds.remove(streamId);
    }

    public synchronized int size() {
        return streamIds.size();
    }

    public synchronized void clear() {
        streamIds.clear();
    }
}
