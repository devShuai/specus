package com.theshuai.specusclient.peer;

import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * The names consumers bound to their fake addresses with name-bind, kept by most recent use.
 *
 * <p>Phase two of peer egress on the egress side (protocol/spec/peer-egress-dns.md). A binding is a
 * few bytes and is only read when a flow opens, so the caps bound memory against a consumer that
 * binds without end rather than being reached in use. Not thread-safe; the runtime's lock covers it.
 */
final class PeerEgressNameTable {
    static final int CAPACITY = 65_536;
    static final int CAPACITY_PER_CONSUMER = 4_096;

    private record Key(long consumer, int address) {
    }

    /** Access order: iteration starts at the least recently used binding. */
    private final LinkedHashMap<Key, String> entries = new LinkedHashMap<>(16, 0.75f, true);
    private final Map<Long, Integer> perConsumer = new HashMap<>();

    /** Records or replaces a consumer's name for an address. The name must already be valid. */
    void bind(long consumer, int address, String name) {
        Key key = new Key(consumer, address);
        if (entries.containsKey(key)) {
            entries.put(key, name);
            return;
        }
        while (perConsumer.getOrDefault(consumer, 0) >= CAPACITY_PER_CONSUMER) {
            evictOldest(consumer);
        }
        while (entries.size() >= CAPACITY) {
            evictOldest(null);
        }
        entries.put(key, name);
        perConsumer.merge(consumer, 1, Integer::sum);
    }

    private void evictOldest(Long consumer) {
        Iterator<Key> keys = entries.keySet().iterator();
        while (keys.hasNext()) {
            Key key = keys.next();
            if (consumer == null || key.consumer() == consumer) {
                keys.remove();
                forget(key.consumer());
                return;
            }
        }
    }

    private void forget(long consumer) {
        int remaining = perConsumer.getOrDefault(consumer, 0) - 1;
        if (remaining > 0) {
            perConsumer.put(consumer, remaining);
        } else {
            perConsumer.remove(consumer);
        }
    }

    /** The name a consumer bound to an address, refreshing it, or null. */
    String lookup(long consumer, int address) {
        return entries.get(new Key(consumer, address));
    }

    /** Forgets every binding of a consumer, for when it is revoked. */
    void dropConsumer(long consumer) {
        entries.keySet().removeIf(key -> key.consumer() == consumer);
        perConsumer.remove(consumer);
    }

    int size() {
        return entries.size();
    }
}
