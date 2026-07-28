package com.theshuai.specusclient.peer;

import java.net.InetAddress;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;

final class PeerUdpProbeRateLimiter {
    private static final long WINDOW_MILLIS = 1_000;
    private static final long SOURCE_TTL_MILLIS = 60_000;
    private static final int GLOBAL_PACKETS_PER_WINDOW = 2_000;
    private static final int SOURCE_PACKETS_PER_WINDOW = 100;
    private static final int MAX_SOURCES = 4_096;

    private final Map<InetAddress, Window> sourceWindows = new LinkedHashMap<>(64, 0.75f, true);
    private long globalWindowStartedMillis;
    private int globalPackets;

    synchronized boolean tryAcquire(InetAddress source, long nowMillis) {
        if (nowMillis - globalWindowStartedMillis >= WINDOW_MILLIS) {
            globalWindowStartedMillis = nowMillis;
            globalPackets = 0;
        }
        if (++globalPackets > GLOBAL_PACKETS_PER_WINDOW || source == null) {
            return false;
        }

        Window window = sourceWindows.get(source);
        if (window == null) {
            evictIfNeeded(nowMillis);
            window = new Window(nowMillis, 0, nowMillis);
            sourceWindows.put(source, window);
        }
        if (nowMillis - window.startedMillis >= WINDOW_MILLIS) {
            window.startedMillis = nowMillis;
            window.packets = 0;
        }
        window.lastSeenMillis = nowMillis;
        return ++window.packets <= SOURCE_PACKETS_PER_WINDOW;
    }

    synchronized void cleanup(long nowMillis) {
        sourceWindows.entrySet().removeIf(entry -> nowMillis - entry.getValue().lastSeenMillis > SOURCE_TTL_MILLIS);
    }

    private void evictIfNeeded(long nowMillis) {
        Iterator<Map.Entry<InetAddress, Window>> iterator = sourceWindows.entrySet().iterator();
        while (iterator.hasNext() && sourceWindows.size() >= MAX_SOURCES) {
            Map.Entry<InetAddress, Window> entry = iterator.next();
            if (nowMillis - entry.getValue().lastSeenMillis > SOURCE_TTL_MILLIS || sourceWindows.size() >= MAX_SOURCES) {
                iterator.remove();
            }
        }
    }

    private static final class Window {
        private long startedMillis;
        private int packets;
        private long lastSeenMillis;

        private Window(long startedMillis, int packets, long lastSeenMillis) {
            this.startedMillis = startedMillis;
            this.packets = packets;
            this.lastSeenMillis = lastSeenMillis;
        }
    }
}
