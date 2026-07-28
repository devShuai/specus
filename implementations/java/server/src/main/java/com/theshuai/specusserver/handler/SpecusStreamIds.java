package com.theshuai.specusserver.handler;

import java.util.concurrent.atomic.AtomicInteger;

/** Allocates positive stream ids; zero is reserved for connection-level control frames. */
public final class SpecusStreamIds {
    private static final AtomicInteger NEXT = new AtomicInteger(1);

    private SpecusStreamIds() {
    }

    public static int next() {
        return NEXT.getAndUpdate(current -> current == Integer.MAX_VALUE ? 1 : current + 1);
    }
}
