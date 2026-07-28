package com.theshuai.specusserver.management.service;

import java.util.concurrent.ThreadLocalRandom;

public final class ClientIdGenerator {
    private static final long MAX_JS_SAFE_INTEGER = 9_007_199_254_740_991L;

    private ClientIdGenerator() {
    }

    public static long newId() {
        return ThreadLocalRandom.current().nextLong(1, MAX_JS_SAFE_INTEGER + 1);
    }
}
