package com.theshuai.specus.android;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.function.LongSupplier;

/** Authenticated SPM2 packetization-layer MTU messages and per-path discovery state. */
final class PeerPathMtu {
    static final int MIN_INNER_MTU = 576;
    static final int MAX_INNER_MTU = 9_000;
    static final int MAX_ATTEMPTS = 3;
    static final long PROBE_TIMEOUT_MILLIS = 750L;
    static final long CACHE_TTL_MILLIS = 10L * 60_000L;

    private static final byte[] MAGIC = "SPMTU2".getBytes(StandardCharsets.US_ASCII);
    private static final int TYPE_PROBE = 1;
    private static final int TYPE_ACK = 2;
    private static final int HEADER_BYTES = MAGIC.length + 1 + Long.BYTES + Short.BYTES;

    private PeerPathMtu() {
    }

    static byte[] probe(long nonce, int innerMtu) {
        validate(nonce, innerMtu);
        byte[] payload = new byte[innerMtu];
        writeHeader(payload, TYPE_PROBE, nonce, innerMtu);
        return payload;
    }

    static byte[] ack(long nonce, int innerMtu) {
        validate(nonce, innerMtu);
        byte[] payload = new byte[HEADER_BYTES];
        writeHeader(payload, TYPE_ACK, nonce, innerMtu);
        return payload;
    }

    static boolean looksLike(byte[] payload) {
        if (payload == null || payload.length < MAGIC.length) {
            return false;
        }
        for (int index = 0; index < MAGIC.length; index++) {
            if (payload[index] != MAGIC[index]) {
                return false;
            }
        }
        return true;
    }

    static Message decode(byte[] payload) {
        if (!looksLike(payload) || payload.length < HEADER_BYTES) {
            return null;
        }
        ByteBuffer input = ByteBuffer.wrap(payload, MAGIC.length, payload.length - MAGIC.length);
        int type = input.get() & 0xFF;
        long nonce = input.getLong();
        int innerMtu = input.getShort() & 0xFFFF;
        if (nonce <= 0 || innerMtu < MIN_INNER_MTU || innerMtu > MAX_INNER_MTU) {
            return null;
        }
        if (type == TYPE_PROBE && payload.length == innerMtu) {
            return new Message(true, nonce, innerMtu);
        }
        return type == TYPE_ACK && payload.length == HEADER_BYTES
                ? new Message(false, nonce, innerMtu)
                : null;
    }

    private static void writeHeader(byte[] output, int type, long nonce, int innerMtu) {
        ByteBuffer.wrap(output)
                .put(MAGIC)
                .put((byte) type)
                .putLong(nonce)
                .putShort((short) innerMtu);
    }

    private static void validate(long nonce, int innerMtu) {
        if (nonce <= 0 || innerMtu < MIN_INNER_MTU || innerMtu > MAX_INNER_MTU) {
            throw new IllegalArgumentException("invalid path MTU message");
        }
    }

    static final class Message {
        final boolean probe;
        final long nonce;
        final int innerMtu;

        Message(boolean probe, long nonce, int innerMtu) {
            this.probe = probe;
            this.nonce = nonce;
            this.innerMtu = innerMtu;
        }
    }

    static final class Probe {
        final long nonce;
        final int innerMtu;

        Probe(long nonce, int innerMtu) {
            this.nonce = nonce;
            this.innerMtu = innerMtu;
        }
    }

    static final class Transition {
        final Probe probe;
        final Integer completedMtu;

        Transition(Probe probe, Integer completedMtu) {
            this.probe = probe;
            this.completedMtu = completedMtu;
        }

        static Transition idle() {
            return new Transition(null, null);
        }
    }

    static final class Discovery {
        private String pathKey = "";
        private int ceiling = MIN_INNER_MTU;
        private int lower = MIN_INNER_MTU;
        private int upper = MIN_INNER_MTU;
        private int effective = MIN_INNER_MTU;
        private int pendingSize;
        private long pendingNonce;
        private int attempts;
        private boolean sawFailure;
        private long validUntilMillis;

        synchronized Transition activate(String nextPathKey,
                                         int configuredMtu,
                                         Integer cachedMtu,
                                         long cachedUntilMillis,
                                         long nowMillis,
                                         LongSupplier nonceSupplier) {
            int normalized = normalize(configuredMtu);
            boolean samePath = nextPathKey != null && nextPathKey.equals(pathKey);
            if (samePath && (pendingSize > 0 || validUntilMillis > nowMillis)) {
                return Transition.idle();
            }
            pathKey = nextPathKey == null ? "" : nextPathKey;
            ceiling = normalized;
            lower = MIN_INNER_MTU;
            upper = normalized;
            pendingSize = 0;
            pendingNonce = 0L;
            attempts = 0;
            sawFailure = false;
            if (cachedMtu != null && cachedUntilMillis > nowMillis) {
                effective = Math.min(normalized, normalize(cachedMtu));
                lower = effective;
                upper = effective;
                validUntilMillis = cachedUntilMillis;
                return Transition.idle();
            }
            effective = normalized;
            validUntilMillis = 0L;
            return issue(normalized, nonceSupplier);
        }

        synchronized Transition acknowledge(long nonce,
                                            int innerMtu,
                                            long nowMillis,
                                            LongSupplier nonceSupplier) {
            if (pendingSize == 0 || pendingNonce != nonce || pendingSize != innerMtu) {
                return Transition.idle();
            }
            lower = Math.max(lower, innerMtu);
            effective = sawFailure ? lower : ceiling;
            pendingSize = 0;
            pendingNonce = 0L;
            attempts = 0;
            if (lower >= upper) {
                return complete(nowMillis);
            }
            return issue(lower + ((upper - lower + 1) / 2), nonceSupplier);
        }

        synchronized Transition timeout(long nonce, long nowMillis, LongSupplier nonceSupplier) {
            if (pendingSize == 0 || pendingNonce != nonce) {
                return Transition.idle();
            }
            if (attempts < MAX_ATTEMPTS) {
                attempts++;
                return new Transition(new Probe(pendingNonce, pendingSize), null);
            }
            sawFailure = true;
            upper = Math.max(MIN_INNER_MTU, pendingSize - 1);
            effective = Math.min(effective, upper);
            pendingSize = 0;
            pendingNonce = 0L;
            attempts = 0;
            if (upper <= lower) {
                effective = lower;
                return complete(nowMillis);
            }
            return issue(lower + ((upper - lower + 1) / 2), nonceSupplier);
        }

        synchronized int effectiveMtu(int configuredMtu) {
            return Math.min(normalize(configuredMtu), Math.max(MIN_INNER_MTU, effective));
        }

        synchronized String pathKey() {
            return pathKey;
        }

        private Transition issue(int size, LongSupplier nonceSupplier) {
            long nonce;
            do {
                nonce = nonceSupplier.getAsLong() & Long.MAX_VALUE;
            } while (nonce == 0L);
            pendingSize = Math.max(MIN_INNER_MTU, Math.min(ceiling, size));
            pendingNonce = nonce;
            attempts = 1;
            return new Transition(new Probe(nonce, pendingSize), null);
        }

        private Transition complete(long nowMillis) {
            effective = Math.max(MIN_INNER_MTU, Math.min(ceiling, effective));
            validUntilMillis = nowMillis + CACHE_TTL_MILLIS;
            return new Transition(null, effective);
        }

        private static int normalize(int mtu) {
            return Math.max(MIN_INNER_MTU, Math.min(MAX_INNER_MTU, mtu));
        }
    }
}
