package com.theshuai.common.peeregress;

import java.time.Duration;

/**
 * Version negotiation for peer egress split routing.
 *
 * <p>The version is tracked separately from the individual target capabilities so that a later
 * release adding domain rules can coexist with clients that only understand address targets,
 * instead of gating everything on the version number alone.
 */
public final class PeerEgressProtocol {
    /** The split-routing version this build speaks. */
    public static final int PROTOCOL_VERSION = 1;

    /**
     * Cap on one {@code egress-report} envelope. The report carries counters only, so this is far
     * above what a well-formed one needs; it exists to bound what a client can send.
     */
    public static final int MAX_REPORT_BYTES = 8 * 1024;

    /** Reports accepted per control session inside {@link #REPORT_RATE_WINDOW}. */
    public static final int REPORT_RATE_LIMIT = 20;

    public static final Duration REPORT_RATE_WINDOW = Duration.ofMinutes(1);

    /**
     * Hard ceiling on tracked rate-limit sessions. Reached only under abuse, and refusing there is
     * safer than letting a client-driven map grow without bound.
     */
    public static final int MAX_RATE_TABLE_ENTRIES = 4096;

    private PeerEgressProtocol() {
    }

    /**
     * Clamps a client-announced version to what this build understands.
     *
     * @return {@code 0} when the client cannot take part, in which case the server must not push
     *     {@code egress-config} or {@code egress-catalog} to it
     */
    public static int normalizeVersion(int version) {
        if (version < 1) {
            return 0;
        }
        return Math.min(version, PROTOCOL_VERSION);
    }
}
