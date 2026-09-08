package com.theshuai.common.peeregress;

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
