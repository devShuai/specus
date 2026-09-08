package com.theshuai.common.peeregress;

import java.util.Set;

/**
 * Result codes defined by {@code protocol/spec/peer-egress.md}.
 *
 * <p>Every code is exercised by {@code protocol/test-vectors/peer-egress-authz-v1.json},
 * {@code peer-egress-rules-v1.json} or {@code peer-egress-frame-v1.json}. Implementations must
 * return the same code for the same input, not merely the same allow/deny outcome.
 */
public final class PeerEgressCodes {
    public static final String ALLOWED = "EGRESS_ALLOWED";

    // Authorization, evaluated in this order.
    public static final String HOP_NOT_ALLOWED = "EGRESS_HOP_NOT_ALLOWED";
    public static final String DISABLED = "EGRESS_DISABLED";
    public static final String PEER_ACL_DENIED = "EGRESS_PEER_ACL_DENIED";
    public static final String CONSUMER_DENIED = "EGRESS_CONSUMER_DENIED";
    public static final String FORBIDDEN_DESTINATION = "EGRESS_FORBIDDEN_DESTINATION";
    public static final String SCOPE_DENIED = "EGRESS_SCOPE_DENIED";
    public static final String DEST_DENIED = "EGRESS_DEST_DENIED";
    public static final String PROTOCOL_DENIED = "EGRESS_PROTOCOL_DENIED";
    public static final String PORT_DENIED = "EGRESS_PORT_DENIED";
    public static final String LIMIT_EXCEEDED = "EGRESS_LIMIT_EXCEEDED";

    // Consumer rule configuration validation.
    public static final String RULE_DOMAIN_UNSUPPORTED = "EGRESS_RULE_DOMAIN_UNSUPPORTED";
    public static final String RULE_IPV6_UNSUPPORTED = "EGRESS_RULE_IPV6_UNSUPPORTED";
    public static final String RULE_MALFORMED = "EGRESS_RULE_MALFORMED";
    public static final String RULE_MISSING_TARGET = "EGRESS_RULE_MISSING_TARGET";
    public static final String RULE_MESH_OVERLAP = "EGRESS_RULE_MESH_OVERLAP";
    public static final String RULE_DEFAULT_ROUTE = "EGRESS_RULE_DEFAULT_ROUTE";
    public static final String RULE_PORT_UNSUPPORTED = "EGRESS_RULE_PORT_UNSUPPORTED";

    // SPEG1 frame decoding.
    public static final String FRAME_BAD_MAGIC = "EGRESS_FRAME_BAD_MAGIC";
    public static final String FRAME_UNKNOWN_TYPE = "EGRESS_FRAME_UNKNOWN_TYPE";
    public static final String FRAME_RESERVED_SET = "EGRESS_FRAME_RESERVED_SET";
    public static final String FRAME_TRUNCATED = "EGRESS_FRAME_TRUNCATED";
    public static final String FRAME_TRAILING_BYTES = "EGRESS_FRAME_TRAILING_BYTES";
    public static final String IPV6_UNSUPPORTED = "EGRESS_IPV6_UNSUPPORTED";
    public static final String FRAME_MALFORMED_CONTROL = "EGRESS_FRAME_MALFORMED_CONTROL";
    public static final String CONTROL_UNSUPPORTED = "EGRESS_CONTROL_UNSUPPORTED";

    /**
     * Every code this build defines.
     *
     * <p>Built from the constants above rather than repeated as literals, so a code cannot be
     * listed here under a different spelling than the one implementations return.
     */
    private static final Set<String> KNOWN = Set.of(
            ALLOWED,
            HOP_NOT_ALLOWED, DISABLED, PEER_ACL_DENIED, CONSUMER_DENIED, FORBIDDEN_DESTINATION,
            SCOPE_DENIED, DEST_DENIED, PROTOCOL_DENIED, PORT_DENIED, LIMIT_EXCEEDED,
            RULE_DOMAIN_UNSUPPORTED, RULE_IPV6_UNSUPPORTED, RULE_MALFORMED, RULE_MISSING_TARGET,
            RULE_MESH_OVERLAP, RULE_DEFAULT_ROUTE, RULE_PORT_UNSUPPORTED,
            FRAME_BAD_MAGIC, FRAME_UNKNOWN_TYPE, FRAME_RESERVED_SET, FRAME_TRUNCATED,
            FRAME_TRAILING_BYTES, IPV6_UNSUPPORTED, FRAME_MALFORMED_CONTROL, CONTROL_UNSUPPORTED);

    /**
     * Reports whether a code is one this build defines.
     *
     * <p>Used to filter client-reported refusal counters: without it a client could grow the stored
     * map with keys of its own invention.
     */
    public static boolean isKnown(String code) {
        return code != null && KNOWN.contains(code);
    }

    private PeerEgressCodes() {
    }
}
