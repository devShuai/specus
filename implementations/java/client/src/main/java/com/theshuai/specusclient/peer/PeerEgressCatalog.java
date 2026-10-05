package com.theshuai.specusclient.peer;

import com.theshuai.common.peeregress.PeerEgressCatalogMessage;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

/**
 * What this consumer has learned from {@code egress-catalog}: which egresses are listed, the
 * {@code egressVersion} each announced, and which resolve names.
 *
 * <p>The revision works as it does for {@code egress-config}: it rises within one control session,
 * a catalogue at or below the last accepted one is ignored, and a new session only resets that
 * floor. What was learned stays until the next accepted catalogue replaces it whole: an egress it
 * no longer lists is taken not to resolve names. Shared vector: the {@code catalog} section of
 * {@code protocol/test-vectors/peer-egress-dns-v1.json}.
 *
 * <p>Whether a catalogue was accepted is per control session, unlike what it said. The standing of
 * an egress ({@link Standing}) is only judged from a catalogue this session's server sent: a server
 * too old to send one must leave every egress {@code unknown}, and what an earlier server said
 * about an egress is no evidence about this one's view. Shared vector:
 * {@code protocol/test-vectors/peer-egress-standing-v1.json}.
 *
 * <p>Time arrives as an argument. Thread-safe: the control connection writes it, the mesh's tick
 * and the status read it.
 */
final class PeerEgressCatalog {

    /**
     * How long after control authentication a session may go without a catalogue before the status
     * says the server sent none: {@code catalogWaitSeconds} in the standing vector. A server that
     * supports peer egress pushes one at login, so this is a generous wait, not a deadline it races.
     */
    static final long WAIT_MILLIS = 30_000L;

    /** The status's {@code consumer.catalog}. */
    static final String STATE_WAITING = "waiting";
    static final String STATE_NONE = "none";
    static final String STATE_RECEIVED = "received";

    /**
     * What the catalogue says about one egress a rule names (protocol/spec/peer-egress.md,
     * "能力不支持"). Whether the egress is online is the mesh's to say and comes first; this is only
     * the catalogue's half.
     */
    enum Standing {
        /** No catalogue accepted this control session. An older server never sends one. */
        UNKNOWN("unknown", null),
        /** A catalogue was accepted and does not list it: not offered to this device. */
        NOT_OFFERED("not-offered", "egress-not-offered"),
        /** Listed, and its online session announced no peer egress: an older client. */
        UNSUPPORTED("unsupported", "egress-unsupported"),
        /** Listed with egressVersion 1 or more, or with none at all (an older server). */
        OFFERED("offered", null);

        private final String wireName;
        private final String blockedReason;

        Standing(String wireName, String blockedReason) {
            this.wireName = wireName;
            this.blockedReason = blockedReason;
        }

        /** The name the status and the vector use. */
        String wireName() {
            return wireName;
        }

        /** The blocked reason a flow to an online egress with this standing counts, or null when it goes. */
        String blockedReason() {
            return blockedReason;
        }

        /**
         * The standing from whether a catalogue was accepted this control session, whether it lists
         * the egress, and the egressVersion its entry carries (null for none).
         *
         * <p>{@code unknown} does not block, so a deployment that works under an older server keeps
         * working when its clients are upgraded first.
         */
        static Standing of(boolean received, boolean listed, Long egressVersion) {
            if (!received) {
                return UNKNOWN;
            }
            if (!listed) {
                return NOT_OFFERED;
            }
            if (egressVersion != null && egressVersion < 1) {
                return UNSUPPORTED;
            }
            return OFFERED;
        }
    }

    /**
     * What the consumer judges flows by, taken in one piece so a reader never pairs one catalogue's
     * list with another's versions.
     *
     * @param received       whether a catalogue was accepted in this control session
     * @param listed         the egresses the last accepted catalogue lists
     * @param egressVersions the usable egressVersion of each listed egress that carries one
     * @param domainCapable  the egresses the last accepted catalogue says resolve names
     */
    record Snapshot(boolean received, Set<Long> listed, Map<Long, Long> egressVersions, Set<Long> domainCapable) {

        /** Before any catalogue: every egress unknown, none resolving names. */
        static Snapshot empty() {
            return new Snapshot(false, Set.of(), Map.of(), Set.of());
        }

        Standing standing(long egress) {
            return Standing.of(received, listed.contains(egress), egressVersions.get(egress));
        }
    }

    /** The last accepted revision this control session, or null before the first. */
    private Long floor;
    private Set<Long> domainCapable = Set.of();
    private Set<Long> listed = Set.of();
    private Map<Long, Long> egressVersions = Map.of();
    /** Whether a catalogue was accepted since the control session began. */
    private boolean received;
    /** When the control session authenticated, or null before the first. */
    private Long sessionAtMs;

    /**
     * A new control session: its server numbers from wherever it likes, and has said nothing yet
     * about which egresses it offers.
     */
    synchronized void newSession(long nowMs) {
        floor = null;
        received = false;
        sessionAtMs = nowMs;
    }

    /**
     * Reads one pushed catalogue and reports whether it was accepted. A refused one -- not a
     * catalogue, malformed, or not newer -- leaves what is known unchanged.
     */
    synchronized boolean read(String payload) {
        PeerEgressCatalogMessage message = PeerEgressCatalogMessage.decode(payload);
        if (message == null || (floor != null && message.revision() <= floor)) {
            return false;
        }
        floor = message.revision();
        domainCapable = message.domainTargetCapable();
        listed = message.listed();
        egressVersions = message.egressVersions();
        received = true;
        return true;
    }

    /** What the consumer judges by now. */
    synchronized Snapshot snapshot() {
        return new Snapshot(received, listed, egressVersions, domainCapable);
    }

    /**
     * The status's {@code consumer.catalog}: {@code received} once one was accepted this control
     * session, {@code none} when {@link #WAIT_MILLIS} have passed since the session authenticated
     * without one (the server may be too old for peer egress), {@code waiting} until then and
     * before any session has authenticated. A clock that stepped back keeps it waiting.
     */
    synchronized String state(long nowMs) {
        if (received) {
            return STATE_RECEIVED;
        }
        if (sessionAtMs != null && nowMs - sessionAtMs >= WAIT_MILLIS) {
            return STATE_NONE;
        }
        return STATE_WAITING;
    }

    /** The egresses the last accepted catalogue says resolve names. */
    synchronized Set<Long> domainCapable() {
        return domainCapable;
    }

    /** The same, sorted, for a log line or a test. */
    synchronized List<Long> domainCapableIds() {
        return List.copyOf(new TreeSet<>(domainCapable));
    }

    /** The egresses the last accepted catalogue lists, sorted. */
    synchronized List<Long> listedIds() {
        return List.copyOf(new TreeSet<>(listed));
    }

    /** The egressVersion of each listed egress that carries a usable one. */
    synchronized Map<Long, Long> egressVersions() {
        return egressVersions;
    }

    /** The last accepted revision, 0 before any. */
    synchronized long revision() {
        return floor == null ? 0L : floor;
    }
}
