package com.theshuai.specusclient.peer;

import com.theshuai.common.peeregress.PeerEgressCatalogMessage;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;

/**
 * What this consumer has learned from {@code egress-catalog}: which egresses resolve names.
 *
 * <p>The revision works as it does for {@code egress-config}: it rises within one control session,
 * a catalogue at or below the last accepted one is ignored, and a new session only resets that
 * floor. What was learned stays until the next accepted catalogue replaces it whole: an egress it
 * no longer lists is taken not to resolve names. Shared vector: the {@code catalog} section of
 * {@code protocol/test-vectors/peer-egress-dns-v1.json}.
 *
 * <p>Thread-safe: the control connection writes it, the mesh's tick and the status read it.
 */
final class PeerEgressCatalog {

    /** The last accepted revision this control session, or null before the first. */
    private Long floor;
    private Set<Long> domainCapable = Set.of();

    /** A new control session: its server numbers from wherever it likes. */
    synchronized void newSession() {
        floor = null;
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
        return true;
    }

    /** The egresses the last accepted catalogue says resolve names. */
    synchronized Set<Long> domainCapable() {
        return domainCapable;
    }

    /** The same, sorted, for a log line or a test. */
    synchronized List<Long> domainCapableIds() {
        return List.copyOf(new TreeSet<>(domainCapable));
    }

    /** The last accepted revision, 0 before any. */
    synchronized long revision() {
        return floor == null ? 0L : floor;
    }
}
