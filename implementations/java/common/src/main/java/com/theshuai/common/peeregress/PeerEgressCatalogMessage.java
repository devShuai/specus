package com.theshuai.common.peeregress;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.Collections;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;

/**
 * The {@code egress-catalog} push, as a consumer reads it.
 *
 * <p>Three things are kept. Which egresses are listed and the {@code egressVersion} each one's
 * online session announced decide whether a flow to an egress a rule names can go at all
 * ({@code protocol/spec/peer-egress.md}, "能力不支持"): an online egress the catalogue does not list,
 * or one that announced no peer egress, would only drop what it is sent. {@code domainTargetCapable}
 * decides whether a domain rule pointed at it is in force (phase two). Whether an egress is online
 * is the mesh's own peer state, not the catalogue's {@code online}, and nothing else in an entry
 * changes what a consumer does today. See {@code protocol/spec/peer-egress-dns.md} ("consumer reads
 * the catalogue"); shared vector: the {@code catalog} section of
 * {@code protocol/test-vectors/peer-egress-dns-v1.json}.
 *
 * @param revision            the snapshot number, for the caller's monotonic guard
 * @param domainTargetCapable the egresses whose entry says JSON {@code true}, and only those
 * @param listed              every egress with an entry that has a usable {@code clientId}
 * @param egressVersions      the listed egresses whose entry carries a usable {@code egressVersion},
 *                            and that version; a listed egress missing here carries none
 */
public record PeerEgressCatalogMessage(long revision, Set<Long> domainTargetCapable, Set<Long> listed,
        Map<Long, Long> egressVersions) {

    public static final String TYPE = "egress-catalog";

    private static final ObjectMapper MAPPER = new ObjectMapper();

    /**
     * Reads a push, returning null for one that must be refused whole: text that is not a JSON
     * object, a type naming something else, a revision that is not a positive integer, or an
     * {@code egresses} that is present and not a list. An absent list is an empty catalogue.
     *
     * <p>Inside the list an entry without a usable {@code clientId} is skipped rather than refusing
     * the message, and only a JSON {@code true} counts as capable: the string {@code "true"} or the
     * number {@code 1} is a server bug, and reading it as yes would put domain rules in force for an
     * egress that never said it resolves names. Unknown keys are ignored, so a server that adds a
     * field does not stop every older client from reading the catalogue.
     *
     * <p>{@code egressVersion} counts only as a non-negative JSON integer; anything else reads as
     * though the entry had none. An older server sends none, and an entry without one is taken as
     * offered rather than unsupported: guessing 0 from a string or a boolean would block an egress
     * that works.
     *
     * <p>The revision guard is the caller's, as for {@link PeerEgressConfigMessage}: this gives the
     * same answer for the same message every time.
     */
    public static PeerEgressCatalogMessage decode(String payload) {
        JsonNode message;
        try {
            message = MAPPER.readTree(payload == null ? "" : payload);
        } catch (Exception unreadable) {
            return null;
        }
        if (message == null || !message.isObject() || !TYPE.equals(message.path("type").asText(null))) {
            return null;
        }
        JsonNode revision = message.path("revision");
        if (!positiveInteger(revision)) {
            return null;
        }
        JsonNode egresses = message.path("egresses");
        if (!egresses.isMissingNode() && !egresses.isArray()) {
            return null;
        }
        // A later entry for the same egress replaces an earlier one, as a map built from the list
        // in order would; that includes taking away a version the earlier entry carried.
        Map<Long, Boolean> capable = new TreeMap<>();
        Map<Long, Long> versions = new TreeMap<>();
        for (JsonNode entry : egresses) {
            if (!entry.isObject() || !positiveInteger(entry.path("clientId"))) {
                continue;
            }
            long id = entry.path("clientId").longValue();
            JsonNode flag = entry.path("domainTargetCapable");
            capable.put(id, flag.isBoolean() && flag.booleanValue());
            Long version = egressVersion(entry.path("egressVersion"));
            if (version == null) {
                versions.remove(id);
            } else {
                versions.put(id, version);
            }
        }
        Set<Long> ids = new TreeSet<>();
        capable.forEach((id, able) -> {
            if (able) {
                ids.add(id);
            }
        });
        return new PeerEgressCatalogMessage(revision.longValue(), Collections.unmodifiableSet(ids),
                Collections.unmodifiableSet(new TreeSet<>(capable.keySet())), Collections.unmodifiableMap(versions));
    }

    /** A JSON integer above zero: not a string, not a boolean, not a fraction, and fits a long. */
    private static boolean positiveInteger(JsonNode node) {
        return node.isIntegralNumber() && node.canConvertToLong() && node.longValue() > 0;
    }

    /**
     * A JSON integer at or above zero, or null. One too large for a long is still a version of at
     * least 1, which is all a consumer asks of it, so it is held as the largest long rather than
     * dropped.
     */
    private static Long egressVersion(JsonNode node) {
        if (!node.isIntegralNumber() || node.bigIntegerValue().signum() < 0) {
            return null;
        }
        return node.canConvertToLong() ? node.longValue() : Long.MAX_VALUE;
    }
}
