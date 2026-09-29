package com.theshuai.common.peeregress;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;

/**
 * The {@code egress-catalog} push, as a consumer reads it.
 *
 * <p>Only {@code domainTargetCapable} is kept: whether an egress resolves names decides whether a
 * domain rule pointed at it is in force (phase two). Whether an egress is available is the mesh's
 * own peer state, not the catalogue's {@code online}, and nothing else in an entry changes what a
 * consumer does today. See {@code protocol/spec/peer-egress-dns.md} ("consumer reads the
 * catalogue"); shared vector: the {@code catalog} section of
 * {@code protocol/test-vectors/peer-egress-dns-v1.json}.
 *
 * @param revision            the snapshot number, for the caller's monotonic guard
 * @param domainTargetCapable the egresses whose entry says JSON {@code true}, and only those
 */
public record PeerEgressCatalogMessage(long revision, Set<Long> domainTargetCapable) {

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
        // in order would.
        Map<Long, Boolean> capable = new TreeMap<>();
        for (JsonNode entry : egresses) {
            if (!entry.isObject() || !positiveInteger(entry.path("clientId"))) {
                continue;
            }
            JsonNode flag = entry.path("domainTargetCapable");
            capable.put(entry.path("clientId").longValue(), flag.isBoolean() && flag.booleanValue());
        }
        Set<Long> ids = new TreeSet<>();
        capable.forEach((id, able) -> {
            if (able) {
                ids.add(id);
            }
        });
        return new PeerEgressCatalogMessage(revision.longValue(), Set.copyOf(ids));
    }

    /** A JSON integer above zero: not a string, not a boolean, not a fraction, and fits a long. */
    private static boolean positiveInteger(JsonNode node) {
        return node.isIntegralNumber() && node.canConvertToLong() && node.longValue() > 0;
    }
}
