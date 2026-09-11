package com.theshuai.common.peeregress;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * The {@code egress-config} push, as a client reads it.
 *
 * <p>The message is produced by three server implementations and read by three clients, so what a
 * client makes of it is a contract. The parts most likely to drift are the ones a JSON library
 * decides rather than the protocol: what an absent field becomes, and whether a value is normalised
 * before it is compared.
 *
 * <p>Shared vector: {@code protocol/test-vectors/peer-egress-control-v1.json}.
 *
 * @param revision the snapshot number, for the caller's monotonic guard
 */
public record PeerEgressConfigMessage(long revision, PeerEgressPolicy policy) {

    public static final String TYPE = "egress-config";

    private static final ObjectMapper MAPPER = new ObjectMapper();

    /**
     * Reads a push, returning null for anything that is not one.
     *
     * <p>Refused: a type naming something else, a payload that is not an object, or text that is
     * not JSON. Reading a catalogue as a policy would install one.
     *
     * <p>The revision guard is deliberately not here. It is the caller's state, and this has to
     * give the same answer for the same message every time it is called.
     */
    public static PeerEgressConfigMessage decode(String payload) {
        JsonNode message;
        try {
            message = MAPPER.readTree(payload == null ? "" : payload);
        } catch (Exception unreadable) {
            return null;
        }
        if (message == null || !message.isObject() || !TYPE.equals(message.path("type").asText(null))) {
            return null;
        }

        PeerEgressPolicy policy = new PeerEgressPolicy();
        policy.setEnabled(message.path("enabled").asBoolean(false));
        // Trimmed and uppercased before it is stored. The judgment layer compares this for equality
        // against a scope it computes itself, so a push saying "public" would be refused by an
        // implementation that kept the raw string. An absent scope stays empty, which denies: a
        // missing authorization field must not fall back to the permissive value.
        policy.setScope(message.path("scope").asText("").trim().toUpperCase(Locale.ROOT));

        List<Long> consumers = new ArrayList<>();
        for (JsonNode entry : message.path("allowedConsumerClientIds")) {
            consumers.add(entry.asLong());
        }
        policy.setAllowedConsumerClientIds(List.copyOf(consumers));

        List<PeerEgressPolicy.PeerEgressDestinationRule> rules = new ArrayList<>();
        for (JsonNode raw : message.path("destinationRules")) {
            if (!raw.isObject()) {
                continue;
            }
            PeerEgressPolicy.PeerEgressDestinationRule rule =
                    new PeerEgressPolicy.PeerEgressDestinationRule();
            rule.setCidr(raw.path("cidr").asText(""));
            List<String> protocols = new ArrayList<>();
            for (JsonNode protocol : raw.path("protocols")) {
                protocols.add(protocol.asText(""));
            }
            rule.setProtocols(List.copyOf(protocols));
            List<List<Integer>> ranges = new ArrayList<>();
            for (JsonNode pair : raw.path("portRanges")) {
                List<Integer> bounds = new ArrayList<>();
                for (JsonNode bound : pair) {
                    bounds.add(bound.asInt());
                }
                ranges.add(List.copyOf(bounds));
            }
            rule.setPortRanges(List.copyOf(ranges));
            rules.add(rule);
        }
        policy.setDestinationRules(List.copyOf(rules));

        // Absent limits decode as zeros rather than as this class's defaults. Whether a zero means
        // "use the default" or "no limit" is the runtime's decision, and inventing a number here
        // would hide from it that the server named none.
        JsonNode limits = message.path("limits");
        PeerEgressPolicy.PeerEgressLimits decoded = new PeerEgressPolicy.PeerEgressLimits();
        decoded.setMaxConcurrentFlows(limits.path("maxConcurrentFlows").asInt(0));
        decoded.setMaxFlowsPerConsumer(limits.path("maxFlowsPerConsumer").asInt(0));
        decoded.setIdleTimeoutSeconds(limits.path("idleTimeoutSeconds").asInt(0));
        policy.setLimits(decoded);

        return new PeerEgressConfigMessage(message.path("revision").asLong(0), policy);
    }
}
