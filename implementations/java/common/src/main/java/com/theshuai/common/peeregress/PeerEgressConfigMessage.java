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
 * <p>Shared vectors: {@code protocol/test-vectors/peer-egress-control-v1.json}, and for the domain
 * rules {@code protocol/test-vectors/peer-egress-domain-policy-v1.json}.
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
            rule.setProtocols(protocolsOf(raw));
            rule.setPortRanges(portRangesOf(raw));
            rules.add(rule);
        }
        policy.setDestinationRules(List.copyOf(rules));
        policy.setDomainRules(domainRulesOf(message.path("domainRules")));

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

    /**
     * The domain rules a push carries. An absent field, or one that is not an array, is no domain
     * rules: an older server sends none, and the destination rules alone then decide. An entry is
     * skipped, and the rest kept, when it is not an object, when its match is not a name or
     * {@code *.name} as a consumer's domain rule would write it, or when its protocols is not an
     * array of strings or its portRanges not an array of {@code [integer, integer]} pairs. A rule
     * this egress cannot read must grant nothing, not void the policy around it. Absent or null
     * lists read as empty, and such a rule allows no flow.
     */
    private static List<PeerEgressPolicy.PeerEgressDomainRule> domainRulesOf(JsonNode value) {
        if (!value.isArray()) {
            return List.of();
        }
        List<PeerEgressPolicy.PeerEgressDomainRule> rules = new ArrayList<>();
        for (JsonNode raw : value) {
            if (!raw.isObject() || !raw.path("match").isTextual()) {
                continue;
            }
            String match = raw.path("match").asText().trim();
            if (!PeerEgressNames.validMatch(match)) {
                continue;
            }
            List<String> protocols = strictProtocolsOf(raw.path("protocols"));
            List<List<Integer>> ranges = strictPortRangesOf(raw.path("portRanges"));
            if (protocols == null || ranges == null) {
                continue;
            }
            PeerEgressPolicy.PeerEgressDomainRule rule = new PeerEgressPolicy.PeerEgressDomainRule();
            rule.setMatch(PeerEgressNames.normalize(match));
            rule.setProtocols(protocols);
            rule.setPortRanges(ranges);
            rules.add(rule);
        }
        return List.copyOf(rules);
    }

    /**
     * A domain rule's protocols, or null when they are not an array of strings. Stricter than the
     * destination rules' reading on purpose: a rule in a shape the server could not have stored is
     * one this egress does not understand, and every implementation skips it rather than each
     * guessing what a bare {@code "tcp"} or a number was meant to say.
     */
    private static List<String> strictProtocolsOf(JsonNode value) {
        if (value.isMissingNode() || value.isNull()) {
            return List.of();
        }
        if (!value.isArray()) {
            return null;
        }
        List<String> protocols = new ArrayList<>();
        for (JsonNode protocol : value) {
            if (!protocol.isTextual()) {
                return null;
            }
            protocols.add(protocol.asText());
        }
        return List.copyOf(protocols);
    }

    /** A domain rule's port ranges, or null when they are not an array of two-integer arrays. */
    private static List<List<Integer>> strictPortRangesOf(JsonNode value) {
        if (value.isMissingNode() || value.isNull()) {
            return List.of();
        }
        if (!value.isArray()) {
            return null;
        }
        List<List<Integer>> ranges = new ArrayList<>();
        for (JsonNode pair : value) {
            if (!pair.isArray() || pair.size() != 2
                    || !pair.get(0).isIntegralNumber() || !pair.get(1).isIntegralNumber()) {
                return null;
            }
            ranges.add(List.of(saturated(pair.get(0)), saturated(pair.get(1))));
        }
        return List.copyOf(ranges);
    }

    /**
     * An integral bound as an int. One beyond the int range is held at the nearest end, which
     * compares against every port in 0-65535 exactly as the value itself would.
     */
    private static int saturated(JsonNode bound) {
        if (bound.canConvertToInt()) {
            return bound.intValue();
        }
        return bound.bigIntegerValue().signum() > 0 ? Integer.MAX_VALUE : Integer.MIN_VALUE;
    }

    private static List<String> protocolsOf(JsonNode rule) {
        List<String> protocols = new ArrayList<>();
        for (JsonNode protocol : rule.path("protocols")) {
            protocols.add(protocol.asText(""));
        }
        return List.copyOf(protocols);
    }

    private static List<List<Integer>> portRangesOf(JsonNode rule) {
        List<List<Integer>> ranges = new ArrayList<>();
        for (JsonNode pair : rule.path("portRanges")) {
            List<Integer> bounds = new ArrayList<>();
            for (JsonNode bound : pair) {
                bounds.add(bound.asInt());
            }
            ranges.add(List.copyOf(bounds));
        }
        return List.copyOf(ranges);
    }
}
