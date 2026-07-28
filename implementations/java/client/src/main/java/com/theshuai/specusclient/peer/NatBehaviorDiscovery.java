package com.theshuai.specusclient.peer;

import java.net.InetSocketAddress;
import java.util.Objects;

/**
 * RFC 5780 mapping/filtering discovery state. Network I/O and retransmission
 * stay in {@link PeerMeshClient}; this class only owns probe ordering and
 * classification.
 */
final class NatBehaviorDiscovery {
    static final String DISCOVERY_RFC5780 = "RFC5780";
    static final String DISCOVERY_BASIC = "BASIC";

    static final String ENDPOINT_INDEPENDENT = "ENDPOINT_INDEPENDENT";
    static final String ADDRESS_DEPENDENT = "ADDRESS_DEPENDENT";
    static final String ADDRESS_AND_PORT_DEPENDENT = "ADDRESS_AND_PORT_DEPENDENT";
    static final String UNKNOWN = "UNKNOWN";
    static final String UNSUPPORTED = "UNSUPPORTED";

    private int generation;
    private Probe pendingProbe;
    private InetSocketAddress primaryEndpoint;
    private InetSocketAddress otherEndpoint;
    private InetSocketAddress primaryMappedEndpoint;
    private InetSocketAddress alternateIpMappedEndpoint;
    private String mappingBehavior = "";
    private String filteringBehavior = "";
    private boolean complete;

    synchronized Transition begin(InetSocketAddress primaryEndpoint,
                                  InetSocketAddress primaryMappedEndpoint,
                                  InetSocketAddress otherEndpoint) {
        requireResolved(primaryEndpoint, "primaryEndpoint");
        requireResolved(primaryMappedEndpoint, "primaryMappedEndpoint");
        requireResolved(otherEndpoint, "otherEndpoint");
        if (sameAddress(primaryEndpoint, otherEndpoint)
                || primaryEndpoint.getPort() == otherEndpoint.getPort()) {
            throw new IllegalArgumentException(
                    "RFC 5780 discovery requires another IP address and another UDP port");
        }

        generation++;
        this.primaryEndpoint = primaryEndpoint;
        this.primaryMappedEndpoint = primaryMappedEndpoint;
        this.otherEndpoint = otherEndpoint;
        alternateIpMappedEndpoint = null;
        mappingBehavior = "";
        filteringBehavior = "";
        complete = false;
        return next(Probe.FILTER_CHANGE_IP_AND_PORT);
    }

    synchronized Transition succeeded(int expectedGeneration,
                                      Probe probe,
                                      InetSocketAddress mappedEndpoint) {
        if (!accepts(expectedGeneration, probe)) {
            return ignored();
        }
        requireResolved(mappedEndpoint, "mappedEndpoint");
        return switch (probe) {
            case FILTER_CHANGE_IP_AND_PORT -> {
                filteringBehavior = ENDPOINT_INDEPENDENT;
                yield next(Probe.MAPPING_ALTERNATE_IP);
            }
            case FILTER_CHANGE_PORT -> {
                filteringBehavior = ADDRESS_DEPENDENT;
                yield next(Probe.MAPPING_ALTERNATE_IP);
            }
            case MAPPING_ALTERNATE_IP -> {
                alternateIpMappedEndpoint = mappedEndpoint;
                // Test III also proves A2:P2 is operational. That validation is
                // needed before treating a missing filtering response as NAT behavior.
                yield next(Probe.MAPPING_ALTERNATE_IP_AND_PORT);
            }
            case MAPPING_ALTERNATE_IP_AND_PORT -> finishMapping(mappedEndpoint);
        };
    }

    synchronized Transition timedOut(int expectedGeneration, Probe probe) {
        if (!accepts(expectedGeneration, probe)) {
            return ignored();
        }
        return switch (probe) {
            case FILTER_CHANGE_IP_AND_PORT -> next(Probe.FILTER_CHANGE_PORT);
            case FILTER_CHANGE_PORT -> {
                filteringBehavior = ADDRESS_AND_PORT_DEPENDENT;
                yield next(Probe.MAPPING_ALTERNATE_IP);
            }
            case MAPPING_ALTERNATE_IP, MAPPING_ALTERNATE_IP_AND_PORT -> finishMappingFailure();
        };
    }

    synchronized Transition failed(int expectedGeneration, Probe probe, boolean unsupported) {
        if (!accepts(expectedGeneration, probe)) {
            return ignored();
        }
        return switch (probe) {
            case FILTER_CHANGE_IP_AND_PORT, FILTER_CHANGE_PORT -> {
                filteringBehavior = unsupported ? UNSUPPORTED : UNKNOWN;
                yield next(Probe.MAPPING_ALTERNATE_IP);
            }
            case MAPPING_ALTERNATE_IP, MAPPING_ALTERNATE_IP_AND_PORT -> finishMappingFailure();
        };
    }

    synchronized Snapshot snapshot() {
        return new Snapshot(
                generation,
                DISCOVERY_RFC5780,
                mappingBehavior,
                filteringBehavior,
                primaryMappedEndpoint,
                complete);
    }

    synchronized boolean isActive() {
        return pendingProbe != null && !complete;
    }

    private Transition finishMapping(InetSocketAddress alternateIpAndPortMappedEndpoint) {
        if (sameEndpoint(primaryMappedEndpoint, alternateIpMappedEndpoint)) {
            mappingBehavior = ENDPOINT_INDEPENDENT;
        } else if (sameEndpoint(alternateIpMappedEndpoint, alternateIpAndPortMappedEndpoint)) {
            mappingBehavior = ADDRESS_DEPENDENT;
        } else {
            mappingBehavior = ADDRESS_AND_PORT_DEPENDENT;
        }
        pendingProbe = null;
        complete = true;
        return accepted(null);
    }

    private Transition finishMappingFailure() {
        mappingBehavior = UNKNOWN;
        // Endpoint-independent filtering was confirmed by an actual A2:P2
        // response. Other filtering outcomes depend on missing A2 traffic and
        // cannot be trusted when the normal A2 validation probe also failed.
        if (!ENDPOINT_INDEPENDENT.equals(filteringBehavior)
                && !UNSUPPORTED.equals(filteringBehavior)) {
            filteringBehavior = UNKNOWN;
        }
        pendingProbe = null;
        complete = true;
        return accepted(null);
    }

    private Transition next(Probe probe) {
        pendingProbe = probe;
        return accepted(request(probe));
    }

    private ProbeRequest request(Probe probe) {
        InetSocketAddress alternateIpPrimaryPort =
                new InetSocketAddress(otherEndpoint.getAddress(), primaryEndpoint.getPort());
        InetSocketAddress primaryIpAlternatePort =
                new InetSocketAddress(primaryEndpoint.getAddress(), otherEndpoint.getPort());
        return switch (probe) {
            case FILTER_CHANGE_IP_AND_PORT -> new ProbeRequest(
                    generation,
                    probe,
                    primaryEndpoint,
                    otherEndpoint,
                    true,
                    true);
            case FILTER_CHANGE_PORT -> new ProbeRequest(
                    generation,
                    probe,
                    primaryEndpoint,
                    primaryIpAlternatePort,
                    false,
                    true);
            case MAPPING_ALTERNATE_IP -> new ProbeRequest(
                    generation,
                    probe,
                    alternateIpPrimaryPort,
                    alternateIpPrimaryPort,
                    false,
                    false);
            case MAPPING_ALTERNATE_IP_AND_PORT -> new ProbeRequest(
                    generation,
                    probe,
                    otherEndpoint,
                    otherEndpoint,
                    false,
                    false);
        };
    }

    private boolean accepts(int expectedGeneration, Probe probe) {
        return expectedGeneration == generation && pendingProbe == probe && !complete;
    }

    private Transition accepted(ProbeRequest nextProbe) {
        return new Transition(true, nextProbe, snapshot());
    }

    private Transition ignored() {
        return new Transition(false, null, snapshot());
    }

    private static void requireResolved(InetSocketAddress endpoint, String name) {
        Objects.requireNonNull(endpoint, name);
        if (endpoint.isUnresolved() || endpoint.getAddress() == null || endpoint.getPort() <= 0) {
            throw new IllegalArgumentException(name + " must be a resolved UDP endpoint");
        }
    }

    private static boolean sameEndpoint(InetSocketAddress first, InetSocketAddress second) {
        return first != null
                && second != null
                && first.getPort() == second.getPort()
                && sameAddress(first, second);
    }

    private static boolean sameAddress(InetSocketAddress first, InetSocketAddress second) {
        return first != null
                && second != null
                && first.getAddress() != null
                && first.getAddress().equals(second.getAddress());
    }

    enum Probe {
        FILTER_CHANGE_IP_AND_PORT("rfc5780-filter-change-ip-port"),
        FILTER_CHANGE_PORT("rfc5780-filter-change-port"),
        MAPPING_ALTERNATE_IP("rfc5780-mapping-alternate-ip"),
        MAPPING_ALTERNATE_IP_AND_PORT("rfc5780-mapping-alternate-ip-port");

        private final String role;

        Probe(String role) {
            this.role = role;
        }

        String role() {
            return role;
        }
    }

    record ProbeRequest(int generation,
                        Probe probe,
                        InetSocketAddress targetEndpoint,
                        InetSocketAddress expectedResponseEndpoint,
                        boolean changeIp,
                        boolean changePort) {
    }

    record Snapshot(int generation,
                    String discovery,
                    String mappingBehavior,
                    String filteringBehavior,
                    InetSocketAddress mappedEndpoint,
                    boolean complete) {
    }

    record Transition(boolean accepted, ProbeRequest nextProbe, Snapshot snapshot) {
    }
}
