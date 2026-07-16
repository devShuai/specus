package com.theshuai.common.stun;

import java.net.InetSocketAddress;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

public final class StunEndpointTopology {
    public static final EndpointId PRIMARY = new EndpointId(AddressSlot.PRIMARY, PortSlot.PRIMARY);
    public static final EndpointId PRIMARY_ALTERNATE_PORT =
            new EndpointId(AddressSlot.PRIMARY, PortSlot.ALTERNATE);
    public static final EndpointId ALTERNATE_PRIMARY_PORT =
            new EndpointId(AddressSlot.ALTERNATE, PortSlot.PRIMARY);
    public static final EndpointId ALTERNATE =
            new EndpointId(AddressSlot.ALTERNATE, PortSlot.ALTERNATE);

    private final Map<EndpointId, Endpoint> endpoints;
    private final boolean rfc5780;

    private StunEndpointTopology(Map<EndpointId, Endpoint> endpoints, boolean rfc5780) {
        this.endpoints = Collections.unmodifiableMap(new LinkedHashMap<>(endpoints));
        this.rfc5780 = rfc5780;
    }

    public static StunEndpointTopology basic(Endpoint primary, Endpoint alternatePort) {
        requireId(primary, PRIMARY);
        Map<EndpointId, Endpoint> endpoints = new LinkedHashMap<>();
        endpoints.put(primary.id(), primary);
        if (alternatePort != null) {
            requireId(alternatePort, PRIMARY_ALTERNATE_PORT);
            validateAddressSlot(primary, alternatePort, "primary");
            endpoints.put(alternatePort.id(), alternatePort);
        }
        return new StunEndpointTopology(endpoints, false);
    }

    public static StunEndpointTopology rfc5780(Endpoint primary,
                                                Endpoint primaryAlternatePort,
                                                Endpoint alternatePrimaryPort,
                                                Endpoint alternate) {
        requireId(primary, PRIMARY);
        requireId(primaryAlternatePort, PRIMARY_ALTERNATE_PORT);
        requireId(alternatePrimaryPort, ALTERNATE_PRIMARY_PORT);
        requireId(alternate, ALTERNATE);

        Map<EndpointId, Endpoint> endpoints = new LinkedHashMap<>();
        endpoints.put(primary.id(), primary);
        endpoints.put(primaryAlternatePort.id(), primaryAlternatePort);
        endpoints.put(alternatePrimaryPort.id(), alternatePrimaryPort);
        endpoints.put(alternate.id(), alternate);
        validateRfc5780(endpoints);
        return new StunEndpointTopology(endpoints, true);
    }

    public Endpoint endpoint(EndpointId id) {
        Endpoint endpoint = endpoints.get(id);
        if (endpoint == null) {
            throw new IllegalArgumentException("STUN endpoint is not configured: " + id);
        }
        return endpoint;
    }

    public Collection<Endpoint> endpoints() {
        return endpoints.values();
    }

    public boolean supportsRfc5780() {
        return rfc5780;
    }

    public EndpointId responseEndpoint(EndpointId incoming, StunMessage.ChangeRequest changeRequest) {
        Objects.requireNonNull(incoming, "incoming");
        StunMessage.ChangeRequest request =
                changeRequest == null ? StunMessage.ChangeRequest.NONE : changeRequest;
        if (!rfc5780 || (!request.changeIp() && !request.changePort())) {
            return incoming;
        }
        EndpointId result = new EndpointId(
                request.changeIp() ? incoming.addressSlot().other() : incoming.addressSlot(),
                request.changePort() ? incoming.portSlot().other() : incoming.portSlot());
        endpoint(result);
        return result;
    }

    public Optional<EndpointId> otherEndpoint(EndpointId incoming) {
        if (!rfc5780) {
            return Optional.empty();
        }
        EndpointId other = new EndpointId(incoming.addressSlot().other(), incoming.portSlot().other());
        return endpoints.containsKey(other) ? Optional.of(other) : Optional.empty();
    }

    public Optional<EndpointId> legacyAlternatePortEndpoint(EndpointId incoming) {
        EndpointId otherPort = new EndpointId(incoming.addressSlot(), incoming.portSlot().other());
        return endpoints.containsKey(otherPort) ? Optional.of(otherPort) : Optional.empty();
    }

    private static void requireId(Endpoint endpoint, EndpointId expected) {
        Objects.requireNonNull(endpoint, "endpoint");
        if (!expected.equals(endpoint.id())) {
            throw new IllegalArgumentException("Expected STUN endpoint " + expected + " but got " + endpoint.id());
        }
    }

    private static void validateRfc5780(Map<EndpointId, Endpoint> endpoints) {
        Endpoint a1p1 = endpoints.get(PRIMARY);
        Endpoint a1p2 = endpoints.get(PRIMARY_ALTERNATE_PORT);
        Endpoint a2p1 = endpoints.get(ALTERNATE_PRIMARY_PORT);
        Endpoint a2p2 = endpoints.get(ALTERNATE);

        validateAddressSlot(a1p1, a1p2, "primary");
        validateAddressSlot(a2p1, a2p2, "alternate");
        validatePortSlot(a1p1, a2p1, "primary");
        validatePortSlot(a1p2, a2p2, "alternate");
        if (a1p1.bindAddress().getAddress().isAnyLocalAddress()
                || a2p1.bindAddress().getAddress().isAnyLocalAddress()) {
            throw new IllegalArgumentException("RFC 5780 requires two explicit bind IP addresses");
        }
        if (sameAddress(a1p1.bindAddress(), a2p1.bindAddress())) {
            throw new IllegalArgumentException("RFC 5780 requires two distinct bind IP addresses");
        }
        if (sameAddress(a1p1.advertisedAddress(), a2p1.advertisedAddress())) {
            throw new IllegalArgumentException("RFC 5780 requires two distinct advertised IP addresses");
        }
        if (addressBytes(a1p1.advertisedAddress()) != addressBytes(a2p1.advertisedAddress())) {
            throw new IllegalArgumentException("RFC 5780 endpoints must use the same address family");
        }
    }

    private static void validateAddressSlot(Endpoint first, Endpoint second, String slot) {
        if (!sameAddress(first.bindAddress(), second.bindAddress())
                || !sameAddress(first.advertisedAddress(), second.advertisedAddress())) {
            throw new IllegalArgumentException(
                    "STUN " + slot + " address endpoints must use the same bind and advertised IP");
        }
        if (first.bindAddress().getPort() == second.bindAddress().getPort()) {
            throw new IllegalArgumentException("STUN endpoints on one IP require two distinct ports");
        }
    }

    private static void validatePortSlot(Endpoint first, Endpoint second, String slot) {
        if (first.bindAddress().getPort() != second.bindAddress().getPort()
                || first.advertisedAddress().getPort() != second.advertisedAddress().getPort()) {
            throw new IllegalArgumentException(
                    "RFC 5780 " + slot + " port must be identical on both IP addresses");
        }
    }

    private static boolean sameAddress(InetSocketAddress first, InetSocketAddress second) {
        return first.getAddress().equals(second.getAddress());
    }

    private static int addressBytes(InetSocketAddress address) {
        return address.getAddress().getAddress().length;
    }

    public enum AddressSlot {
        PRIMARY,
        ALTERNATE;

        public AddressSlot other() {
            return this == PRIMARY ? ALTERNATE : PRIMARY;
        }
    }

    public enum PortSlot {
        PRIMARY,
        ALTERNATE;

        public PortSlot other() {
            return this == PRIMARY ? ALTERNATE : PRIMARY;
        }
    }

    public record EndpointId(AddressSlot addressSlot, PortSlot portSlot) {
        public EndpointId {
            Objects.requireNonNull(addressSlot, "addressSlot");
            Objects.requireNonNull(portSlot, "portSlot");
        }

        @Override
        public String toString() {
            return addressSlot.name().toLowerCase() + "-" + portSlot.name().toLowerCase();
        }
    }

    public record Endpoint(EndpointId id,
                           InetSocketAddress bindAddress,
                           InetSocketAddress advertisedAddress) {
        public Endpoint {
            Objects.requireNonNull(id, "id");
            Objects.requireNonNull(bindAddress, "bindAddress");
            Objects.requireNonNull(advertisedAddress, "advertisedAddress");
            if (bindAddress.isUnresolved() || advertisedAddress.isUnresolved()) {
                throw new IllegalArgumentException("STUN endpoint addresses must be resolved");
            }
            if (bindAddress.getPort() <= 0 || advertisedAddress.getPort() <= 0) {
                throw new IllegalArgumentException("STUN endpoint ports must be positive");
            }
            if (bindAddress.getPort() != advertisedAddress.getPort()) {
                throw new IllegalArgumentException("STUN bind and advertised ports must match");
            }
            if (addressBytes(bindAddress) != addressBytes(advertisedAddress)) {
                throw new IllegalArgumentException("STUN bind and advertised addresses must use the same family");
            }
            if (advertisedAddress.getAddress().isAnyLocalAddress()) {
                throw new IllegalArgumentException("STUN advertised address cannot be a wildcard address");
            }
        }
    }
}
