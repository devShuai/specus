package com.theshuai.common.stun;

import java.net.InetSocketAddress;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

public final class StunBindingService {
    private static final int CHANGE_REQUEST_FLAGS_MASK = 0x06;

    private final StunEndpointTopology topology;
    private final String software;
    private final boolean legacySingleIpOtherAddress;

    public StunBindingService(StunEndpointTopology topology,
                              String software,
                              boolean legacySingleIpOtherAddress) {
        this.topology = Objects.requireNonNull(topology, "topology");
        this.software = software == null || software.isBlank() ? "shuai-stun-server" : software.trim();
        this.legacySingleIpOtherAddress = legacySingleIpOtherAddress;
    }

    public BindingResult process(StunMessage request,
                                 InetSocketAddress remote,
                                 StunEndpointTopology.EndpointId incomingEndpoint) {
        Objects.requireNonNull(request, "request");
        Objects.requireNonNull(remote, "remote");
        Objects.requireNonNull(incomingEndpoint, "incomingEndpoint");
        if (request.type() != StunMessage.BINDING_REQUEST) {
            throw new IllegalArgumentException("Only STUN Binding requests are supported");
        }

        StunMessage.ChangeRequest changeRequest = StunMessage.ChangeRequest.NONE;
        if (request.hasAttribute(StunMessage.ATTR_CHANGE_REQUEST)) {
            StunMessage.Attribute attribute = request.first(StunMessage.ATTR_CHANGE_REQUEST).orElseThrow();
            if (attribute.value().length != Integer.BYTES) {
                return error(incomingEndpoint, request, 400, "invalid-change-request");
            }
            int flags = java.nio.ByteBuffer.wrap(attribute.value()).getInt();
            if ((flags & ~CHANGE_REQUEST_FLAGS_MASK) != 0) {
                return error(incomingEndpoint, request, 400, "invalid-change-request-flags");
            }
            changeRequest = request.changeRequest().orElseThrow();
            if (!topology.supportsRfc5780()) {
                return error(
                        incomingEndpoint,
                        request,
                        420,
                        "unsupported-change-request",
                        StunMessage.unknownAttributes(StunMessage.ATTR_CHANGE_REQUEST));
            }
        }

        StunEndpointTopology.EndpointId responseEndpoint =
                topology.responseEndpoint(incomingEndpoint, changeRequest);
        InetSocketAddress responseOrigin = topology.endpoint(responseEndpoint).advertisedAddress();
        List<StunMessage.Attribute> attributes = new ArrayList<>();
        attributes.add(StunMessage.mappedAddress(remote));
        attributes.add(StunMessage.xorMappedAddress(remote, request.transactionId()));
        attributes.add(StunMessage.software(software));

        if (topology.supportsRfc5780()) {
            attributes.add(StunMessage.responseOrigin(responseOrigin));
            topology.otherEndpoint(incomingEndpoint)
                    .map(topology::endpoint)
                    .map(StunEndpointTopology.Endpoint::advertisedAddress)
                    .map(StunMessage::otherAddress)
                    .ifPresent(attributes::add);
        } else if (legacySingleIpOtherAddress) {
            attributes.add(new StunMessage.Attribute(
                    StunMessage.ATTR_RESPONSE_ORIGIN,
                    StunMessage.encodeXorAddress(responseOrigin, request.transactionId())));
            topology.legacyAlternatePortEndpoint(incomingEndpoint)
                    .map(topology::endpoint)
                    .map(StunEndpointTopology.Endpoint::advertisedAddress)
                    .map(address -> new StunMessage.Attribute(
                            StunMessage.ATTR_OTHER_ADDRESS,
                            StunMessage.encodeXorAddress(address, request.transactionId())))
                    .ifPresent(attributes::add);
        } else {
            attributes.add(StunMessage.responseOrigin(responseOrigin));
        }

        return new BindingResult(
                responseEndpoint,
                new StunMessage(StunMessage.BINDING_SUCCESS, request.transactionId(), attributes));
    }

    private BindingResult error(StunEndpointTopology.EndpointId responseEndpoint,
                                StunMessage request,
                                int code,
                                String reason,
                                StunMessage.Attribute... extras) {
        List<StunMessage.Attribute> attributes = new ArrayList<>();
        attributes.add(StunMessage.errorCode(code, reason));
        attributes.add(StunMessage.software(software));
        if (extras != null) {
            attributes.addAll(List.of(extras));
        }
        return new BindingResult(
                responseEndpoint,
                new StunMessage(StunMessage.BINDING_ERROR, request.transactionId(), attributes));
    }

    public record BindingResult(StunEndpointTopology.EndpointId responseEndpoint, StunMessage response) {
        public BindingResult {
            Objects.requireNonNull(responseEndpoint, "responseEndpoint");
            Objects.requireNonNull(response, "response");
        }
    }
}
