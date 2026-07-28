package com.theshuai.common.stun;

import java.net.InetSocketAddress;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

public final class StunBindingService {
    private static final int CHANGE_REQUEST_FLAGS_MASK = 0x06;
    private static final int DEFAULT_MAX_PADDING_RESPONSE_BYTES = 1_472;

    private final StunEndpointTopology topology;
    private final String software;
    private final boolean legacySingleIpOtherAddress;
    private final int maxPaddingResponseBytes;

    public StunBindingService(StunEndpointTopology topology,
                              String software,
                              boolean legacySingleIpOtherAddress) {
        this(topology, software, legacySingleIpOtherAddress, DEFAULT_MAX_PADDING_RESPONSE_BYTES);
    }

    public StunBindingService(StunEndpointTopology topology,
                              String software,
                              boolean legacySingleIpOtherAddress,
                              int maxPaddingResponseBytes) {
        this.topology = Objects.requireNonNull(topology, "topology");
        this.software = software == null || software.isBlank() ? "specus-stun-server" : software.trim();
        this.legacySingleIpOtherAddress = legacySingleIpOtherAddress;
        if (maxPaddingResponseBytes < 0 || maxPaddingResponseBytes > 65_503) {
            throw new IllegalArgumentException(
                    "maxPaddingResponseBytes must be between 0 and 65503");
        }
        this.maxPaddingResponseBytes = maxPaddingResponseBytes;
    }

    public BindingResult process(StunMessage request,
                                 InetSocketAddress remote,
                                 StunEndpointTopology.EndpointId incomingEndpoint) {
        return process(request, remote, incomingEndpoint, request.toBytes().length);
    }

    public BindingResult process(StunMessage request,
                                 InetSocketAddress remote,
                                 StunEndpointTopology.EndpointId incomingEndpoint,
                                 int receivedBytes) {
        Objects.requireNonNull(request, "request");
        Objects.requireNonNull(remote, "remote");
        Objects.requireNonNull(incomingEndpoint, "incomingEndpoint");
        if (request.type() != StunMessage.BINDING_REQUEST) {
            throw new IllegalArgumentException("Only STUN Binding requests are supported");
        }

        boolean hasResponsePort = request.hasAttribute(StunMessage.ATTR_RESPONSE_PORT);
        boolean hasPadding = request.hasAttribute(StunMessage.ATTR_PADDING);
        if (hasResponsePort && hasPadding) {
            return error(
                    incomingEndpoint,
                    remote,
                    request,
                    400,
                    "response-port-and-padding-are-mutually-exclusive");
        }

        InetSocketAddress responseTarget = remote;
        if (hasResponsePort) {
            StunMessage.Attribute attribute =
                    request.first(StunMessage.ATTR_RESPONSE_PORT).orElseThrow();
            if (attribute.value().length != Short.BYTES) {
                return error(
                        incomingEndpoint,
                        remote,
                        request,
                        400,
                        "invalid-response-port");
            }
            int responsePort = request.responsePort().orElseThrow();
            if (responsePort == 0) {
                return error(
                        incomingEndpoint,
                        remote,
                        request,
                        400,
                        "invalid-response-port");
            }
            responseTarget = new InetSocketAddress(remote.getAddress(), responsePort);
        }

        StunMessage.ChangeRequest changeRequest = StunMessage.ChangeRequest.NONE;
        if (request.hasAttribute(StunMessage.ATTR_CHANGE_REQUEST)) {
            StunMessage.Attribute attribute = request.first(StunMessage.ATTR_CHANGE_REQUEST).orElseThrow();
            if (attribute.value().length != Integer.BYTES) {
                return error(
                        incomingEndpoint,
                        responseTarget,
                        request,
                        400,
                        "invalid-change-request");
            }
            int flags = java.nio.ByteBuffer.wrap(attribute.value()).getInt();
            if ((flags & ~CHANGE_REQUEST_FLAGS_MASK) != 0) {
                return error(
                        incomingEndpoint,
                        responseTarget,
                        request,
                        400,
                        "invalid-change-request-flags");
            }
            changeRequest = request.changeRequest().orElseThrow();
            if (!topology.supportsRfc5780()) {
                return error(
                        incomingEndpoint,
                        responseTarget,
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
        if (hasPadding) {
            int requestPaddingBytes = request.paddingValue().orElseThrow().length;
            int boundedByDatagram = Math.max(0, receivedBytes - StunMessage.HEADER_BYTES);
            int responsePaddingBytes =
                    Math.min(requestPaddingBytes, Math.min(maxPaddingResponseBytes, boundedByDatagram));
            attributes.add(StunMessage.padding(responsePaddingBytes));
        }

        return new BindingResult(
                responseEndpoint,
                responseTarget,
                new StunMessage(StunMessage.BINDING_SUCCESS, request.transactionId(), attributes));
    }

    private BindingResult error(StunEndpointTopology.EndpointId responseEndpoint,
                                InetSocketAddress responseTarget,
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
                responseTarget,
                new StunMessage(StunMessage.BINDING_ERROR, request.transactionId(), attributes));
    }

    public record BindingResult(StunEndpointTopology.EndpointId responseEndpoint,
                                InetSocketAddress responseTarget,
                                StunMessage response) {
        public BindingResult {
            Objects.requireNonNull(responseEndpoint, "responseEndpoint");
            Objects.requireNonNull(responseTarget, "responseTarget");
            Objects.requireNonNull(response, "response");
        }
    }
}
