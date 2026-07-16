package com.theshuai.tunnelclient.peer;

import org.junit.jupiter.api.Test;

import java.net.InetSocketAddress;

import static org.assertj.core.api.Assertions.assertThat;

class NatBehaviorDiscoveryTests {
    private static final InetSocketAddress A1_P1 = endpoint("203.0.113.10", 3478);
    private static final InetSocketAddress A2_P2 = endpoint("203.0.113.11", 3479);
    private static final InetSocketAddress MAPPED_I = endpoint("198.51.100.20", 52000);

    @Test
    void classifiesEndpointIndependentMappingAndFiltering() {
        NatBehaviorDiscovery discovery = new NatBehaviorDiscovery();

        var filterBoth = discovery.begin(A1_P1, MAPPED_I, A2_P2).nextProbe();
        assertThat(filterBoth.probe())
                .isEqualTo(NatBehaviorDiscovery.Probe.FILTER_CHANGE_IP_AND_PORT);
        assertThat(filterBoth.expectedResponseEndpoint()).isEqualTo(A2_P2);

        var mappingAlternateIp = discovery.succeeded(
                filterBoth.generation(),
                filterBoth.probe(),
                MAPPED_I).nextProbe();
        assertThat(mappingAlternateIp.probe())
                .isEqualTo(NatBehaviorDiscovery.Probe.MAPPING_ALTERNATE_IP);
        assertThat(mappingAlternateIp.targetEndpoint()).isEqualTo(endpoint("203.0.113.11", 3478));

        var mappingAlternateIpPort = discovery.succeeded(
                mappingAlternateIp.generation(),
                mappingAlternateIp.probe(),
                MAPPED_I).nextProbe();
        var completed = discovery.succeeded(
                mappingAlternateIpPort.generation(),
                mappingAlternateIpPort.probe(),
                MAPPED_I).snapshot();

        assertThat(completed.complete()).isTrue();
        assertThat(completed.mappingBehavior()).isEqualTo(NatBehaviorDiscovery.ENDPOINT_INDEPENDENT);
        assertThat(completed.filteringBehavior()).isEqualTo(NatBehaviorDiscovery.ENDPOINT_INDEPENDENT);
    }

    @Test
    void classifiesAddressDependentMappingAndFiltering() {
        NatBehaviorDiscovery discovery = new NatBehaviorDiscovery();

        var filterBoth = discovery.begin(A1_P1, MAPPED_I, A2_P2).nextProbe();
        var filterPort = discovery.timedOut(filterBoth.generation(), filterBoth.probe()).nextProbe();
        assertThat(filterPort.expectedResponseEndpoint()).isEqualTo(endpoint("203.0.113.10", 3479));

        var mappingAlternateIp = discovery.succeeded(
                filterPort.generation(),
                filterPort.probe(),
                MAPPED_I).nextProbe();
        InetSocketAddress mappedII = endpoint("198.51.100.20", 52010);
        var mappingAlternateIpPort = discovery.succeeded(
                mappingAlternateIp.generation(),
                mappingAlternateIp.probe(),
                mappedII).nextProbe();
        var completed = discovery.succeeded(
                mappingAlternateIpPort.generation(),
                mappingAlternateIpPort.probe(),
                mappedII).snapshot();

        assertThat(completed.mappingBehavior()).isEqualTo(NatBehaviorDiscovery.ADDRESS_DEPENDENT);
        assertThat(completed.filteringBehavior()).isEqualTo(NatBehaviorDiscovery.ADDRESS_DEPENDENT);
    }

    @Test
    void classifiesAddressAndPortDependentMappingAndFiltering() {
        NatBehaviorDiscovery discovery = new NatBehaviorDiscovery();

        var filterBoth = discovery.begin(A1_P1, MAPPED_I, A2_P2).nextProbe();
        var filterPort = discovery.timedOut(filterBoth.generation(), filterBoth.probe()).nextProbe();
        var mappingAlternateIp = discovery.timedOut(
                filterPort.generation(),
                filterPort.probe()).nextProbe();
        var mappingAlternateIpPort = discovery.succeeded(
                mappingAlternateIp.generation(),
                mappingAlternateIp.probe(),
                endpoint("198.51.100.20", 52010)).nextProbe();
        var completed = discovery.succeeded(
                mappingAlternateIpPort.generation(),
                mappingAlternateIpPort.probe(),
                endpoint("198.51.100.20", 52020)).snapshot();

        assertThat(completed.mappingBehavior())
                .isEqualTo(NatBehaviorDiscovery.ADDRESS_AND_PORT_DEPENDENT);
        assertThat(completed.filteringBehavior())
                .isEqualTo(NatBehaviorDiscovery.ADDRESS_AND_PORT_DEPENDENT);
    }

    @Test
    void keepsMappingDiscoveryWhenChangeRequestIsUnsupported() {
        NatBehaviorDiscovery discovery = new NatBehaviorDiscovery();

        var filterBoth = discovery.begin(A1_P1, MAPPED_I, A2_P2).nextProbe();
        var mappingAlternateIp = discovery.failed(
                filterBoth.generation(),
                filterBoth.probe(),
                true).nextProbe();
        var mappingAlternateIpPort = discovery.succeeded(
                mappingAlternateIp.generation(),
                mappingAlternateIp.probe(),
                MAPPED_I).nextProbe();
        var completed = discovery.succeeded(
                mappingAlternateIpPort.generation(),
                mappingAlternateIpPort.probe(),
                MAPPED_I).snapshot();

        assertThat(completed.mappingBehavior()).isEqualTo(NatBehaviorDiscovery.ENDPOINT_INDEPENDENT);
        assertThat(completed.filteringBehavior()).isEqualTo(NatBehaviorDiscovery.UNSUPPORTED);
    }

    @Test
    void doesNotTrustNegativeFilteringWhenAlternateEndpointValidationFails() {
        NatBehaviorDiscovery discovery = new NatBehaviorDiscovery();

        var filterBoth = discovery.begin(A1_P1, MAPPED_I, A2_P2).nextProbe();
        var filterPort = discovery.timedOut(filterBoth.generation(), filterBoth.probe()).nextProbe();
        var mappingAlternateIp = discovery.succeeded(
                filterPort.generation(),
                filterPort.probe(),
                MAPPED_I).nextProbe();
        var completed = discovery.timedOut(
                mappingAlternateIp.generation(),
                mappingAlternateIp.probe()).snapshot();

        assertThat(completed.mappingBehavior()).isEqualTo(NatBehaviorDiscovery.UNKNOWN);
        assertThat(completed.filteringBehavior()).isEqualTo(NatBehaviorDiscovery.UNKNOWN);
    }

    private static InetSocketAddress endpoint(String address, int port) {
        return new InetSocketAddress(address, port);
    }
}
