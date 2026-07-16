package com.theshuai.tunnel.android;

import org.junit.Test;

import java.net.InetSocketAddress;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

public class NatBehaviorDiscoveryTest {
    private static final InetSocketAddress PRIMARY = endpoint("203.0.113.10", 3478);
    private static final InetSocketAddress OTHER = endpoint("203.0.113.11", 3479);
    private static final InetSocketAddress MAPPED = endpoint("198.51.100.20", 52000);

    @Test
    public void classifiesEndpointIndependentMappingAndFiltering() {
        NatBehaviorDiscovery discovery = new NatBehaviorDiscovery();
        NatBehaviorDiscovery.ProbeRequest filter = requireProbe(
                discovery.begin(PRIMARY, MAPPED, OTHER),
                NatBehaviorDiscovery.Probe.FILTER_CHANGE_IP_AND_PORT);
        assertEquals(OTHER, filter.expectedResponseEndpoint());

        NatBehaviorDiscovery.ProbeRequest mappingIp = requireProbe(
                discovery.succeeded(filter.generation(), filter.probe(), MAPPED),
                NatBehaviorDiscovery.Probe.MAPPING_ALTERNATE_IP);
        NatBehaviorDiscovery.ProbeRequest mappingIpPort = requireProbe(
                discovery.succeeded(mappingIp.generation(), mappingIp.probe(), MAPPED),
                NatBehaviorDiscovery.Probe.MAPPING_ALTERNATE_IP_AND_PORT);
        NatBehaviorDiscovery.Snapshot completed = discovery.succeeded(
                mappingIpPort.generation(),
                mappingIpPort.probe(),
                MAPPED).snapshot();

        assertTrue(completed.complete());
        assertEquals(NatBehaviorDiscovery.ENDPOINT_INDEPENDENT, completed.mappingBehavior());
        assertEquals(NatBehaviorDiscovery.ENDPOINT_INDEPENDENT, completed.filteringBehavior());
    }

    @Test
    public void classifiesAddressDependentMappingAndFiltering() {
        NatBehaviorDiscovery discovery = new NatBehaviorDiscovery();
        NatBehaviorDiscovery.ProbeRequest filterBoth = requireProbe(
                discovery.begin(PRIMARY, MAPPED, OTHER),
                NatBehaviorDiscovery.Probe.FILTER_CHANGE_IP_AND_PORT);
        NatBehaviorDiscovery.ProbeRequest filterPort = requireProbe(
                discovery.timedOut(filterBoth.generation(), filterBoth.probe()),
                NatBehaviorDiscovery.Probe.FILTER_CHANGE_PORT);
        assertEquals(endpoint("203.0.113.10", 3479), filterPort.expectedResponseEndpoint());

        NatBehaviorDiscovery.ProbeRequest mappingIp = requireProbe(
                discovery.succeeded(filterPort.generation(), filterPort.probe(), MAPPED),
                NatBehaviorDiscovery.Probe.MAPPING_ALTERNATE_IP);
        InetSocketAddress mappedII = endpoint("198.51.100.20", 52010);
        NatBehaviorDiscovery.ProbeRequest mappingIpPort = requireProbe(
                discovery.succeeded(mappingIp.generation(), mappingIp.probe(), mappedII),
                NatBehaviorDiscovery.Probe.MAPPING_ALTERNATE_IP_AND_PORT);
        NatBehaviorDiscovery.Snapshot completed = discovery.succeeded(
                mappingIpPort.generation(),
                mappingIpPort.probe(),
                mappedII).snapshot();

        assertEquals(NatBehaviorDiscovery.ADDRESS_DEPENDENT, completed.mappingBehavior());
        assertEquals(NatBehaviorDiscovery.ADDRESS_DEPENDENT, completed.filteringBehavior());
    }

    @Test
    public void classifiesAddressAndPortDependentAndUnsupportedFiltering() {
        NatBehaviorDiscovery discovery = new NatBehaviorDiscovery();
        NatBehaviorDiscovery.ProbeRequest filter = requireProbe(
                discovery.begin(PRIMARY, MAPPED, OTHER),
                NatBehaviorDiscovery.Probe.FILTER_CHANGE_IP_AND_PORT);
        NatBehaviorDiscovery.ProbeRequest mappingIp = requireProbe(
                discovery.failed(filter.generation(), filter.probe(), true),
                NatBehaviorDiscovery.Probe.MAPPING_ALTERNATE_IP);
        NatBehaviorDiscovery.ProbeRequest mappingIpPort = requireProbe(
                discovery.succeeded(
                        mappingIp.generation(),
                        mappingIp.probe(),
                        endpoint("198.51.100.20", 52010)),
                NatBehaviorDiscovery.Probe.MAPPING_ALTERNATE_IP_AND_PORT);
        NatBehaviorDiscovery.Snapshot completed = discovery.succeeded(
                mappingIpPort.generation(),
                mappingIpPort.probe(),
                endpoint("198.51.100.20", 52020)).snapshot();

        assertEquals(NatBehaviorDiscovery.ADDRESS_AND_PORT_DEPENDENT, completed.mappingBehavior());
        assertEquals(NatBehaviorDiscovery.UNSUPPORTED, completed.filteringBehavior());
    }

    private static NatBehaviorDiscovery.ProbeRequest requireProbe(
            NatBehaviorDiscovery.Transition transition,
            NatBehaviorDiscovery.Probe expected) {
        assertTrue(transition.accepted());
        assertNotNull(transition.nextProbe());
        assertEquals(expected, transition.nextProbe().probe());
        return transition.nextProbe();
    }

    private static InetSocketAddress endpoint(String host, int port) {
        return new InetSocketAddress(host, port);
    }
}
