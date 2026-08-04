package com.theshuai.specus.android;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetSocketAddress;
import java.util.ArrayList;
import java.util.List;

public class PeerMeshProbeStrategyTest {
    @Test
    public void predictsPortsFromRemoteObservationsThenLocalFallback() {
        PeerMeshEngine.PeerCandidate base = candidate("203.0.113.8", 40_000);
        List<PeerMeshEngine.PeerCandidate> remote = List.of(
                base,
                candidate("203.0.113.8", 40_004),
                candidate("203.0.113.8", 40_010),
                candidate("198.51.100.8", 55_000));

        List<Integer> predicted = PeerMeshEngine.adaptivePredictedPorts(base, remote, List.of());

        assertEquals(List.of(40_004, 39_996, 40_006, 39_994), predicted);

        List<Integer> localFallback = PeerMeshEngine.adaptivePredictedPorts(
                base, List.of(base), List.of(51_000, 51_003, 51_009));
        assertEquals(List.of(40_003, 39_997, 40_006, 39_994), localFallback);
    }

    @Test
    public void predictionIsBoundedToSixteenValidPorts() {
        PeerMeshEngine.PeerCandidate base = candidate("203.0.113.9", 40_000);
        List<PeerMeshEngine.PeerCandidate> observations = new ArrayList<>();
        observations.add(base);
        int port = 40_000;
        for (int delta = 1; delta <= 20; delta++) {
            port += delta;
            observations.add(candidate(base.address, port));
        }

        List<Integer> predicted = PeerMeshEngine.adaptivePredictedPorts(
                base, observations, List.of());

        assertEquals(16, predicted.size());
        assertEquals(16, predicted.stream().distinct().count());
        assertTrue(predicted.stream().allMatch(item -> item > 0 && item <= 65_535));
    }

    @Test
    public void resolvedStunEndpointsAreConcreteAndIpv4First() {
        List<InetSocketAddress> endpoints = PeerMeshEngine.resolveEndpoints("localhost", 3478);

        assertTrue(!endpoints.isEmpty());
        assertTrue(endpoints.stream().allMatch(endpoint -> endpoint.getAddress() != null));
        boolean seenIpv6 = false;
        for (InetSocketAddress endpoint : endpoints) {
            if (endpoint.getAddress() instanceof Inet6Address) {
                seenIpv6 = true;
            }
            if (endpoint.getAddress() instanceof Inet4Address) {
                assertTrue(!seenIpv6);
            }
        }
    }

    private static PeerMeshEngine.PeerCandidate candidate(String address, int port) {
        PeerMeshEngine.PeerCandidate candidate = new PeerMeshEngine.PeerCandidate();
        candidate.type = "srflx";
        candidate.transport = "udp";
        candidate.address = address;
        candidate.port = port;
        candidate.priority = 800L;
        return candidate;
    }
}
