package com.theshuai.common.peermesh;

import com.theshuai.common.util.JsonUtil;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PeerServiceDiscoveryTests {

    @Test
    void rejectsPublicHostnamesAndUrls() {
        assertThrows(IllegalArgumentException.class, () -> PeerServiceDiscovery.requireTargetHost("evil.example"));
        assertThrows(IllegalArgumentException.class, () -> PeerServiceDiscovery.requireTargetHost("http://127.0.0.1"));
        assertThrows(IllegalArgumentException.class, () -> PeerServiceDiscovery.requireTargetHost("0.0.0.0"));
        assertEquals("127.0.0.1", PeerServiceDiscovery.requireTargetHost("127.0.0.1"));
        assertEquals("localhost", PeerServiceDiscovery.requireTargetHost("localhost"));
        assertEquals("192.168.1.10", PeerServiceDiscovery.requireTargetHost("192.168.1.10"));
    }

    @Test
    void rejectsUnsafePathsAndCommands() {
        assertThrows(IllegalArgumentException.class, () -> PeerServiceDiscovery.normalizePath("javascript:alert(1)", "http"));
        assertThrows(IllegalArgumentException.class, () -> PeerServiceDiscovery.normalizePath("/../etc/passwd", "http"));
        assertThrows(IllegalArgumentException.class, () -> PeerServiceDiscovery.normalizePath("http://evil", "http"));
        assertEquals("/admin", PeerServiceDiscovery.normalizePath("/admin", "https"));
        assertEquals("/", PeerServiceDiscovery.normalizePath("", "http"));
        assertEquals("", PeerServiceDiscovery.normalizePath("", "ssh"));
    }

    @Test
    void advertisedSnapshotDropsTargetHostAndCapsSize() {
        PeerAdvertisedService service = sample("svc-0001", 2222);
        String json = JsonUtil.objectToString(PeerServiceDiscovery.sanitizeAdvertised(service));
        assertFalse(json.contains("targetHost"));
        assertFalse(json.contains("127.0.0.1"));

        List<PeerAdvertisedService> tooMany = new ArrayList<>();
        for (int i = 0; i < PeerServiceDiscovery.MAX_SERVICES_PER_SESSION + 1; i++) {
            tooMany.add(sample("svc-" + String.format("%04d", i), 2000 + i));
        }
        assertThrows(IllegalArgumentException.class, () -> PeerServiceDiscovery.sanitizeAdvertisedList(tooMany));
    }

    @Test
    void accessUrlUsesVirtualIpPortAndSafePathOnly() {
        PeerAdvertisedService http = sample("svc-http01", 8080);
        http.setApplication("http");
        http.setPath("/panel");
        assertEquals("http://100.96.0.2:8080/panel", PeerServiceDiscovery.accessUrl("100.96.0.2", http));

        PeerAdvertisedService ssh = sample("svc-ssh001", 2222);
        ssh.setApplication("ssh");
        ssh.setPath("");
        assertEquals("100.96.0.2:2222", PeerServiceDiscovery.accessUrl("100.96.0.2", ssh));
    }

    @Test
    void udpApplicationRequiresUdpTransport() {
        assertEquals("udp", PeerServiceDiscovery.requireTransportForApplication("udp", "udp"));
        assertThrows(IllegalArgumentException.class,
                () -> PeerServiceDiscovery.requireTransportForApplication("tcp", "udp"));
        assertThrows(IllegalArgumentException.class,
                () -> PeerServiceDiscovery.requireTransportForApplication("udp", "http"));
        PeerAdvertisedService udp = sample("svc-udp001", 5353);
        udp.setApplication("udp");
        udp.setTransport("udp");
        assertEquals("udp", PeerServiceDiscovery.sanitizeAdvertised(udp).getTransport());
    }

    @Test
    void encodesAllowedClientIdsAndSanitizesMdns() {
        assertEquals("2,1", PeerServiceDiscovery.encodeClientIds(java.util.Arrays.asList(2L, 1L, 1L, 0L, null)));
        assertEquals(List.of(1L, 2L), PeerServiceDiscovery.decodeClientIds("1,2,x,0"));
        PeerMdnsCandidate publicHost = new PeerMdnsCandidate();
        publicHost.setName("web");
        publicHost.setTransport("tcp");
        publicHost.setApplication("http");
        publicHost.setTargetHost("evil.example");
        publicHost.setTargetPort(80);
        PeerMdnsCandidate local = new PeerMdnsCandidate();
        local.setName("web");
        local.setTransport("tcp");
        local.setApplication("http");
        local.setTargetHost("127.0.0.1");
        local.setTargetPort(80);
        List<PeerMdnsCandidate> sanitized = PeerServiceDiscovery.sanitizeMdnsCandidates(List.of(publicHost, local));
        assertEquals(1, sanitized.size());
        assertEquals("127.0.0.1", sanitized.getFirst().getTargetHost());
    }

    @Test
    void unknownApplicationsAndOldVersionsNormalizeToUnsupported() {
        assertEquals(0, PeerServiceDiscovery.normalizeVersion(0));
        assertEquals(1, PeerServiceDiscovery.normalizeVersion(9));
        assertTrue(PeerServiceDiscovery.normalizeApplications(List.of("http", "ftp", "SSH"), 1)
                .containsAll(List.of("http", "ssh")));
        assertTrue(PeerServiceDiscovery.normalizeApplications(List.of("http"), 0).isEmpty());
    }

    private static PeerAdvertisedService sample(String serviceId, int port) {
        PeerAdvertisedService service = new PeerAdvertisedService();
        service.setServiceId(serviceId);
        service.setName("demo");
        service.setTransport("tcp");
        service.setApplication("ssh");
        service.setPublishedPort(port);
        return service;
    }
}
