package com.theshuai.tunnel.android;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

import java.net.InetAddress;
import java.net.InetSocketAddress;

public class PeerAddressFamilyTest {
    @Test
    public void hostCandidateFilterAcceptsGlobalIpv6() throws Exception {
        assertTrue(PeerMeshEngine.isUsableHostCandidate(InetAddress.getByName("192.0.2.20")));
        assertTrue(PeerMeshEngine.isUsableHostCandidate(InetAddress.getByName("2001:db8::20")));
        assertFalse(PeerMeshEngine.isUsableHostCandidate(InetAddress.getByName("fd00::20")));
        assertFalse(PeerMeshEngine.isUsableHostCandidate(InetAddress.getByName("fe80::20")));
        assertFalse(PeerMeshEngine.isUsableHostCandidate(InetAddress.getLoopbackAddress()));
    }

    @Test
    public void endpointParserSupportsBracketedIpv6() {
        InetSocketAddress endpoint = PeerMeshEngine.parseHostPort("[2001:db8::20]:3478", 0, true);
        assertNotNull(endpoint);
        assertEquals(3478, endpoint.getPort());
        assertEquals("2001:db8:0:0:0:0:0:20", endpoint.getAddress().getHostAddress());

        assertNotNull(PeerMeshEngine.parseHostPort("2001:db8::20", 3478, false));
        assertNull(PeerMeshEngine.parseHostPort("2001:db8::20", 0, true));
    }
}
