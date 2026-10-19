package com.theshuai.common.peeregress;

import com.fasterxml.jackson.databind.JsonNode;
import com.theshuai.common.clientauth.ClientEnvironmentInfo;
import com.theshuai.common.util.JsonUtil;
import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.*;

class PeerEgressIpv6PacketAnnouncementVectorTests {
    @Test
    void ipv6PacketAnnouncementsMatchTheSharedContract() throws Exception {
        Path directory = Path.of("").toAbsolutePath();
        Path vector = null;
        while (directory != null) {
            Path candidate = directory.resolve("protocol/test-vectors/peer-egress-ipv6-packet-announcement-v1.json");
            if (Files.isRegularFile(candidate)) { vector = candidate; break; }
            directory = directory.getParent();
        }
        assertNotNull(vector, "shared announcement vector not found");
        JsonNode root = JsonUtil.readString(Files.readString(vector));
        assertNotNull(root);
        assertEquals("client_egress_ipv6_packets", root.path("sessionColumn").asText());
        assertFalse(root.path("legacyDefault").asBoolean(true));
        assertEquals(8, root.path("login").size());
        boolean sawTargetOnly = false;
        for (JsonNode example : root.path("login")) {
            String name = example.path("name").asText();
            // Decode through the shared model, so a target flag cannot stand in for a packet flag.
            ClientEnvironmentInfo.ClientEgressCapabilities capabilities = example.path("capabilities").isObject()
                    ? JsonUtil.stringToObject(example.path("capabilities").toString(),
                            ClientEnvironmentInfo.ClientEgressCapabilities.class)
                    : new ClientEnvironmentInfo.ClientEgressCapabilities();
            assertNotNull(capabilities, name);
            int version = capabilities.getVersion();
            assertEquals(example.path("normalizedVersion").asInt(), PeerEgressProtocol.normalizeVersion(version), name);
            assertEquals(example.path("stored").asBoolean(),
                    PeerEgressProtocol.declaresIpv6Packets(version, capabilities.isIpv6PacketCapable()), name);
            if (name.equals("target-flag-is-not-packet-flag")) {
                sawTargetOnly = true;
                assertTrue(PeerEgressProtocol.declaresIpv6Targets(version, capabilities.isIpv6TargetCapable()), name);
            }
        }
        assertTrue(sawTargetOnly, "the vector pins that the two flags are independent");
    }
}
