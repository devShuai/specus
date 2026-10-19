package com.theshuai.common.peeregress;

import com.fasterxml.jackson.databind.JsonNode;
import com.theshuai.common.util.JsonUtil;
import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.*;

class PeerEgressIpv6AnnouncementVectorTests {
    @Test
    void existingIpv6TargetSocketAnnouncementsMatchTheSharedContract() throws Exception {
        Path directory = Path.of("").toAbsolutePath();
        Path vector = null;
        while (directory != null) {
            Path candidate = directory.resolve("protocol/test-vectors/peer-egress-ipv6-target-announcement-v1.json");
            if (Files.isRegularFile(candidate)) { vector = candidate; break; }
            directory = directory.getParent();
        }
        assertNotNull(vector, "shared announcement vector not found");
        JsonNode root = JsonUtil.readString(Files.readString(vector));
        assertNotNull(root);
        assertFalse(root.path("consumerIpv6DataPlaneEnabled").asBoolean(true));
        assertEquals(7, root.path("login").size());
        for (JsonNode example : root.path("login")) {
            JsonNode capabilities = example.path("capabilities");
            int version = capabilities.path("version").asInt(0);
            boolean declared = capabilities.path("ipv6TargetCapable").asBoolean(false);
            assertEquals(example.path("normalizedVersion").asInt(), PeerEgressProtocol.normalizeVersion(version),
                    example.path("name").asText());
            assertEquals(example.path("stored").asBoolean(), PeerEgressProtocol.declaresIpv6Targets(version, declared),
                    example.path("name").asText());
        }
    }
}
