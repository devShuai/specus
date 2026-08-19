package com.theshuai.common.clientauth;

import com.fasterxml.jackson.databind.JsonNode;
import com.theshuai.common.util.JsonUtil;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ClientEnvironmentInfoTests {

    @Test
    void serializesUnsupportedAttachmentCapabilitiesExplicitly() {
        ClientAuthLoginRequest request = new ClientAuthLoginRequest();
        request.setEnvironment(new ClientEnvironmentInfo());

        JsonNode json = JsonUtil.readString(JsonUtil.objectToString(request));
        assertNotNull(json);
        JsonNode capabilities = json.path("environment").path("clientMessageCapabilities");
        assertTrue(capabilities.isObject());
        assertFalse(capabilities.path("attachments").asBoolean(true));
        assertTrue(capabilities.has("maxAttachmentBytes"));
        assertTrue(capabilities.path("maxAttachmentBytes").canConvertToLong());
        assertEquals(0L, capabilities.path("maxAttachmentBytes").asLong(-1));

        JsonNode discovery = json.path("environment").path("clientPeerServiceCapabilities");
        assertTrue(discovery.isObject());
        assertEquals(0, discovery.path("version").asInt(-1));
        assertTrue(discovery.path("applications").isArray());
        assertEquals(0, discovery.path("applications").size());
    }
}
