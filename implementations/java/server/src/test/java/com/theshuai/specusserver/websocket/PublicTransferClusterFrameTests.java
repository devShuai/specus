package com.theshuai.specusserver.websocket;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.HexFormat;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class PublicTransferClusterFrameTests {

    @Test
    void textEventMatchesCanonicalVectorAndRoundTrips() throws Exception {
        JsonNode root = new ObjectMapper().readTree(Files.readString(findVector()));
        JsonNode vector = root.path("canonicalText");
        byte[] payload = vector.path("payloadUtf8").asText()
                .getBytes(java.nio.charset.StandardCharsets.UTF_8);
        PublicTransferClusterFrame.Event event = new PublicTransferClusterFrame.Event(
                (byte) vector.path("kind").asInt(),
                vector.path("excludeSource").asBoolean(),
                vector.path("revision").asLong(),
                vector.path("groupId").asText(),
                vector.path("targetPeerId").asText(),
                vector.path("sourceLeaseId").asText(),
                payload);
        byte[] encoded = PublicTransferClusterFrame.encode(event);

        assertThat(encoded).containsExactly(HexFormat.of().parseHex(vector.path("frameHex").asText()));

        PublicTransferClusterFrame.Event decoded = PublicTransferClusterFrame.decode(
                encoded);

        assertThat(decoded.kind()).isEqualTo(PublicTransferClusterFrame.KIND_TEXT);
        assertThat(decoded.excludeSource()).isTrue();
        assertThat(decoded.revision()).isEqualTo(17);
        assertThat(decoded.groupId()).isEqualTo("0123456789abcdef");
        assertThat(decoded.targetPeerId()).isEqualTo("peer-b");
        assertThat(decoded.sourceLeaseId()).isEqualTo("lease-a");
        assertThat(decoded.payload()).containsExactly(payload);
    }

    @Test
    void managementEventMatchesCanonicalVectorAndTenantBinding() throws Exception {
        JsonNode vector = new ObjectMapper().readTree(Files.readString(findVector()))
                .path("canonicalManagement");
        byte[] payload = vector.path("payloadUtf8").asText()
                .getBytes(java.nio.charset.StandardCharsets.UTF_8);
        PublicTransferClusterFrame.Event event = new PublicTransferClusterFrame.Event(
                (byte) vector.path("kind").asInt(),
                vector.path("excludeSource").asBoolean(),
                vector.path("revision").asLong(),
                vector.path("groupId").asText(),
                vector.path("targetPeerId").asText(),
                vector.path("sourceLeaseId").asText(),
                payload);

        byte[] encoded = PublicTransferClusterFrame.encode(event);

        assertThat(encoded).containsExactly(HexFormat.of().parseHex(vector.path("frameHex").asText()));
        PublicTransferClusterFrame.Event decoded = PublicTransferClusterFrame.decode(encoded);
        assertThat(decoded.kind()).isEqualTo(event.kind());
        assertThat(decoded.groupId()).isEqualTo(event.groupId());
        assertThat(decoded.payload()).containsExactly(payload);
        assertThat(PublicTransferCoordinationService.managementGroupId(vector.path("tenantId").asText()))
                .isEqualTo(vector.path("groupId").asText());
        assertThatThrownBy(() -> PublicTransferClusterFrame.encode(
                new PublicTransferClusterFrame.Event(
                        PublicTransferClusterFrame.KIND_MANAGEMENT, false, 0,
                        event.groupId(), "unexpected-target", "", payload)))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("management event shape");
    }

    @Test
    void decoderRejectsTrailingBytesAndBinaryWithoutTarget() {
        PublicTransferClusterFrame.Event event = new PublicTransferClusterFrame.Event(
                PublicTransferClusterFrame.KIND_ROSTER,
                false,
                1,
                "group",
                "",
                "",
                new byte[0]);
        byte[] encoded = PublicTransferClusterFrame.encode(event);
        assertThatThrownBy(() -> PublicTransferClusterFrame.decode(
                Arrays.copyOf(encoded, encoded.length + 1)))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("length mismatch");

        assertThatThrownBy(() -> PublicTransferClusterFrame.encode(
                new PublicTransferClusterFrame.Event(
                        PublicTransferClusterFrame.KIND_BINARY,
                        false,
                        0,
                        "group",
                        "",
                        "",
                        new byte[]{1})))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void groupIdIsStableAndSeparatesRoomComponents() throws Exception {
        JsonNode derivation = new ObjectMapper().readTree(Files.readString(findVector()))
                .path("groupIdDerivation");
        assertThat(PublicTransferCoordinationService.groupId("nearby", "public:203.0.113.8"))
                .isEqualTo(derivation.path("groupId").asText());
        assertThat(PublicTransferCoordinationService.groupId("a\nb", "c"))
                .isNotEqualTo(PublicTransferCoordinationService.groupId("a", "b\nc"));
    }

    private static Path findVector() {
        Path current = Path.of("").toAbsolutePath();
        for (int depth = 0; current != null && depth < 8; depth++, current = current.getParent()) {
            Path candidate = current.resolve("protocol/test-vectors/public-transfer-cluster-v2.json");
            if (Files.isRegularFile(candidate)) {
                return candidate;
            }
        }
        throw new IllegalStateException("cannot locate public transfer cluster v2 vector");
    }
}
