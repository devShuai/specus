package com.theshuai.specusserver.management.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.theshuai.common.protocol.MessageType;
import com.theshuai.common.protocol.response.MessageResponsePacket;
import com.theshuai.common.serialize.Serializer;
import com.theshuai.specusserver.management.model.HttpRouteMapping;
import com.theshuai.specusserver.management.model.SpecusMapping;
import com.theshuai.specusserver.management.repository.ClientAccountRepository;
import com.theshuai.specusserver.management.repository.HttpRouteMappingRepository;
import com.theshuai.specusserver.management.repository.SpecusMappingRepository;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

/**
 * Replays the sizing of {@code protocol/test-vectors/nat-control-size-v1.json}: the MESSAGE body a
 * NAT_CONTROL takes in this server's encoding, its client name counted at the longest a rename
 * allows. {@link NatControlSizeLimitHttpTests} replays the management steps.
 */
class NatControlSizingVectorTests {
    static final String TARGET_PREFIX = "http://127.0.0.1:8080/";

    private final NatControlService service = new NatControlService(
            mock(SpecusMappingRepository.class), mock(HttpRouteMappingRepository.class),
            mock(ClientAccountRepository.class), mock(WorkbenchReferences.class), 7010, "");

    @Test
    void sizingMatchesTheVector() throws IOException {
        JsonNode vector = readVector();
        assertThat(vector.get("messageBodyLimitBytes").asInt()).isEqualTo(NatControlService.MESSAGE_BODY_LIMIT);
        assertThat(vector.get("clientNameReserve").get("maxCharacters").asInt())
                .isEqualTo(NatControlService.CLIENT_NAME_RESERVE_CHARACTERS);
        for (JsonNode sizing : vector.get("sizing")) {
            int jsonBytes = sizing.get("jsonBytesWithEmptyClientName").asInt();
            HttpRouteMapping route = route(1L, "sized", TARGET_PREFIX);
            int shortest = jsonBytes(service, List.of(), List.of(route));
            assertThat(jsonBytes).as("J=%d is shorter than one route", jsonBytes).isGreaterThanOrEqualTo(shortest);
            route.setTargetBaseUrl(TARGET_PREFIX + "a".repeat(jsonBytes - shortest));
            assertThat(jsonBytes(service, List.of(), List.of(route))).isEqualTo(jsonBytes);

            int body = service.reservedBodyBytes(List.of(), List.of(route));
            assertThat(body).as("J=%d", jsonBytes).isEqualTo(sizing.get("bodyBytes").asInt());
            assertThat(body <= NatControlService.MESSAGE_BODY_LIMIT).as("J=%d fits", jsonBytes)
                    .isEqualTo(sizing.get("fits").asBoolean());
        }
    }

    /** Whatever a rename makes the client's name, its NAT_CONTROL as sent is never larger than the body counted. */
    @Test
    void theReserveCoversEveryNameARenameAllows() {
        SpecusMapping mapping = new SpecusMapping();
        mapping.setId(1L);
        mapping.setListenPort(42_001);
        mapping.setTargetAddress("127.0.0.1");
        mapping.setTargetPort(22);
        mapping.setEnabled(true);
        List<SpecusMapping> mappings = List.of(mapping);
        List<HttpRouteMapping> routes = List.of(route(2L, "web", TARGET_PREFIX + "?a=1&b=<2>"));
        int reserved = service.reservedBodyBytes(mappings, routes);
        // 120 UTF-16 code units each: the longest name every server's rename accepts.
        for (String name : List.of(Character.toString(0x01).repeat(120), "\"".repeat(120), "中".repeat(120),
                Character.toString(0x1F600).repeat(60), Character.toString(0x2028).repeat(120), "a".repeat(120))) {
            MessageResponsePacket packet = new MessageResponsePacket();
            packet.setClientName(name);
            packet.setMessageType(MessageType.NAT_CONTROL);
            packet.setMessage(service.messageJson(name, mappings, routes));
            assertThat(Serializer.COMPACT_BINARY.serialize(packet).length)
                    .as("name of %s", name.substring(0, 2))
                    .isLessThanOrEqualTo(reserved);
        }
    }

    static HttpRouteMapping route(Long id, String name, String targetBaseUrl) {
        HttpRouteMapping route = new HttpRouteMapping();
        route.setId(id);
        route.setRoute(name);
        route.setTargetBaseUrl(targetBaseUrl);
        route.setEnabled(true);
        route.setInsecureSkipVerify(false);
        return route;
    }

    /** The NAT_CONTROL JSON of these entries with an empty client name: the J of the vector. */
    static int jsonBytes(NatControlService service, List<SpecusMapping> mappings, List<HttpRouteMapping> routes) {
        return service.messageJson("", mappings, routes).getBytes(StandardCharsets.UTF_8).length;
    }

    static JsonNode readVector() throws IOException {
        Path directory = Path.of("").toAbsolutePath();
        while (directory != null) {
            Path candidate = directory.resolve("protocol/test-vectors/nat-control-size-v1.json");
            if (Files.isRegularFile(candidate)) {
                return new ObjectMapper().readTree(candidate.toFile());
            }
            directory = directory.getParent();
        }
        throw new IOException("protocol/test-vectors/nat-control-size-v1.json not found");
    }
}
