package com.theshuai.common.protocol;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.theshuai.common.command.Command;
import com.theshuai.common.serialize.SerializerAlgorithm;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HexFormat;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * Replays {@code protocol/test-vectors/nat-metadata-json-v1.json}: the metadata of an OPEN is read
 * strictly by RFC 8259 as one UTF-8 JSON object, and every refused case is a malformed body.
 */
class NatMetadataJsonVectorTests {
    @Test
    void acceptsAndRefusesTheSharedCases() throws Exception {
        JsonNode vector = new ObjectMapper().readTree(Files.readString(findVector()));
        assertEquals(1, vector.get("version").asInt());
        int accepted = 0;
        for (JsonNode testCase : vector.get("accepted")) {
            ByteBuf frame = openFrame(HexFormat.of().parseHex(testCase.get("metadataHex").asText()));
            try {
                assertInstanceOf(NatMessagePacket.class, PacketCodec.INSTANCE.decode(frame),
                        testCase.get("name").asText());
            } finally {
                frame.release();
            }
            accepted++;
        }
        int rejected = 0;
        for (JsonNode testCase : vector.get("rejected")) {
            String name = testCase.get("name").asText();
            ByteBuf frame = openFrame(HexFormat.of().parseHex(testCase.get("metadataHex").asText()));
            try {
                ProtocolException exception = assertThrows(ProtocolException.class,
                        () -> PacketCodec.INSTANCE.decode(frame), name);
                assertEquals(ProtocolException.Reason.MALFORMED_BODY, exception.getReason(), name);
            } finally {
                frame.release();
            }
            rejected++;
        }
        assertEquals(8, accepted);
        assertEquals(34, rejected);
    }

    private static ByteBuf openFrame(byte[] metadata) {
        ByteBuf body = Unpooled.buffer(PacketCodec.NAT_BODY_HEADER_SIZE + metadata.length)
                .writeByte(NatMessageType.OPEN.getCode())
                .writeByte(0)
                .writeShort(metadata.length)
                .writeInt(1)
                .writeInt(0)
                .writeInt(0)
                .writeBytes(metadata);
        try {
            return Unpooled.buffer(PacketCodec.HEADER_SIZE + body.readableBytes())
                    .writeInt(PacketCodec.MAGIC_NUMBER)
                    .writeByte(PacketCodec.PROTOCOL_VERSION)
                    .writeByte(SerializerAlgorithm.BIN)
                    .writeByte(Command.NAT_MESSAGE)
                    .writeInt(body.readableBytes())
                    .writeBytes(body);
        } finally {
            body.release();
        }
    }

    private static Path findVector() {
        Path current = Path.of("").toAbsolutePath();
        for (int depth = 0; current != null && depth < 6; depth++, current = current.getParent()) {
            Path candidate = current.resolve("protocol/test-vectors/nat-metadata-json-v1.json");
            if (Files.isRegularFile(candidate)) {
                return candidate;
            }
        }
        throw new IllegalStateException("cannot locate the NAT metadata JSON vector");
    }
}
