package com.theshuai.specusserver.handler;

import com.theshuai.common.codec.PacketCodecHandler;
import com.theshuai.common.codec.Spliter;
import com.theshuai.common.command.Command;
import com.theshuai.common.protocol.PacketCodec;
import com.theshuai.common.serialize.SerializerAlgorithm;
import com.theshuai.common.session.Session;
import com.theshuai.specusserver.attribute.ServerAttributes;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.embedded.EmbeddedChannel;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Frames refused while decoding, through the decoding part of NettyServer's pipeline in its order
 * (pre-auth Spliter, PacketCodecHandler, ControlProtocolMetricsHandler): every
 * ProtocolException reason reaches specus.control.protocol.rejected although the codec, a
 * MessageToMessageCodec, hands it on wrapped in a DecoderException.
 */
class ControlProtocolMetricsHandlerTests {
    private static final List<String> REASONS = List.of(
            "invalid_magic", "unsupported_version", "unsupported_serializer",
            "unknown_command", "invalid_length", "malformed_body");

    @Test
    void codecRejectionsAreCountedByTheirReason() {
        assertRejectedAs("invalid_magic",
                frame(0, PacketCodec.PROTOCOL_VERSION, SerializerAlgorithm.BIN, Command.LOGIN_REQUEST, new byte[0]));
        assertRejectedAs("unsupported_version",
                frame(PacketCodec.MAGIC_NUMBER, 9, SerializerAlgorithm.BIN, Command.LOGIN_REQUEST, new byte[0]));
        assertRejectedAs("unsupported_serializer",
                frame(PacketCodec.MAGIC_NUMBER, PacketCodec.PROTOCOL_VERSION, 1, Command.LOGIN_REQUEST, new byte[0]));
        assertRejectedAs("unknown_command",
                frame(PacketCodec.MAGIC_NUMBER, PacketCodec.PROTOCOL_VERSION, SerializerAlgorithm.BIN, 99, new byte[0]));
        // A NAT body shorter than its 16-byte header.
        assertRejectedAs("invalid_length",
                frame(PacketCodec.MAGIC_NUMBER, PacketCodec.PROTOCOL_VERSION, SerializerAlgorithm.BIN,
                        Command.NAT_MESSAGE, new byte[5]));
        // A login body CompactBinary cannot read: a varint that never ends.
        assertRejectedAs("malformed_body",
                frame(PacketCodec.MAGIC_NUMBER, PacketCodec.PROTOCOL_VERSION, SerializerAlgorithm.BIN,
                        Command.LOGIN_REQUEST, new byte[]{(byte) 0xff}));
    }

    @Test
    void anOversizedFrameBeforeLoginCountsOnlyThePreAuthCounter() {
        SimpleMeterRegistry registry = new SimpleMeterRegistry();
        EmbeddedChannel channel = pipeline(registry);
        // Refused from the length field alone, whatever the rest of the header says.
        channel.writeInbound(header(0, 9, 1, 99, PacketCodec.PRE_AUTH_MAX_FRAME_SIZE));

        assertThat(channel.isOpen()).isFalse();
        assertThat(registry.get("specus.control.preauth.oversize.rejected").counter().count()).isEqualTo(1.0);
        for (String reason : REASONS) {
            assertThat(rejected(registry, reason)).as(reason).isZero();
        }
    }

    @Test
    void anOversizedFrameAfterLoginIsNotAPreAuthRejection() {
        SimpleMeterRegistry registry = new SimpleMeterRegistry();
        EmbeddedChannel channel = pipeline(registry);
        channel.attr(ServerAttributes.SESSION).set(new Session("logged-in"));
        channel.writeInbound(header(PacketCodec.MAGIC_NUMBER, PacketCodec.PROTOCOL_VERSION, SerializerAlgorithm.BIN,
                Command.LOGIN_REQUEST, PacketCodec.PRE_AUTH_MAX_FRAME_SIZE));

        assertThat(channel.isOpen()).isFalse();
        assertThat(registry.get("specus.control.preauth.oversize.rejected").counter().count()).isZero();
        for (String reason : REASONS) {
            assertThat(rejected(registry, reason)).as(reason).isZero();
        }
    }

    private static void assertRejectedAs(String expected, ByteBuf frame) {
        SimpleMeterRegistry registry = new SimpleMeterRegistry();
        EmbeddedChannel channel = pipeline(registry);
        channel.writeInbound(frame);

        assertThat(channel.isOpen()).as(expected + " closes the channel").isFalse();
        for (String reason : REASONS) {
            assertThat(rejected(registry, reason)).as(expected + " counted as " + reason)
                    .isEqualTo(reason.equals(expected) ? 1.0 : 0.0);
        }
        assertThat(registry.get("specus.control.preauth.oversize.rejected").counter().count()).isZero();
    }

    /** The decoding handlers of NettyServer's channel initializer, in the same order. */
    private static EmbeddedChannel pipeline(SimpleMeterRegistry registry) {
        return new EmbeddedChannel(
                new Spliter(PacketCodec.PRE_AUTH_MAX_FRAME_SIZE),
                PacketCodecHandler.INSTANCE,
                new ControlProtocolMetricsHandler(registry));
    }

    private static double rejected(SimpleMeterRegistry registry, String reason) {
        return registry.get("specus.control.protocol.rejected").tag("reason", reason).counter().count();
    }

    private static ByteBuf header(int magic, int version, int serializer, int command, int bodyLength) {
        return Unpooled.buffer()
                .writeInt(magic)
                .writeByte(version)
                .writeByte(serializer)
                .writeByte(command)
                .writeInt(bodyLength);
    }

    private static ByteBuf frame(int magic, int version, int serializer, int command, byte[] body) {
        return header(magic, version, serializer, command, body.length).writeBytes(body);
    }
}
