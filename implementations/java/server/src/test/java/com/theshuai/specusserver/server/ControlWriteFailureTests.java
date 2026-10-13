package com.theshuai.specusserver.server;

import com.theshuai.common.codec.PacketCodecHandler;
import com.theshuai.common.protocol.MessageType;
import com.theshuai.common.protocol.Packet;
import com.theshuai.common.protocol.PacketCodec;
import com.theshuai.common.protocol.response.HeartBeatResponsePacket;
import com.theshuai.common.protocol.response.MessageResponsePacket;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.ByteBufUtil;
import io.netty.buffer.Unpooled;
import io.netty.channel.ChannelFuture;
import io.netty.channel.ChannelOutboundBuffer;
import io.netty.channel.embedded.EmbeddedChannel;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * "帧写入失败" in protocol/spec/control-protocol.md as the Java server meets it, with the codec of its
 * control and data pipeline ({@link NettyServer}). Each frame is encoded into one buffer, so a frame is
 * written whole or not at all as far as the pipeline goes. A transport write that fails partway with an
 * IOException makes Netty close the channel (autoClose, which the server leaves at its default), so
 * nothing is written after the cut frame. And a frame being written cannot be cut short by its caller:
 * Netty makes a write's promise uncancellable once it is flushed.
 */
class ControlWriteFailureTests {

    @Test
    void aWriteCutShortClosesTheChannelAndNothingFollowsIt() {
        CutShortChannel channel = new CutShortChannel(true);

        ChannelFuture first = channel.writeAndFlush(message("first"));
        assertThat(first.isSuccess()).isFalse();
        assertThat(first.cause()).isInstanceOf(IOException.class);
        int cut = channel.wire.size();
        assertThat(cut).as("the failed write put nothing on the wire; the test cuts no frame short").isPositive();
        channel.runPendingTasks();
        assertThat(channel.isOpen()).as("the channel stayed open after a frame was cut short").isFalse();

        ChannelFuture second = channel.writeAndFlush(message("second"));
        ChannelFuture heartbeat = channel.writeAndFlush(new HeartBeatResponsePacket());
        channel.runPendingTasks();
        assertThat(second.isSuccess()).isFalse();
        assertThat(heartbeat.isSuccess()).isFalse();
        assertThat(channel.wire.size()).as("bytes written after the cut frame").isEqualTo(cut);
    }

    @Test
    void aFrameBeingWrittenCannotBeCutShortByItsCaller() throws Exception {
        CutShortChannel channel = new CutShortChannel(false);
        MessageResponsePacket firstPacket = message("first");
        MessageResponsePacket secondPacket = message("second");

        ChannelFuture first = channel.writeAndFlush(firstPacket);
        assertThat(channel.wire.size()).isEqualTo(encode(firstPacket).length / 2);
        assertThat(first.cancel(true)).as("a frame half on the wire was cancelled").isFalse();
        ChannelFuture second = channel.writeAndFlush(secondPacket);
        assertThat(channel.wire.size()).as("the next frame went out after half a frame")
                .isEqualTo(encode(firstPacket).length / 2);

        channel.release();
        assertThat(first.isSuccess()).isTrue();
        assertThat(second.isSuccess()).isTrue();
        ByteArrayOutputStream expected = new ByteArrayOutputStream();
        expected.writeBytes(encode(firstPacket));
        expected.writeBytes(encode(secondPacket));
        assertThat(channel.wire.toByteArray()).isEqualTo(expected.toByteArray());
        assertThat(channel.isOpen()).isTrue();
        channel.finishAndReleaseAll();
    }

    private static MessageResponsePacket message(String text) {
        MessageResponsePacket packet = new MessageResponsePacket();
        packet.setClientName("server");
        packet.setToClientName("client");
        packet.setMessageType(MessageType.SERVER_TO_CLIENT);
        packet.setMessage(text + "x".repeat(4096));
        return packet;
    }

    private static byte[] encode(Packet packet) throws Exception {
        ByteBuf buffer = Unpooled.buffer();
        try {
            PacketCodec.INSTANCE.encode(buffer, packet);
            return ByteBufUtil.getBytes(buffer);
        } finally {
            buffer.release();
        }
    }

    /**
     * A channel whose transport puts the first half of the first frame on the wire and then either fails
     * with an IOException, as a write cut short by a reset or a write timeout, or holds there, as one
     * waiting on a client that stopped reading, until {@link #release()}. Everything after goes out whole.
     */
    private static final class CutShortChannel extends EmbeddedChannel {
        private final ByteArrayOutputStream wire = new ByteArrayOutputStream();
        private final boolean failFirstWrite;
        private boolean firstWriteStarted;
        private boolean held;

        CutShortChannel(boolean failFirstWrite) {
            super(PacketCodecHandler.INSTANCE);
            this.failFirstWrite = failFirstWrite;
        }

        void release() {
            held = false;
            flush();
        }

        @Override
        protected void doWrite(ChannelOutboundBuffer in) throws Exception {
            for (Object message = in.current(); message != null; message = in.current()) {
                if (held) {
                    return;
                }
                ByteBuf buffer = (ByteBuf) message;
                if (!firstWriteStarted) {
                    firstWriteStarted = true;
                    int half = buffer.readableBytes() / 2;
                    buffer.readBytes(wire, half);
                    in.progress(half);
                    if (failFirstWrite) {
                        throw new IOException("connection reset after half a frame");
                    }
                    held = true;
                    return;
                }
                int rest = buffer.readableBytes();
                buffer.readBytes(wire, rest);
                in.progress(rest);
                in.remove();
            }
        }
    }
}
