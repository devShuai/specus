package com.theshuai.common.codec;

import com.theshuai.common.protocol.MessageType;
import com.theshuai.common.protocol.PacketCodec;
import com.theshuai.common.protocol.response.MessageResponsePacket;
import io.netty.buffer.AbstractByteBufAllocator;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.ChannelFuture;
import io.netty.channel.embedded.EmbeddedChannel;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PacketCodecHandlerTests {
    // A NAT_CONTROL past the 1 MiB MESSAGE body fails its write, and the buffer allocated for it is
    // released rather than leaked; the channel stays open and writes nothing.
    @Test
    void aPacketThatCannotBeEncodedFailsItsWriteAndReleasesItsBuffer() {
        RecordingAllocator allocator = new RecordingAllocator();
        EmbeddedChannel channel = new EmbeddedChannel(PacketCodecHandler.INSTANCE);
        channel.config().setAllocator(allocator);
        try {
            MessageResponsePacket packet = new MessageResponsePacket();
            packet.setClientName("client");
            packet.setMessageType(MessageType.NAT_CONTROL);
            packet.setMessage("x".repeat(PacketCodec.MAX_MESSAGE_BODY_BYTES));

            ChannelFuture write = channel.writeOneOutbound(packet);
            channel.flushOutbound();

            assertFalse(write.isSuccess());
            assertNull(channel.readOutbound());
            assertTrue(channel.isOpen());
            assertEquals(1, allocator.buffers.size());
            assertEquals(0, allocator.buffers.get(0).refCnt());
        } finally {
            channel.finishAndReleaseAll();
        }
    }

    /** Unpooled buffers, each kept so the test can see whether it was released. */
    private static final class RecordingAllocator extends AbstractByteBufAllocator {
        private final List<ByteBuf> buffers = new ArrayList<>();

        RecordingAllocator() {
            super(false);
        }

        @Override
        protected ByteBuf newHeapBuffer(int initialCapacity, int maxCapacity) {
            return record(Unpooled.buffer(initialCapacity, maxCapacity));
        }

        @Override
        protected ByteBuf newDirectBuffer(int initialCapacity, int maxCapacity) {
            return record(Unpooled.directBuffer(initialCapacity, maxCapacity));
        }

        @Override
        public boolean isDirectBufferPooled() {
            return false;
        }

        private ByteBuf record(ByteBuf buffer) {
            buffers.add(buffer);
            return buffer;
        }
    }
}
