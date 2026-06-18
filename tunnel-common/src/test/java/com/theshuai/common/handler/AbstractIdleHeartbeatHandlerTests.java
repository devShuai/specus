package com.theshuai.common.handler;

import com.theshuai.common.codec.PacketEncoder;
import com.theshuai.common.protocol.Packet;
import com.theshuai.common.protocol.PacketCodec;
import com.theshuai.common.protocol.response.HeartBeatResponsePacket;
import io.netty.buffer.ByteBuf;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.embedded.EmbeddedChannel;
import io.netty.handler.timeout.IdleStateEvent;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertInstanceOf;

class AbstractIdleHeartbeatHandlerTests {

    @Test
    void writerIdleHeartbeatShouldPassThroughPacketEncoder() throws Exception {
        ProbeIdleHandler idleHandler = new ProbeIdleHandler();
        EmbeddedChannel channel = new EmbeddedChannel(idleHandler, new PacketEncoder());

        idleHandler.triggerWriterIdle();

        ByteBuf outbound = assertInstanceOf(ByteBuf.class, channel.readOutbound());
        try {
            Packet packet = PacketCodec.INSTANCE.decode(outbound);
            assertInstanceOf(HeartBeatResponsePacket.class, packet);
        } finally {
            outbound.release();
            channel.finishAndReleaseAll();
        }
    }

    private static final class ProbeIdleHandler extends AbstractIdleHeartbeatHandler {
        private ChannelHandlerContext context;

        private ProbeIdleHandler() {
            super(60, 30);
        }

        @Override
        public void handlerAdded(ChannelHandlerContext ctx) throws Exception {
            super.handlerAdded(ctx);
            this.context = ctx;
        }

        @Override
        protected Packet buildHeartbeat() {
            return new HeartBeatResponsePacket();
        }

        void triggerWriterIdle() throws Exception {
            channelIdle(context, IdleStateEvent.WRITER_IDLE_STATE_EVENT);
        }
    }
}
