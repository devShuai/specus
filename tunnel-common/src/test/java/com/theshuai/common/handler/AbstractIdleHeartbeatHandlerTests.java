package com.theshuai.common.handler;

import com.theshuai.common.codec.PacketEncoder;
import com.theshuai.common.protocol.Packet;
import com.theshuai.common.protocol.PacketCodec;
import com.theshuai.common.protocol.response.HeartBeatResponsePacket;
import io.netty.buffer.ByteBuf;
import io.netty.channel.embedded.EmbeddedChannel;
import io.netty.handler.timeout.IdleStateEvent;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertInstanceOf;

class AbstractIdleHeartbeatHandlerTests {

    @Test
    void writerIdleHeartbeatShouldPassThroughPacketEncoder() throws Exception {
        EmbeddedChannel channel = new EmbeddedChannel(new SocketIdleStateHandler(), new PacketEncoder());

        channel.pipeline().fireUserEventTriggered(IdleStateEvent.WRITER_IDLE_STATE_EVENT);

        ByteBuf outbound = assertInstanceOf(ByteBuf.class, channel.readOutbound());
        try {
            Packet packet = PacketCodec.INSTANCE.decode(outbound);
            assertInstanceOf(HeartBeatResponsePacket.class, packet);
        } finally {
            outbound.release();
            channel.finishAndReleaseAll();
        }
    }
}
