package com.theshuai.specusclient.handler;

import com.theshuai.common.handler.StreamFlowController;
import com.theshuai.common.protocol.NatMessagePacket;
import com.theshuai.common.protocol.NatMessageType;
import com.theshuai.common.protocol.WebSocketSpecusFrame;
import com.theshuai.specusclient.bean.SpecusBean;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.embedded.EmbeddedChannel;
import io.netty.handler.codec.http.websocketx.CloseWebSocketFrame;
import io.netty.handler.codec.http.websocketx.TextWebSocketFrame;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;

class WsLocalSpecusHandlerTests {

    @Test
    void releasesConsumedWebSocketFrame() {
        Fixture fixture = fixture(5_000);
        TextWebSocketFrame frame = new TextWebSocketFrame("hello");
        try {
            fixture.local.writeInbound(frame);
            fixture.control.runPendingTasks();

            assertEquals(0, frame.refCnt());
            NatMessagePacket packet = fixture.control.readOutbound();
            assertEquals(NatMessageType.DATA, packet.getNatMessageType());
            WebSocketSpecusFrame decoded = WebSocketSpecusFrame.decode(packet.getData());
            assertEquals(WebSocketSpecusFrame.OPCODE_TEXT, decoded.opcode());
            assertEquals("hello", new String(decoded.payload(), java.nio.charset.StandardCharsets.UTF_8));
        } finally {
            fixture.close();
        }
    }

    @Test
    void forwardsNonWebSocketMessagesWithoutReleasingThem() {
        Fixture fixture = fixture(5_000);
        ByteBuf message = Unpooled.buffer().writeByte(7);
        try {
            fixture.local.writeInbound(message);

            assertSame(message, fixture.local.readInbound());
            assertEquals(1, message.refCnt());
            message.release();
        } finally {
            fixture.close();
        }
    }

    @Test
    void sendsFinOnlyAfterCloseDataIsWritten() {
        Fixture fixture = fixture(5_000);
        CloseWebSocketFrame frame = new CloseWebSocketFrame(1000, "done");
        try {
            fixture.local.writeInbound(frame);
            fixture.control.runPendingTasks();

            assertEquals(0, frame.refCnt());
            NatMessagePacket close = fixture.control.readOutbound();
            NatMessagePacket fin = fixture.control.readOutbound();
            assertEquals(NatMessageType.DATA, close.getNatMessageType());
            assertEquals(WebSocketSpecusFrame.OPCODE_CLOSE,
                    WebSocketSpecusFrame.decode(close.getData()).opcode());
            assertEquals(NatMessageType.FIN, fin.getNatMessageType());
            assertFalse(fixture.local.isActive());
        } finally {
            fixture.close();
        }
    }

    @Test
    void resetsCloseWhenPeerDoesNotReturnCredit() {
        Fixture fixture = fixture(50);
        try {
            StreamFlowController flow = StreamFlowController.get(fixture.control);
            flow.send(17, new byte[(int) StreamFlowController.INITIAL_WINDOW_BYTES], null, null);
            fixture.control.runPendingTasks();
            drain(fixture.control);

            fixture.local.writeInbound(new CloseWebSocketFrame(1000, "done"));
            fixture.control.advanceTimeBy(50, TimeUnit.MILLISECONDS);
            fixture.control.runScheduledPendingTasks();
            fixture.control.runPendingTasks();

            NatMessagePacket reset = fixture.control.readOutbound();
            assertEquals(NatMessageType.RST, reset.getNatMessageType());
            assertEquals(8, reset.getValue());
            assertEquals("websocket close credit timeout", reset.getMetaData().get("reason"));
            assertFalse(fixture.local.isActive());
        } finally {
            fixture.close();
        }
    }

    private static Fixture fixture(long closeTimeoutMillis) {
        SpecusBean bean = new SpecusBean();
        bean.setClientName("client");
        bean.setRemoteAddress("127.0.0.1");
        bean.setSpecusConfigList(List.of());
        bean.setHttpSpecusConfigList(List.of());
        NatClientHandler nat = new NatClientHandler(bean);
        EmbeddedChannel control = new EmbeddedChannel(nat);
        EmbeddedChannel local = new EmbeddedChannel(
                new WsLocalSpecusHandler(nat, 17, "remote", closeTimeoutMillis));
        return new Fixture(control, local);
    }

    private static void drain(EmbeddedChannel channel) {
        while (channel.readOutbound() != null) {
            // Drain the credit-consuming DATA frames.
        }
    }

    private record Fixture(EmbeddedChannel control, EmbeddedChannel local) {
        void close() {
            local.finishAndReleaseAll();
            control.finishAndReleaseAll();
        }
    }
}
