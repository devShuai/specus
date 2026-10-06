package com.theshuai.specusclient.handler;

import com.theshuai.common.handler.StreamFlowController;
import com.theshuai.common.protocol.NatMessagePacket;
import com.theshuai.common.protocol.NatMessageType;
import com.theshuai.common.protocol.WebSocketSpecusFrame;
import com.theshuai.specusclient.bean.SpecusBean;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelOutboundHandlerAdapter;
import io.netty.channel.ChannelPromise;
import io.netty.channel.embedded.EmbeddedChannel;
import io.netty.handler.codec.http.websocketx.CloseWebSocketFrame;
import io.netty.handler.codec.http.websocketx.TextWebSocketFrame;
import io.netty.handler.codec.http.websocketx.WebSocketClientProtocolHandler;
import io.netty.util.ReferenceCountUtil;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

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
            assertTrue(fixture.local.isActive(), "the app's close handshake still waits for the peer's reply");
        } finally {
            fixture.close();
        }
    }

    @Test
    void relaysThePeersCloseReplyBeforeClosingOnASeparateFin() throws Exception {
        HeldWrites held = new HeldWrites();
        Fixture fixture = registeredFixture(5_000, held);
        try {
            startAppClose(fixture);

            // The server relays the browser's CLOSE reply, then ends the stream with its own FIN.
            fixture.control.writeInbound(data(17, appCloseReply(), 0));
            fixture.control.writeInbound(fin(17));
            fixture.control.runPendingTasks();

            assertCloseReplyHeldThenClosed(fixture, held);
        } finally {
            held.releaseAll();
            fixture.close();
        }
    }

    @Test
    void relaysThePeersCloseReplyBeforeClosingOnEndStream() throws Exception {
        HeldWrites held = new HeldWrites();
        Fixture fixture = registeredFixture(5_000, held);
        try {
            startAppClose(fixture);

            // DATA|END_STREAM is the same CLOSE reply followed by FIN.
            fixture.control.writeInbound(data(17, appCloseReply(), NatMessagePacket.FLAG_END_STREAM));
            fixture.control.runPendingTasks();

            assertCloseReplyHeldThenClosed(fixture, held);
        } finally {
            held.releaseAll();
            fixture.close();
        }
    }

    @Test
    void stopsWaitingForACloseReplyThatNeverComes() throws Exception {
        Fixture fixture = registeredFixture(50, null);
        try {
            startAppClose(fixture);

            fixture.control.advanceTimeBy(50, TimeUnit.MILLISECONDS);
            fixture.control.runScheduledPendingTasks();
            fixture.control.runPendingTasks();

            assertFalse(fixture.local.isActive());
            assertNull(fixture.control.readOutbound(), "our FIN already ended this direction");
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

    @Test
    void returnsCreditOnlyOnceTheFrameReachesTheLocalSocket() {
        HeldWrites held = new HeldWrites();
        Fixture fixture = fixture(5_000, held);
        try {
            byte[] payload = new WebSocketSpecusFrame(WebSocketSpecusFrame.OPCODE_TEXT, true, 0, 0,
                    "hello".getBytes(java.nio.charset.StandardCharsets.UTF_8)).encode();
            fixture.handler().writeFrame(fixture.localContext(), payload);
            fixture.control.runPendingTasks();

            assertNull(fixture.control.readOutbound(),
                    "credit returned before the local write lets the server run ahead of a slow socket");

            held.completeAll();
            fixture.control.runPendingTasks();
            NatMessagePacket credit = fixture.control.readOutbound();
            assertEquals(NatMessageType.WINDOW_UPDATE, credit.getNatMessageType());
            assertEquals(17, credit.getStreamId());
            assertEquals(payload.length, credit.getValue());
        } finally {
            held.releaseAll();
            fixture.close();
        }
    }

    @Test
    void resetsTheStreamWhenTheServerOverrunsTheReceiveWindow() {
        HeldWrites held = new HeldWrites();
        Fixture fixture = fixture(5_000, held);
        try {
            byte[] payload = new WebSocketSpecusFrame(WebSocketSpecusFrame.OPCODE_BINARY, true, 0, 0,
                    new byte[WebSocketSpecusFrame.MAX_PAYLOAD_BYTES]).encode();
            long window = StreamFlowController.INITIAL_WINDOW_BYTES;
            for (long sent = 0; sent < window; sent += payload.length) {
                fixture.handler().writeFrame(fixture.localContext(), payload);
            }
            fixture.control.runPendingTasks();
            assertNull(fixture.control.readOutbound(), "a full window is still within the rules");
            assertTrue(fixture.local.isActive());

            fixture.handler().writeFrame(fixture.localContext(), payload);
            fixture.control.runPendingTasks();

            NatMessagePacket reset = fixture.control.readOutbound();
            assertEquals(NatMessageType.RST, reset.getNatMessageType());
            assertEquals(8, reset.getValue());
            assertEquals("pending local WebSocket data exceeds receive window",
                    reset.getMetaData().get("reason"));
            assertFalse(fixture.local.isActive());
        } finally {
            held.releaseAll();
            fixture.close();
        }
    }

    private static Fixture fixture(long closeTimeoutMillis) {
        return fixture(closeTimeoutMillis, null);
    }

    /** A stream past its handshake, so NatClientHandler routes the server's DATA/FIN to it. */
    @SuppressWarnings("unchecked")
    private static Fixture registeredFixture(long closeTimeoutMillis, ChannelOutboundHandlerAdapter localSocket)
            throws Exception {
        Fixture fixture = fixture(closeTimeoutMillis, localSocket);
        NatClientHandler nat = fixture.control.pipeline().get(NatClientHandler.class);
        Field pending = NatClientHandler.class.getDeclaredField("pendingStreamIds");
        pending.setAccessible(true);
        ((Set<Integer>) pending.get(nat)).add(17);
        fixture.local.pipeline().fireUserEventTriggered(
                WebSocketClientProtocolHandler.ClientHandshakeStateEvent.HANDSHAKE_COMPLETE);
        return fixture;
    }

    /** The app sends CLOSE 1001; it goes to the server as SWS2 CLOSE followed by FIN. */
    private static void startAppClose(Fixture fixture) {
        fixture.local.writeInbound(new CloseWebSocketFrame(1001, "app going away"));
        fixture.control.runPendingTasks();
        NatMessagePacket close = fixture.control.readOutbound();
        NatMessagePacket fin = fixture.control.readOutbound();
        assertEquals(NatMessageType.DATA, close.getNatMessageType());
        assertEquals(WebSocketSpecusFrame.OPCODE_CLOSE, WebSocketSpecusFrame.decode(close.getData()).opcode());
        assertEquals(NatMessageType.FIN, fin.getNatMessageType());
        assertTrue(fixture.local.isActive(), "the app's close handshake still waits for the peer's reply");
    }

    private static byte[] appCloseReply() {
        return new WebSocketSpecusFrame(WebSocketSpecusFrame.OPCODE_CLOSE, true, 0, 1001,
                "app going away".getBytes(java.nio.charset.StandardCharsets.UTF_8)).encode();
    }

    /** The reply sits in the local socket: the channel may close only once it is written. */
    private static void assertCloseReplyHeldThenClosed(Fixture fixture, HeldWrites held) {
        assertEquals(1, held.messages.size(), "the peer's CLOSE reply never reached the local socket");
        CloseWebSocketFrame reply = assertInstanceOf(CloseWebSocketFrame.class, held.messages.get(0));
        assertEquals(1001, reply.statusCode());
        assertEquals("app going away", reply.reasonText());
        assertTrue(fixture.local.isActive(), "closed before the CLOSE reply was written");

        held.completeAll();
        fixture.local.runPendingTasks();
        assertFalse(fixture.local.isActive());
    }

    private static NatMessagePacket data(int streamId, byte[] payload, int flags) {
        NatMessagePacket packet = new NatMessagePacket();
        packet.setNatMessageType(NatMessageType.DATA);
        packet.setStreamId(streamId);
        packet.setData(payload);
        packet.setFlags(flags);
        return packet;
    }

    private static NatMessagePacket fin(int streamId) {
        NatMessagePacket packet = new NatMessagePacket();
        packet.setNatMessageType(NatMessageType.FIN);
        packet.setStreamId(streamId);
        return packet;
    }

    private static Fixture fixture(long closeTimeoutMillis, ChannelOutboundHandlerAdapter localSocket) {
        SpecusBean bean = new SpecusBean();
        bean.setClientName("client");
        bean.setRemoteAddress("127.0.0.1");
        bean.setSpecusConfigList(List.of());
        bean.setHttpSpecusConfigList(List.of());
        NatClientHandler nat = new NatClientHandler(bean);
        EmbeddedChannel control = new EmbeddedChannel(nat);
        WsLocalSpecusHandler handler = new WsLocalSpecusHandler(nat, 17, "remote", closeTimeoutMillis);
        EmbeddedChannel local = localSocket == null
                ? new EmbeddedChannel(handler)
                : new EmbeddedChannel(localSocket, handler);
        return new Fixture(control, local);
    }

    /** Stands in for a local socket that has not yet taken the bytes written to it. */
    private static final class HeldWrites extends ChannelOutboundHandlerAdapter {
        private final List<ChannelPromise> promises = new ArrayList<>();
        private final List<Object> messages = new ArrayList<>();

        @Override
        public void write(ChannelHandlerContext ctx, Object msg, ChannelPromise promise) {
            messages.add(msg);
            promises.add(promise);
        }

        void completeAll() {
            promises.forEach(ChannelPromise::trySuccess);
            promises.clear();
        }

        void releaseAll() {
            messages.forEach(ReferenceCountUtil::release);
            messages.clear();
        }
    }

    private static void drain(EmbeddedChannel channel) {
        while (channel.readOutbound() != null) {
            // Drain the credit-consuming DATA frames.
        }
    }

    private record Fixture(EmbeddedChannel control, EmbeddedChannel local) {
        WsLocalSpecusHandler handler() {
            return local.pipeline().get(WsLocalSpecusHandler.class);
        }

        ChannelHandlerContext localContext() {
            return local.pipeline().context(WsLocalSpecusHandler.class);
        }

        void close() {
            local.finishAndReleaseAll();
            control.finishAndReleaseAll();
        }
    }
}
