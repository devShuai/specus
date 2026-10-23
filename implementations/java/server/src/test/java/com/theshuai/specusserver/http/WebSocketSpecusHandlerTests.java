package com.theshuai.specusserver.http;

import com.theshuai.common.handler.StreamFlowController;
import com.theshuai.common.protocol.NatMessagePacket;
import com.theshuai.common.protocol.NatMessageType;
import com.theshuai.common.protocol.WebSocketSpecusFrame;
import com.theshuai.common.session.Session;
import com.theshuai.specusserver.httpshare.HttpShareStreamRegistry;
import com.theshuai.specusserver.session.SessionUtil;
import io.netty.channel.embedded.EmbeddedChannel;
import org.apache.tomcat.websocket.WsSession;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.web.socket.BinaryMessage;
import org.springframework.web.socket.CloseStatus;
import org.springframework.web.socket.TextMessage;
import org.springframework.web.socket.WebSocketMessage;
import org.springframework.web.socket.WebSocketSession;
import org.springframework.web.socket.adapter.NativeWebSocketSession;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockingDetails;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.mockito.Mockito.withSettings;

class WebSocketSpecusHandlerTests {

    @Test
    void rejectsNewMessageBeforeFragmentedMessageCompletes() throws Exception {
        Fixture fixture = fixture();

        fixture.handler.writeFrame(7, frame(WebSocketSpecusFrame.OPCODE_BINARY, false, "first"));
        fixture.handler.writeFrame(7, frame(WebSocketSpecusFrame.OPCODE_TEXT, true, "replacement"));

        verify(fixture.session).close(CloseStatus.GOING_AWAY);
    }

    @Test
    void preservesUtf8BytesAcrossTextFragments() throws Exception {
        Fixture fixture = fixture();
        byte[] utf8 = "你".getBytes(StandardCharsets.UTF_8);

        fixture.handler.writeFrame(7, new WebSocketSpecusFrame(
                WebSocketSpecusFrame.OPCODE_TEXT, false, 0, 0,
                Arrays.copyOfRange(utf8, 0, 1)).encode());
        fixture.handler.writeFrame(7, new WebSocketSpecusFrame(
                WebSocketSpecusFrame.OPCODE_CONTINUATION, true, 0, 0,
                Arrays.copyOfRange(utf8, 1, utf8.length)).encode());

        ArgumentCaptor<WebSocketMessage<?>> message = ArgumentCaptor.forClass(WebSocketMessage.class);
        verify(fixture.session).sendMessage(message.capture());
        assertThat(message.getValue()).isInstanceOf(TextMessage.class);
        assertThat(((TextMessage) message.getValue()).asBytes()).containsExactly(utf8);
        verify(fixture.session, never()).close(any(CloseStatus.class));
    }

    @Test
    void sendsFinOnlyAfterCloseDataIsWritten() throws Exception {
        TunnelFixture fixture = tunnelFixture(5_000);
        try {
            fixture.handler.afterConnectionClosed(fixture.session, CloseStatus.NORMAL);
            fixture.control.runPendingTasks();

            NatMessagePacket close = fixture.control.readOutbound();
            NatMessagePacket fin = fixture.control.readOutbound();
            assertThat(close.getNatMessageType()).isEqualTo(NatMessageType.DATA);
            assertThat(WebSocketSpecusFrame.decode(close.getData()).opcode())
                    .isEqualTo(WebSocketSpecusFrame.OPCODE_CLOSE);
            assertThat(fin.getNatMessageType()).isEqualTo(NatMessageType.FIN);
        } finally {
            fixture.close();
        }
    }

    @Test
    void resetsCloseWhenPeerDoesNotReturnCredit() throws Exception {
        TunnelFixture fixture = tunnelFixture(50);
        try {
            StreamFlowController flow = StreamFlowController.get(fixture.control);
            flow.send(fixture.streamId, new byte[(int) StreamFlowController.INITIAL_WINDOW_BYTES],
                    null, null);
            fixture.control.runPendingTasks();
            drain(fixture.control);

            fixture.handler.afterConnectionClosed(fixture.session, CloseStatus.NORMAL);
            fixture.control.advanceTimeBy(50, TimeUnit.MILLISECONDS);
            fixture.control.runScheduledPendingTasks();
            fixture.control.runPendingTasks();

            NatMessagePacket reset = fixture.control.readOutbound();
            assertThat(reset.getNatMessageType()).isEqualTo(NatMessageType.RST);
            assertThat(reset.getValue()).isEqualTo(8);
            assertThat(reset.getMetaData()).containsEntry(
                    "reason", "websocket close credit timeout");
            assertThat((Object) fixture.control.readOutbound()).isNull();
        } finally {
            fixture.close();
        }
    }

    @Test
    void browserLeavingWithoutCloseResetsStreamAndReleasesShareSlot() throws Exception {
        HttpShareStreamRegistry shares = new HttpShareStreamRegistry();
        HttpShareStreamRegistry.InFlight slot = shares.tryAcquire("share-1", Long.MAX_VALUE / 2000);
        TunnelFixture fixture = tunnelFixture(5_000,
                Map.of(WebSocketSpecusHandler.ATTR_SHARE_STREAM, slot), plainSession());
        try {
            // Tomcat reports a browser that dropped its connection without a CLOSE as 1006, which
            // must never go on the wire: the device hears RST, as from the C and .NET servers.
            fixture.handler.afterConnectionClosed(fixture.session,
                    CloseStatus.NO_CLOSE_FRAME.withReason("Write timeout"));
            fixture.control.runPendingTasks();

            NatMessagePacket reset = fixture.control.readOutbound();
            assertThat(reset.getNatMessageType()).isEqualTo(NatMessageType.RST);
            assertThat(reset.getStreamId()).isEqualTo(fixture.streamId);
            assertThat(reset.getValue()).isEqualTo(31);
            assertThat(reset.getMetaData()).containsEntry("reason", "WebSocket browser closed");
            assertThat((Object) fixture.control.readOutbound()).isNull();
            assertThat(shares.count("share-1")).as("the share slot is free again").isZero();
        } finally {
            fixture.close();
        }
    }

    @Test
    void browserCloseWithoutStatusEndsStreamWithCodelessCloseAndFin() throws Exception {
        TunnelFixture fixture = tunnelFixture(5_000);
        try {
            fixture.handler.afterConnectionClosed(fixture.session, CloseStatus.NO_STATUS_CODE);
            fixture.control.runPendingTasks();

            NatMessagePacket close = fixture.control.readOutbound();
            NatMessagePacket fin = fixture.control.readOutbound();
            assertThat(close.getNatMessageType()).isEqualTo(NatMessageType.DATA);
            WebSocketSpecusFrame frame = WebSocketSpecusFrame.decode(close.getData());
            assertThat(frame.opcode()).isEqualTo(WebSocketSpecusFrame.OPCODE_CLOSE);
            assertThat(frame.closeCode()).isZero();
            assertThat(frame.payload()).isEmpty();
            assertThat(fin.getNatMessageType()).isEqualTo(NatMessageType.FIN);
        } finally {
            fixture.close();
        }
    }

    @Test
    void forwardsSixteenMebibyteBrowserMessageHandedOverInParts() throws Exception {
        TunnelFixture fixture = tunnelFixture(5_000);
        try {
            assertThat(fixture.handler.supportsPartialMessages())
                    .as("Tomcat must hand big messages over in parts instead of buffering 16 MiB")
                    .isTrue();
            byte[] message = pattern(MAX_MESSAGE_BYTES);
            DeviceSide device = new DeviceSide(fixture);
            for (int offset = 0; offset < message.length; offset += PART_BYTES) {
                int end = Math.min(message.length, offset + PART_BYTES);
                fixture.handler.handleMessage(fixture.session, new BinaryMessage(
                        Arrays.copyOfRange(message, offset, end), end == message.length));
                device.take(true);
            }

            assertThat(device.resets()).isEmpty();
            List<WebSocketSpecusFrame> frames = device.frames();
            assertThat(frames.getFirst().opcode()).isEqualTo(WebSocketSpecusFrame.OPCODE_BINARY);
            assertThat(frames.subList(1, frames.size()))
                    .allSatisfy(frame -> assertThat(frame.opcode())
                            .isEqualTo(WebSocketSpecusFrame.OPCODE_CONTINUATION));
            assertThat(frames.subList(0, frames.size() - 1))
                    .noneSatisfy(frame -> assertThat(frame.finalFragment()).isTrue());
            assertThat(frames.getLast().finalFragment()).isTrue();
            assertThat(device.payload()).isEqualTo(message);
            verify(fixture.session, never()).close(any(CloseStatus.class));
        } finally {
            fixture.close();
        }
    }

    @Test
    void refusesBrowserMessageOverSixteenMebibytesCountedInUtf8BytesWith1009() throws Exception {
        TunnelFixture fixture = tunnelFixture(5_000);
        try {
            // 5,592,405 three-byte characters are 16 MiB - 1 bytes but far fewer than 16 Mi chars.
            String head = "你".repeat((MAX_MESSAGE_BYTES - 1) / 3);
            DeviceSide device = new DeviceSide(fixture);
            int chunk = PART_BYTES / 3;
            for (int offset = 0; offset < head.length(); offset += chunk) {
                fixture.handler.handleMessage(fixture.session, new TextMessage(
                        head.substring(offset, Math.min(head.length(), offset + chunk)), false));
                device.take(true);
            }
            fixture.handler.handleMessage(fixture.session, new TextMessage("ab", true));
            device.take(true);

            verify(fixture.session).close(org.mockito.ArgumentMatchers.argThat(
                    (CloseStatus status) -> status.getCode() == 1009));
            List<WebSocketSpecusFrame> frames = device.frames();
            WebSocketSpecusFrame close = frames.getLast();
            assertThat(close.opcode()).isEqualTo(WebSocketSpecusFrame.OPCODE_CLOSE);
            assertThat(close.closeCode()).isEqualTo(1009);
            assertThat(device.payload()).as("nothing past the limit reaches the device")
                    .hasSize(MAX_MESSAGE_BYTES - 1);
            assertThat(device.packets().getLast().getNatMessageType()).isEqualTo(NatMessageType.FIN);
            assertThat(device.resets()).isEmpty();
        } finally {
            fixture.close();
        }
    }

    @Test
    void pausesBrowserReadsWhileDeviceWithholdsCredit() throws Exception {
        WsSession tomcat = mock(WsSession.class);
        WebSocketSession session = mock(WebSocketSession.class,
                withSettings().extraInterfaces(NativeWebSocketSession.class));
        when(((NativeWebSocketSession) session).getNativeSession(WsSession.class)).thenReturn(tomcat);
        TunnelFixture fixture = tunnelFixture(5_000, Map.of(), session);
        try {
            // A text part of a third of a frame in UTF-16 units still fits one frame as UTF-8.
            verify(session).setTextMessageSizeLimit(PART_BYTES / 3);
            verify(session).setBinaryMessageSizeLimit(PART_BYTES);
            DeviceSide device = new DeviceSide(fixture);
            int parts = pauseReads(fixture, device, tomcat);
            verify(tomcat).suspend();
            assertThat((long) parts * PART_BYTES).isGreaterThanOrEqualTo(StreamFlowController.INITIAL_WINDOW_BYTES);
            assertThat(device.resets()).isEmpty();

            device.returnCredit();
            verify(tomcat).resume();
            assertThat(device.resets()).isEmpty();
        } finally {
            fixture.close();
        }
    }

    @Test
    void streamEndingWhileBrowserReadsArePausedResumesThem() throws Exception {
        WsSession tomcat = mock(WsSession.class);
        WebSocketSession session = mock(WebSocketSession.class,
                withSettings().extraInterfaces(NativeWebSocketSession.class));
        when(((NativeWebSocketSession) session).getNativeSession(WsSession.class)).thenReturn(tomcat);
        TunnelFixture fixture = tunnelFixture(5_000, Map.of(), session);
        try {
            DeviceSide device = new DeviceSide(fixture);
            pauseReads(fixture, device, tomcat);
            verify(tomcat, never()).resume();

            // The device ends the stream (its FIN or RST) while no credit came back: reads go on,
            // so the container sees the browser's answer to the GOING_AWAY close.
            fixture.handler.closeFromClient(fixture.streamId);
            verify(tomcat).resume();
            verify(session).close(CloseStatus.GOING_AWAY);

            // Whatever the container still delivers afterwards goes nowhere.
            fixture.control.runPendingTasks();
            drain(fixture.control);
            fixture.handler.handleMessage(fixture.session, new BinaryMessage(new byte[16], true));
            fixture.control.runPendingTasks();
            assertThat((Object) fixture.control.readOutbound()).isNull();
        } finally {
            fixture.close();
        }
    }

    @Test
    void browserLeavingWithoutCloseSendsItsQueuedDataBeforeTheReset() throws Exception {
        TunnelFixture fixture = tunnelFixture(5_000);
        try {
            DeviceSide device = new DeviceSide(fixture);
            // 16 frames use the 1 MiB window, 4 more wait for credit.
            for (int part = 0; part < 20; part++) {
                fixture.handler.handleMessage(fixture.session, new BinaryMessage(pattern(PART_BYTES), part == 19));
                device.take(false);
            }
            assertThat(device.frames()).hasSize(16);

            fixture.handler.afterConnectionClosed(fixture.session, CloseStatus.NO_CLOSE_FRAME);
            device.take(false);
            assertThat(device.resets()).as("the reset waits for the queued frames").isEmpty();

            device.returnCredit();
            assertThat(device.frames()).hasSize(20);
            assertThat(device.frames().getLast().finalFragment()).isTrue();
            NatMessagePacket last = device.packets().getLast();
            assertThat(last.getNatMessageType()).isEqualTo(NatMessageType.RST);
            assertThat(last.getValue()).isEqualTo(31);
        } finally {
            fixture.close();
        }
    }

    @Test
    void browserLeavingWithoutCloseResetsAtTheCloseCreditTimeoutWithoutCredit() throws Exception {
        TunnelFixture fixture = tunnelFixture(50);
        try {
            DeviceSide device = new DeviceSide(fixture);
            for (int part = 0; part < 20; part++) {
                fixture.handler.handleMessage(fixture.session, new BinaryMessage(pattern(PART_BYTES), false));
                device.take(false);
            }
            fixture.handler.afterConnectionClosed(fixture.session, CloseStatus.NO_CLOSE_FRAME);
            device.take(false);
            assertThat(device.resets()).isEmpty();

            fixture.control.advanceTimeBy(50, TimeUnit.MILLISECONDS);
            fixture.control.runScheduledPendingTasks();
            device.take(false);
            assertThat(device.resets()).singleElement()
                    .satisfies(reset -> assertThat(reset.getValue()).isEqualTo(31));
            assertThat(device.frames()).as("frames still without credit are dropped").hasSize(16);
        } finally {
            fixture.close();
        }
    }

    @Test
    void shareCutBeforeTheStreamOpensResetsTheOpenedStreamAndLeavesNothingBehind() throws Exception {
        HttpShareStreamRegistry shares = new HttpShareStreamRegistry();
        HttpShareStreamRegistry.InFlight slot = shares.tryAcquire("share-2", Long.MAX_VALUE / 2000);
        // Revoked or expired between the share's admission and the handler taking the connection.
        slot.cut();

        WebSocketStreamRegistry registry = new WebSocketStreamRegistry();
        WebSocketSpecusHandler handler = new WebSocketSpecusHandler(registry, 5_000);
        EmbeddedChannel control = new EmbeddedChannel();
        String clientName = "client-" + UUID.randomUUID();
        SessionUtil.bindDataSession(new Session(clientName), control);
        WebSocketSession session = mock(WebSocketSession.class);
        Map<String, Object> attributes = new HashMap<>();
        attributes.put(WebSocketSpecusHandler.ATTR_CLIENT_NAME, clientName);
        attributes.put(WebSocketSpecusHandler.ATTR_ROUTE, "route");
        attributes.put(WebSocketSpecusHandler.ATTR_SHARE_STREAM, slot);
        when(session.getAttributes()).thenReturn(attributes);
        when(session.isOpen()).thenReturn(true);
        // Tomcat runs afterConnectionClosed inside close(), before close() returns.
        doAnswer(invocation -> {
            handler.afterConnectionClosed(session, invocation.getArgument(0));
            return null;
        }).when(session).close(any(CloseStatus.class));
        try {
            handler.afterConnectionEstablished(session);
            control.runPendingTasks();
            int streamId = (Integer) attributes.get(WebSocketSpecusHandler.ATTR_STREAM_ID);

            NatMessagePacket open = control.readOutbound();
            NatMessagePacket reset = control.readOutbound();
            assertThat(open.getNatMessageType()).isEqualTo(NatMessageType.OPEN);
            assertThat(reset.getNatMessageType()).as("the device hears RST for a stream it was told of")
                    .isEqualTo(NatMessageType.RST);
            assertThat(reset.getStreamId()).isEqualTo(streamId);
            assertThat(reset.getMetaData()).containsEntry("reason", "HTTP share ended");
            verify(session).close(CloseStatus.POLICY_VIOLATION);
            assertThat(registry.getByStreamId(streamId)).isNull();
            assertThat(shares.count("share-2")).isZero();

            // Nothing of the stream is left: a late browser message and a late close send nothing.
            handler.handleMessage(session, new BinaryMessage(new byte[16], true));
            handler.afterConnectionClosed(session, CloseStatus.NO_CLOSE_FRAME);
            control.runPendingTasks();
            assertThat((Object) control.readOutbound()).isNull();
        } finally {
            control.finishAndReleaseAll();
        }
    }

    @Test
    void forwardsTextWithFourByteCharactersExactlyAcrossParts() throws Exception {
        TunnelFixture fixture = tunnelFixture(5_000);
        try {
            // Surrogate pairs on both sides of every part boundary; Tomcat's decoder never splits a
            // pair, so every part holds whole characters.
            String text = "😀a你".repeat(9_000);
            DeviceSide device = new DeviceSide(fixture);
            int partChars = PART_BYTES / 3 - 1; // even, so no part ends inside a pair
            for (int offset = 0; offset < text.length(); offset += partChars) {
                int end = Math.min(text.length(), offset + partChars);
                fixture.handler.handleMessage(fixture.session,
                        new TextMessage(text.substring(offset, end), end == text.length()));
                device.take(true);
            }

            assertThat(device.frames()).allSatisfy(frame ->
                    assertThat(frame.payload().length).isLessThanOrEqualTo(PART_BYTES));
            assertThat(device.frames().getFirst().opcode()).isEqualTo(WebSocketSpecusFrame.OPCODE_TEXT);
            assertThat(device.frames().subList(1, device.frames().size())).isNotEmpty()
                    .allSatisfy(frame -> assertThat(frame.opcode())
                            .isEqualTo(WebSocketSpecusFrame.OPCODE_CONTINUATION));
            assertThat(device.payload()).isEqualTo(text.getBytes(StandardCharsets.UTF_8));
        } finally {
            fixture.close();
        }
    }

    /** Feeds binary parts without returning credit until the handler suspends Tomcat's reads. */
    private static int pauseReads(TunnelFixture fixture, DeviceSide device, WsSession tomcat) throws Exception {
        int parts = 0;
        while (mockingDetails(tomcat).getInvocations().isEmpty()) {
            fixture.handler.handleMessage(fixture.session, new BinaryMessage(new byte[PART_BYTES], false));
            device.take(false);
            parts++;
            assertThat(parts).as("reads pause before the stream queue overflows").isLessThan(64);
        }
        return parts;
    }

    private static final int MAX_MESSAGE_BYTES = 16 * 1024 * 1024;
    private static final int PART_BYTES = WebSocketSpecusFrame.MAX_PAYLOAD_BYTES;

    private static byte[] pattern(int length) {
        byte[] bytes = new byte[length];
        for (int i = 0; i < length; i++) {
            bytes[i] = (byte) (i % 251);
        }
        return bytes;
    }

    /** Plays the device end of the data connection: reads what the server wrote and returns credit. */
    private static final class DeviceSide {
        private final TunnelFixture fixture;
        private final List<NatMessagePacket> packets = new ArrayList<>();
        private long uncredited;

        DeviceSide(TunnelFixture fixture) {
            this.fixture = fixture;
        }

        void take(boolean returnCredit) {
            fixture.control.runPendingTasks();
            NatMessagePacket packet;
            while ((packet = fixture.control.readOutbound()) != null) {
                packets.add(packet);
                if (packet.getNatMessageType() == NatMessageType.DATA) {
                    if (returnCredit) {
                        StreamFlowController.get(fixture.control)
                                .onWindowUpdate(fixture.streamId, packet.getData().length);
                    } else {
                        uncredited += packet.getData().length;
                    }
                }
            }
        }

        void returnCredit() {
            long credit = uncredited;
            uncredited = 0;
            StreamFlowController.get(fixture.control).onWindowUpdate(fixture.streamId, credit);
            take(true);
        }

        List<NatMessagePacket> packets() {
            return packets;
        }

        List<NatMessagePacket> resets() {
            return packets.stream().filter(packet -> packet.getNatMessageType() == NatMessageType.RST).toList();
        }

        List<WebSocketSpecusFrame> frames() {
            return packets.stream().filter(packet -> packet.getNatMessageType() == NatMessageType.DATA)
                    .map(packet -> WebSocketSpecusFrame.decode(packet.getData())).toList();
        }

        /** The data-frame payloads in order, without control frames. */
        byte[] payload() {
            java.io.ByteArrayOutputStream all = new java.io.ByteArrayOutputStream();
            for (WebSocketSpecusFrame frame : frames()) {
                if (frame.opcode() < WebSocketSpecusFrame.OPCODE_CLOSE) {
                    all.writeBytes(frame.payload());
                }
            }
            return all.toByteArray();
        }
    }

    private static byte[] frame(int opcode, boolean finalFragment, String payload) {
        return new WebSocketSpecusFrame(opcode, finalFragment, 0, 0,
                payload.getBytes(StandardCharsets.UTF_8)).encode();
    }

    private static Fixture fixture() {
        WebSocketStreamRegistry registry = new WebSocketStreamRegistry();
        WebSocketSpecusHandler handler = new WebSocketSpecusHandler(registry, 1_000);
        WebSocketSession session = mock(WebSocketSession.class);
        when(session.isOpen()).thenReturn(true);
        when(session.getId()).thenReturn("browser");
        registry.register(7, "channel", session, "client");
        return new Fixture(handler, session);
    }

    private static TunnelFixture tunnelFixture(long closeTimeoutMillis) throws Exception {
        return tunnelFixture(closeTimeoutMillis, Map.of(), plainSession());
    }

    private static WebSocketSession plainSession() {
        return mock(WebSocketSession.class);
    }

    private static TunnelFixture tunnelFixture(long closeTimeoutMillis, Map<String, Object> extraAttributes,
                                               WebSocketSession session) throws Exception {
        WebSocketStreamRegistry registry = new WebSocketStreamRegistry();
        WebSocketSpecusHandler handler = new WebSocketSpecusHandler(registry, closeTimeoutMillis);
        EmbeddedChannel control = new EmbeddedChannel();
        String clientName = "client-" + UUID.randomUUID();
        SessionUtil.bindDataSession(new Session(clientName), control);

        Map<String, Object> attributes = new HashMap<>(extraAttributes);
        attributes.put(WebSocketSpecusHandler.ATTR_CLIENT_NAME, clientName);
        attributes.put(WebSocketSpecusHandler.ATTR_ROUTE, "route");
        when(session.getAttributes()).thenReturn(attributes);
        when(session.isOpen()).thenReturn(true);
        when(session.getId()).thenReturn("browser");
        handler.afterConnectionEstablished(session);
        control.runPendingTasks();
        drain(control);
        return new TunnelFixture(handler, session, control,
                (Integer) attributes.get(WebSocketSpecusHandler.ATTR_STREAM_ID));
    }

    private static void drain(EmbeddedChannel channel) {
        while (channel.readOutbound() != null) {
            // Drain setup or credit-consuming frames.
        }
    }

    private record Fixture(WebSocketSpecusHandler handler, WebSocketSession session) {
    }

    private record TunnelFixture(WebSocketSpecusHandler handler, WebSocketSession session,
                                 EmbeddedChannel control, int streamId) {
        void close() {
            control.finishAndReleaseAll();
        }
    }
}
