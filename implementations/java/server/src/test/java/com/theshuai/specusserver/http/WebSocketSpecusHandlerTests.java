package com.theshuai.specusserver.http;

import com.theshuai.common.handler.StreamFlowController;
import com.theshuai.common.protocol.NatMessagePacket;
import com.theshuai.common.protocol.NatMessageType;
import com.theshuai.common.protocol.WebSocketSpecusFrame;
import com.theshuai.common.session.Session;
import com.theshuai.specusserver.session.SessionUtil;
import io.netty.channel.embedded.EmbeddedChannel;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.web.socket.CloseStatus;
import org.springframework.web.socket.TextMessage;
import org.springframework.web.socket.WebSocketMessage;
import org.springframework.web.socket.WebSocketSession;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

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
        WebSocketStreamRegistry registry = new WebSocketStreamRegistry();
        WebSocketSpecusHandler handler = new WebSocketSpecusHandler(registry, closeTimeoutMillis);
        EmbeddedChannel control = new EmbeddedChannel();
        String clientName = "client-" + UUID.randomUUID();
        SessionUtil.bindDataSession(new Session(clientName), control);

        WebSocketSession session = mock(WebSocketSession.class);
        Map<String, Object> attributes = new HashMap<>();
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
