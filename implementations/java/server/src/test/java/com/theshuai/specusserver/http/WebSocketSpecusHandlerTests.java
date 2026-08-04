package com.theshuai.specusserver.http;

import com.theshuai.common.protocol.WebSocketSpecusFrame;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.web.socket.CloseStatus;
import org.springframework.web.socket.TextMessage;
import org.springframework.web.socket.WebSocketMessage;
import org.springframework.web.socket.WebSocketSession;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

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

    private record Fixture(WebSocketSpecusHandler handler, WebSocketSession session) {
    }
}
