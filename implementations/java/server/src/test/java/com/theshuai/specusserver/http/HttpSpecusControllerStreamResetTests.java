package com.theshuai.specusserver.http;

import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.theshuai.common.protocol.NatMessagePacket;
import com.theshuai.common.protocol.NatMessageType;
import com.theshuai.common.session.Session;
import com.theshuai.specusserver.attribute.ServerAttributes;
import com.theshuai.specusserver.handler.NatServerHandler;
import com.theshuai.specusserver.management.repository.HttpRouteMappingRepository;
import com.theshuai.specusserver.management.service.ClientAccountService;
import com.theshuai.specusserver.management.service.HttpMediaCaptureService;
import com.theshuai.specusserver.management.service.TrafficInspectionService;
import com.theshuai.specusserver.management.service.TrafficUsageService;
import com.theshuai.specusserver.session.SessionUtil;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelOutboundHandlerAdapter;
import io.netty.channel.ChannelPromise;
import io.netty.channel.embedded.EmbeddedChannel;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class HttpSpecusControllerStreamResetTests {
    private static final String LEAKY_REASON =
            "dial http://10.20.30.40:8080/admin/internal?token=s3cret&user=root failed: connection refused"
                    + "\r\nX-Forged: yes";

    private final TrafficUsageService trafficUsageService = mock(TrafficUsageService.class);
    private final TrafficInspectionService trafficInspectionService = mock(TrafficInspectionService.class);
    private final HttpRouteAuthenticationService authenticationService = mock(HttpRouteAuthenticationService.class);
    private final HttpSpecusController controller = new HttpSpecusController(
            trafficUsageService,
            trafficInspectionService,
            mock(HttpMediaCaptureService.class),
            mock(ResponseRewriter.class),
            mock(ClientAccountService.class),
            mock(HttpRouteMappingRepository.class),
            authenticationService,
            5_000,
            1_024,
            0);

    @Test
    void clientResetBeforeResponseHeadersReturnsGenericBadGatewayAndLogsEscapedReason() throws Exception {
        String clientName = "reset-test-" + UUID.randomUUID();
        when(authenticationService.authorize(clientName, "api", null))
                .thenReturn(new HttpRouteAuthenticationService.Decision(
                        HttpRouteAuthenticationService.Outcome.PUBLIC));
        NatServerHandler natHandler = new NatServerHandler(
                null, null, null, null, mock(WebSocketStreamRegistry.class),
                mock(WebSocketSpecusHandler.class));
        EmbeddedChannel channel = new EmbeddedChannel(new ResetAfterRequestFin(LEAKY_REASON), natHandler);
        channel.attr(ServerAttributes.TENANT_ID).set("tenant-a");
        SessionUtil.bindDataSession(new Session(clientName), channel);
        Logger logger = (Logger) LoggerFactory.getLogger(HttpSpecusController.class);
        ListAppender<ILoggingEvent> logs = new ListAppender<>();
        logs.start();
        logger.addAppender(logs);
        MockHttpServletResponse response = new MockHttpServletResponse();
        try {
            MockHttpServletRequest request = new MockHttpServletRequest(
                    "GET", "/http/" + clientName + "/api/admin/internal");
            request.setQueryString("token=s3cret&user=root");
            request.setRemoteAddr("203.0.113.10");
            request.setRemotePort(45678);

            controller.forward(clientName, "api", request, response);
        } finally {
            logger.detachAppender(logs);
            channel.finishAndReleaseAll();
        }

        assertThat(response.getStatus()).isEqualTo(502);
        String body = response.getContentAsString(StandardCharsets.UTF_8);
        assertThat(body).isEqualTo(HttpSpecusController.STREAM_RESET_BODY)
                .isNotEqualTo("客户端不在线")
                .doesNotContain("10.20.30.40", "s3cret", "http://", "X-Forged");
        assertThat(response.getHeaderNames()).noneMatch(name -> name.equalsIgnoreCase("X-Forged"));

        List<String> messages = logs.list.stream().map(ILoggingEvent::getFormattedMessage).toList();
        assertThat(messages).anySatisfy(message -> assertThat(message)
                .contains("stream reset")
                .contains("http://10.20.30.40:8080/admin/internal?token=s3cret&user=root")
                .contains("\\r\\nX-Forged: yes")
                .doesNotContain("\r", "\n"));
        verify(trafficInspectionService).recordHttpExchange(
                eq(clientName), eq("api"), eq("GET"), eq("/admin/internal"), eq("token=s3cret&user=root"),
                any(), any(byte[].class), eq(0L), eq(502), any(), any(byte[].class), eq(0L),
                anyLong(), any(), eq(HttpSpecusController.logSafeReason(LEAKY_REASON)));
    }

    @Test
    void logSafeReasonEscapesControlCharactersAndTruncates() {
        assertThat(HttpSpecusController.logSafeReason("a\r\nb\tc\u0000d\u2028e\\f"))
                .isEqualTo("a\\r\\nb\\tc\\u0000d\\u2028e\\\\f");
        assertThat(HttpSpecusController.logSafeReason(null)).isEmpty();

        String truncated = HttpSpecusController.logSafeReason("x".repeat(300));
        assertThat(truncated).isEqualTo("x".repeat(256) + "...(truncated)");
    }

    /** Plays the client: answers the request FIN with an RST before any response OPEN. */
    private static final class ResetAfterRequestFin extends ChannelOutboundHandlerAdapter {
        private final String reason;

        private ResetAfterRequestFin(String reason) {
            this.reason = reason;
        }

        @Override
        public void write(ChannelHandlerContext ctx, Object msg, ChannelPromise promise) {
            boolean requestFin = msg instanceof NatMessagePacket packet
                    && packet.getNatMessageType() == NatMessageType.FIN;
            int streamId = msg instanceof NatMessagePacket packet ? packet.getStreamId() : 0;
            ctx.write(msg, promise);
            if (requestFin) {
                NatMessagePacket reset = new NatMessagePacket();
                reset.setNatMessageType(NatMessageType.RST);
                reset.setStreamId(streamId);
                reset.setValue(1);
                reset.setMetaData(Map.of("reason", reason));
                ctx.fireChannelRead(reset);
            }
        }
    }
}
