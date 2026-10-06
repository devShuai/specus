package com.theshuai.specusserver.http;

import com.theshuai.common.protocol.NatMessagePacket;
import com.theshuai.common.protocol.NatMessageType;
import com.theshuai.common.session.Session;
import com.theshuai.specusserver.attribute.ServerAttributes;
import com.theshuai.specusserver.handler.NatServerHandler;
import com.theshuai.specusserver.session.SessionUtil;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelOutboundHandlerAdapter;
import io.netty.channel.ChannelPromise;
import io.netty.channel.embedded.EmbeddedChannel;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * Plays a connected tunnel client on an {@link EmbeddedChannel} bound as the data connection of a
 * client name: it records every NAT frame the server writes (the OPEN metadata is what the device
 * would forward) and answers each HTTP request FIN with a configurable response.
 */
final class FakeShareDevice implements AutoCloseable {
    /** The response a device sends for one HTTP stream: head, then body; {@code finish} sends FIN. */
    record Response(int status, List<String> headers, String body, boolean finish) {
        static Response ok() {
            return new Response(200, List.of("Content-Type:text/plain"), "", true);
        }
    }

    private final EmbeddedChannel channel;
    private final List<NatMessagePacket> written = new CopyOnWriteArrayList<>();
    private volatile Response response = Response.ok();

    FakeShareDevice(String clientName, WebSocketSpecusHandler webSocketHandler, WebSocketStreamRegistry registry) {
        NatServerHandler natHandler = new NatServerHandler(null, null, null, null, registry, webSocketHandler);
        channel = new EmbeddedChannel(new Device(), natHandler);
        channel.attr(ServerAttributes.TENANT_ID).set("t1");
        SessionUtil.bindDataSession(new Session(clientName), channel);
    }

    FakeShareDevice respondWith(Response next) {
        this.response = next;
        return this;
    }

    /** The metadata of every OPEN the server sent (HTTP and WebSocket streams). */
    List<Map<String, Object>> opens() {
        List<Map<String, Object>> opens = new ArrayList<>();
        for (NatMessagePacket packet : written) {
            if (packet.getNatMessageType() == NatMessageType.OPEN) {
                opens.add(packet.getMetaData());
            }
        }
        return opens;
    }

    boolean sawReset(int streamId) {
        return written.stream().anyMatch(packet -> packet.getNatMessageType() == NatMessageType.RST
                && packet.getStreamId() == streamId);
    }

    List<NatMessagePacket> written() {
        return written;
    }

    void clear() {
        written.clear();
    }

    @Override
    public void close() {
        SessionUtil.unBindSession(channel);
        channel.finishAndReleaseAll();
    }

    private final class Device extends ChannelOutboundHandlerAdapter {
        @Override
        public void write(ChannelHandlerContext ctx, Object msg, ChannelPromise promise) {
            if (msg instanceof NatMessagePacket packet) {
                written.add(packet);
            }
            ctx.write(msg, promise);
            if (msg instanceof NatMessagePacket packet && packet.getNatMessageType() == NatMessageType.FIN
                    && isHttpStream(packet.getStreamId())) {
                Response answer = response;
                NatMessagePacket head = new NatMessagePacket();
                head.setNatMessageType(NatMessageType.OPEN);
                head.setStreamId(packet.getStreamId());
                head.setMetaData(Map.of("source", "http", "phase", "response",
                        "statusCode", answer.status(), "headers", answer.headers()));
                ctx.fireChannelRead(head);
                if (!answer.body().isEmpty()) {
                    NatMessagePacket data = new NatMessagePacket();
                    data.setNatMessageType(NatMessageType.DATA);
                    data.setStreamId(packet.getStreamId());
                    data.setData(answer.body().getBytes(StandardCharsets.UTF_8));
                    ctx.fireChannelRead(data);
                }
                if (answer.finish()) {
                    NatMessagePacket fin = new NatMessagePacket();
                    fin.setNatMessageType(NatMessageType.FIN);
                    fin.setStreamId(packet.getStreamId());
                    ctx.fireChannelRead(fin);
                }
            }
        }

        private boolean isHttpStream(int streamId) {
            for (NatMessagePacket packet : written) {
                if (packet.getNatMessageType() == NatMessageType.OPEN && packet.getStreamId() == streamId
                        && packet.getMetaData() != null && "http".equals(packet.getMetaData().get("source"))) {
                    return true;
                }
            }
            return false;
        }
    }
}
