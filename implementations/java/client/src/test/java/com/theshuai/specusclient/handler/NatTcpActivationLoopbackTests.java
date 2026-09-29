package com.theshuai.specusclient.handler;

import com.theshuai.common.protocol.NatMessagePacket;
import com.theshuai.common.protocol.NatMessageType;
import com.theshuai.specusclient.bean.SpecusBean;
import com.theshuai.specusclient.bean.SpecusConfig;
import com.theshuai.specusclient.client.TcpConnection;
import io.netty.channel.ChannelFuture;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import io.netty.channel.ChannelInitializer;
import io.netty.channel.embedded.EmbeddedChannel;
import io.netty.channel.socket.SocketChannel;
import org.junit.jupiter.api.Test;

import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

/**
 * DATA and FIN that reach the client between a local connection's connect completing and its
 * channelActive firing must be delivered, not answered with a reset.
 *
 * <p>Netty completes the connect promise before it fires channelActive on the new channel's loop, so
 * the OPEN handler returns from its connect while that channel is still on its way to active. The C
 * server sends OPEN and the first DATA back to back, and the NAT smoke test caught the gap: the
 * stream was reset as "not active", and the upstream connection it had just opened was left behind
 * with no owner, holding the single-threaded echo upstream so every later stream got nothing back.
 */
class NatTcpActivationLoopbackTests {
    private static final int REMOTE_PORT = 19_003;

    @Test
    void dataAndFinArrivingBeforeTheLocalChannelIsActiveAreDelivered() throws Exception {
        byte[] request = "sent-with-the-open".getBytes(StandardCharsets.UTF_8);
        CountDownLatch holdActive = new CountDownLatch(1);
        CountDownLatch activeHeld = new CountDownLatch(1);

        try (ServerSocket upstream = new ServerSocket(0)) {
            upstream.setSoTimeout(5_000);
            CompletableFuture<byte[]> received = CompletableFuture.supplyAsync(() -> {
                try (Socket socket = upstream.accept()) {
                    socket.setSoTimeout(5_000);
                    return socket.getInputStream().readAllBytes();
                } catch (Exception error) {
                    throw new IllegalStateException(error);
                }
            });

            NatClientHandler handler = new NatClientHandler(
                    bean(upstream.getLocalPort()), new ActivationHoldingConnection(holdActive, activeHeld));
            EmbeddedChannel control = new EmbeddedChannel(handler);
            try {
                while (control.readOutbound() != null) {
                    // REGISTER
                }
                int streamId = 61;
                control.writeInbound(open(streamId));
                assertTrue(activeHeld.await(5, TimeUnit.SECONDS), "the local channel never connected");

                // The connect has completed and the stream is published, but channelActive is still held.
                control.writeInbound(frame(NatMessageType.DATA, streamId, request));
                control.writeInbound(frame(NatMessageType.FIN, streamId, null));
                control.runPendingTasks();
                assertNoReset(control, streamId);

                holdActive.countDown();
                assertArrayEquals(request, received.get(5, TimeUnit.SECONDS),
                        "DATA and FIN sent before channelActive must reach the upstream in order");
                control.runPendingTasks();
                assertNoReset(control, streamId);
            } finally {
                holdActive.countDown();
                control.finishAndReleaseAll();
            }
        }
    }

    private static void assertNoReset(EmbeddedChannel control, int streamId) {
        Object outbound;
        while ((outbound = control.readOutbound()) != null) {
            if (outbound instanceof NatMessagePacket packet
                    && packet.getStreamId() == streamId
                    && packet.getNatMessageType() == NatMessageType.RST) {
                fail("stream was reset: " + packet.getMetaData());
            }
        }
    }

    /** Opens the real connection, with a handler in front that holds channelActive until released. */
    private static final class ActivationHoldingConnection extends TcpConnection {
        private final CountDownLatch release;
        private final CountDownLatch held;

        ActivationHoldingConnection(CountDownLatch release, CountDownLatch held) {
            this.release = release;
            this.held = held;
        }

        @Override
        public ChannelFuture connect(String host, int port, ChannelInitializer<SocketChannel> initializer)
                throws InterruptedException {
            return super.connect(host, port, new ChannelInitializer<>() {
                @Override
                protected void initChannel(SocketChannel channel) {
                    channel.pipeline().addLast(new ChannelInboundHandlerAdapter() {
                        @Override
                        public void channelActive(ChannelHandlerContext ctx) throws Exception {
                            held.countDown();
                            release.await(5, TimeUnit.SECONDS);
                            super.channelActive(ctx);
                        }
                    });
                    channel.pipeline().addLast(initializer);
                }
            });
        }
    }

    private static SpecusBean bean(int upstreamPort) {
        SpecusConfig mapping = new SpecusConfig();
        mapping.setPort(REMOTE_PORT);
        mapping.setSpecusAddress("127.0.0.1");
        mapping.setSpecusPort(upstreamPort);

        SpecusBean bean = new SpecusBean();
        bean.setClientName("activation-test");
        bean.setRemoteAddress("127.0.0.1");
        bean.setSpecusConfigList(List.of(mapping));
        return bean;
    }

    private static NatMessagePacket open(int streamId) {
        NatMessagePacket packet = new NatMessagePacket();
        packet.setNatMessageType(NatMessageType.OPEN);
        packet.setStreamId(streamId);
        packet.setMetaData(Map.of("port", REMOTE_PORT, "channelId", "activation"));
        return packet;
    }

    private static NatMessagePacket frame(NatMessageType type, int streamId, byte[] payload) {
        NatMessagePacket packet = new NatMessagePacket();
        packet.setNatMessageType(type);
        packet.setStreamId(streamId);
        packet.setData(payload);
        return packet;
    }
}
