package com.theshuai.specusclient.handler;

import com.theshuai.common.handler.StreamFlowController;
import com.theshuai.common.protocol.NatMessagePacket;
import com.theshuai.common.protocol.NatMessageType;
import com.theshuai.specusclient.bean.SpecusBean;
import com.theshuai.specusclient.bean.SpecusConfig;
import com.theshuai.specusclient.client.TcpConnection;
import io.netty.bootstrap.Bootstrap;
import io.netty.bootstrap.ServerBootstrap;
import io.netty.channel.Channel;
import io.netty.channel.ChannelInitializer;
import io.netty.channel.ChannelInboundHandlerAdapter;
import io.netty.channel.DefaultEventLoopGroup;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelOutboundHandlerAdapter;
import io.netty.channel.ChannelPromise;
import io.netty.channel.local.LocalAddress;
import io.netty.channel.local.LocalChannel;
import io.netty.channel.local.LocalServerChannel;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Queue;
import java.util.UUID;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import java.util.function.BooleanSupplier;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * A stream whose upstream stops reading must hold back only itself.
 *
 * <p>The data connection carries every stream, so pausing it because one local socket stopped
 * draining also stalls the others, including the stream the stalled upstream may be waiting on. A
 * single-threaded upstream with a second connection queued behind the first deadlocks that way.
 */
class NatTcpBackpressureLoopbackTests {
    private static final int STALLED_PORT = 19_001;
    private static final int ECHO_PORT = 19_002;
    private static final int FRAME = 64 * 1024;
    private static final long WINDOW = StreamFlowController.INITIAL_WINDOW_BYTES;

    @Test
    void localWorkerMustNotBeTheDataEventLoop() throws Exception {
        SentFrames sent = new SentFrames();
        try (ControlFixture fixture = new ControlFixture(sent, new NatClientHandler(bean(0, 0)))) {
            Channel control = fixture.control;
            CompletableFuture<Boolean> mistakenOwner = new CompletableFuture<>();
            Thread worker = new Thread(() -> mistakenOwner.complete(control.eventLoop().inEventLoop()),
                    "upstream-thread-ownership-probe");
            try {
                worker.start();
                assertFalse(mistakenOwner.get(5, TimeUnit.SECONDS),
                        "a local socket worker must queue data flow operations onto the data event loop");
            } finally {
                worker.join(5_000);
                assertFalse(worker.isAlive(), "ownership probe must terminate");
            }
        }
    }

    @Test
    void aStreamWhoseUpstreamStopsReadingLeavesTheDataConnectionReading() throws Exception {
        try (StalledUpstream stalled = new StalledUpstream(); EchoUpstream echo = new EchoUpstream()) {
            NatClientHandler handler = new NatClientHandler(
                    bean(stalled.port(), echo.port()), new TcpConnection());
            SentFrames sent = new SentFrames();
            try (ControlFixture fixture = new ControlFixture(sent, handler)) {
                Channel control = fixture.control;
                int stuck = 51;
                int flowing = 52;
                inbound(control, open(stuck, STALLED_PORT));
                inbound(control, open(flowing, ECHO_PORT));
                await(() -> handler.hasLocalTcpStream(stuck) && handler.hasLocalTcpStream(flowing));

                long queued = fillUntilTheUpstreamStops(control, sent, stuck);
                assertTrue(queued > 2L * FRAME,
                        "the stalled upstream must leave bytes queued in front of its socket, queued=" + queued);
                assertTrue(control.isActive(), "the shared data connection must remain active");
                assertTrue(handler.hasLocalTcpStream(flowing), "the independent echo stream must remain active");

                assertTrue(control.config().isAutoRead(),
                        "one stalled upstream must not stop the data connection from reading");

                byte[] ping = "still-flowing".getBytes(StandardCharsets.UTF_8);
                inbound(control, data(flowing, ping));
                assertArrayEquals(ping, awaitData(control, sent, flowing, ping.length),
                        "another stream must keep moving while the first one is stalled");
                assertTrue(control.config().isAutoRead());
                assertNull(sent.threadViolation, "outbound callbacks must share the data event loop");
            }
        }
    }

    @Test
    void dataPastTheReceiveWindowResetsTheStreamInsteadOfQueueingIt() throws Exception {
        try (StalledUpstream stalled = new StalledUpstream(); EchoUpstream echo = new EchoUpstream()) {
            NatClientHandler handler = new NatClientHandler(
                    bean(stalled.port(), echo.port()), new TcpConnection());
            SentFrames sent = new SentFrames();
            try (ControlFixture fixture = new ControlFixture(sent, handler)) {
                Channel control = fixture.control;
                int streamId = 53;
                inbound(control, open(streamId, STALLED_PORT));
                await(() -> handler.hasLocalTcpStream(streamId));

                // Far more than any socket buffer takes from a peer that is not reading, sent without
                // waiting for credit, which a server honouring the window never does.
                byte[] chunk = new byte[FRAME];
                for (long offered = 0; offered < 32 * WINDOW; offered += FRAME) {
                    inbound(control, data(streamId, chunk));
                }

                NatMessagePacket reset = awaitReset(control, sent, streamId);
                assertNotNull(reset, "the stream must be reset once the server overruns the window");
                assertEquals(8, reset.getValue());
                assertEquals("pending local TCP data exceeds receive window", reset.getMetaData().get("reason"));
                await(() -> !handler.hasLocalTcpStream(streamId));
                assertNull(sent.threadViolation, "outbound callbacks must share the data event loop");
            }
        }
    }

    /**
     * Plays a server that honours the window: keeps the stream's window full as credit comes back,
     * until the upstream stops taking bytes and credit stops coming. How much the kernel buffers for
     * a peer that is not reading differs by platform, so a fixed amount would not reliably get there.
     * Returns what is left queued in front of the local socket.
     */
    private static long fillUntilTheUpstreamStops(Channel control, SentFrames sent, int streamId)
            throws Exception {
        byte[] chunk = new byte[FRAME];
        long offered = 0;
        long credited = 0;
        long lastCredit = System.nanoTime();
        long deadline = lastCredit + Duration.ofSeconds(20).toNanos();
        while (System.nanoTime() - lastCredit < Duration.ofMillis(500).toNanos()
                && System.nanoTime() < deadline) {
            while (offered - credited + FRAME <= WINDOW) {
                inbound(control, data(streamId, chunk));
                offered += FRAME;
            }
            NatMessagePacket packet;
            while ((packet = sent.frames.poll()) != null) {
                if (packet.getStreamId() == streamId && packet.getNatMessageType() == NatMessageType.WINDOW_UPDATE) {
                    credited += packet.getValue();
                    lastCredit = System.nanoTime();
                }
            }
            Thread.sleep(10);
        }
        return offered - credited;
    }

    private static byte[] awaitData(Channel control, SentFrames sent, int streamId, int length)
            throws Exception {
        ByteArrayOutputStream received = new ByteArrayOutputStream();
        long deadline = System.nanoTime() + Duration.ofSeconds(5).toNanos();
        while (System.nanoTime() < deadline && received.size() < length) {
            NatMessagePacket packet;
            while ((packet = sent.frames.poll()) != null) {
                if (packet.getStreamId() == streamId && packet.getNatMessageType() == NatMessageType.DATA) {
                    received.write(packet.getData());
                } else if (packet.getStreamId() == streamId && packet.getNatMessageType() == NatMessageType.RST) {
                    throw new AssertionError("the independent stream was reset: " + packet.getMetaData());
                }
            }
            Thread.sleep(10);
        }
        return received.toByteArray();
    }

    private static NatMessagePacket awaitReset(Channel control, SentFrames sent, int streamId)
            throws Exception {
        long deadline = System.nanoTime() + Duration.ofSeconds(5).toNanos();
        while (System.nanoTime() < deadline) {
            NatMessagePacket packet;
            while ((packet = sent.frames.poll()) != null) {
                if (packet.getStreamId() == streamId && packet.getNatMessageType() == NatMessageType.RST) {
                    return packet;
                }
            }
            Thread.sleep(10);
        }
        return null;
    }

    private static void await(BooleanSupplier condition) throws Exception {
        long deadline = System.nanoTime() + Duration.ofSeconds(5).toNanos();
        while (System.nanoTime() < deadline) {
            if (condition.getAsBoolean()) {
                return;
            }
            Thread.sleep(10);
        }
        assertTrue(condition.getAsBoolean(), "condition was not met before timeout");
    }

    /**
     * Collects what the client sends on the data connection. Credit and resets are written from the
     * local channels' threads and marshalled onto this channel's actual single-thread loop.
     * The test thread observes only this concurrent queue, never the channel's private buffers.
     */
    private static final class SentFrames extends ChannelOutboundHandlerAdapter {
        private final Queue<NatMessagePacket> frames = new ConcurrentLinkedQueue<>();
        private volatile Thread owner;
        private volatile Throwable threadViolation;

        @Override
        public void handlerAdded(ChannelHandlerContext ctx) {
            owner = Thread.currentThread();
        }

        @Override
        public void write(ChannelHandlerContext ctx, Object msg, ChannelPromise promise) {
            if (Thread.currentThread() != owner) {
                threadViolation = new AssertionError("control write escaped its single-thread data event loop");
                promise.tryFailure(threadViolation);
                return;
            }
            if (msg instanceof NatMessagePacket packet) {
                frames.add(packet);
            }
            promise.trySuccess();
        }
    }

    private static void inbound(Channel channel, NatMessagePacket packet) throws Exception {
        channel.eventLoop().submit(() -> {
            channel.pipeline().fireChannelRead(packet);
            channel.pipeline().fireChannelReadComplete();
        }).sync();
    }

    /**
     * A registered, active Netty channel with a real owning thread. EmbeddedEventLoop reports
     * inEventLoop=true from every thread, so combining it with real upstream NIO threads lets
     * StreamFlowController's loop-confined Map and queues run concurrently. Local transport
     * preserves the real event-loop contract without adding a wire codec to this focused test.
     */
    private static final class ControlFixture implements AutoCloseable {
        private final DefaultEventLoopGroup group = new DefaultEventLoopGroup(1);
        private Channel listener;
        private Channel peer;
        private Channel control;

        ControlFixture(SentFrames sent, NatClientHandler handler) throws Exception {
            CompletableFuture<Channel> accepted = new CompletableFuture<>();
            try {
                LocalAddress address = new LocalAddress("nat-backpressure-" + UUID.randomUUID());
                listener = new ServerBootstrap().group(group).channel(LocalServerChannel.class)
                        .childHandler(new ChannelInitializer<LocalChannel>() {
                            @Override
                            protected void initChannel(LocalChannel channel) {
                                channel.pipeline().addLast(sent, new ChannelInboundHandlerAdapter() {
                                    @Override
                                    public void channelActive(ChannelHandlerContext ctx) throws Exception {
                                        ctx.fireChannelActive();
                                        accepted.complete(ctx.channel());
                                    }
                                }, handler);
                            }
                        }).bind(address).sync().channel();
                peer = new Bootstrap().group(group).channel(LocalChannel.class)
                        .handler(new ChannelInboundHandlerAdapter()).connect(address).sync().channel();
                control = accepted.get(5, TimeUnit.SECONDS);
            } catch (Exception failure) {
                close();
                throw failure;
            }
        }

        @Override
        public void close() {
            if (control != null) control.close().syncUninterruptibly();
            if (peer != null) peer.close().syncUninterruptibly();
            if (listener != null) listener.close().syncUninterruptibly();
            assertTrue(group.shutdownGracefully(0, 5, TimeUnit.SECONDS).awaitUninterruptibly(6, TimeUnit.SECONDS),
                    "data event-loop group must terminate");
        }
    }

    private static SpecusBean bean(int stalledPort, int echoPort) {
        SpecusBean bean = new SpecusBean();
        bean.setClientName("backpressure-test");
        bean.setRemoteAddress("127.0.0.1");
        bean.setSpecusConfigList(List.of(mapping(STALLED_PORT, stalledPort), mapping(ECHO_PORT, echoPort)));
        return bean;
    }

    private static SpecusConfig mapping(int remotePort, int upstreamPort) {
        SpecusConfig mapping = new SpecusConfig();
        mapping.setPort(remotePort);
        mapping.setSpecusAddress("127.0.0.1");
        mapping.setSpecusPort(upstreamPort);
        return mapping;
    }

    private static NatMessagePacket open(int streamId, int port) {
        NatMessagePacket packet = new NatMessagePacket();
        packet.setNatMessageType(NatMessageType.OPEN);
        packet.setStreamId(streamId);
        packet.setMetaData(Map.of("port", port, "channelId", "loopback-" + streamId));
        return packet;
    }

    private static NatMessagePacket data(int streamId, byte[] payload) {
        NatMessagePacket packet = new NatMessagePacket();
        packet.setNatMessageType(NatMessageType.DATA);
        packet.setStreamId(streamId);
        packet.setData(payload);
        return packet;
    }

    /** Accepts connections and never reads from them, with as small a receive buffer as allowed. */
    private static final class StalledUpstream implements AutoCloseable {
        private final ServerSocket server;
        private final List<Socket> accepted = new CopyOnWriteArrayList<>();
        private final Thread acceptor;

        StalledUpstream() throws IOException {
            server = new ServerSocket();
            server.setReceiveBufferSize(4096);
            server.bind(new java.net.InetSocketAddress("127.0.0.1", 0));
            acceptor = new Thread(() -> {
                try {
                    while (!server.isClosed()) {
                        accepted.add(server.accept());
                    }
                } catch (IOException closed) {
                    // The test is over.
                }
            }, "stalled-upstream");
            acceptor.setDaemon(true);
            acceptor.start();
        }

        int port() {
            return server.getLocalPort();
        }

        @Override
        public void close() throws Exception {
            server.close();
            acceptor.join(5_000);
            assertFalse(acceptor.isAlive(), "stalled acceptor must terminate before closing its sockets");
            for (Socket socket : accepted) {
                socket.close();
            }
        }
    }

    private static final class EchoUpstream implements AutoCloseable {
        private final ServerSocket server;
        private final Thread acceptor;
        private final List<Socket> accepted = new CopyOnWriteArrayList<>();
        private final List<Thread> workers = new CopyOnWriteArrayList<>();

        EchoUpstream() throws IOException {
            server = new ServerSocket(0, 50, java.net.InetAddress.getLoopbackAddress());
            acceptor = new Thread(() -> {
                try {
                    while (!server.isClosed()) {
                        Socket socket = server.accept();
                        accepted.add(socket);
                        Thread echo = new Thread(() -> echo(socket), "echo-upstream-connection");
                        workers.add(echo);
                        echo.setDaemon(true);
                        echo.start();
                    }
                } catch (IOException closed) {
                    // The test is over.
                }
            }, "echo-upstream");
            acceptor.setDaemon(true);
            acceptor.start();
        }

        private static void echo(Socket socket) {
            try (socket; InputStream in = socket.getInputStream(); OutputStream out = socket.getOutputStream()) {
                byte[] buffer = new byte[8192];
                int read;
                while ((read = in.read(buffer)) > 0) {
                    out.write(buffer, 0, read);
                    out.flush();
                }
            } catch (IOException closed) {
                // The peer went away.
            }
        }

        int port() {
            return server.getLocalPort();
        }

        @Override
        public void close() throws Exception {
            server.close();
            acceptor.join(5_000);
            assertFalse(acceptor.isAlive(), "echo acceptor must terminate");
            for (Socket socket : accepted) socket.close();
            for (Thread worker : workers) {
                worker.join(5_000);
                assertFalse(worker.isAlive(), "echo worker must terminate");
            }
        }
    }
}
