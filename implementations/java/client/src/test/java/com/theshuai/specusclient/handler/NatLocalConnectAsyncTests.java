package com.theshuai.specusclient.handler;

import com.theshuai.common.handler.StreamFlowController;
import com.theshuai.common.protocol.NatMessagePacket;
import com.theshuai.common.protocol.NatMessageType;
import com.theshuai.specusclient.bean.SpecusBean;
import com.theshuai.specusclient.bean.SpecusConfig;
import com.theshuai.specusclient.client.TcpConnection;
import io.netty.bootstrap.Bootstrap;
import io.netty.channel.ChannelFuture;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInitializer;
import io.netty.channel.ChannelOption;
import io.netty.channel.ChannelOutboundHandlerAdapter;
import io.netty.channel.ChannelPromise;
import io.netty.channel.EventLoopGroup;
import io.netty.channel.MultiThreadIoEventLoopGroup;
import io.netty.channel.embedded.EmbeddedChannel;
import io.netty.channel.nio.NioIoHandler;
import io.netty.channel.socket.SocketChannel;
import io.netty.channel.socket.nio.NioSocketChannel;
import io.netty.resolver.AddressResolver;
import io.netty.resolver.AddressResolverGroup;
import io.netty.resolver.InetNameResolver;
import io.netty.util.concurrent.EventExecutor;
import io.netty.util.concurrent.Promise;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Queue;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.TimeUnit;
import java.util.function.BooleanSupplier;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

/**
 * A stream's local connect runs alongside the data connection, never on it.
 *
 * <p>The data connection's loop carries every stream on the device. It used to wait on each local
 * connect for up to its 5 second timeout, so one slow target stalled every other stream on the
 * device. The connect now runs on its own, as in the Go and .NET clients: the stream is published
 * while it is under way, DATA and FIN that arrive meanwhile are held within the stream's receive
 * window and replayed in order once it succeeds, a failure resets that stream alone, and an RST
 * from the server abandons the connect.
 *
 * <p>The connects are real ones on loopback. What makes one "slow" is its name lookup, which a
 * resolver here holds until the test releases it, so the connect is under way for as long as a
 * test needs and no loop is blocked while it waits.
 */
class NatLocalConnectAsyncTests {
    private static final int LIVE_PORT = 19_021;
    private static final int HELD_PORT = 19_022;
    private static final int LIVE_STREAM = 81;
    private static final int HELD_STREAM = 82;
    private static final String HELD_HOST = "held-connect.test";

    @Test
    void aConnectStillUnderWayDoesNotHoldUpTheOtherStreams() throws Exception {
        try (EchoUpstream echo = new EchoUpstream(); EchoUpstream heldTarget = new EchoUpstream()) {
            HeldConnection connection = new HeldConnection();
            // Released by a timer, so a client that waits on the connect is late rather than stuck.
            CompletableFuture.delayedExecutor(3, TimeUnit.SECONDS)
                    .execute(() -> connection.release(InetAddress.getLoopbackAddress()));
            NatClientHandler handler = new NatClientHandler(bean(echo.port(), heldTarget.port()), connection);
            Frames frames = new Frames();
            EmbeddedChannel control = new EmbeddedChannel(frames, handler);
            try {
                control.writeInbound(tcpOpen(LIVE_STREAM, LIVE_PORT));
                await(() -> handler.hasLocalTcpStream(LIVE_STREAM), control);
                assertEchoes(control, frames, "before the slow stream", Duration.ofSeconds(5));

                long opening = System.nanoTime();
                control.writeInbound(tcpOpen(HELD_STREAM, HELD_PORT));
                control.writeInbound(data(HELD_STREAM, bytes("held for later")));
                Duration openTook = Duration.ofNanos(System.nanoTime() - opening);
                assertTrue(openTook.compareTo(Duration.ofSeconds(1)) < 0,
                        "OPEN for a slow target must not wait on its connect, took " + openTook);
                assertFalse(connection.released(), "the slow connect must still be under way");

                assertEchoes(control, frames, "while the slow stream connects", Duration.ofSeconds(1));
                assertFalse(connection.released(), "the live stream must not have waited for the slow one");
                assertTrue(control.isActive());
                assertNoReset(frames, LIVE_STREAM);
                assertNoReset(frames, HELD_STREAM);
            } finally {
                connection.release(InetAddress.getLoopbackAddress());
                control.finishAndReleaseAll();
            }
        }
    }

    @Test
    void dataAndFinThatArriveWhileConnectingReachTheUpstreamInOrder() throws Exception {
        try (ServerSocket upstream = new ServerSocket(0, 1, InetAddress.getLoopbackAddress())) {
            upstream.setSoTimeout(10_000);
            CompletableFuture<byte[]> received = CompletableFuture.supplyAsync(() -> readUntilEof(upstream));
            HeldConnection connection = new HeldConnection();
            NatClientHandler handler = new NatClientHandler(bean(closedLoopbackPort(), upstream.getLocalPort()),
                    connection);
            Frames frames = new Frames();
            EmbeddedChannel control = new EmbeddedChannel(frames, handler);
            try {
                control.writeInbound(tcpOpen(HELD_STREAM, HELD_PORT));
                assertTrue(handler.hasLocalTcpStream(HELD_STREAM), "the stream is published while connecting");
                LocalSpecusHandler stream = handler.localTcpStream(HELD_STREAM);

                control.writeInbound(data(HELD_STREAM, bytes("first,")));
                control.writeInbound(data(HELD_STREAM, bytes("second,")));
                control.writeInbound(data(HELD_STREAM, bytes("third")));
                control.writeInbound(fin(HELD_STREAM));
                int held = "first,second,third".length();
                await(() -> stream.heldBytes() == held, control);
                frames.drain();
                assertEquals(0, frames.credit(HELD_STREAM), "held DATA is not credited before it is written");
                assertNoReset(frames, HELD_STREAM);

                connection.release(InetAddress.getLoopbackAddress());

                assertEquals("first,second,third",
                        new String(received.get(10, TimeUnit.SECONDS), StandardCharsets.UTF_8),
                        "held DATA must reach the upstream in order, followed by the FIN");
                await(() -> frames.credit(HELD_STREAM) == held, control);
                assertEquals(0, stream.heldBytes());
                assertNoReset(frames, HELD_STREAM);
                assertTrue(control.isActive());
            } finally {
                connection.release(InetAddress.getLoopbackAddress());
                control.finishAndReleaseAll();
            }
        }
    }

    @Test
    void aConnectThatFailsAfterDataWasHeldResetsTheStreamAndDropsTheData() throws Exception {
        try (EchoUpstream echo = new EchoUpstream()) {
            HeldConnection connection = new HeldConnection();
            NatClientHandler handler = new NatClientHandler(bean(echo.port(), closedLoopbackPort()), connection);
            Frames frames = new Frames();
            EmbeddedChannel control = new EmbeddedChannel(frames, handler);
            try {
                control.writeInbound(tcpOpen(LIVE_STREAM, LIVE_PORT));
                await(() -> handler.hasLocalTcpStream(LIVE_STREAM), control);
                control.writeInbound(tcpOpen(HELD_STREAM, HELD_PORT));
                LocalSpecusHandler stream = handler.localTcpStream(HELD_STREAM);
                control.writeInbound(data(HELD_STREAM, bytes("never delivered")));
                control.writeInbound(fin(HELD_STREAM));
                await(() -> stream.heldBytes() == "never delivered".length(), control);

                // The name resolves, and the port behind it refuses.
                connection.release(InetAddress.getLoopbackAddress());

                NatMessagePacket reset = frames.await(control, HELD_STREAM, NatMessageType.RST);
                assertNotNull(reset, "a failed local connect must reset its stream");
                assertEquals(1, reset.getValue());
                assertEquals("local connect failed", reset.getMetaData().get("reason"));
                assertEquals(1, frames.count(HELD_STREAM, NatMessageType.RST), "the stream is reset once");
                assertEquals(0, stream.heldBytes(), "the held DATA is dropped");
                assertEquals(0, frames.credit(HELD_STREAM), "dropped DATA is never credited");
                assertFalse(handler.hasLocalTcpStream(HELD_STREAM));

                control.writeInbound(rst(HELD_STREAM));
                assertTrue(control.isActive(), "a late RST for the failed stream lands on its tombstone");
                assertEchoes(control, frames, "after the failed stream", Duration.ofSeconds(5));
            } finally {
                control.finishAndReleaseAll();
            }
        }
    }

    @Test
    void anRstFromTheServerWhileConnectingAbandonsTheConnect() throws Exception {
        try (ServerSocket upstream = new ServerSocket(0, 50, InetAddress.getLoopbackAddress())) {
            HeldConnection connection = new HeldConnection();
            NatClientHandler handler = new NatClientHandler(bean(closedLoopbackPort(), upstream.getLocalPort()),
                    connection);
            Frames frames = new Frames();
            EmbeddedChannel control = new EmbeddedChannel(frames, handler);
            try {
                control.writeInbound(tcpOpen(HELD_STREAM, HELD_PORT));
                LocalSpecusHandler stream = handler.localTcpStream(HELD_STREAM);
                control.writeInbound(data(HELD_STREAM, bytes("cancelled")));
                await(() -> stream.heldBytes() == "cancelled".length(), control);

                control.writeInbound(rst(HELD_STREAM));
                assertFalse(handler.hasLocalTcpStream(HELD_STREAM), "the RST ends the stream at once");
                await(() -> stream.heldBytes() == 0, control);

                connection.release(InetAddress.getLoopbackAddress());
                upstream.setSoTimeout(1_000);
                assertThrows(SocketTimeoutException.class, upstream::accept,
                        "a connect abandoned by RST must never reach the upstream");
                control.runPendingTasks();
                frames.drain();
                assertEquals(0, frames.count(HELD_STREAM, NatMessageType.RST),
                        "the server's own RST is not answered with another");
                assertEquals(0, frames.credit(HELD_STREAM));
                assertTrue(control.isActive());

                control.writeInbound(rst(HELD_STREAM));
                assertTrue(control.isActive(), "a repeated RST lands on the stream's tombstone");
            } finally {
                control.finishAndReleaseAll();
            }
        }
    }

    @Test
    void dataHeldBeyondTheReceiveWindowResetsTheStream() throws Exception {
        try (ServerSocket upstream = new ServerSocket(0, 50, InetAddress.getLoopbackAddress())) {
            HeldConnection connection = new HeldConnection();
            NatClientHandler handler = new NatClientHandler(bean(closedLoopbackPort(), upstream.getLocalPort()),
                    connection);
            Frames frames = new Frames();
            EmbeddedChannel control = new EmbeddedChannel(frames, handler);
            try {
                control.writeInbound(tcpOpen(HELD_STREAM, HELD_PORT));
                LocalSpecusHandler stream = handler.localTcpStream(HELD_STREAM);
                int frame = StreamFlowController.MAX_DATA_FRAME_BYTES;
                int window = (int) StreamFlowController.INITIAL_WINDOW_BYTES;
                for (int sent = 0; sent < window; sent += frame) {
                    control.writeInbound(data(HELD_STREAM, new byte[frame]));
                }
                await(() -> stream.heldBytes() == window, control);
                frames.drain();
                assertNoReset(frames, HELD_STREAM);

                // One byte past the window the server was granted.
                control.writeInbound(data(HELD_STREAM, new byte[1]));
                NatMessagePacket reset = frames.await(control, HELD_STREAM, NatMessageType.RST);
                assertNotNull(reset, "DATA past the receive window must not be held");
                assertEquals(8, reset.getValue());
                assertEquals("pending local TCP data exceeds receive window", reset.getMetaData().get("reason"));
                await(() -> stream.heldBytes() == 0 && !handler.hasLocalTcpStream(HELD_STREAM), control);

                connection.release(InetAddress.getLoopbackAddress());
                upstream.setSoTimeout(1_000);
                assertThrows(SocketTimeoutException.class, upstream::accept,
                        "the reset stream's connect is abandoned");
                control.runPendingTasks();
                frames.drain();
                assertEquals(1, frames.count(HELD_STREAM, NatMessageType.RST));
                assertTrue(control.isActive(), "one stream's overrun window does not close the data connection");
            } finally {
                control.finishAndReleaseAll();
            }
        }
    }

    // --- helpers ---

    private static void assertEchoes(EmbeddedChannel control, Frames frames, String when, Duration within)
            throws Exception {
        byte[] payload = bytes("echo " + when);
        frames.drain();
        frames.liveData.reset();
        control.writeInbound(data(LIVE_STREAM, payload));
        long deadline = System.nanoTime() + within.toNanos();
        while (System.nanoTime() < deadline && frames.liveData.size() < payload.length) {
            control.runPendingTasks();
            frames.drain();
            Thread.sleep(5);
        }
        assertArrayEquals(payload, frames.liveData.toByteArray(),
                "the live stream must carry data both ways " + when + " within " + within);
    }

    private static void assertNoReset(Frames frames, int streamId) {
        frames.drain();
        for (NatMessagePacket packet : frames.seen) {
            if (packet.getStreamId() == streamId && packet.getNatMessageType() == NatMessageType.RST) {
                fail("stream " + streamId + " was reset: " + packet.getMetaData());
            }
        }
    }

    private static void await(BooleanSupplier condition, EmbeddedChannel control) throws Exception {
        long deadline = System.nanoTime() + Duration.ofSeconds(10).toNanos();
        while (System.nanoTime() < deadline) {
            control.runPendingTasks();
            if (condition.getAsBoolean()) {
                return;
            }
            Thread.sleep(5);
        }
        assertTrue(condition.getAsBoolean(), "condition was not met before timeout");
    }

    private static byte[] readUntilEof(ServerSocket upstream) {
        try (Socket socket = upstream.accept()) {
            socket.setSoTimeout(10_000);
            return socket.getInputStream().readAllBytes();
        } catch (IOException error) {
            throw new IllegalStateException(error);
        }
    }

    /** A loopback port that was free a moment ago, so a connect to it is refused. */
    private static int closedLoopbackPort() throws IOException {
        try (ServerSocket probe = new ServerSocket(0, 1, InetAddress.getLoopbackAddress())) {
            return probe.getLocalPort();
        }
    }

    /**
     * Opens real loopback connections. One to {@link #HELD_HOST} waits on its name lookup until
     * {@link #release} answers it, which keeps that connect under way without blocking a loop.
     */
    private static final class HeldConnection extends TcpConnection {
        private final EventLoopGroup group = new MultiThreadIoEventLoopGroup(NioIoHandler.newFactory());
        private final CompletableFuture<InetAddress> lookup = new CompletableFuture<>();

        @Override
        public ChannelFuture connect(String host, int port, ChannelInitializer<SocketChannel> initializer) {
            if (!HELD_HOST.equals(host)) {
                return super.connect(host, port, initializer);
            }
            return new Bootstrap()
                    .group(group)
                    .channel(NioSocketChannel.class)
                    .option(ChannelOption.ALLOW_HALF_CLOSURE, true)
                    .option(ChannelOption.CONNECT_TIMEOUT_MILLIS, 5_000)
                    .resolver(new HeldLookup(lookup))
                    .handler(initializer)
                    .connect(host, port);
        }

        void release(InetAddress address) {
            lookup.complete(address);
        }

        boolean released() {
            return lookup.isDone();
        }

        @Override
        public void close() {
            super.close();
            group.shutdownGracefully(0, 1, TimeUnit.SECONDS);
        }
    }

    private static final class HeldLookup extends AddressResolverGroup<InetSocketAddress> {
        private final CompletableFuture<InetAddress> lookup;

        HeldLookup(CompletableFuture<InetAddress> lookup) {
            this.lookup = lookup;
        }

        @Override
        protected AddressResolver<InetSocketAddress> newResolver(EventExecutor executor) {
            return new InetNameResolver(executor) {
                @Override
                protected void doResolve(String host, Promise<InetAddress> promise) {
                    lookup.whenComplete((address, error) -> {
                        if (error != null) {
                            promise.tryFailure(error);
                        } else {
                            promise.trySuccess(address);
                        }
                    });
                }

                @Override
                protected void doResolveAll(String host, Promise<List<InetAddress>> promise) {
                    lookup.whenComplete((address, error) -> {
                        if (error != null) {
                            promise.tryFailure(error);
                        } else {
                            promise.trySuccess(List.of(address));
                        }
                    });
                }
            }.asAddressResolver();
        }
    }

    /**
     * Collects what the client sends on the data connection. Frames are written from the local
     * channels' threads, and EmbeddedChannel's own outbound queue is not safe to share with the test
     * thread, so they are taken here and never reach it.
     */
    private static final class Frames extends ChannelOutboundHandlerAdapter {
        private final Queue<NatMessagePacket> incoming = new ConcurrentLinkedQueue<>();
        private final List<NatMessagePacket> seen = new ArrayList<>();
        private final ByteArrayOutputStream liveData = new ByteArrayOutputStream();

        @Override
        public void write(ChannelHandlerContext ctx, Object msg, ChannelPromise promise) {
            if (msg instanceof NatMessagePacket packet) {
                incoming.add(packet);
            }
            promise.trySuccess();
        }

        private void drain() {
            NatMessagePacket packet;
            while ((packet = incoming.poll()) != null) {
                seen.add(packet);
                if (packet.getStreamId() == LIVE_STREAM && packet.getNatMessageType() == NatMessageType.DATA) {
                    liveData.writeBytes(packet.getData());
                }
            }
        }

        private int count(int streamId, NatMessageType type) {
            drain();
            int count = 0;
            for (NatMessagePacket packet : seen) {
                if (packet.getStreamId() == streamId && packet.getNatMessageType() == type) {
                    count++;
                }
            }
            return count;
        }

        private long credit(int streamId) {
            drain();
            long credit = 0;
            for (NatMessagePacket packet : seen) {
                if (packet.getStreamId() == streamId && packet.getNatMessageType() == NatMessageType.WINDOW_UPDATE) {
                    credit += packet.getValue();
                }
            }
            return credit;
        }

        private NatMessagePacket await(EmbeddedChannel control, int streamId, NatMessageType type)
                throws Exception {
            long deadline = System.nanoTime() + Duration.ofSeconds(10).toNanos();
            while (System.nanoTime() < deadline) {
                control.runPendingTasks();
                drain();
                for (NatMessagePacket packet : seen) {
                    if (packet.getStreamId() == streamId && packet.getNatMessageType() == type) {
                        return packet;
                    }
                }
                Thread.sleep(5);
            }
            return null;
        }
    }

    private static SpecusBean bean(int liveUpstreamPort, int heldUpstreamPort) {
        SpecusConfig live = new SpecusConfig();
        live.setPort(LIVE_PORT);
        live.setSpecusAddress("127.0.0.1");
        live.setSpecusPort(liveUpstreamPort);

        SpecusConfig held = new SpecusConfig();
        held.setPort(HELD_PORT);
        held.setSpecusAddress(HELD_HOST);
        held.setSpecusPort(heldUpstreamPort);

        SpecusBean bean = new SpecusBean();
        bean.setClientName("async-connect-test");
        bean.setRemoteAddress("127.0.0.1");
        bean.setSpecusConfigList(List.of(live, held));
        return bean;
    }

    private static byte[] bytes(String text) {
        return text.getBytes(StandardCharsets.UTF_8);
    }

    private static NatMessagePacket tcpOpen(int streamId, int port) {
        NatMessagePacket packet = new NatMessagePacket();
        packet.setNatMessageType(NatMessageType.OPEN);
        packet.setStreamId(streamId);
        packet.setMetaData(Map.of("port", port, "channelId", "async-" + streamId));
        return packet;
    }

    private static NatMessagePacket data(int streamId, byte[] payload) {
        NatMessagePacket packet = new NatMessagePacket();
        packet.setNatMessageType(NatMessageType.DATA);
        packet.setStreamId(streamId);
        packet.setData(payload);
        return packet;
    }

    private static NatMessagePacket fin(int streamId) {
        NatMessagePacket packet = new NatMessagePacket();
        packet.setNatMessageType(NatMessageType.FIN);
        packet.setStreamId(streamId);
        return packet;
    }

    private static NatMessagePacket rst(int streamId) {
        NatMessagePacket packet = new NatMessagePacket();
        packet.setNatMessageType(NatMessageType.RST);
        packet.setStreamId(streamId);
        packet.setValue(1);
        return packet;
    }

    private static final class EchoUpstream implements AutoCloseable {
        private final ServerSocket server;
        private final Thread acceptor;

        EchoUpstream() throws IOException {
            server = new ServerSocket(0, 50, InetAddress.getLoopbackAddress());
            acceptor = new Thread(() -> {
                try {
                    while (!server.isClosed()) {
                        Socket socket = server.accept();
                        Thread echo = new Thread(() -> echo(socket), "echo-upstream-connection");
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
        }
    }
}
