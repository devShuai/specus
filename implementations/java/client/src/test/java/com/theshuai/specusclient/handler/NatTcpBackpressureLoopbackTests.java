package com.theshuai.specusclient.handler;

import com.theshuai.common.handler.StreamFlowController;
import com.theshuai.common.protocol.NatMessagePacket;
import com.theshuai.common.protocol.NatMessageType;
import com.theshuai.specusclient.bean.SpecusBean;
import com.theshuai.specusclient.bean.SpecusConfig;
import com.theshuai.specusclient.client.TcpConnection;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelOutboundHandlerAdapter;
import io.netty.channel.ChannelPromise;
import io.netty.channel.embedded.EmbeddedChannel;
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
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.BooleanSupplier;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
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
    void aStreamWhoseUpstreamStopsReadingLeavesTheDataConnectionReading() throws Exception {
        try (StalledUpstream stalled = new StalledUpstream(); EchoUpstream echo = new EchoUpstream()) {
            NatClientHandler handler = new NatClientHandler(
                    bean(stalled.port(), echo.port()), new TcpConnection());
            SentFrames sent = new SentFrames();
            EmbeddedChannel control = new EmbeddedChannel(sent, handler);
            try {
                int stuck = 51;
                int flowing = 52;
                control.writeInbound(open(stuck, STALLED_PORT));
                control.writeInbound(open(flowing, ECHO_PORT));
                await(() -> handler.hasLocalTcpStream(stuck) && handler.hasLocalTcpStream(flowing), control);

                long queued = fillUntilTheUpstreamStops(control, sent, stuck);
                assertTrue(queued > 2L * FRAME,
                        "the stalled upstream must leave bytes queued in front of its socket, queued=" + queued);

                assertTrue(control.config().isAutoRead(),
                        "one stalled upstream must not stop the data connection from reading");

                byte[] ping = "still-flowing".getBytes(StandardCharsets.UTF_8);
                control.writeInbound(data(flowing, ping));
                assertArrayEquals(ping, awaitData(control, sent, flowing, ping.length),
                        "another stream must keep moving while the first one is stalled");
                assertTrue(control.config().isAutoRead());
            } finally {
                control.finishAndReleaseAll();
            }
        }
    }

    @Test
    void dataPastTheReceiveWindowResetsTheStreamInsteadOfQueueingIt() throws Exception {
        try (StalledUpstream stalled = new StalledUpstream(); EchoUpstream echo = new EchoUpstream()) {
            NatClientHandler handler = new NatClientHandler(
                    bean(stalled.port(), echo.port()), new TcpConnection());
            SentFrames sent = new SentFrames();
            EmbeddedChannel control = new EmbeddedChannel(sent, handler);
            try {
                int streamId = 53;
                control.writeInbound(open(streamId, STALLED_PORT));
                await(() -> handler.hasLocalTcpStream(streamId), control);

                // Far more than any socket buffer takes from a peer that is not reading, sent without
                // waiting for credit, which a server honouring the window never does.
                byte[] chunk = new byte[FRAME];
                for (long offered = 0; offered < 32 * WINDOW; offered += FRAME) {
                    control.writeInbound(data(streamId, chunk));
                }

                NatMessagePacket reset = awaitReset(control, sent, streamId);
                assertNotNull(reset, "the stream must be reset once the server overruns the window");
                assertEquals(8, reset.getValue());
                assertEquals("pending local TCP data exceeds receive window", reset.getMetaData().get("reason"));
                await(() -> !handler.hasLocalTcpStream(streamId), control);
            } finally {
                control.finishAndReleaseAll();
            }
        }
    }

    /**
     * Plays a server that honours the window: keeps the stream's window full as credit comes back,
     * until the upstream stops taking bytes and credit stops coming. How much the kernel buffers for
     * a peer that is not reading differs by platform, so a fixed amount would not reliably get there.
     * Returns what is left queued in front of the local socket.
     */
    private static long fillUntilTheUpstreamStops(EmbeddedChannel control, SentFrames sent, int streamId)
            throws Exception {
        byte[] chunk = new byte[FRAME];
        long offered = 0;
        long credited = 0;
        long lastCredit = System.nanoTime();
        long deadline = lastCredit + Duration.ofSeconds(20).toNanos();
        while (System.nanoTime() - lastCredit < Duration.ofMillis(500).toNanos()
                && System.nanoTime() < deadline) {
            while (offered - credited + FRAME <= WINDOW) {
                control.writeInbound(data(streamId, chunk));
                offered += FRAME;
            }
            control.runPendingTasks();
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

    private static byte[] awaitData(EmbeddedChannel control, SentFrames sent, int streamId, int length)
            throws Exception {
        ByteArrayOutputStream received = new ByteArrayOutputStream();
        long deadline = System.nanoTime() + Duration.ofSeconds(5).toNanos();
        while (System.nanoTime() < deadline && received.size() < length) {
            control.runPendingTasks();
            NatMessagePacket packet;
            while ((packet = sent.frames.poll()) != null) {
                if (packet.getStreamId() == streamId && packet.getNatMessageType() == NatMessageType.DATA) {
                    received.write(packet.getData());
                }
            }
            Thread.sleep(10);
        }
        return received.toByteArray();
    }

    private static NatMessagePacket awaitReset(EmbeddedChannel control, SentFrames sent, int streamId)
            throws Exception {
        long deadline = System.nanoTime() + Duration.ofSeconds(5).toNanos();
        while (System.nanoTime() < deadline) {
            control.runPendingTasks();
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

    private static void await(BooleanSupplier condition, EmbeddedChannel control) throws Exception {
        long deadline = System.nanoTime() + Duration.ofSeconds(5).toNanos();
        while (System.nanoTime() < deadline) {
            control.runPendingTasks();
            if (condition.getAsBoolean()) {
                return;
            }
            Thread.sleep(10);
        }
        assertTrue(condition.getAsBoolean(), "condition was not met before timeout");
    }

    /**
     * Collects what the client sends on the data connection. Credit and resets are written from the
     * local channels' threads, and EmbeddedChannel's own outbound queue is not safe to share with the
     * test thread, so frames are taken here and never reach it.
     */
    private static final class SentFrames extends ChannelOutboundHandlerAdapter {
        private final Queue<NatMessagePacket> frames = new ConcurrentLinkedQueue<>();

        @Override
        public void write(ChannelHandlerContext ctx, Object msg, ChannelPromise promise) {
            if (msg instanceof NatMessagePacket packet) {
                frames.add(packet);
            }
            promise.trySuccess();
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
            for (Socket socket : accepted) {
                socket.close();
            }
            acceptor.join(5_000);
        }
    }

    private static final class EchoUpstream implements AutoCloseable {
        private final ServerSocket server;
        private final Thread acceptor;

        EchoUpstream() throws IOException {
            server = new ServerSocket(0, 50, java.net.InetAddress.getLoopbackAddress());
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
