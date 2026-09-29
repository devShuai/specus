package com.theshuai.specusclient.handler;

import com.theshuai.common.handler.StreamFlowController;
import com.theshuai.common.protocol.NatMessagePacket;
import com.theshuai.common.protocol.NatMessageType;
import com.theshuai.specusclient.bean.SpecusBean;
import com.theshuai.specusclient.bean.SpecusConfig;
import com.theshuai.specusclient.client.TcpConnection;
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
 * single-threaded upstream with a second connection queued behind the first deadlocks that way, and
 * so did the C server NAT smoke test now and then.
 */
class NatTcpBackpressureLoopbackTests {
    private static final int STALLED_PORT = 19_001;
    private static final int ECHO_PORT = 19_002;
    private static final int FRAME = 64 * 1024;

    @Test
    void aStreamWhoseUpstreamStopsReadingLeavesTheDataConnectionReading() throws Exception {
        try (StalledUpstream stalled = new StalledUpstream(); EchoUpstream echo = new EchoUpstream()) {
            NatClientHandler handler = new NatClientHandler(
                    bean(stalled.port(), echo.port()), new TcpConnection());
            EmbeddedChannel control = new EmbeddedChannel(handler);
            try {
                drainOutbound(control); // REGISTER frames

                int stuck = 51;
                int flowing = 52;
                control.writeInbound(open(stuck, STALLED_PORT));
                control.writeInbound(open(flowing, ECHO_PORT));
                await(() -> handler.hasLocalTcpStream(stuck) && handler.hasLocalTcpStream(flowing), control);

                // A full window towards an upstream that never reads leaves most of it queued in front
                // of the local socket, far past the point where that socket stops being writable.
                byte[] chunk = new byte[FRAME];
                for (int sent = 0; sent < StreamFlowController.INITIAL_WINDOW_BYTES; sent += FRAME) {
                    control.writeInbound(data(stuck, chunk));
                }
                long credited = settledCredit(control, stuck);
                assertTrue(credited <= StreamFlowController.INITIAL_WINDOW_BYTES - 2L * FRAME,
                        "the upstream must be holding back most of the window for this test to mean anything, "
                                + "credited=" + credited);

                assertTrue(control.config().isAutoRead(),
                        "one stalled upstream must not stop the data connection from reading");

                byte[] ping = "still-flowing".getBytes(StandardCharsets.UTF_8);
                control.writeInbound(data(flowing, ping));
                assertArrayEquals(ping, awaitData(control, flowing, ping.length),
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
            EmbeddedChannel control = new EmbeddedChannel(handler);
            try {
                drainOutbound(control);

                int streamId = 53;
                control.writeInbound(open(streamId, STALLED_PORT));
                await(() -> handler.hasLocalTcpStream(streamId), control);

                // A server that honours the window can never get this far ahead of the credit returned.
                byte[] chunk = new byte[FRAME];
                for (int sent = 0; sent < 8 * StreamFlowController.INITIAL_WINDOW_BYTES; sent += FRAME) {
                    control.writeInbound(data(streamId, chunk));
                }

                NatMessagePacket reset = awaitReset(control, streamId);
                assertNotNull(reset, "the stream must be reset once the server overruns the window");
                assertEquals(8, reset.getValue());
                assertEquals("pending local TCP data exceeds receive window", reset.getMetaData().get("reason"));
                await(() -> !handler.hasLocalTcpStream(streamId), control);
            } finally {
                control.finishAndReleaseAll();
            }
        }
    }

    /** Credit returned for one stream once it has stopped changing. */
    private static long settledCredit(EmbeddedChannel control, int streamId) throws Exception {
        long credited = 0;
        long lastChange = System.nanoTime();
        long deadline = lastChange + Duration.ofSeconds(10).toNanos();
        while (System.nanoTime() < deadline
                && System.nanoTime() - lastChange < Duration.ofMillis(500).toNanos()) {
            control.runPendingTasks();
            Object outbound;
            while ((outbound = control.readOutbound()) != null) {
                if (outbound instanceof NatMessagePacket packet
                        && packet.getStreamId() == streamId
                        && packet.getNatMessageType() == NatMessageType.WINDOW_UPDATE) {
                    credited += packet.getValue();
                    lastChange = System.nanoTime();
                }
            }
            Thread.sleep(10);
        }
        return credited;
    }

    private static byte[] awaitData(EmbeddedChannel control, int streamId, int length) throws Exception {
        ByteArrayOutputStream received = new ByteArrayOutputStream();
        long deadline = System.nanoTime() + Duration.ofSeconds(5).toNanos();
        while (System.nanoTime() < deadline && received.size() < length) {
            control.runPendingTasks();
            Object outbound;
            while ((outbound = control.readOutbound()) != null) {
                if (outbound instanceof NatMessagePacket packet
                        && packet.getStreamId() == streamId
                        && packet.getNatMessageType() == NatMessageType.DATA) {
                    received.write(packet.getData());
                }
            }
            Thread.sleep(10);
        }
        return received.toByteArray();
    }

    private static NatMessagePacket awaitReset(EmbeddedChannel control, int streamId) throws Exception {
        long deadline = System.nanoTime() + Duration.ofSeconds(5).toNanos();
        while (System.nanoTime() < deadline) {
            control.runPendingTasks();
            Object outbound;
            while ((outbound = control.readOutbound()) != null) {
                if (outbound instanceof NatMessagePacket packet
                        && packet.getStreamId() == streamId
                        && packet.getNatMessageType() == NatMessageType.RST) {
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

    private static void drainOutbound(EmbeddedChannel channel) {
        while (channel.readOutbound() != null) {
            // Drain setup frames.
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
