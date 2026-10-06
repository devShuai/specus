package com.theshuai.specusclient.handler;

import com.theshuai.common.protocol.NatMessagePacket;
import com.theshuai.common.protocol.NatMessageType;
import com.theshuai.specusclient.bean.HttpSpecusConfig;
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
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Queue;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.function.BooleanSupplier;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

/**
 * A stream whose local target cannot be reached fails alone.
 *
 * <p>The data connection carries every stream on the device. A refused, timed-out or unresolvable
 * target is that one stream's failure: it is answered with a RST for that stream, and the data
 * connection and every other stream on it keep going, as in the Go and .NET clients. The TCP path
 * used to rethrow the connect failure into the pipeline, which closed the data connection and with
 * it every in-flight stream on the device.
 */
class NatLocalConnectFailureIsolationTests {
    private static final int ECHO_PORT = 19_011;
    private static final int REFUSED_PORT = 19_012;
    private static final String REFUSED_ROUTE = "refused";
    private static final int LIVE_STREAM = 71;
    private static final int FAILING_STREAM = 72;

    @Test
    void aTcpStreamWhoseTargetRefusesIsResetAloneAndTheOtherStreamsKeepFlowing() throws Exception {
        NatMessagePacket reset = failOneStreamNextToALiveOne(tcpOpen(FAILING_STREAM, REFUSED_PORT));
        assertEquals(1, reset.getValue());
        assertEquals("local connect failed", reset.getMetaData().get("reason"));
    }

    @Test
    void anHttpStreamWhoseTargetRefusesIsResetAloneAndTheOtherStreamsKeepFlowing() throws Exception {
        NatMessagePacket reset = failOneStreamNextToALiveOne(httpOpen(FAILING_STREAM));
        assertEquals(8, reset.getValue());
    }

    @Test
    void aWebSocketStreamWhoseTargetRefusesIsResetAloneAndTheOtherStreamsKeepFlowing() throws Exception {
        NatMessagePacket reset = failOneStreamNextToALiveOne(webSocketOpen(FAILING_STREAM));
        assertEquals(5, reset.getValue());
        assertEquals("websocket connect failed", reset.getMetaData().get("reason"));
    }

    /**
     * Opens a TCP stream to an echo upstream, then the given stream to a target nobody listens on,
     * and checks the second is reset while the data connection and the first stream stay up.
     */
    private static NatMessagePacket failOneStreamNextToALiveOne(NatMessagePacket failingOpen) throws Exception {
        try (EchoUpstream echo = new EchoUpstream()) {
            int refusedPort = closedLoopbackPort();
            NatClientHandler handler = new NatClientHandler(bean(echo.port(), refusedPort), new TcpConnection());
            Frames frames = new Frames();
            EmbeddedChannel control = new EmbeddedChannel(frames, handler);
            try {
                control.writeInbound(tcpOpen(LIVE_STREAM, ECHO_PORT));
                await(() -> handler.hasLocalTcpStream(LIVE_STREAM), control);
                assertEchoes(control, frames, "before the failing stream");

                control.writeInbound(failingOpen);

                NatMessagePacket reset = frames.await(control, FAILING_STREAM, NatMessageType.RST);
                assertNotNull(reset, "the stream whose target is unreachable must be reset");
                assertTrue(control.isActive(), "one unreachable target must not close the data connection");
                assertFalse(handler.hasLocalTcpStream(FAILING_STREAM));

                // The server may reset the stream too; that RST lands on the stream's tombstone.
                control.writeInbound(rst(FAILING_STREAM));
                assertTrue(control.isActive(), "a late RST for the failed stream must be ignored");

                assertTrue(handler.hasLocalTcpStream(LIVE_STREAM), "the other stream must survive");
                assertEchoes(control, frames, "after the failing stream");
                for (NatMessagePacket packet : frames.seen) {
                    if (packet.getStreamId() == LIVE_STREAM && packet.getNatMessageType() == NatMessageType.RST) {
                        fail("the other stream was reset: " + packet.getMetaData());
                    }
                }
                return reset;
            } finally {
                control.finishAndReleaseAll();
            }
        }
    }

    /** Sends bytes down the live stream and expects the echo upstream to send them back up it. */
    private static void assertEchoes(EmbeddedChannel control, Frames frames, String when) throws Exception {
        byte[] payload = ("echo " + when).getBytes(StandardCharsets.UTF_8);
        frames.drain();
        frames.liveData.reset();
        control.writeInbound(data(LIVE_STREAM, payload));
        long deadline = System.nanoTime() + Duration.ofSeconds(5).toNanos();
        while (System.nanoTime() < deadline && frames.liveData.size() < payload.length) {
            control.runPendingTasks();
            frames.drain();
            Thread.sleep(10);
        }
        assertArrayEquals(payload, frames.liveData.toByteArray(),
                "the live stream must carry data both ways " + when);
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

    /** A loopback port that was free a moment ago, so a connect to it is refused. */
    private static int closedLoopbackPort() throws IOException {
        try (ServerSocket probe = new ServerSocket(0, 1, InetAddress.getLoopbackAddress())) {
            return probe.getLocalPort();
        }
    }

    /**
     * Collects what the client sends on the data connection. Frames are written from the local
     * channels' and forwarders' threads, and EmbeddedChannel's own outbound queue is not safe to
     * share with the test thread, so they are taken here and never reach it.
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
                Thread.sleep(10);
            }
            return null;
        }
    }

    private static SpecusBean bean(int echoPort, int refusedPort) {
        HttpSpecusConfig route = new HttpSpecusConfig();
        route.setRoute(REFUSED_ROUTE);
        route.setTargetBaseUrl("http://127.0.0.1:" + refusedPort);

        SpecusBean bean = new SpecusBean();
        bean.setClientName("connect-failure-test");
        bean.setRemoteAddress("127.0.0.1");
        bean.setSpecusConfigList(List.of(mapping(ECHO_PORT, echoPort), mapping(REFUSED_PORT, refusedPort)));
        bean.setHttpSpecusConfigList(List.of(route));
        return bean;
    }

    private static SpecusConfig mapping(int remotePort, int upstreamPort) {
        SpecusConfig mapping = new SpecusConfig();
        mapping.setPort(remotePort);
        mapping.setSpecusAddress("127.0.0.1");
        mapping.setSpecusPort(upstreamPort);
        return mapping;
    }

    private static NatMessagePacket tcpOpen(int streamId, int port) {
        return open(streamId, Map.of("port", port, "channelId", "loopback-" + streamId));
    }

    private static NatMessagePacket httpOpen(int streamId) {
        return open(streamId, Map.of(
                "source", "http",
                "phase", "request",
                "method", "GET",
                "route", REFUSED_ROUTE,
                "relativePath", "/",
                "headers", List.of()));
    }

    private static NatMessagePacket webSocketOpen(int streamId) {
        return open(streamId, Map.of(
                "source", "ws",
                "channelId", "ws-" + streamId,
                "route", REFUSED_ROUTE,
                "relativePath", "/"));
    }

    private static NatMessagePacket open(int streamId, Map<String, Object> metadata) {
        NatMessagePacket packet = new NatMessagePacket();
        packet.setNatMessageType(NatMessageType.OPEN);
        packet.setStreamId(streamId);
        packet.setMetaData(metadata);
        return packet;
    }

    private static NatMessagePacket data(int streamId, byte[] payload) {
        NatMessagePacket packet = new NatMessagePacket();
        packet.setNatMessageType(NatMessageType.DATA);
        packet.setStreamId(streamId);
        packet.setData(payload);
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
