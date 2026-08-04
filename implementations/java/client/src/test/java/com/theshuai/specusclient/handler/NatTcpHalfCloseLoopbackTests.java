package com.theshuai.specusclient.handler;

import com.theshuai.common.protocol.NatMessagePacket;
import com.theshuai.common.protocol.NatMessageType;
import com.theshuai.specusclient.bean.SpecusBean;
import com.theshuai.specusclient.bean.SpecusConfig;
import com.theshuai.specusclient.client.TcpConnection;
import io.netty.channel.embedded.EmbeddedChannel;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import java.util.function.BooleanSupplier;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class NatTcpHalfCloseLoopbackTests {
    @Test
    void remoteFinHalfClosesOutputButStillRelaysReverseBytesAndCleansUpAfterBothFin() throws Exception {
        byte[] request = "request-after-open".getBytes(StandardCharsets.UTF_8);
        byte[] response = "response-after-request-eof".getBytes(StandardCharsets.UTF_8);

        try (ServerSocket upstream = new ServerSocket(0)) {
            upstream.setSoTimeout(5_000);
            CompletableFuture<byte[]> receivedRequest = CompletableFuture.supplyAsync(() -> {
                try (Socket socket = upstream.accept()) {
                    socket.setSoTimeout(5_000);
                    byte[] received = socket.getInputStream().readAllBytes();
                    socket.getOutputStream().write(response);
                    socket.getOutputStream().flush();
                    socket.shutdownOutput();
                    return received;
                } catch (Exception error) {
                    throw new IllegalStateException(error);
                }
            });

            NatClientHandler handler = new NatClientHandler(bean(upstream.getLocalPort()), new TcpConnection());
            EmbeddedChannel control = new EmbeddedChannel(handler);
            try {
                drainOutbound(control); // REGISTER

                int streamId = 41;
                control.writeInbound(open(streamId));
                await(Duration.ofSeconds(5), () -> handler.hasLocalTcpStream(streamId), control);

                control.writeInbound(data(streamId, request));
                control.writeInbound(fin(streamId));

                assertArrayEquals(request, receivedRequest.get(5, TimeUnit.SECONDS));

                ByteArrayOutputStream relayedResponse = new ByteArrayOutputStream();
                boolean sawFin = awaitFrames(control, streamId, relayedResponse, Duration.ofSeconds(5));
                assertTrue(sawFin, "local input EOF must be propagated as FIN");
                assertArrayEquals(response, relayedResponse.toByteArray(),
                        "bytes written after the upstream observed EOF must still flow in reverse");

                await(Duration.ofSeconds(5), () -> !handler.hasLocalTcpStream(streamId), control);
                assertFalse(handler.hasLocalTcpStream(streamId), "both FIN directions must remove the TCP stream");
            } finally {
                control.finishAndReleaseAll();
            }
        }
    }

    private static boolean awaitFrames(EmbeddedChannel control, int streamId, ByteArrayOutputStream data,
                                       Duration timeout) throws Exception {
        long deadline = System.nanoTime() + timeout.toNanos();
        boolean sawFin = false;
        while (System.nanoTime() < deadline) {
            control.runPendingTasks();
            Object outbound;
            while ((outbound = control.readOutbound()) != null) {
                if (!(outbound instanceof NatMessagePacket packet) || packet.getStreamId() != streamId) {
                    continue;
                }
                if (packet.getNatMessageType() == NatMessageType.DATA) {
                    data.write(packet.getData());
                } else if (packet.getNatMessageType() == NatMessageType.FIN) {
                    sawFin = true;
                }
            }
            if (sawFin) {
                return true;
            }
            Thread.sleep(10);
        }
        return false;
    }

    private static void await(Duration timeout, BooleanSupplier condition, EmbeddedChannel control)
            throws Exception {
        long deadline = System.nanoTime() + timeout.toNanos();
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

    private static SpecusBean bean(int upstreamPort) {
        SpecusConfig mapping = new SpecusConfig();
        mapping.setPort(19_001);
        mapping.setSpecusAddress("127.0.0.1");
        mapping.setSpecusPort(upstreamPort);

        SpecusBean bean = new SpecusBean();
        bean.setClientName("half-close-test");
        bean.setRemoteAddress("127.0.0.1");
        bean.setSpecusConfigList(List.of(mapping));
        return bean;
    }

    private static NatMessagePacket open(int streamId) {
        NatMessagePacket packet = new NatMessagePacket();
        packet.setNatMessageType(NatMessageType.OPEN);
        packet.setStreamId(streamId);
        packet.setMetaData(Map.of("port", 19_001, "channelId", "loopback"));
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
}
