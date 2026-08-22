package com.theshuai.specusclient.handler;

import com.theshuai.specusclient.bean.SpecusBean;
import com.theshuai.specusclient.bean.HttpSpecusConfig;
import io.netty.channel.EventLoopGroup;
import io.netty.channel.MultiThreadIoEventLoopGroup;
import io.netty.channel.nio.NioIoHandler;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class HttpStreamForwarderTrailersTests {

    @Test
    void forwardsRequestFinTrailersAndReturnsResponseTrailers() throws Exception {
        try (ServerSocket upstream = new ServerSocket(0)) {
            CompletableFuture<String> captured = CompletableFuture.supplyAsync(() -> serveOnce(upstream));
            EventLoopGroup group = new MultiThreadIoEventLoopGroup(1, NioIoHandler.newFactory());
            try {
                RecordingNatClientHandler owner = new RecordingNatClientHandler(
                        List.of("X-Response-Trailer"));
                Map<String, Object> metadata = Map.of(
                        "method", "POST",
                        "route", "api",
                        "relativePath", "/trailers",
                        "contentLength", 4L,
                        "trailerNames", List.of("X-Request-Trailer"),
                        "headers", List.of("Content-Type:text/plain"));
                HttpStreamForwarder forwarder = new HttpStreamForwarder(owner, 7, metadata,
                        Map.of("api", routeConfig("api",
                                "http://127.0.0.1:" + upstream.getLocalPort())), group);

                assertTrue(forwarder.onData("ping".getBytes(StandardCharsets.US_ASCII)));
                assertTrue(forwarder.onRequestFin(Map.of("trailers", List.of(
                        "X-Request-Trailer:ok", "Undeclared:ignored"))));
                forwarder.run();

                String request = captured.get(5, TimeUnit.SECONDS);
                assertTrue(request.toLowerCase().contains("transfer-encoding: chunked"));
                assertTrue(request.toLowerCase().contains("trailer: x-request-trailer"));
                assertTrue(request.contains("4\r\nping\r\n0\r\nX-Request-Trailer: ok\r\n\r\n"));
                assertTrue(!request.contains("Undeclared"));
                assertEquals("pong", owner.responseBody.toString(StandardCharsets.US_ASCII));
                assertEquals(List.of("X-Response-Trailer:done"), owner.responseTrailers);
                assertEquals(4, owner.returnedRequestCredit);
                assertNull(owner.failure);
            } finally {
                group.shutdownGracefully(0, 5, TimeUnit.SECONDS)
                        .awaitUninterruptibly(10, TimeUnit.SECONDS);
            }
        }
    }

    @Test
    void preservesKnownContentLengthWhenRequestHasNoTrailers() throws Exception {
        try (ServerSocket upstream = new ServerSocket(0)) {
            CompletableFuture<String> captured = CompletableFuture.supplyAsync(() -> serveFixedLength(upstream));
            EventLoopGroup group = new MultiThreadIoEventLoopGroup(1, NioIoHandler.newFactory());
            try {
                RecordingNatClientHandler owner = new RecordingNatClientHandler(List.of());
                Map<String, Object> metadata = Map.of(
                        "method", "POST",
                        "route", "api",
                        "relativePath", "/fixed",
                        "contentLength", 4L);
                HttpStreamForwarder forwarder = new HttpStreamForwarder(owner, 7, metadata,
                        Map.of("api", routeConfig("api",
                                "http://127.0.0.1:" + upstream.getLocalPort())), group);

                assertTrue(forwarder.onData("ping".getBytes(StandardCharsets.US_ASCII)));
                assertTrue(forwarder.onRequestFin(Map.of()));
                forwarder.run();

                String request = captured.get(5, TimeUnit.SECONDS);
                assertTrue(request.toLowerCase().contains("content-length: 4"));
                assertTrue(!request.toLowerCase().contains("transfer-encoding: chunked"));
                assertTrue(request.endsWith("\r\n\r\nping"));
                assertNull(owner.failure);
            } finally {
                group.shutdownGracefully(0, 5, TimeUnit.SECONDS)
                        .awaitUninterruptibly(10, TimeUnit.SECONDS);
            }
        }
    }

    private static HttpSpecusConfig routeConfig(String route, String targetBaseUrl) {
        HttpSpecusConfig config = new HttpSpecusConfig();
        config.setRoute(route);
        config.setTargetBaseUrl(targetBaseUrl);
        return config;
    }

    private static String serveOnce(ServerSocket server) {
        try (Socket socket = server.accept()) {
            socket.setSoTimeout(5_000);
            InputStream input = socket.getInputStream();
            ByteArrayOutputStream request = new ByteArrayOutputStream();
            byte[] buffer = new byte[1024];
            while (request.size() < 64 * 1024) {
                int read = input.read(buffer);
                if (read < 0) throw new IllegalStateException("request ended before trailers");
                request.write(buffer, 0, read);
                String text = request.toString(StandardCharsets.ISO_8859_1);
                if (text.contains("0\r\nX-Request-Trailer: ok\r\n\r\n")) {
                    socket.getOutputStream().write(("HTTP/1.1 200 OK\r\n"
                            + "Content-Type: text/plain\r\n"
                            + "Transfer-Encoding: chunked\r\n"
                            + "Trailer: X-Response-Trailer\r\n"
                            + "Connection: close\r\n\r\n"
                            + "4\r\npong\r\n"
                            + "0\r\nX-Response-Trailer: done\r\n\r\n")
                            .getBytes(StandardCharsets.ISO_8859_1));
                    socket.getOutputStream().flush();
                    return text;
                }
            }
            throw new IllegalStateException("request exceeded capture limit");
        } catch (Exception error) {
            throw new RuntimeException(error);
        }
    }

    private static String serveFixedLength(ServerSocket server) {
        try (Socket socket = server.accept()) {
            socket.setSoTimeout(5_000);
            InputStream input = socket.getInputStream();
            ByteArrayOutputStream request = new ByteArrayOutputStream();
            byte[] buffer = new byte[1024];
            while (request.size() < 64 * 1024) {
                int read = input.read(buffer);
                if (read < 0) throw new IllegalStateException("request ended before fixed body");
                request.write(buffer, 0, read);
                String text = request.toString(StandardCharsets.ISO_8859_1);
                if (text.contains("\r\n\r\nping")) {
                    socket.getOutputStream().write(("HTTP/1.1 200 OK\r\n"
                            + "Content-Length: 0\r\nConnection: close\r\n\r\n")
                            .getBytes(StandardCharsets.ISO_8859_1));
                    socket.getOutputStream().flush();
                    return text;
                }
            }
            throw new IllegalStateException("request exceeded capture limit");
        } catch (Exception error) {
            throw new RuntimeException(error);
        }
    }

    private static final class RecordingNatClientHandler extends NatClientHandler {
        private final ByteArrayOutputStream responseBody = new ByteArrayOutputStream();
        private volatile List<String> responseTrailers = List.of();
        private volatile int returnedRequestCredit;
        private volatile String failure;
        private final List<String> expectedTrailerNames;

        private RecordingNatClientHandler(List<String> expectedTrailerNames) {
            super(bean());
            this.expectedTrailerNames = expectedTrailerNames;
        }

        @Override
        CompletableFuture<Void> sendHttpResponseHead(int streamId, int statusCode, List<String> headers,
                                                     List<String> trailerNames) {
            assertEquals(7, streamId);
            assertEquals(200, statusCode);
            assertEquals(expectedTrailerNames, trailerNames);
            return CompletableFuture.completedFuture(null);
        }

        @Override
        CompletableFuture<Void> sendHttpResponseData(int streamId, byte[] data) {
            responseBody.writeBytes(data);
            return CompletableFuture.completedFuture(null);
        }

        @Override
        CompletableFuture<Void> finishHttpResponse(int streamId, List<String> trailers) {
            responseTrailers = List.copyOf(trailers);
            return CompletableFuture.completedFuture(null);
        }

        @Override
        void sendHttpWindowUpdate(int streamId, int bytes) {
            returnedRequestCredit += bytes;
        }

        @Override
        void failHttpStream(int streamId, String reason) {
            failure = reason;
        }

        @Override
        void httpForwarderDone(int streamId, HttpStreamForwarder forwarder) {
        }

        private static SpecusBean bean() {
            SpecusBean bean = new SpecusBean();
            bean.setClientName("test-client");
            bean.setSpecusConfigList(List.of());
            bean.setHttpSpecusConfigList(List.of());
            return bean;
        }
    }
}
