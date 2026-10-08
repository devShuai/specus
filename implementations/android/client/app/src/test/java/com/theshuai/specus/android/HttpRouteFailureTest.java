package com.theshuai.specus.android;

import io.netty.channel.ConnectTimeoutException;
import io.netty.handler.ssl.SslHandshakeTimeoutException;

import org.json.JSONObject;
import org.junit.Test;

import java.io.IOException;
import java.io.InputStream;
import java.net.ConnectException;
import java.net.InetAddress;
import java.net.NoRouteToHostException;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.net.URI;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

/**
 * An HTTP route stream that fails before its response OPEN says why on its RST
 * (protocol/spec/service-connectivity-check.md section 6.2), so the connectivity check can tell a
 * refused target from a route the device has not loaded. The failures through the transport are
 * real ones on loopback: a closed port, plain bytes where TLS was expected, a target that closes
 * before the head, and one that answers with something that is no HTTP response.
 */
public class HttpRouteFailureTest {
    @Test
    public void theClosedSetIsTheSharedVectorsOne() throws Exception {
        JSONObject failures = ProtocolVectorTestSupport.read("service-connectivity-check-v1.json")
                .getJSONObject("rstFailures");
        Set<String> names = new HashSet<>();
        failures.keys().forEachRemaining(names::add);
        assertEquals(names, new HashSet<>(HttpRouteFailure.ALL));
    }

    @Test
    public void theLoginDeclaresTheCapability() throws Exception {
        JSONObject environment = new SpecusCore.ClientEnvironment().toJson();
        assertEquals(HttpRouteFailure.CAPABILITY_VERSION, environment
                .getJSONObject("clientHttpRouteCapabilities").getInt("version"));
        assertEquals(1, HttpRouteFailure.CAPABILITY_VERSION);
    }

    @Test
    public void theResetCarriesTheFailureOnlyWhenThereIsOne() {
        assertEquals(Map.of("reason", "refused", "failure", "connect-refused"),
                SpecusCore.resetMetadata("refused", HttpRouteFailure.CONNECT_REFUSED));
        assertEquals(Map.of("reason", "request too large"),
                SpecusCore.resetMetadata("request too large", null));
    }

    @Test
    public void aMissingRouteAndAnUnusableTargetAreToldApart() throws Exception {
        HttpRouteFailure.Classified missing = assertThrows(HttpRouteFailure.Classified.class,
                () -> HttpRouteFailure.target(null, "/", ""));
        assertEquals(HttpRouteFailure.ROUTE_NOT_LOADED, missing.failure);
        assertEquals("HTTP route is not configured", missing.getMessage());
        assertEquals(HttpRouteFailure.ROUTE_NOT_LOADED, assertThrows(HttpRouteFailure.Classified.class,
                () -> HttpRouteFailure.target("  ", "/", "")).failure);
        for (String unusable : List.of("ftp://127.0.0.1/", "http:///no-host", "http://127.0.0.1/?q=1")) {
            HttpRouteFailure.Classified invalid = assertThrows(unusable, HttpRouteFailure.Classified.class,
                    () -> HttpRouteFailure.target(unusable, "/", ""));
            assertEquals(unusable, HttpRouteFailure.TARGET_INVALID, invalid.failure);
        }
        assertEquals(HttpRouteFailure.TARGET_INVALID, assertThrows(HttpRouteFailure.Classified.class,
                () -> HttpRouteFailure.target("http://127.0.0.1:8080", "no-leading-slash", "")).failure);
        assertEquals(new URI("http://127.0.0.1:8080/base/a?b=1"),
                HttpRouteFailure.target("http://127.0.0.1:8080/base", "/a", "b=1"));
    }

    @Test
    public void failuresArePlacedByTypeAndPhaseNeverByText() {
        assertEquals(HttpRouteFailure.CONNECT_TIMEOUT,
                HttpRouteFailure.connectFailure(new ConnectTimeoutException("connection refused")));
        assertEquals(HttpRouteFailure.DNS_FAILED,
                HttpRouteFailure.connectFailure(new UnknownHostException("timed out")));
        assertEquals(HttpRouteFailure.UNREACHABLE,
                HttpRouteFailure.connectFailure(new NoRouteToHostException()));
        assertEquals(HttpRouteFailure.CONNECT_REFUSED,
                HttpRouteFailure.connectFailure(new ExecutionException(new ConnectException("x"))));
        // Network unreachable and a reset while connecting are plain SocketExceptions on the JVM.
        assertNull(HttpRouteFailure.connectFailure(new SocketException("Network is unreachable")));
        assertNull(HttpRouteFailure.connectFailure(new IOException("connection refused")));

        assertEquals(HttpRouteFailure.CONNECT_TIMEOUT,
                HttpRouteFailure.handshakeFailure(new SslHandshakeTimeoutException("slow")));
        assertEquals(HttpRouteFailure.TLS_FAILED,
                HttpRouteFailure.handshakeFailure(new IOException("connection closed")));

        assertEquals(HttpRouteFailure.PROTOCOL_ERROR,
                HttpRouteFailure.exchangeFailure(new IOException("upstream HTTP connection closed")));
        assertNull(HttpRouteFailure.exchangeFailure(new IllegalStateException("internal")));

        assertEquals(HttpRouteFailure.TARGET_INVALID, HttpRouteFailure.carried(
                new HttpRouteFailure.Classified(HttpRouteFailure.TARGET_INVALID, "bad", null)));
        assertNull(HttpRouteFailure.carried(new IOException("plain")));
    }

    @Test
    public void aClosedPortIsARefusedConnect() throws Exception {
        int port;
        try (ServerSocket probe = new ServerSocket(0, 1, InetAddress.getByName("127.0.0.1"))) {
            port = probe.getLocalPort();
        }
        NettyHttpTransport transport = failedExchange("http://127.0.0.1:" + port + "/");
        assertEquals(HttpRouteFailure.CONNECT_REFUSED, transport.failureClassification());
    }

    @Test
    public void plainBytesWhereTlsWasExpectedAreATlsFailure() throws Exception {
        try (Target target = new Target(socket -> {
            socket.getOutputStream().write("HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n"
                    .getBytes(StandardCharsets.ISO_8859_1));
            socket.getOutputStream().flush();
            drain(socket.getInputStream());
        })) {
            NettyHttpTransport transport = failedExchange("https://127.0.0.1:" + target.port() + "/");
            assertEquals(HttpRouteFailure.TLS_FAILED, transport.failureClassification());
        }
    }

    @Test
    public void aTargetClosingBeforeTheHeadIsAProtocolError() throws Exception {
        try (Target target = new Target(socket -> readHead(socket.getInputStream()))) {
            NettyHttpTransport transport = failedExchange("http://127.0.0.1:" + target.port() + "/");
            assertEquals(HttpRouteFailure.PROTOCOL_ERROR, transport.failureClassification());
        }
    }

    @Test
    public void aFailureAfterTheHeadIsNotClassified() throws Exception {
        try (Target target = new Target(socket -> {
            readHead(socket.getInputStream());
            socket.getOutputStream().write("HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\nshort"
                    .getBytes(StandardCharsets.ISO_8859_1));
            socket.getOutputStream().flush();
        })) {
            AtomicInteger heads = new AtomicInteger();
            NettyHttpTransport transport = failedExchange(
                    "http://127.0.0.1:" + target.port() + "/", "GET", heads);
            assertEquals(1, heads.get());
            assertNull(transport.failureClassification());
        }
    }

    @Test
    public void closingFromThisSideIsNoFailureOfTheTarget() throws Exception {
        CountDownLatch accepted = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        try (Target target = new Target(socket -> {
            accepted.countDown();
            release.await(10, TimeUnit.SECONDS);
        })) {
            NettyHttpTransport transport =
                    transport("http://127.0.0.1:" + target.port() + "/", "HEAD", null);
            transport.start();
            assertTrue(accepted.await(5, TimeUnit.SECONDS));
            transport.close();
            assertThrows(IOException.class, transport::awaitCompletion);
            assertNull(transport.failureClassification());
            release.countDown();
        }
    }

    private static NettyHttpTransport failedExchange(String url) throws Exception {
        return failedExchange(url, "HEAD", null);
    }

    /** Runs a request to {@code url} that must fail, and returns its transport. */
    private static NettyHttpTransport failedExchange(String url, String method, AtomicInteger heads)
            throws Exception {
        NettyHttpTransport transport = transport(url, method, heads);
        try {
            transport.start();
            assertThrows(Exception.class, () -> {
                transport.finishRequest(List.of());
                transport.awaitCompletion();
            });
        } finally {
            transport.close();
        }
        return transport;
    }

    private static NettyHttpTransport transport(String url, String method, AtomicInteger heads)
            throws Exception {
        return new NettyHttpTransport(new URI(url), method, List.of(), null, 0L, List.of(), null,
                new NettyHttpTransport.Listener() {
                    @Override
                    public void onResponseHead(int statusCode, List<String> headers,
                                               List<String> trailerNames) {
                        if (heads != null) {
                            heads.incrementAndGet();
                        }
                    }

                    @Override
                    public void onResponseData(byte[] data) {
                    }

                    @Override
                    public void onResponseEnd(List<String> trailers) {
                    }
                });
    }

    private static void readHead(InputStream input) throws IOException {
        int matched = 0;
        while (matched < 4) {
            int value = input.read();
            if (value < 0) {
                return;
            }
            matched = value == "\r\n\r\n".charAt(matched) ? matched + 1 : value == '\r' ? 1 : 0;
        }
    }

    private static void drain(InputStream input) throws IOException {
        byte[] buffer = new byte[4096];
        while (input.read(buffer) >= 0) {
            // Until the client gives up.
        }
    }

    private interface Exchange {
        void serve(Socket socket) throws Exception;
    }

    /** A loopback target that serves one connection and then closes it. */
    private static final class Target implements AutoCloseable {
        private final ServerSocket server;
        private final Thread thread;

        Target(Exchange exchange) throws IOException {
            server = new ServerSocket(0, 1, InetAddress.getByName("127.0.0.1"));
            thread = new Thread(() -> {
                try (Socket socket = server.accept()) {
                    socket.setSoTimeout(10_000);
                    exchange.serve(socket);
                } catch (Exception ignored) {
                    // The client may give up first.
                }
            }, "http-route-failure-target");
            thread.setDaemon(true);
            thread.start();
        }

        int port() {
            return server.getLocalPort();
        }

        @Override
        public void close() throws Exception {
            server.close();
            thread.join(10_000L);
        }
    }
}
