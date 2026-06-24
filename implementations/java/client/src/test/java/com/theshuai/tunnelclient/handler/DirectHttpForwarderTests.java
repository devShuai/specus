package com.theshuai.tunnelclient.handler;

import com.sun.net.httpserver.HttpServer;
import com.theshuai.common.protocol.request.DirectHttpRequestPacket;
import com.theshuai.common.protocol.response.DirectHttpResponsePacket;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class DirectHttpForwarderTests {
    private HttpServer server;

    @AfterEach
    void stopServer() {
        if (server != null) {
            server.stop(0);
        }
    }

    @Test
    void shouldForwardMethodPathQueryHeadersAndBinaryBody() throws Exception {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/base/upload", exchange -> {
            assertEquals("PATCH", exchange.getRequestMethod());
            assertEquals("source=tunnel", exchange.getRequestURI().getRawQuery());
            assertEquals("demo", exchange.getRequestHeaders().getFirst("X-Tunnel-Test"));
            assertArrayEquals(new byte[]{0, 1, 2, -1}, exchange.getRequestBody().readAllBytes());
            exchange.getResponseHeaders().add("X-Upstream", "ok");
            byte[] response = "forwarded".getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(201, response.length);
            exchange.getResponseBody().write(response);
            exchange.close();
        });
        server.start();

        DirectHttpRequestPacket request = new DirectHttpRequestPacket();
        request.setRequestId("request-id");
        request.setRequestMethod("PATCH");
        request.setRoute("web");
        request.setRelativePath("/upload");
        request.setRawQuery("source=tunnel");
        request.setHeaders(List.of("X-Tunnel-Test:demo", "Connection:close"));
        request.setBody(new byte[]{0, 1, 2, -1});

        DirectHttpResponsePacket response = DirectHttpForwarder.forward(
                request,
                Map.of("web", "http://127.0.0.1:" + server.getAddress().getPort() + "/base")
        );

        assertEquals(201, response.getStatusCode());
        assertArrayEquals("forwarded".getBytes(StandardCharsets.UTF_8), response.getBody());
        assertTrue(response.getHeaders().contains("X-upstream:ok"));
    }

    @Test
    void shouldRejectUnknownRoute() {
        DirectHttpRequestPacket request = new DirectHttpRequestPacket();
        request.setRequestId("request-id");
        request.setRequestMethod("GET");
        request.setRoute("missing");
        request.setRelativePath("/");

        DirectHttpResponsePacket response = DirectHttpForwarder.forward(request, Map.of());

        assertEquals(502, response.getStatusCode());
        assertTrue(response.getError().contains("未配置"));
    }

    @Test
    void shouldRejectPathOutsideConfiguredBasePath() {
        DirectHttpRequestPacket request = new DirectHttpRequestPacket();
        request.setRequestId("request-id");
        request.setRequestMethod("GET");
        request.setRoute("web");
        request.setRelativePath("/../admin");

        DirectHttpResponsePacket response = DirectHttpForwarder.forward(
                request,
                Map.of("web", "http://127.0.0.1:8080/base")
        );

        assertEquals(502, response.getStatusCode());
        assertTrue(response.getError().contains("越界"));
    }

    @Test
    void shouldReturnRedirectWithoutFollowingIt() throws Exception {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/redirect", exchange -> {
            exchange.getResponseHeaders().add("Location", "http://127.0.0.1:" + server.getAddress().getPort() + "/target");
            exchange.sendResponseHeaders(302, -1);
            exchange.close();
        });
        server.createContext("/target", exchange -> {
            throw new AssertionError("redirect must not be followed");
        });
        server.start();

        DirectHttpRequestPacket request = new DirectHttpRequestPacket();
        request.setRequestId("request-id");
        request.setRequestMethod("GET");
        request.setRoute("web");
        request.setRelativePath("/redirect");

        DirectHttpResponsePacket response = DirectHttpForwarder.forward(
                request,
                Map.of("web", "http://127.0.0.1:" + server.getAddress().getPort())
        );

        assertEquals(302, response.getStatusCode());
    }

    @Test
    void shouldBoundOpenEndedRangeForVideoPlayback() throws Exception {
        AtomicReference<String> upstreamRange = new AtomicReference<>();
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/video", exchange -> {
            upstreamRange.set(exchange.getRequestHeaders().getFirst("Range"));
            byte[] response = "chunk".getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().add("Accept-Ranges", "bytes");
            exchange.getResponseHeaders().add("Content-Range", "bytes 100-8388707/99999999");
            exchange.sendResponseHeaders(206, response.length);
            exchange.getResponseBody().write(response);
            exchange.close();
        });
        server.start();

        DirectHttpRequestPacket request = new DirectHttpRequestPacket();
        request.setRequestId("request-id");
        request.setRequestMethod("GET");
        request.setRoute("jellyfin");
        request.setRelativePath("/video");
        request.setHeaders(List.of("Range: bytes=100-"));

        DirectHttpResponsePacket response = DirectHttpForwarder.forward(
                request,
                Map.of("jellyfin", "http://127.0.0.1:" + server.getAddress().getPort())
        );

        assertEquals(206, response.getStatusCode());
        assertEquals("bytes=100-8388707", upstreamRange.get());
        assertTrue(response.getHeaders().contains("Content-range:bytes 100-8388707/99999999"));
    }

    @Test
    void shouldNormalizeOversizedRangeHeaders() {
        assertEquals("bytes=0-8388607", DirectHttpForwarder.boundedRange("bytes=0-999999999"));
        assertEquals("bytes=100-8388707", DirectHttpForwarder.boundedRange("bytes=100-"));
        assertEquals("bytes=-8388608", DirectHttpForwarder.boundedRange("bytes=-999999999"));
        assertEquals("bytes=0-1023", DirectHttpForwarder.boundedRange("bytes=0-1023"));
        assertNull(DirectHttpForwarder.boundedRange("bytes=0-1023,2048-4095"));
        assertNull(DirectHttpForwarder.boundedRange("items=0-1023"));
    }
}
