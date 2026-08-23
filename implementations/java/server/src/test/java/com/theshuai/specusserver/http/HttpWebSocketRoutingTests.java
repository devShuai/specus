package com.theshuai.specusserver.http;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.InetAddress;
import java.net.Socket;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest(
        webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        properties = {
                "spring.datasource.url=jdbc:sqlite::memory:",
                "spring.jpa.database-platform=org.hibernate.community.dialect.SQLiteDialect",
                "spring.jpa.hibernate.ddl-auto=create-drop",
                "specus.netty.port=0",
                "specus.database.seed-demo-client=false",
                "specus.env=dev",
                "specus.auth.username=admin",
                "specus.auth.password=admin"
        }
)
class HttpWebSocketRoutingTests {

    @Value("${local.server.port}")
    private int port;

    @Test
    void websocketUpgradeUsesTunnelHandlerInsteadOfHttpController() throws Exception {
        try (Socket socket = new Socket(InetAddress.getLoopbackAddress(), port)) {
            socket.setSoTimeout(5_000);
            String request = "GET /http/offline-client/route/socket HTTP/1.1\r\n"
                    + "Host: localhost:" + port + "\r\n"
                    + "Connection: Upgrade\r\n"
                    + "Upgrade: websocket\r\n"
                    + "Sec-WebSocket-Version: 13\r\n"
                    + "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
                    + "Origin: http://localhost:" + port + "\r\n"
                    + "\r\n";
            socket.getOutputStream().write(request.getBytes(StandardCharsets.US_ASCII));
            socket.getOutputStream().flush();

            BufferedReader response = new BufferedReader(new InputStreamReader(
                    socket.getInputStream(), StandardCharsets.US_ASCII));
            assertThat(response.readLine()).startsWith("HTTP/1.1 101");
        }
    }

    @Test
    void plainHttpGetIsNotCapturedByWebSocketHandshake() throws Exception {
        HttpResponse<String> response = HttpClient.newHttpClient().send(
                HttpRequest.newBuilder(URI.create(
                        "http://localhost:" + port + "/http/offline-client/route/")).GET().build(),
                HttpResponse.BodyHandlers.ofString());
        assertThat(response.statusCode())
                .as("plain GET must reach HttpSpecusController, not the WebSocket handshake: %s",
                        response.body())
                .isEqualTo(502);
        assertThat(response.body()).contains("客户端不在线");
    }

    @Test
    void rawQueryBracesReachTunnelControllerInsteadOfTomcat400() throws Exception {
        try (Socket socket = new Socket(InetAddress.getLoopbackAddress(), port)) {
            socket.setSoTimeout(5_000);
            String request = "GET /http/offline-client/route/webapi/entry.cgi?path=icon_{0}.png HTTP/1.1\r\n"
                    + "Host: localhost:" + port + "\r\n"
                    + "Connection: close\r\n"
                    + "\r\n";
            socket.getOutputStream().write(request.getBytes(StandardCharsets.US_ASCII));
            socket.getOutputStream().flush();

            BufferedReader response = new BufferedReader(new InputStreamReader(
                    socket.getInputStream(), StandardCharsets.US_ASCII));
            assertThat(response.readLine())
                    .as("raw braces in a tunnel query must reach HttpSpecusController")
                    .startsWith("HTTP/1.1 502");
        }
    }

    @Test
    void unrelatedRawQueryCharactersRemainRejectedByTomcat() throws Exception {
        try (Socket socket = new Socket(InetAddress.getLoopbackAddress(), port)) {
            socket.setSoTimeout(5_000);
            String request = "GET /http/offline-client/route/items?invalid=| HTTP/1.1\r\n"
                    + "Host: localhost:" + port + "\r\n"
                    + "Connection: close\r\n"
                    + "\r\n";
            socket.getOutputStream().write(request.getBytes(StandardCharsets.US_ASCII));
            socket.getOutputStream().flush();

            BufferedReader response = new BufferedReader(new InputStreamReader(
                    socket.getInputStream(), StandardCharsets.US_ASCII));
            assertThat(response.readLine())
                    .as("Tomcat relaxation must remain limited to query braces")
                    .startsWith("HTTP/1.1 400");
        }
    }

    @Test
    void runtimePolyfillAssetIsPublicJavaScript() throws Exception {
        HttpResponse<String> response = HttpClient.newHttpClient().send(
                HttpRequest.newBuilder(URI.create(
                        "http://localhost:" + port + "/specus-http-route-runtime.js?v=2")).GET().build(),
                HttpResponse.BodyHandlers.ofString());

        assertThat(response.statusCode()).isEqualTo(200);
        assertThat(response.headers().firstValue("Content-Type").orElse(""))
                .containsIgnoringCase("javascript");
        assertThat(response.body())
                .contains("data-specus-prefix")
                .contains("normalizePath");
    }
}
