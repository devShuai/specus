package com.theshuai.specusserver.security;

import com.sun.net.httpserver.HttpServer;
import com.theshuai.specusserver.config.TurnstileProperties;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.server.ResponseStatusException;

import java.net.InetSocketAddress;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class TurnstileVerifierTests {
    private HttpServer server;

    @AfterEach
    void stopServer() {
        if (server != null) {
            server.stop(0);
        }
    }

    @Test
    void declaresTheProductionConstructorAsTheInjectionPoint() {
        long injectionConstructors = Arrays.stream(TurnstileVerifier.class.getDeclaredConstructors())
                .filter(constructor -> constructor.isAnnotationPresent(Autowired.class))
                .count();

        assertThat(injectionConstructors).isEqualTo(1);
    }

    @Test
    void verifiesActionAndHostname() throws Exception {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/verify", exchange -> {
            String requestBody = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
            assertThat(requestBody).contains("secret=test-secret", "response=browser-token");
            byte[] body = "{\"success\":true,\"action\":\"login\",\"hostname\":\"specus.example.com\"}"
                    .getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().set("Content-Type", "application/json");
            exchange.sendResponseHeaders(200, body.length);
            exchange.getResponseBody().write(body);
            exchange.close();
        });
        server.start();

        TurnstileProperties properties = properties();
        properties.setVerifyUrl("http://127.0.0.1:" + server.getAddress().getPort() + "/verify");
        TurnstileVerifier verifier = new TurnstileVerifier(properties, HttpClient.newHttpClient());
        verifier.verify("browser-token", TurnstileVerifier.LOGIN_ACTION);

        assertThatThrownBy(() -> verifier.verify("browser-token", TurnstileVerifier.REGISTER_ACTION))
                .isInstanceOf(ResponseStatusException.class)
                .hasMessageContaining("400 BAD_REQUEST");
    }

    @Test
    void rejectsUnexpectedHostname() throws Exception {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/verify", exchange -> {
            byte[] body = "{\"success\":true,\"action\":\"login\",\"hostname\":\"attacker.example\"}"
                    .getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(200, body.length);
            exchange.getResponseBody().write(body);
            exchange.close();
        });
        server.start();
        TurnstileProperties properties = properties();
        properties.setVerifyUrl("http://127.0.0.1:" + server.getAddress().getPort() + "/verify");
        TurnstileVerifier verifier = new TurnstileVerifier(properties, HttpClient.newHttpClient());

        assertThatThrownBy(() -> verifier.verify("token", TurnstileVerifier.LOGIN_ACTION))
                .isInstanceOf(ResponseStatusException.class)
                .hasMessageContaining("400 BAD_REQUEST");
    }

    @Test
    void failsClosedWhenEnabledWithoutKeysOrHostnames() {
        TurnstileProperties properties = new TurnstileProperties();
        properties.setEnabled(true);
        TurnstileVerifier verifier = new TurnstileVerifier(properties, HttpClient.newHttpClient());

        assertThatThrownBy(() -> verifier.verify("token", TurnstileVerifier.LOGIN_ACTION))
                .isInstanceOf(ResponseStatusException.class)
                .hasMessageContaining("503 SERVICE_UNAVAILABLE");
    }

    private static TurnstileProperties properties() {
        TurnstileProperties properties = new TurnstileProperties();
        properties.setEnabled(true);
        properties.setSiteKey("test-site");
        properties.setSecretKey("test-secret");
        properties.setAllowedHostnames(List.of("specus.example.com"));
        return properties;
    }
}
