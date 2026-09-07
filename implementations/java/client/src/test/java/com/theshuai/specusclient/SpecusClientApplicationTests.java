package com.theshuai.specusclient;

import org.junit.jupiter.api.Test;
import com.sun.net.httpserver.HttpServer;
import com.theshuai.specusclient.bean.ClientStartupConfig;
import com.theshuai.specusclient.auth.HttpLoginFailure;
import com.theshuai.specusclient.auth.FirstLoginRetry;
import com.theshuai.common.clientauth.ClientAuthLoginRequest;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

//@SpringBootTest
class SpecusClientApplicationTests {
    @Test void loginBudgetAlsoBoundsAStalledResponseBody() throws Exception {
        var server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        var bodyStarted = new java.util.concurrent.atomic.AtomicBoolean();
        server.createContext("/api/client/auth/login", exchange -> {
            exchange.getRequestBody().readAllBytes();
            exchange.sendResponseHeaders(200, 100);
            try {
                exchange.getResponseBody().write('{');
                exchange.getResponseBody().flush();
                bodyStarted.set(true);
                Thread.sleep(2_000);
            } catch (InterruptedException error) { Thread.currentThread().interrupt(); }
            finally { exchange.close(); }
        });
        server.start();
        try {
            var config = new ClientStartupConfig();
            config.setServerBaseUrl("http://127.0.0.1:" + server.getAddress().getPort());
            long start = System.nanoTime();
            assertThatThrownBy(() -> SpecusClientApplication.postLogin(config, new ClientAuthLoginRequest(), Duration.ofMillis(750)))
                    .isInstanceOf(HttpLoginFailure.class);
            assertThat(bodyStarted.get()).as("test must reach the stalled body, not just a connect timeout").isTrue();
            assertThat(Duration.ofNanos(System.nanoTime() - start)).isLessThan(Duration.ofMillis(1500));
        } finally { server.stop(0); }
    }

    @Test void realHttpErrorsAndMalformedResponsesDoNotExposeBody() throws Exception {
        var server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        var status = new AtomicInteger(401);
        server.createContext("/api/client/auth/login", exchange -> {
            exchange.getRequestBody().readAllBytes();
            byte[] body = "{\"accessToken\":DO_NOT_PRINT_TOKEN}".getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(status.get(), body.length);
            try (var output = exchange.getResponseBody()) { output.write(body); }
        });
        server.start();
        try {
            var config = new ClientStartupConfig();
            config.setServerBaseUrl("http://127.0.0.1:" + server.getAddress().getPort());
            for (int code : new int[]{400, 401, 403, 503, 200}) {
                status.set(code);
                assertThatThrownBy(() -> SpecusClientApplication.postLogin(config, new ClientAuthLoginRequest(), Duration.ofSeconds(2)))
                        .isInstanceOf(HttpLoginFailure.class).hasMessageNotContaining("DO_NOT_PRINT_TOKEN")
                        .hasNoCause();
            }
        } finally { server.stop(0); }
    }

    @Test void firstLoginRecoversFromTemporaryHttpFailure() throws Exception {
        var server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        var calls = new AtomicInteger();
        server.createContext("/api/client/auth/login", exchange -> {
            exchange.getRequestBody().readAllBytes();
            boolean ready = calls.incrementAndGet() > 1;
            byte[] body = (ready ? "{\"clientName\":\"test\",\"clientSessionId\":1,\"accessToken\":\"token\",\"nettyHost\":\"127.0.0.1\",\"nettyPort\":8080}" : "unavailable").getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(ready ? 200 : 503, body.length);
            try (var output = exchange.getResponseBody()) { output.write(body); }
        });
        server.start();
        try {
            var config = new ClientStartupConfig();
            config.setServerBaseUrl("http://127.0.0.1:" + server.getAddress().getPort());
            var response = FirstLoginRetry.login(Duration.ofSeconds(5),
                    remaining -> SpecusClientApplication.postLogin(config, new ClientAuthLoginRequest(), remaining), ignored -> { });
            assertThat(response.getClientName()).isEqualTo("test");
            assertThat(calls.get()).isEqualTo(2);
        } finally { server.stop(0); }
    }

    //    @Test
    void contextLoads() {
    }

    @Test
    void reportsManifestVersionOrDeterministicDevelopmentFallback() {
        assertThat(SpecusClientApplication.currentVersion()).isNotBlank();
        if (SpecusClientApplication.class.getPackage().getImplementationVersion() == null) {
            assertThat(SpecusClientApplication.currentVersion()).isEqualTo("0.0.0-dev");
        }
    }

}
