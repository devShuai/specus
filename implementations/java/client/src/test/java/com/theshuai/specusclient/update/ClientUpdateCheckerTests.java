package com.theshuai.specusclient.update;

import com.sun.net.httpserver.HttpServer;
import com.theshuai.specusclient.bean.ClientStartupConfig;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class ClientUpdateCheckerTests {
    @Test
    void checksJavaAnyTargetAndNotifiesOnceWithoutReplacingTheJar() throws Exception {
        AtomicInteger requests = new AtomicInteger();
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/api/public/client-version-check", exchange -> {
            requests.incrementAndGet();
            assertThat(exchange.getRequestURI().getRawQuery())
                    .contains("implementation=java", "platform=any", "arch=any", "current=1.2.3");
            byte[] body = ("{\"updateAvailable\":true,\"latestVersion\":\"v1.3.0+build.01\"," +
                    "\"packageId\":42,\"sha256\":\"" + "a".repeat(64) + "\"," +
                    "\"fileSize\":123,\"changelogUrl\":\"https://example.test/changes\"," +
                    "\"mandatory\":false,\"downloadUrl\":\"/api/public/client-packages/42/download\"}")
                    .getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().set("Content-Type", "application/json");
            exchange.sendResponseHeaders(200, body.length);
            exchange.getResponseBody().write(body);
            exchange.close();
        });
        server.start();

        AtomicReference<Notification> notification = new AtomicReference<>();
        AtomicInteger notifications = new AtomicInteger();
        ClientStartupConfig config = new ClientStartupConfig();
        config.setServerBaseUrl("http://127.0.0.1:" + server.getAddress().getPort());
        config.setAutoUpdate(true);
        ClientUpdateChecker checker = new ClientUpdateChecker(
                config, "1.2.3", (current, response, guide, download) -> {
                    notifications.incrementAndGet();
                    notification.set(new Notification(current, response.latestVersion(), guide, download));
                });
        try {
            checker.checkSafely();
            checker.checkSafely();
        } finally {
            checker.close();
            server.stop(0);
        }

        assertThat(requests).hasValue(2);
        assertThat(notifications).hasValue(1);
        assertThat(notification.get().current()).isEqualTo("1.2.3");
        assertThat(notification.get().latest()).isEqualTo("v1.3.0+build.01");
        assertThat(notification.get().guide().getPath()).isEqualTo("/download");
        assertThat(notification.get().download().getPath())
                .isEqualTo("/api/public/client-packages/42/download");
    }

    @Test
    void defaultsToStartupAndTwentyFourHourChecksButAllowsExplicitDisable() {
        ClientStartupConfig config = new ClientStartupConfig();
        assertThat(config.isUpdateCheckEnabled()).isTrue();
        assertThat(config.getUpdateCheckIntervalHours()).isEqualTo(24);
        assertThat(config.isOpenUpdatePage()).isTrue();
        assertThat(config.isAutoUpdate()).isFalse();
        config.setUpdateCheckEnabled(false);
        assertThat(config.isUpdateCheckEnabled()).isFalse();
        assertThat(ClientUpdateChecker.normalizedIntervalHours(-1)).isEqualTo(24);
        assertThat(ClientUpdateChecker.normalizedIntervalHours(0)).isEqualTo(24);
        assertThat(ClientUpdateChecker.normalizedIntervalHours(1)).isEqualTo(1);
        assertThat(ClientUpdateChecker.normalizedIntervalHours(24)).isEqualTo(24);
        assertThat(ClientUpdateChecker.normalizedIntervalHours(999)).isEqualTo(168);
    }

    @Test
    void acceptsAuthoritativeExternalReleaseAssetWithoutHostedPackageId() throws Exception {
        String external = "https://github.com/devShuai/specus/releases/download/v1.3.0/specus-java.zip";
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/api/public/client-version-check", exchange -> {
            byte[] body = updateJson("null", '"' + "a".repeat(64) + '"', 123,
                    '"' + external + '"').getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(200, body.length);
            exchange.getResponseBody().write(body);
            exchange.close();
        });
        server.start();
        AtomicReference<URI> download = new AtomicReference<>();
        ClientUpdateChecker checker = checker(server,
                (current, response, guide, uri) -> download.set(uri));
        try {
            checker.checkSafely();
            assertThat(download.get()).isEqualTo(URI.create(external));
        } finally {
            checker.close();
            server.stop(0);
        }
    }

    @Test
    void rejectsVersionMetadataLargerThanSixtyFourKiB() throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/api/public/client-version-check", exchange -> {
            byte[] body = "x".repeat(64 * 1024 + 1).getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(200, body.length);
            exchange.getResponseBody().write(body);
            exchange.close();
        });
        server.start();
        ClientUpdateChecker checker = checker(server, (current, response, guide, download) -> { });
        try {
            assertThatThrownBy(checker::checkOnce)
                    .isInstanceOf(IOException.class)
                    .hasMessageContaining("64 KiB");
        } finally {
            checker.close();
            server.stop(0);
        }
    }

    @Test
    void timesOutWhenServerStallsAfterSendingResponseHeaders() throws Exception {
        CountDownLatch releaseBody = new CountDownLatch(1);
        ExecutorService serverExecutor = Executors.newCachedThreadPool();
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.setExecutor(serverExecutor);
        server.createContext("/api/public/client-version-check", exchange -> {
            exchange.sendResponseHeaders(200, 0L);
            exchange.getResponseBody().write('{');
            exchange.getResponseBody().flush();
            try {
                releaseBody.await();
            } catch (InterruptedException exception) {
                Thread.currentThread().interrupt();
            } finally {
                exchange.close();
            }
        });
        server.start();
        ClientStartupConfig config = new ClientStartupConfig();
        config.setServerBaseUrl("http://127.0.0.1:" + server.getAddress().getPort());
        ClientUpdateChecker checker = new ClientUpdateChecker(config, "1.2.3",
                (current, response, guide, download) -> { }, HttpClient.newHttpClient(),
                Duration.ofMillis(150));
        try {
            assertThatThrownBy(checker::checkOnce)
                    .isInstanceOf(IOException.class)
                    .hasMessageContaining("timed out");
        } finally {
            releaseBody.countDown();
            checker.close();
            server.stop(0);
            serverExecutor.shutdownNow();
        }
    }

    @ParameterizedTest
    @MethodSource("invalidHostedMetadata")
    void rejectsUpdateWithInvalidHostedMetadata(String body, String expectedMessage) throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/api/public/client-version-check", exchange -> {
            byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().set("Content-Type", "application/json");
            exchange.sendResponseHeaders(200, bytes.length);
            exchange.getResponseBody().write(bytes);
            exchange.close();
        });
        server.start();
        AtomicInteger notifications = new AtomicInteger();
        ClientUpdateChecker checker = checker(server,
                (current, response, guide, download) -> notifications.incrementAndGet());
        try {
            assertThatThrownBy(checker::checkOnce)
                    .isInstanceOf(IOException.class)
                    .hasMessageContaining(expectedMessage);
            checker.checkSafely();
            assertThat(notifications).hasValue(0);
        } finally {
            checker.close();
            server.stop(0);
        }
    }

    private static Stream<Arguments> invalidHostedMetadata() {
        String sha = "a".repeat(64);
        return Stream.of(
                Arguments.of(updateJson("null", '"' + sha + '"', 10,
                        "\"/api/public/client-packages/42/download\""), "absolute HTTPS"),
                Arguments.of(updateJson("0", '"' + sha + '"', 10,
                        "\"/api/public/client-packages/42/download\""), "packageId"),
                Arguments.of(updateJson("42", "\"bad\"", 10,
                        "\"/api/public/client-packages/42/download\""), "sha256"),
                Arguments.of(updateJson("42", '"' + sha + '"', 0,
                        "\"/api/public/client-packages/42/download\""), "fileSize"),
                Arguments.of(updateJson("42", '"' + sha + '"', 10,
                        "\"https://updates.invalid/api/public/client-packages/42/download\""), "server origin"),
                Arguments.of(updateJson("42", '"' + sha + '"', 10,
                        "\"/api/public/client-packages/99/download\""), "server origin"),
                Arguments.of(updateJson("null", '"' + sha + '"', 10,
                        "\"http://github.com/devShuai/specus/releases/download/v1.3.0/client.zip\""),
                        "absolute HTTPS"),
                Arguments.of(updateJson("null", '"' + sha + '"', 10,
                        "\"https://github.com/devShuai/specus/releases/download/v1.3.0/client.zip?raw=1\""),
                        "absolute HTTPS"),
                Arguments.of(updateJson("42", '"' + sha + '"', 10,
                        "\"/api/public/client-packages/42/download\"")
                        .replace("\"latestVersion\":\"1.3.0\"",
                                "\"latestVersion\":\"1.3.0-01\""), "latestVersion")
        );
    }

    private static String updateJson(String packageId, String sha256, long fileSize, String downloadUrl) {
        return "{\"updateAvailable\":true,\"latestVersion\":\"1.3.0\","
                + "\"packageId\":" + packageId + ",\"sha256\":" + sha256 + ","
                + "\"fileSize\":" + fileSize + ",\"mandatory\":false,"
                + "\"downloadUrl\":" + downloadUrl + "}";
    }

    private ClientUpdateChecker checker(HttpServer server, ClientUpdateChecker.UpdateNotifier notifier) {
        ClientStartupConfig config = new ClientStartupConfig();
        config.setServerBaseUrl("http://127.0.0.1:" + server.getAddress().getPort());
        return new ClientUpdateChecker(config, "1.2.3", notifier);
    }

    private record Notification(String current, String latest, URI guide, URI download) { }
}
