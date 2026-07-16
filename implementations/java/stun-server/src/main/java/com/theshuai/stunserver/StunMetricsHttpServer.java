package com.theshuai.stunserver;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Objects;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.function.Supplier;

final class StunMetricsHttpServer implements AutoCloseable {
    private final StandaloneStunMetricsConfig config;
    private final Supplier<String> content;
    private HttpServer server;
    private ExecutorService executor;

    StunMetricsHttpServer(
            StandaloneStunMetricsConfig config,
            Supplier<String> content) {
        this.config = Objects.requireNonNull(config, "config");
        this.content = Objects.requireNonNull(content, "content");
    }

    void start() throws IOException {
        if (!config.enabled()) {
            return;
        }
        server = HttpServer.create(config.socketAddress(), 16);
        server.createContext("/metrics", this::handle);
        executor = Executors.newSingleThreadExecutor(runnable -> {
            Thread thread = new Thread(runnable, "standalone-stun-metrics");
            thread.setDaemon(true);
            return thread;
        });
        server.setExecutor(executor);
        server.start();
    }

    private void handle(HttpExchange exchange) throws IOException {
        try {
            if (!"GET".equalsIgnoreCase(exchange.getRequestMethod())) {
                exchange.sendResponseHeaders(405, -1);
                return;
            }
            byte[] body = content.get().getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().set(
                    "Content-Type",
                    "text/plain; version=0.0.4; charset=utf-8");
            exchange.getResponseHeaders().set("Cache-Control", "no-store");
            exchange.sendResponseHeaders(200, body.length);
            exchange.getResponseBody().write(body);
        } finally {
            exchange.close();
        }
    }

    @Override
    public void close() {
        if (server != null) {
            server.stop(0);
            server = null;
        }
        if (executor != null) {
            executor.shutdownNow();
            executor = null;
        }
    }
}
