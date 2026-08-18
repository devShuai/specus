package com.theshuai.specusclient.update;

import com.theshuai.common.util.JsonUtil;
import com.theshuai.specusclient.bean.ClientStartupConfig;
import lombok.extern.slf4j.Slf4j;
import org.springframework.util.StringUtils;

import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Objects;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

/** Startup and 24-hour update checks. Phase one deliberately never downloads or replaces the jar. */
@Slf4j
public final class ClientUpdateChecker implements AutoCloseable {
    private final ClientStartupConfig config;
    private final String currentVersion;
    private final UpdateNotifier notifier;
    private final HttpClient httpClient;
    private final ScheduledExecutorService executor;
    private final AtomicBoolean started = new AtomicBoolean();
    private volatile String lastNotifiedVersion;

    public ClientUpdateChecker(ClientStartupConfig config, String currentVersion, UpdateNotifier notifier) {
        this(config, currentVersion, notifier,
                HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(10)).build());
    }

    ClientUpdateChecker(ClientStartupConfig config, String currentVersion, UpdateNotifier notifier,
                        HttpClient httpClient) {
        this.config = Objects.requireNonNull(config);
        this.currentVersion = requireVersion(currentVersion);
        this.notifier = Objects.requireNonNull(notifier);
        this.httpClient = Objects.requireNonNull(httpClient);
        this.executor = Executors.newSingleThreadScheduledExecutor(runnable -> {
            Thread thread = new Thread(runnable, "specus-update-check");
            thread.setDaemon(true);
            return thread;
        });
    }

    public void start() {
        if (!config.isUpdateCheckEnabled() || !started.compareAndSet(false, true)) {
            return;
        }
        long intervalHours = Math.max(1L, config.getUpdateCheckIntervalHours());
        executor.scheduleWithFixedDelay(this::checkSafely, 0L, intervalHours, TimeUnit.HOURS);
    }

    /** Visible for deterministic tests and an eventual explicit "check now" command. */
    public UpdateCheckResponse checkOnce() throws IOException, InterruptedException {
        URI endpoint = URI.create(baseUrl() + "/api/public/client-version-check"
                + "?implementation=java&platform=any&arch=any&current=" + encode(currentVersion));
        HttpRequest request = HttpRequest.newBuilder(endpoint)
                .timeout(Duration.ofSeconds(20))
                .header("Accept", "application/json")
                .GET()
                .build();
        HttpResponse<String> response = httpClient.send(
                request, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
        if (response.statusCode() < 200 || response.statusCode() >= 300) {
            throw new IOException("version check returned HTTP " + response.statusCode());
        }
        UpdateCheckResponse result = JsonUtil.stringToObject(response.body(), UpdateCheckResponse.class);
        if (result == null) {
            throw new IOException("version check returned an empty response");
        }
        return result;
    }

    private void checkSafely() {
        try {
            UpdateCheckResponse result = checkOnce();
            if (!result.updateAvailable() || !StringUtils.hasText(result.latestVersion())
                    || result.latestVersion().equals(lastNotifiedVersion)) {
                return;
            }
            URI download = resolveDownload(result);
            URI guide = URI.create(baseUrl() + "/downloads");
            notifier.notifyUpdate(currentVersion, result, guide, download);
            lastNotifiedVersion = result.latestVersion();
        } catch (InterruptedException exception) {
            Thread.currentThread().interrupt();
        } catch (RuntimeException | IOException exception) {
            // Update availability must never make the tunnelling client fail to start or reconnect.
            log.warn("客户端更新检查失败，将在下一个周期重试: {}", exception.getMessage());
        }
    }

    private URI resolveDownload(UpdateCheckResponse result) {
        if (StringUtils.hasText(result.downloadUrl())) {
            URI candidate = URI.create(result.downloadUrl().trim());
            return candidate.isAbsolute() ? candidate : URI.create(baseUrl() + ensureLeadingSlash(candidate.toString()));
        }
        if (result.packageId() != null && result.packageId() > 0) {
            return URI.create(baseUrl() + "/api/public/client-packages/"
                    + result.packageId() + "/download");
        }
        return URI.create(baseUrl() + "/downloads");
    }

    private String baseUrl() {
        String value = config.getServerBaseUrl() == null ? "" : config.getServerBaseUrl().trim();
        while (value.endsWith("/")) {
            value = value.substring(0, value.length() - 1);
        }
        if (!StringUtils.hasText(value)) {
            throw new IllegalStateException("serverBaseUrl is required for update checks");
        }
        return value;
    }

    private static String ensureLeadingSlash(String value) {
        return value.startsWith("/") ? value : "/" + value;
    }

    private static String encode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }

    private static String requireVersion(String value) {
        if (!StringUtils.hasText(value)) {
            throw new IllegalArgumentException("currentVersion cannot be blank");
        }
        return value.trim();
    }

    @Override
    public void close() {
        executor.shutdownNow();
    }

    @FunctionalInterface
    public interface UpdateNotifier {
        void notifyUpdate(String currentVersion, UpdateCheckResponse response,
                          URI guidePage, URI downloadUri);
    }

    public record UpdateCheckResponse(
            boolean updateAvailable,
            String latestVersion,
            Long packageId,
            String sha256,
            long fileSize,
            String changelogUrl,
            boolean mandatory,
            String downloadUrl
    ) { }
}
