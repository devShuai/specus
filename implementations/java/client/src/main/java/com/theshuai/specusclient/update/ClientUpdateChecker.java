package com.theshuai.specusclient.update;

import com.theshuai.common.util.JsonUtil;
import com.theshuai.specusclient.bean.ClientStartupConfig;
import lombok.extern.slf4j.Slf4j;
import org.springframework.util.StringUtils;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Locale;
import java.util.Objects;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Startup and 24-hour update checks. Phase one deliberately never downloads or replaces the jar. */
@Slf4j
public final class ClientUpdateChecker implements AutoCloseable {
    private static final int MAX_METADATA_BYTES = 64 * 1024;
    private static final Duration BODY_READ_TIMEOUT = Duration.ofSeconds(20);
    private static final Pattern SEMANTIC_VERSION = Pattern.compile(
            "^(0|[1-9]\\d*)\\.(0|[1-9]\\d*)\\.(0|[1-9]\\d*)"
                    + "(?:-([0-9A-Za-z-]+(?:\\.[0-9A-Za-z-]+)*))?"
                    + "(?:\\+([0-9A-Za-z-]+(?:\\.[0-9A-Za-z-]+)*))?$"
    );

    private final ClientStartupConfig config;
    private final String currentVersion;
    private final UpdateNotifier notifier;
    private final HttpClient httpClient;
    private final Duration bodyReadTimeout;
    private final ScheduledExecutorService executor;
    private final ExecutorService bodyExecutor;
    private final AtomicBoolean started = new AtomicBoolean();
    private volatile String lastNotifiedVersion;

    public ClientUpdateChecker(ClientStartupConfig config, String currentVersion, UpdateNotifier notifier) {
        this(config, currentVersion, notifier,
                HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(10)).build());
    }

    ClientUpdateChecker(ClientStartupConfig config, String currentVersion, UpdateNotifier notifier,
                        HttpClient httpClient) {
        this(config, currentVersion, notifier, httpClient, BODY_READ_TIMEOUT);
    }

    ClientUpdateChecker(ClientStartupConfig config, String currentVersion, UpdateNotifier notifier,
                        HttpClient httpClient, Duration bodyReadTimeout) {
        this.config = Objects.requireNonNull(config);
        this.currentVersion = requireVersion(currentVersion);
        this.notifier = Objects.requireNonNull(notifier);
        this.httpClient = Objects.requireNonNull(httpClient);
        this.bodyReadTimeout = Objects.requireNonNull(bodyReadTimeout);
        if (bodyReadTimeout.isZero() || bodyReadTimeout.isNegative()) {
            throw new IllegalArgumentException("bodyReadTimeout must be positive");
        }
        this.executor = Executors.newSingleThreadScheduledExecutor(runnable -> {
            Thread thread = new Thread(runnable, "specus-update-check");
            thread.setDaemon(true);
            return thread;
        });
        this.bodyExecutor = Executors.newThreadPerTaskExecutor(
                Thread.ofVirtual().name("specus-update-body-", 0L).factory());
    }

    public void start() {
        if (!config.isUpdateCheckEnabled() || !started.compareAndSet(false, true)) {
            return;
        }
        long intervalHours = normalizedIntervalHours(config.getUpdateCheckIntervalHours());
        executor.scheduleWithFixedDelay(this::checkSafely, 0L, intervalHours, TimeUnit.HOURS);
    }

    static long normalizedIntervalHours(long configured) {
        return configured <= 0L ? 24L : Math.min(168L, configured);
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
        HttpResponse<InputStream> response = httpClient.send(request, HttpResponse.BodyHandlers.ofInputStream());
        try (InputStream body = response.body()) {
            if (response.statusCode() < 200 || response.statusCode() >= 300) {
                throw new IOException("version check returned HTTP " + response.statusCode());
            }
            long declaredLength = response.headers().firstValueAsLong("Content-Length").orElse(-1L);
            if (declaredLength > MAX_METADATA_BYTES) {
                throw new IOException("version check response exceeds 64 KiB");
            }
            byte[] bytes = readBodyWithDeadline(body);
            if (bytes.length > MAX_METADATA_BYTES) {
                throw new IOException("version check response exceeds 64 KiB");
            }
            UpdateCheckResponse result = JsonUtil.stringToObject(
                    new String(bytes, StandardCharsets.UTF_8), UpdateCheckResponse.class);
            if (result == null) {
                throw new IOException("version check returned an empty response");
            }
            validateUpdateMetadata(result);
            return result;
        }
    }

    private byte[] readBodyWithDeadline(InputStream body) throws IOException, InterruptedException {
        Future<byte[]> read = bodyExecutor.submit(() -> body.readNBytes(MAX_METADATA_BYTES + 1));
        try {
            return read.get(bodyReadTimeout.toMillis(), TimeUnit.MILLISECONDS);
        } catch (TimeoutException exception) {
            closeQuietly(body);
            read.cancel(true);
            throw new IOException("version check response body timed out", exception);
        } catch (ExecutionException exception) {
            Throwable cause = exception.getCause();
            if (cause instanceof IOException ioException) {
                throw ioException;
            }
            if (cause instanceof RuntimeException runtimeException) {
                throw runtimeException;
            }
            throw new IOException("version check response body could not be read", cause);
        } catch (InterruptedException exception) {
            closeQuietly(body);
            read.cancel(true);
            throw exception;
        }
    }

    private static void closeQuietly(InputStream body) {
        try {
            body.close();
        } catch (IOException ignored) {
            // The original timeout/interruption remains the useful failure.
        }
    }

    void checkSafely() {
        try {
            UpdateCheckResponse result = checkOnce();
            if (!result.updateAvailable() || !StringUtils.hasText(result.latestVersion())
                    || result.latestVersion().equals(lastNotifiedVersion)) {
                return;
            }
            URI download = resolveDownload(result);
            URI guide = URI.create(baseUrl() + "/download");
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
        try {
            return validatedDownloadUri(result);
        } catch (IOException exception) {
            throw new IllegalArgumentException(exception.getMessage(), exception);
        }
    }

    private void validateUpdateMetadata(UpdateCheckResponse result) throws IOException {
        if (!result.updateAvailable()) {
            return;
        }
        if (!isSemanticVersion(result.latestVersion())) {
            throw new IOException("version check returned an invalid latestVersion");
        }
        if (result.packageId() != null && result.packageId() <= 0) {
            throw new IOException("version check returned an invalid packageId");
        }
        if (result.fileSize() <= 0) {
            throw new IOException("version check returned an invalid fileSize");
        }
        if (result.sha256() == null || !result.sha256().matches("[0-9a-fA-F]{64}")) {
            throw new IOException("version check returned an invalid sha256");
        }
        validatedDownloadUri(result);
    }

    private boolean isSemanticVersion(String value) {
        if (!StringUtils.hasText(value)) {
            return false;
        }
        String normalized = value.trim();
        if (normalized.startsWith("v")) {
            normalized = normalized.substring(1);
        }
        if (normalized.isEmpty() || normalized.length() > 32) {
            return false;
        }
        Matcher matcher = SEMANTIC_VERSION.matcher(normalized);
        if (!matcher.matches()) {
            return false;
        }
        if (matcher.group(4) != null) {
            for (String identifier : matcher.group(4).split("\\.")) {
                if (identifier.length() > 1 && identifier.chars().allMatch(Character::isDigit)
                        && identifier.charAt(0) == '0') {
                    return false;
                }
            }
        }
        return true;
    }

    private URI validatedDownloadUri(UpdateCheckResponse result) throws IOException {
        if (!StringUtils.hasText(result.downloadUrl())) {
            throw new IOException("version check returned an invalid downloadUrl");
        }
        URI server;
        URI download;
        try {
            server = URI.create(baseUrl());
            URI candidate = URI.create(result.downloadUrl().trim());
            download = result.packageId() == null
                    ? candidate
                    : (candidate.isAbsolute() ? candidate : server.resolve(candidate));
        } catch (IllegalArgumentException exception) {
            throw new IOException("version check returned an invalid downloadUrl", exception);
        }
        if (result.packageId() != null) {
            String expectedPath = "/api/public/client-packages/" + result.packageId() + "/download";
            if (!sameOrigin(server, download)
                    || download.getUserInfo() != null
                    || !expectedPath.equals(download.getRawPath())
                    || download.getRawQuery() != null
                    || download.getRawFragment() != null) {
                throw new IOException("hosted update download must use the version server origin");
            }
            return download;
        }
        if (!download.isAbsolute()
                || !"https".equalsIgnoreCase(download.getScheme())
                || download.getHost() == null
                || download.getUserInfo() != null
                || download.getRawQuery() != null
                || download.getRawFragment() != null) {
            throw new IOException("external update download must use an absolute HTTPS URL");
        }
        return download;
    }

    private static boolean sameOrigin(URI left, URI right) {
        String leftScheme = left.getScheme() == null ? "" : left.getScheme().toLowerCase(Locale.ROOT);
        String rightScheme = right.getScheme() == null ? "" : right.getScheme().toLowerCase(Locale.ROOT);
        return ("http".equals(leftScheme) || "https".equals(leftScheme))
                && leftScheme.equals(rightScheme)
                && left.getHost() != null && right.getHost() != null
                && left.getHost().equalsIgnoreCase(right.getHost())
                && effectivePort(left) == effectivePort(right);
    }

    private static int effectivePort(URI uri) {
        if (uri.getPort() >= 0) {
            return uri.getPort();
        }
        return "https".equals(uri.getScheme().toLowerCase(Locale.ROOT)) ? 443 : 80;
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
        bodyExecutor.shutdownNow();
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
