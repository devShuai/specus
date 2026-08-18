package com.theshuai.specus.android;

import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Locale;

/** Small, dependency-free client for the anonymous version catalog. */
final class ClientUpdateChecker {
    static final long CHECK_INTERVAL_MILLIS = 24L * 60L * 60L * 1000L;
    private static final int MAX_RESPONSE_BYTES = 64 * 1024;
    private static final int TIMEOUT_MILLIS = 8_000;

    private ClientUpdateChecker() {
    }

    static boolean shouldCheck(long lastCheckMillis, long nowMillis) {
        return lastCheckMillis <= 0 || nowMillis < lastCheckMillis
                || nowMillis - lastCheckMillis >= CHECK_INTERVAL_MILLIS;
    }

    static Result check(String serverBaseUrl, String currentVersion) throws Exception {
        URI base = requireSafeBaseUri(serverBaseUrl);
        String query = "implementation=android&platform=android&arch=any&current="
                + URLEncoder.encode(normalizeVersion(currentVersion), StandardCharsets.UTF_8);
        URI endpoint = base.resolve("/api/public/client-version-check?" + query);
        HttpURLConnection connection = (HttpURLConnection) endpoint.toURL().openConnection();
        connection.setConnectTimeout(TIMEOUT_MILLIS);
        connection.setReadTimeout(TIMEOUT_MILLIS);
        connection.setInstanceFollowRedirects(false);
        connection.setRequestMethod("GET");
        connection.setRequestProperty("Accept", "application/json");
        connection.setRequestProperty("User-Agent", "specus-android/" + normalizeVersion(currentVersion));
        try {
            int status = connection.getResponseCode();
            if (status != HttpURLConnection.HTTP_OK) {
                throw new IOException("version check returned HTTP " + status);
            }
            String body;
            try (InputStream input = connection.getInputStream()) {
                body = new String(readBounded(input), StandardCharsets.UTF_8);
            }
            return parse(body, base);
        } finally {
            connection.disconnect();
        }
    }

    static Result parse(String json, URI serverBaseUri) throws Exception {
        JSONObject body = new JSONObject(json == null ? "" : json);
        boolean updateAvailable = body.optBoolean("updateAvailable", false);
        boolean mandatory = body.optBoolean("mandatory", false);
        String latestVersion = body.optString("latestVersion", "").trim();
        if (!updateAvailable) {
            return new Result(false, mandatory, latestVersion, null, null);
        }
        if (latestVersion.isEmpty()) {
            throw new IOException("version response omitted latestVersion");
        }
        String sha256 = body.optString("sha256", "").trim().toLowerCase(Locale.ROOT);
        if (!sha256.matches("[0-9a-f]{64}")) {
            throw new IOException("version response contains an invalid sha256");
        }
        long fileSize = body.optLong("fileSize", -1L);
        if (fileSize < 1L) {
            throw new IOException("version response contains an invalid fileSize");
        }
        String rawDownloadUrl = body.optString("downloadUrl", "").trim();
        if (rawDownloadUrl.isEmpty()) {
            throw new IOException("version response omitted downloadUrl");
        }
        URI downloadUri = serverBaseUri.resolve(rawDownloadUrl);
        requireSafeDownloadUri(serverBaseUri, downloadUri);
        String changelog = body.optString("changelogUrl", "").trim();
        URI changelogUri = null;
        if (!changelog.isEmpty()) {
            URI candidate = serverBaseUri.resolve(changelog);
            requireSafeDownloadUri(serverBaseUri, candidate);
            changelogUri = candidate;
        }
        return new Result(true, mandatory, latestVersion, downloadUri.toString(),
                changelogUri == null ? null : changelogUri.toString());
    }

    private static URI requireSafeBaseUri(String raw) throws Exception {
        URI uri = new URI(raw == null ? "" : raw.trim());
        if (!uri.isAbsolute() || uri.getHost() == null || !isSafeScheme(uri)) {
            throw new IOException("serverBaseUrl must be an absolute HTTPS URL");
        }
        String normalized = uri.toString();
        if (!normalized.endsWith("/")) {
            normalized += "/";
        }
        return new URI(normalized);
    }

    private static void requireSafeDownloadUri(URI base, URI value) throws IOException {
        if (!value.isAbsolute() || value.getHost() == null || !isSafeScheme(value)) {
            throw new IOException("version response contains an unsafe URL");
        }
        // Relative package links must stay on the configured server. Absolute HTTPS changelog or
        // package URLs remain supported for reverse proxies and external release notes.
        if (!"https".equalsIgnoreCase(value.getScheme())
                && !value.getHost().equalsIgnoreCase(base.getHost())) {
            throw new IOException("clear-text download URL must stay on the configured server");
        }
    }

    private static boolean isSafeScheme(URI uri) {
        if ("https".equalsIgnoreCase(uri.getScheme())) {
            return true;
        }
        if (!"http".equalsIgnoreCase(uri.getScheme())) {
            return false;
        }
        String host = uri.getHost();
        return "localhost".equalsIgnoreCase(host) || "127.0.0.1".equals(host) || "::1".equals(host);
    }

    private static String normalizeVersion(String value) {
        String normalized = value == null ? "" : value.trim();
        return normalized.startsWith("v") ? normalized.substring(1) : normalized;
    }

    private static byte[] readBounded(InputStream input) throws IOException {
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        byte[] buffer = new byte[4096];
        int read;
        while ((read = input.read(buffer)) >= 0) {
            if (output.size() + read > MAX_RESPONSE_BYTES) {
                throw new IOException("version response is too large");
            }
            output.write(buffer, 0, read);
        }
        return output.toByteArray();
    }

    record Result(boolean updateAvailable, boolean mandatory, String latestVersion,
                  String downloadUrl, String changelogUrl) {
    }
}
