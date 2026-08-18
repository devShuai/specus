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
import java.util.regex.Pattern;

/** Small, dependency-free client for the anonymous version catalog. */
final class ClientUpdateChecker {
    static final long CHECK_INTERVAL_MILLIS = 24L * 60L * 60L * 1000L;
    private static final int MAX_RESPONSE_BYTES = 64 * 1024;
    private static final int TIMEOUT_MILLIS = 8_000;
    private static final int MAX_VERSION_LENGTH = 32;
    private static final Pattern SEMVER = Pattern.compile(
            "^(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)"
                    + "(?:-(?:0|[1-9][0-9]*|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*)"
                    + "(?:\\.(?:0|[1-9][0-9]*|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*))*)?"
                    + "(?:\\+[0-9A-Za-z-]+(?:\\.[0-9A-Za-z-]+)*)?$");

    private ClientUpdateChecker() {
    }

    static boolean shouldCheck(long lastCheckMillis, long nowMillis) {
        return lastCheckMillis <= 0 || nowMillis < lastCheckMillis
                || nowMillis - lastCheckMillis >= CHECK_INTERVAL_MILLIS;
    }

    static Result check(String serverBaseUrl, String currentVersion) throws Exception {
        URI base = requireSafeBaseUri(serverBaseUrl);
        String query = "implementation=android&platform=android&arch=any&current="
                + URLEncoder.encode(normalizeVersion(currentVersion), StandardCharsets.UTF_8.name());
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
        if (!latestVersion.isEmpty()) {
            latestVersion = requireSemanticVersion(latestVersion);
        }
        if (!updateAvailable) {
            return new Result(false, mandatory, latestVersion, null, null);
        }
        if (latestVersion.isEmpty()) {
            throw new IOException("version response omitted latestVersion");
        }
        Long packageId = body.has("packageId") && !body.isNull("packageId")
                ? body.optLong("packageId", -1L)
                : null;
        if (packageId != null && packageId <= 0L) {
            throw new IOException("version response contains an invalid packageId");
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
        URI rawDownloadUri = new URI(rawDownloadUrl);
        URI downloadUri;
        if (packageId != null) {
            downloadUri = serverBaseUri.resolve(rawDownloadUri);
            requireSafeHostedPackageUri(serverBaseUri, downloadUri, packageId);
        } else {
            downloadUri = rawDownloadUri;
            requireSafeExternalPackageUri(downloadUri);
        }
        String changelog = body.optString("changelogUrl", "").trim();
        URI changelogUri = null;
        if (!changelog.isEmpty()) {
            URI candidate = serverBaseUri.resolve(changelog);
            requireSafeChangelogUri(serverBaseUri, candidate);
            changelogUri = candidate;
        }
        return new Result(true, mandatory, latestVersion, downloadUri.toString(),
                changelogUri == null ? null : changelogUri.toString());
    }

    private static URI requireSafeBaseUri(String raw) throws Exception {
        URI uri = new URI(raw == null ? "" : raw.trim());
        if (!uri.isAbsolute() || uri.getHost() == null || uri.getUserInfo() != null
                || !isSafeScheme(uri)) {
            throw new IOException("serverBaseUrl must be an absolute HTTPS URL");
        }
        String normalized = uri.toString();
        if (!normalized.endsWith("/")) {
            normalized += "/";
        }
        return new URI(normalized);
    }

    private static void requireSafeHostedPackageUri(URI base, URI value, long packageId) throws IOException {
        String expectedPath = "/api/public/client-packages/" + packageId + "/download";
        if (!isSafeAbsoluteUri(value) || !sameOrigin(base, value)
                || !expectedPath.equals(value.getRawPath())
                || value.getRawQuery() != null || value.getRawFragment() != null) {
            throw new IOException("hosted package URL must stay on the configured server origin");
        }
    }

    private static void requireSafeExternalPackageUri(URI value) throws IOException {
        if (!isSafeAbsoluteUri(value)
                || !"https".equalsIgnoreCase(value.getScheme())
                || value.getRawQuery() != null || value.getRawFragment() != null) {
            throw new IOException("external package URL must be an absolute HTTPS URL");
        }
    }

    private static void requireSafeChangelogUri(URI base, URI value) throws IOException {
        if (!isSafeAbsoluteUri(value)
                || (!"https".equalsIgnoreCase(value.getScheme()) && !sameOrigin(base, value))) {
            throw new IOException("version response contains an unsafe changelog URL");
        }
    }

    private static boolean isSafeAbsoluteUri(URI value) {
        return value.isAbsolute() && value.getHost() != null && value.getUserInfo() == null
                && isSafeScheme(value);
    }

    private static boolean sameOrigin(URI left, URI right) {
        return left.getScheme().equalsIgnoreCase(right.getScheme())
                && left.getHost().equalsIgnoreCase(right.getHost())
                && effectivePort(left) == effectivePort(right);
    }

    private static int effectivePort(URI value) {
        if (value.getPort() >= 0) {
            return value.getPort();
        }
        return "https".equalsIgnoreCase(value.getScheme()) ? 443 : 80;
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

    private static String normalizeVersion(String value) throws IOException {
        String normalized = value == null ? "" : value.trim();
        return requireSemanticVersion(normalized);
    }

    private static String requireSemanticVersion(String value) throws IOException {
        String normalized = value.startsWith("v") ? value.substring(1) : value;
        if (normalized.length() < 5 || normalized.length() > MAX_VERSION_LENGTH
                || !SEMVER.matcher(normalized).matches()) {
            throw new IOException("version response contains an invalid semantic version");
        }
        return normalized;
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
