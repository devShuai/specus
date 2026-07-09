package com.theshuai.tunnelserver.management.storage.object;

import com.theshuai.tunnelserver.config.ObjectStorageProperties;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;

@Service
public class AliyunOssObjectStorageService implements ObjectStorageService {
    private static final DateTimeFormatter HTTP_DATE =
            DateTimeFormatter.RFC_1123_DATE_TIME.withZone(ZoneOffset.UTC);

    private final ObjectStorageProperties properties;
    private final HttpClient httpClient = HttpClient.newHttpClient();

    public AliyunOssObjectStorageService(ObjectStorageProperties properties) {
        this.properties = properties;
    }

    @Override
    public boolean isEnabled() {
        return "aliyun-oss".equalsIgnoreCase(properties.getProvider())
                && StringUtils.hasText(properties.getEndpoint())
                && StringUtils.hasText(properties.getBucket())
                && StringUtils.hasText(properties.getAccessKeyId())
                && StringUtils.hasText(properties.getAccessKeySecret());
    }

    @Override
    public void validateObjectKey(String objectKey) {
        if (!StringUtils.hasText(objectKey)) {
            throw new IllegalArgumentException("objectKey cannot be blank");
        }
        String normalizedPrefix = normalizedPrefix();
        String normalized = objectKey.trim();
        if (normalized.startsWith("/") || normalized.contains("\\") || normalized.contains("..")
                || normalized.contains("//") || normalized.chars().anyMatch(ch -> ch < 32)) {
            throw new IllegalArgumentException("objectKey is invalid");
        }
        if (StringUtils.hasText(normalizedPrefix) && !normalized.startsWith(normalizedPrefix + "/")) {
            throw new IllegalArgumentException("objectKey is outside the configured prefix");
        }
    }

    @Override
    public PresignedObjectUrl presignUpload(String objectKey, String contentType, Duration ttl) {
        ensureEnabled();
        validateObjectKey(objectKey);
        String safeContentType = StringUtils.hasText(contentType) ? contentType.trim() : "application/octet-stream";
        long expires = Instant.now().plus(ttl).getEpochSecond();
        String signature = signature("PUT", safeContentType, expires, objectKey);
        Map<String, String> headers = new LinkedHashMap<>();
        headers.put("Content-Type", safeContentType);
        return new PresignedObjectUrl(
                signedUrl(objectKey, expires, signature),
                headers,
                Instant.ofEpochSecond(expires).toString()
        );
    }

    @Override
    public PresignedObjectUrl presignDownload(String objectKey, Duration ttl) {
        ensureEnabled();
        validateObjectKey(objectKey);
        long expires = Instant.now().plus(ttl).getEpochSecond();
        String signature = signature("GET", "", expires, objectKey);
        return new PresignedObjectUrl(
                signedUrl(objectKey, expires, signature),
                Map.of(),
                Instant.ofEpochSecond(expires).toString()
        );
    }

    @Override
    public ObjectStat statObject(String objectKey) {
        ensureEnabled();
        validateObjectKey(objectKey);
        String now = HTTP_DATE.format(Instant.now());
        String canonicalResource = canonicalResource(objectKey);
        String stringToSign = "HEAD\n\n\n" + now + "\n" + canonicalResource;
        String signature = hmacSha1(stringToSign);
        HttpRequest request = HttpRequest.newBuilder(URI.create(objectUrl(objectKey)))
                .timeout(Duration.ofSeconds(20))
                .header("Date", now)
                .header("Authorization", "OSS " + properties.getAccessKeyId() + ":" + signature)
                .method("HEAD", HttpRequest.BodyPublishers.noBody())
                .build();
        try {
            HttpResponse<Void> response = httpClient.send(request, HttpResponse.BodyHandlers.discarding());
            int status = response.statusCode();
            if (status == 404) {
                return new ObjectStat(false, -1L);
            }
            if (status >= 400) {
                throw new IllegalStateException("failed to stat object: HTTP " + status);
            }
            long length = response.headers().firstValueAsLong("Content-Length").orElse(-1L);
            return new ObjectStat(true, length);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("stat object interrupted", e);
        } catch (Exception e) {
            throw new IllegalStateException("failed to stat object", e);
        }
    }

    @Override
    public void deleteObject(String objectKey) {
        ensureEnabled();
        validateObjectKey(objectKey);
        String now = HTTP_DATE.format(Instant.now());
        String canonicalResource = canonicalResource(objectKey);
        String stringToSign = "DELETE\n\n\n" + now + "\n" + canonicalResource;
        String signature = hmacSha1(stringToSign);
        HttpRequest request = HttpRequest.newBuilder(URI.create(objectUrl(objectKey)))
                .timeout(Duration.ofSeconds(20))
                .header("Date", now)
                .header("Authorization", "OSS " + properties.getAccessKeyId() + ":" + signature)
                .DELETE()
                .build();
        try {
            HttpResponse<Void> response = httpClient.send(request, HttpResponse.BodyHandlers.discarding());
            if (response.statusCode() >= 400 && response.statusCode() != 404) {
                throw new IllegalStateException("failed to delete object: HTTP " + response.statusCode());
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("delete object interrupted", e);
        } catch (Exception e) {
            throw new IllegalStateException("failed to delete object", e);
        }
    }

    public String normalizedPrefix() {
        String prefix = properties.getObjectPrefix() == null ? "" : properties.getObjectPrefix().trim();
        while (prefix.startsWith("/")) {
            prefix = prefix.substring(1);
        }
        while (prefix.endsWith("/")) {
            prefix = prefix.substring(0, prefix.length() - 1);
        }
        return prefix;
    }

    private void ensureEnabled() {
        if (!isEnabled()) {
            throw new IllegalStateException("object storage is not configured");
        }
    }

    private String signature(String method, String contentType, long expires, String objectKey) {
        String stringToSign = method.toUpperCase(Locale.ROOT)
                + "\n\n"
                + (contentType == null ? "" : contentType)
                + "\n"
                + expires
                + "\n"
                + canonicalResource(objectKey);
        return hmacSha1(stringToSign);
    }

    private String hmacSha1(String value) {
        try {
            Mac mac = Mac.getInstance("HmacSHA1");
            mac.init(new SecretKeySpec(properties.getAccessKeySecret().getBytes(StandardCharsets.UTF_8), "HmacSHA1"));
            return Base64.getEncoder().encodeToString(mac.doFinal(value.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception e) {
            throw new IllegalStateException("failed to sign object storage request", e);
        }
    }

    private String signedUrl(String objectKey, long expires, String signature) {
        return objectUrl(objectKey)
                + "?OSSAccessKeyId=" + urlEncode(properties.getAccessKeyId())
                + "&Expires=" + expires
                + "&Signature=" + urlEncode(signature);
    }

    private String objectUrl(String objectKey) {
        String endpoint = properties.getEndpoint().trim();
        if (!endpoint.startsWith("http://") && !endpoint.startsWith("https://")) {
            endpoint = "https://" + endpoint;
        }
        while (endpoint.endsWith("/")) {
            endpoint = endpoint.substring(0, endpoint.length() - 1);
        }
        URI endpointUri = URI.create(endpoint);
        String host = endpointUri.getHost();
        int port = endpointUri.getPort();
        String authority = properties.getBucket() + "." + host + (port > 0 ? ":" + port : "");
        return endpointUri.getScheme() + "://" + authority + "/" + encodeObjectKey(objectKey);
    }

    private String canonicalResource(String objectKey) {
        return "/" + properties.getBucket() + "/" + objectKey;
    }

    private String encodeObjectKey(String objectKey) {
        return urlEncode(objectKey).replace("%2F", "/");
    }

    private String urlEncode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8).replace("+", "%20");
    }
}
