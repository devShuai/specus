package com.theshuai.specusserver.management.storage.object;

import com.theshuai.common.util.JsonUtil;
import com.theshuai.specusserver.config.ObjectStorageProperties;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.net.URI;
import java.net.URLDecoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Comparator;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.TreeMap;
import java.util.concurrent.ConcurrentHashMap;

@Service
public class AliyunOssObjectStorageService implements ObjectStorageService {
    private static final String ALGORITHM = "OSS4-HMAC-SHA256";
    private static final String TERMINATOR = "aliyun_v4_request";
    private static final String UNSIGNED_PAYLOAD = "UNSIGNED-PAYLOAD";
    private static final long MAX_PRESIGN_TTL_SECONDS = 7L * 24L * 60L * 60L;
    private static final DateTimeFormatter OSS_DATE =
            DateTimeFormatter.ofPattern("yyyyMMdd").withZone(ZoneOffset.UTC);
    private static final DateTimeFormatter OSS_TIMESTAMP =
            DateTimeFormatter.ofPattern("yyyyMMdd'T'HHmmss'Z'").withZone(ZoneOffset.UTC);

    private final ObjectStorageProperties properties;
    private final HttpClient httpClient;
    private final Clock clock;
    private final Map<String, PublicKey> callbackPublicKeys = new ConcurrentHashMap<>();

    @Autowired
    public AliyunOssObjectStorageService(ObjectStorageProperties properties) {
        this(properties, HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NEVER).build(),
                Clock.systemUTC());
    }

    AliyunOssObjectStorageService(ObjectStorageProperties properties, HttpClient httpClient, Clock clock) {
        this.properties = properties;
        this.httpClient = httpClient;
        this.clock = clock;
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
        String safeContentType = StringUtils.hasText(contentType)
                ? contentType.trim()
                : "application/octet-stream";
        return presign("PUT", objectKey, ttl, safeContentType, null);
    }

    @Override
    public PresignedObjectUrl presignDownload(String objectKey, Duration ttl) {
        return presignDownload(objectKey, ttl, null);
    }

    @Override
    public PresignedObjectUrl presignDownload(String objectKey, Duration ttl, String downloadGrantId) {
        ensureEnabled();
        validateObjectKey(objectKey);
        return presign("GET", objectKey, ttl, null, downloadGrantId);
    }

    @Override
    public boolean verifyUploadCallback(String requestTarget, byte[] body,
                                        String authorization, String publicKeyUrl) {
        if (!isEnabled() || !StringUtils.hasText(properties.getUploadCallbackUrl())
                || !StringUtils.hasText(requestTarget) || body == null || body.length > 64 * 1024
                || !StringUtils.hasText(authorization) || !StringUtils.hasText(publicKeyUrl)) {
            return false;
        }
        try {
            PublicKey key = callbackPublicKey(publicKeyUrl.trim());
            String signatureValue = authorization.trim();
            if (signatureValue.regionMatches(true, 0, "OSS ", 0, 4)) {
                signatureValue = signatureValue.substring(4).trim();
            }
            byte[] signatureBytes = Base64.getDecoder().decode(signatureValue);
            Signature verifier = Signature.getInstance("MD5withRSA");
            verifier.initVerify(key);
            verifier.update(callbackStringToVerify(requestTarget, body).getBytes(StandardCharsets.UTF_8));
            return verifier.verify(signatureBytes);
        } catch (Exception ignored) {
            return false;
        }
    }

    @Override
    public ObjectStat statObject(String objectKey) {
        ensureEnabled();
        validateObjectKey(objectKey);
        HttpRequest request = authorizedRequest("HEAD", objectKey);
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
        HttpRequest request = authorizedRequest("DELETE", objectKey);
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

    private PresignedObjectUrl presign(String method, String objectKey, Duration ttl,
                                       String contentType, String downloadGrantId) {
        Instant now = clock.instant();
        long ttlSeconds = normalizePresignTtl(ttl);
        Instant expiresAt = now.plusSeconds(ttlSeconds);
        String date = OSS_DATE.format(now);
        String timestamp = OSS_TIMESTAMP.format(now);
        String region = resolvedRegion();
        String scope = date + "/" + region + "/oss/" + TERMINATOR;
        String additionalHeaders = "host";

        Map<String, String> query = new TreeMap<>();
        query.put("x-oss-additional-headers", additionalHeaders);
        query.put("x-oss-credential", properties.getAccessKeyId().trim() + "/" + scope);
        query.put("x-oss-date", timestamp);
        query.put("x-oss-expires", Long.toString(ttlSeconds));
        query.put("x-oss-signature-version", ALGORITHM);
        if (StringUtils.hasText(downloadGrantId)) {
            query.put("x-st-grant", downloadGrantId.trim());
        }

        Map<String, String> canonicalHeaders = new TreeMap<>();
        canonicalHeaders.put("host", objectHost());
        Map<String, String> responseHeaders = new LinkedHashMap<>();
        if (StringUtils.hasText(contentType)) {
            canonicalHeaders.put("content-type", contentType);
            responseHeaders.put("Content-Type", contentType);
        }
        if ("PUT".equalsIgnoreCase(method)) {
            String callback = uploadCallbackHeader();
            if (StringUtils.hasText(callback)) {
                canonicalHeaders.put("x-oss-callback", callback);
                responseHeaders.put("x-oss-callback", callback);
            }
        }

        String canonicalRequest = canonicalRequest(method, objectKey, query, canonicalHeaders,
                additionalHeaders, UNSIGNED_PAYLOAD);
        String signature = signature(now, canonicalRequest, region);
        query.put("x-oss-signature", signature);
        return new PresignedObjectUrl(
                objectUrl(objectKey) + "?" + canonicalQuery(query),
                responseHeaders,
                expiresAt.toString()
        );
    }

    private HttpRequest authorizedRequest(String method, String objectKey) {
        Instant now = clock.instant();
        String timestamp = OSS_TIMESTAMP.format(now);
        String date = OSS_DATE.format(now);
        String region = resolvedRegion();
        String additionalHeaders = "host";
        Map<String, String> headers = new TreeMap<>();
        headers.put("host", objectHost());
        headers.put("x-oss-content-sha256", UNSIGNED_PAYLOAD);
        headers.put("x-oss-date", timestamp);
        String canonicalRequest = canonicalRequest(method, objectKey, Map.of(), headers,
                additionalHeaders, UNSIGNED_PAYLOAD);
        String authorization = ALGORITHM
                + " Credential=" + properties.getAccessKeyId().trim() + "/"
                + date + "/" + region + "/oss/" + TERMINATOR
                + ", AdditionalHeaders=" + additionalHeaders
                + ", Signature=" + signature(now, canonicalRequest, region);

        return HttpRequest.newBuilder(URI.create(objectUrl(objectKey)))
                .timeout(Duration.ofSeconds(20))
                .header("x-oss-content-sha256", UNSIGNED_PAYLOAD)
                .header("x-oss-date", timestamp)
                .header("Authorization", authorization)
                .method(method, HttpRequest.BodyPublishers.noBody())
                .build();
    }

    private String canonicalRequest(String method, String objectKey, Map<String, String> query,
                                    Map<String, String> headers, String additionalHeaders,
                                    String payloadHash) {
        return method.toUpperCase(Locale.ROOT) + "\n"
                + canonicalResource(objectKey) + "\n"
                + canonicalQuery(query) + "\n"
                + canonicalHeaders(headers) + "\n"
                + additionalHeaders + "\n"
                + payloadHash;
    }

    private String signature(Instant now, String canonicalRequest, String region) {
        String date = OSS_DATE.format(now);
        String scope = date + "/" + region + "/oss/" + TERMINATOR;
        String stringToSign = ALGORITHM + "\n"
                + OSS_TIMESTAMP.format(now) + "\n"
                + scope + "\n"
                + sha256Hex(canonicalRequest);
        byte[] dateKey = hmacSha256(
                ("aliyun_v4" + properties.getAccessKeySecret()).getBytes(StandardCharsets.UTF_8), date);
        byte[] regionKey = hmacSha256(dateKey, region);
        byte[] serviceKey = hmacSha256(regionKey, "oss");
        byte[] signingKey = hmacSha256(serviceKey, TERMINATOR);
        return HexFormat.of().formatHex(hmacSha256(signingKey, stringToSign));
    }

    private byte[] hmacSha256(byte[] key, String value) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key, "HmacSHA256"));
            return mac.doFinal(value.getBytes(StandardCharsets.UTF_8));
        } catch (Exception e) {
            throw new IllegalStateException("failed to sign object storage request", e);
        }
    }

    private String sha256Hex(String value) {
        try {
            return HexFormat.of().formatHex(
                    MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception e) {
            throw new IllegalStateException("failed to hash object storage request", e);
        }
    }

    private String canonicalHeaders(Map<String, String> headers) {
        StringBuilder result = new StringBuilder();
        headers.entrySet().stream()
                .sorted(Map.Entry.comparingByKey())
                .forEach(entry -> result.append(entry.getKey().toLowerCase(Locale.ROOT))
                        .append(':')
                        .append(entry.getValue().trim())
                        .append('\n'));
        return result.toString();
    }

    private String canonicalQuery(Map<String, String> query) {
        List<Map.Entry<String, String>> entries = new ArrayList<>(query.entrySet());
        entries.sort(Comparator
                .comparing((Map.Entry<String, String> entry) -> uriEncode(entry.getKey(), true))
                .thenComparing(entry -> uriEncode(entry.getValue(), true)));
        StringBuilder result = new StringBuilder();
        for (Map.Entry<String, String> entry : entries) {
            if (!result.isEmpty()) {
                result.append('&');
            }
            result.append(uriEncode(entry.getKey(), true))
                    .append('=')
                    .append(uriEncode(entry.getValue(), true));
        }
        return result.toString();
    }

    private long normalizePresignTtl(Duration ttl) {
        long seconds = ttl == null ? 1L : ttl.toSeconds();
        return Math.max(1L, Math.min(MAX_PRESIGN_TTL_SECONDS, seconds));
    }

    private String uploadCallbackHeader() {
        if (!StringUtils.hasText(properties.getUploadCallbackUrl())) {
            return "";
        }
        URI callbackUrl = URI.create(properties.getUploadCallbackUrl().trim());
        String scheme = callbackUrl.getScheme();
        if (!("http".equalsIgnoreCase(scheme) || "https".equalsIgnoreCase(scheme))
                || !StringUtils.hasText(callbackUrl.getHost()) || callbackUrl.getFragment() != null
                || callbackUrl.getUserInfo() != null) {
            throw new IllegalStateException("object storage upload callback URL is invalid");
        }
        Map<String, Object> callback = new LinkedHashMap<>();
        callback.put("callbackUrl", callbackUrl.toASCIIString());
        callback.put("callbackBody",
                "{\"bucket\":${bucket},\"object\":${object},\"size\":${size},"
                        + "\"mimeType\":${mimeType},\"etag\":${etag}}");
        callback.put("callbackBodyType", "application/json");
        if ("https".equalsIgnoreCase(scheme)) {
            callback.put("callbackSNI", true);
        }
        String json = JsonUtil.objectToString(callback);
        if (!StringUtils.hasText(json)) {
            throw new IllegalStateException("failed to serialize object storage upload callback");
        }
        return Base64.getEncoder().encodeToString(json.getBytes(StandardCharsets.UTF_8));
    }

    private PublicKey callbackPublicKey(String encodedUrl) throws Exception {
        String decoded = new String(Base64.getDecoder().decode(encodedUrl), StandardCharsets.UTF_8);
        URI supplied = URI.create(decoded.trim());
        if (!"gosspublic.alicdn.com".equalsIgnoreCase(supplied.getHost())
                || !("http".equalsIgnoreCase(supplied.getScheme())
                || "https".equalsIgnoreCase(supplied.getScheme()))
                || supplied.getUserInfo() != null || supplied.getFragment() != null
                || supplied.getQuery() != null || supplied.getPort() != -1
                || supplied.getPath() == null
                || !supplied.getPath().startsWith("/callback_pub_key")) {
            throw new IllegalArgumentException("OSS callback public key URL is invalid");
        }
        URI secureUrl = new URI("https", null, "gosspublic.alicdn.com", -1,
                supplied.getPath(), null, null);
        String cacheKey = secureUrl.toASCIIString();
        PublicKey cached = callbackPublicKeys.get(cacheKey);
        if (cached != null) {
            return cached;
        }
        HttpRequest request = HttpRequest.newBuilder(secureUrl)
                .timeout(Duration.ofSeconds(3))
                .GET()
                .build();
        HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
        if (response.statusCode() != 200 || response.body() == null || response.body().length() > 64 * 1024) {
            throw new IllegalStateException("failed to load OSS callback public key");
        }
        String pem = response.body()
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replaceAll("\\s", "");
        PublicKey parsed = KeyFactory.getInstance("RSA")
                .generatePublic(new X509EncodedKeySpec(Base64.getDecoder().decode(pem)));
        callbackPublicKeys.putIfAbsent(cacheKey, parsed);
        return callbackPublicKeys.get(cacheKey);
    }

    private String callbackStringToVerify(String requestTarget, byte[] body) {
        int queryIndex = requestTarget.indexOf('?');
        String rawPath = queryIndex < 0 ? requestTarget : requestTarget.substring(0, queryIndex);
        String rawQuery = queryIndex < 0 ? "" : requestTarget.substring(queryIndex);
        return URLDecoder.decode(rawPath, StandardCharsets.UTF_8)
                + rawQuery + "\n" + new String(body, StandardCharsets.UTF_8);
    }

    private String resolvedRegion() {
        if (StringUtils.hasText(properties.getRegion())) {
            return properties.getRegion().trim();
        }
        String host = endpointUri().getHost();
        if (host != null && host.toLowerCase(Locale.ROOT).startsWith("oss-")) {
            int end = host.indexOf('.');
            String candidate = end > 4 ? host.substring(4, end) : host.substring(4);
            if (candidate.endsWith("-internal")) {
                candidate = candidate.substring(0, candidate.length() - "-internal".length());
            }
            if (candidate.matches("[a-z]{2}-[a-z0-9-]+") && !"accelerate".equals(candidate)) {
                return candidate;
            }
        }
        throw new IllegalStateException("object storage region is required for OSS V4 signing");
    }

    private void ensureEnabled() {
        if (!isEnabled()) {
            throw new IllegalStateException("object storage is not configured");
        }
    }

    private URI endpointUri() {
        String endpoint = properties.getEndpoint().trim();
        if (!endpoint.startsWith("http://") && !endpoint.startsWith("https://")) {
            endpoint = "https://" + endpoint;
        }
        while (endpoint.endsWith("/")) {
            endpoint = endpoint.substring(0, endpoint.length() - 1);
        }
        URI uri = URI.create(endpoint);
        if (!StringUtils.hasText(uri.getHost())) {
            throw new IllegalStateException("object storage endpoint is invalid");
        }
        return uri;
    }

    private String objectHost() {
        URI endpoint = endpointUri();
        int port = endpoint.getPort();
        return properties.getBucket().trim() + "." + endpoint.getHost()
                + (port > 0 ? ":" + port : "");
    }

    private String objectUrl(String objectKey) {
        URI endpoint = endpointUri();
        return endpoint.getScheme() + "://" + objectHost() + "/" + uriEncode(objectKey, false);
    }

    private String canonicalResource(String objectKey) {
        return uriEncode("/" + properties.getBucket().trim() + "/" + objectKey, false);
    }

    private String uriEncode(String value, boolean encodeSlash) {
        byte[] bytes = value.getBytes(StandardCharsets.UTF_8);
        StringBuilder encoded = new StringBuilder(bytes.length);
        for (byte current : bytes) {
            int ch = current & 0xff;
            boolean unreserved = ch >= 'A' && ch <= 'Z'
                    || ch >= 'a' && ch <= 'z'
                    || ch >= '0' && ch <= '9'
                    || ch == '-' || ch == '_' || ch == '.' || ch == '~';
            if (unreserved || !encodeSlash && ch == '/') {
                encoded.append((char) ch);
            } else {
                encoded.append('%');
                encoded.append(Character.toUpperCase(Character.forDigit((ch >>> 4) & 0xf, 16)));
                encoded.append(Character.toUpperCase(Character.forDigit(ch & 0xf, 16)));
            }
        }
        return encoded.toString();
    }
}
