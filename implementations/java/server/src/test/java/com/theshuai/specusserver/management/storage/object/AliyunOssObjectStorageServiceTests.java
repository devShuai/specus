package com.theshuai.specusserver.management.storage.object;

import com.theshuai.specusserver.config.ObjectStorageProperties;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Arrays;
import java.util.Base64;
import java.util.Map;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

class AliyunOssObjectStorageServiceTests {

    @Test
    void presignedDownloadUsesV4AndSignsGrantMarker() {
        ObjectStorageProperties properties = new ObjectStorageProperties();
        properties.setProvider("aliyun-oss");
        properties.setEndpoint("https://oss-cn-hangzhou.aliyuncs.com");
        properties.setBucket("examplebucket");
        properties.setAccessKeyId("test-access-key");
        properties.setAccessKeySecret("test-secret-key");
        properties.setObjectPrefix("prefix");
        Clock clock = Clock.fixed(Instant.parse("2024-12-03T03:44:20Z"), ZoneOffset.UTC);
        AliyunOssObjectStorageService storage = new AliyunOssObjectStorageService(
                properties, HttpClient.newHttpClient(), clock);

        PresignedObjectUrl result = storage.presignDownload(
                "prefix/example.txt", Duration.ofSeconds(600), "grant-123");

        URI uri = URI.create(result.url());
        Map<String, String> query = Arrays.stream(uri.getRawQuery().split("&"))
                .map(value -> value.split("=", 2))
                .collect(Collectors.toMap(parts -> parts[0], parts -> parts.length > 1 ? parts[1] : ""));
        assertThat(uri.getHost()).isEqualTo("examplebucket.oss-cn-hangzhou.aliyuncs.com");
        assertThat(query).doesNotContainKeys("OSSAccessKeyId", "Expires", "Signature");
        assertThat(query.get("x-oss-signature-version")).isEqualTo("OSS4-HMAC-SHA256");
        assertThat(query.get("x-oss-credential"))
                .isEqualTo("test-access-key%2F20241203%2Fcn-hangzhou%2Foss%2Faliyun_v4_request");
        assertThat(query.get("x-oss-date")).isEqualTo("20241203T034420Z");
        assertThat(query.get("x-oss-expires")).isEqualTo("600");
        assertThat(query.get("x-st-grant")).isEqualTo("grant-123");
        assertThat(query.get("x-oss-signature"))
                .isEqualTo("c2fae9c2ac1a8e6ec5d0ef73e0ac015f40deaf92c3ec5626139a7cacb71225ac");
    }

    @Test
    void presignedUploadIncludesSignedOssCallbackHeader() {
        ObjectStorageProperties properties = new ObjectStorageProperties();
        properties.setProvider("aliyun-oss");
        properties.setEndpoint("https://oss-cn-hangzhou.aliyuncs.com");
        properties.setBucket("examplebucket");
        properties.setAccessKeyId("test-access-key");
        properties.setAccessKeySecret("test-secret-key");
        properties.setObjectPrefix("prefix");
        properties.setUploadCallbackUrl(
                "https://specus.example/api/public/transfer/oss-callback");
        AliyunOssObjectStorageService storage = new AliyunOssObjectStorageService(
                properties, HttpClient.newHttpClient(), Clock.systemUTC());

        PresignedObjectUrl result = storage.presignUpload(
                "prefix/example.txt", "text/plain", Duration.ofMinutes(10));

        String encoded = result.headers().get("x-oss-callback");
        String callback = new String(Base64.getDecoder().decode(encoded),
                java.nio.charset.StandardCharsets.UTF_8);
        assertThat(callback)
                .contains("\"callbackUrl\":\"https://specus.example/api/public/transfer/oss-callback\"")
                .contains("\"callbackBodyType\":\"application/json\"")
                .contains("${object}")
                .contains("\"callbackSNI\":true");
    }

    @Test
    void uploadCallbackVerificationPinsAndCachesAliyunPublicKey() throws Exception {
        var keyGenerator = KeyPairGenerator.getInstance("RSA");
        keyGenerator.initialize(2048);
        var keyPair = keyGenerator.generateKeyPair();
        String publicKey = "-----BEGIN PUBLIC KEY-----\n"
                + Base64.getMimeEncoder(64, new byte[]{'\n'})
                .encodeToString(keyPair.getPublic().getEncoded())
                + "\n-----END PUBLIC KEY-----\n";
        HttpClient client = mock(HttpClient.class);
        @SuppressWarnings("unchecked")
        HttpResponse<String> response = mock(HttpResponse.class);
        doReturn(200).when(response).statusCode();
        doReturn(publicKey).when(response).body();
        doReturn(response).when(client).send(any(HttpRequest.class), any());

        ObjectStorageProperties properties = new ObjectStorageProperties();
        properties.setProvider("aliyun-oss");
        properties.setEndpoint("https://oss-cn-hangzhou.aliyuncs.com");
        properties.setBucket("examplebucket");
        properties.setAccessKeyId("test-access-key");
        properties.setAccessKeySecret("test-secret-key");
        properties.setObjectPrefix("prefix");
        properties.setUploadCallbackUrl(
                "https://specus.example/api/public/transfer/oss-callback");
        AliyunOssObjectStorageService storage = new AliyunOssObjectStorageService(
                properties, client, Clock.systemUTC());
        String target = "/api/public/transfer/oss-callback";
        byte[] body = "{\"bucket\":\"examplebucket\"}".getBytes(StandardCharsets.UTF_8);
        Signature signer = Signature.getInstance("MD5withRSA");
        signer.initSign(keyPair.getPrivate());
        signer.update((target + "\n" + new String(body, StandardCharsets.UTF_8))
                .getBytes(StandardCharsets.UTF_8));
        String authorization = Base64.getEncoder().encodeToString(signer.sign());
        String publicKeyUrl = Base64.getEncoder().encodeToString(
                "http://gosspublic.alicdn.com/callback_pub_key_v1.pem"
                        .getBytes(StandardCharsets.UTF_8));

        assertThat(storage.verifyUploadCallback(
                target, body, authorization, publicKeyUrl)).isTrue();
        assertThat(storage.verifyUploadCallback(
                target, body, authorization, publicKeyUrl)).isTrue();
        var requestCaptor = org.mockito.ArgumentCaptor.forClass(HttpRequest.class);
        verify(client, times(1)).send(requestCaptor.capture(), any());
        assertThat(requestCaptor.getValue().uri().toString())
                .isEqualTo("https://gosspublic.alicdn.com/callback_pub_key_v1.pem");
    }
}
