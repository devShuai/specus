package com.theshuai.specusserver.management.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.theshuai.specusserver.config.ClientPackageProperties;
import org.junit.jupiter.api.Test;

import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Clock;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class GitHubReleaseCatalogTests {
    private static final String DIGEST = "a".repeat(64);

    @Test
    void mapsOnlyTrustedAssetsAndNormalizesReleaseTag() throws Exception {
        String payload = """
                {
                  "tag_name": "v1.2.3",
                  "published_at": "2026-08-22T00:00:00Z",
                  "assets": [
                    {
                      "id": 101,
                      "name": "specus-client-java-v1.2.3.jar",
                      "browser_download_url": "https://github.com/devShuai/specus/releases/download/v1.2.3/specus-client-java-v1.2.3.jar",
                      "digest": "sha256:%s",
                      "size": 4096
                    },
                    {
                      "id": 102,
                      "name": "specus-client-go-v1.2.3-windows-x64.zip",
                      "browser_download_url": "https://attacker.test/specus-client-go-v1.2.3-windows-x64.zip",
                      "digest": "sha256:%s",
                      "size": 4096
                    },
                    {
                      "id": 103,
                      "name": "specus-client-android-v1.2.3.apk",
                      "browser_download_url": "https://github.com/devShuai/specus/releases/download/v1.2.3/specus-client-android-v1.2.3.apk?raw=1",
                      "digest": "sha256:%s",
                      "size": 4096
                    }
                  ]
                }
                """.formatted(DIGEST, DIGEST, DIGEST);

        List<GitHubReleaseCatalog.ReleasePackage> packages = GitHubReleaseCatalog.mapRelease(
                new ObjectMapper().readTree(payload));

        assertThat(packages).hasSize(1);
        assertThat(packages.getFirst().implementation()).isEqualTo("java");
        assertThat(packages.getFirst().version()).isEqualTo("1.2.3");
        assertThat(packages.getFirst().sha256()).isEqualTo(DIGEST);
        assertThat(packages.getFirst().fileSize()).isEqualTo(4096L);
    }

    @Test
    @SuppressWarnings("unchecked")
    void cachesSuccessfulReleaseResponse() throws Exception {
        String payload = """
                {
                  "tag_name": "v1.2.3",
                  "assets": [{
                    "id": 201,
                    "name": "specus-client-java-v1.2.3.jar",
                    "browser_download_url": "https://github.com/devShuai/specus/releases/download/v1.2.3/specus-client-java-v1.2.3.jar",
                    "digest": "sha256:%s",
                    "size": 2048
                  }]
                }
                """.formatted(DIGEST);
        ClientPackageProperties properties = new ClientPackageProperties();
        HttpClient httpClient = mock(HttpClient.class);
        HttpResponse<String> response = mock(HttpResponse.class);
        when(response.statusCode()).thenReturn(200);
        when(response.body()).thenReturn(payload);
        when(httpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(response);
        GitHubReleaseCatalog catalog = new GitHubReleaseCatalog(
                properties, httpClient, Clock.systemUTC(), new ObjectMapper());

        assertThat(catalog.latestPackages()).hasSize(1);
        assertThat(catalog.latestPackages()).hasSize(1);

        verify(httpClient, times(1)).send(
                any(HttpRequest.class), any(HttpResponse.BodyHandler.class));
    }
}
