package com.theshuai.specusserver.config;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.annotation.DirtiesContext;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties = {
        "spring.datasource.url=jdbc:sqlite::memory:",
        "spring.jpa.database-platform=org.hibernate.community.dialect.SQLiteDialect",
        "spring.jpa.hibernate.ddl-auto=create-drop",
        "specus.netty.port=0",
        "specus.database.seed-demo-client=false",
        "specus.client-packages.github-release-fallback-enabled=false",
        "specus.env=test",
        "specus.auth.username=page-test-admin",
        "specus.auth.password=isolated-page-test-password"
})
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_CLASS)
class PublicPageRoutingTests {
    private static final String[] ENTRIES = {"/nat-detect", "/transfer", "/diagram", "/diagram-embed", "/download"};
    @Value("${local.server.port}") private int port;
    private final HttpClient http = HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NEVER).build();

    private HttpResponse<String> request(String method, String path) throws Exception {
        return http.send(HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + port + path))
                .method(method, HttpRequest.BodyPublishers.noBody()).build(), HttpResponse.BodyHandlers.ofString());
    }

    @Test
    void publicEntriesKeepTheirUrlAndServeTheActualIndexForGetAndHead() throws Exception {
        var index = request("GET", "/index.html");
        assertThat(index.statusCode()).isEqualTo(200);
        assertThat(index.body()).contains("<html");
        for (String entry : ENTRIES) for (String suffix : new String[]{"", "/", "?roomId=fixture&view=file", "/?roomId=fixture&view=file"}) {
            for (String method : new String[]{"GET", "HEAD"}) {
                var response = request(method, entry + suffix);
                assertThat(response.statusCode()).as(method + " " + entry + suffix).isEqualTo(200);
                assertThat(response.uri().getRawPath() + (response.uri().getRawQuery() == null ? "" : "?" + response.uri().getRawQuery())).isEqualTo(entry + suffix);
                assertThat(response.headers().firstValue("location")).isEmpty();
                assertThat(response.headers().firstValue("content-type").orElse("")).startsWith("text/html");
                assertThat(response.headers().firstValue("x-content-type-options").orElse("")).isEqualTo("nosniff");
                assertThat(response.headers().firstValue("content-security-policy").orElse("")).contains("frame-ancestors 'none'");
                assertThat(response.headers().firstValue("cache-control").orElse("")).doesNotContain("immutable");
                assertThat(response.body()).isEqualTo(method.equals("HEAD") ? "" : index.body());
            }
        }
    }

    @Test
    void missingResourcesAndApplicationProxiesAreNotPortalFallbacks() throws Exception {
        for (String path : new String[]{"/transfer/unknown", "/transfer.js", "/transfer-other", "/assets/missing.js", "/api/public/missing", "/api/admin/missing", "/http/missing-client/missing-route/", "/http-share/missing/"}) {
            var response = request("GET", path);
            assertThat(response.statusCode()).as(path).isGreaterThanOrEqualTo(400);
            assertThat(response.body()).doesNotContain("<html");
        }
    }

    @Test
    void publicEntriesRejectWriteMethods() throws Exception {
        for (String entry : ENTRIES) for (String method : new String[]{"POST", "PUT", "DELETE"}) {
            assertThat(request(method, entry).statusCode()).as(method + " " + entry).isEqualTo(405);
        }
    }
}
