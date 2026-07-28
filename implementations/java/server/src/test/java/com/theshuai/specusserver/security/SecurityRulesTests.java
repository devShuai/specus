package com.theshuai.specusserver.security;

import com.fasterxml.jackson.databind.JsonNode;
import com.theshuai.common.util.JsonUtil;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest(
        webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        properties = {
                "spring.datasource.url=jdbc:sqlite::memory:",
                "spring.jpa.database-platform=org.hibernate.community.dialect.SQLiteDialect",
                "spring.jpa.hibernate.ddl-auto=create-drop",
                "specus.netty.port=0",
                "specus.database.seed-demo-client=false",
                "specus.auth.username=admin",
                "specus.auth.password=admin"
        }
)
class SecurityRulesTests {

    @Value("${local.server.port}")
    private int port;

    private final HttpClient httpClient = HttpClient.newHttpClient();

    @Test
    void adminApiRequiresAuthentication() throws Exception {
        assertThat(get("/api/admin/overview", null).statusCode()).isEqualTo(401);
    }

    @Test
    void cloudDiagramApiRequiresAuthentication() throws Exception {
        assertThat(get("/api/admin/diagrams", null).statusCode()).isEqualTo(401);
    }

    @Test
    void publicTransferObjectStorageRequiresAuthentication() throws Exception {
        HttpResponse<String> response = sendJson(
                "POST",
                "/api/public/transfer/attachments/presign-upload",
                "{\"fileName\":\"note.txt\",\"mimeType\":\"text/plain\",\"sizeBytes\":4,"
                        + "\"roomId\":\"security-test\",\"roomToken\":\"security-test-token\"}",
                null
        );

        assertThat(response.statusCode()).isEqualTo(401);
    }

    @Test
    void oneTimeDownloadGrantIsPublicButUnknownTokenIsGone() throws Exception {
        assertThat(get("/api/public/transfer/downloads/not-a-real-token", null).statusCode())
                .isEqualTo(410);
    }

    @Test
    void oneTimeDownloadGrantRejectsHeadWithoutConsumingIt() throws Exception {
        assertThat(head("/api/public/transfer/downloads/not-a-real-token").statusCode())
                .isEqualTo(405);
    }

    @Test
    void ossUploadCallbackIsAnonymousButRejectsInvalidSignature() throws Exception {
        HttpResponse<String> response = sendJson(
                "POST",
                "/api/public/transfer/oss-callback",
                "{}",
                null
        );

        assertThat(response.statusCode()).isEqualTo(403);
    }

    @Test
    void authenticatedAccountCanReachPublicTransferObjectStorage() throws Exception {
        HttpResponse<String> login = postJson("/auth/login", "{\"username\":\"admin\",\"password\":\"admin\"}");
        String token = JsonUtil.readString(login.body()).path("accessToken").asText();

        HttpResponse<String> response = sendJson(
                "POST",
                "/api/public/transfer/attachments/presign-upload",
                "{\"fileName\":\"note.txt\",\"mimeType\":\"text/plain\",\"sizeBytes\":4,"
                        + "\"roomId\":\"security-test\",\"roomToken\":\"security-test-token\"}",
                token
        );

        assertThat(response.statusCode())
                .as("authenticated request should reach the disabled object-storage boundary: %s", response.body())
                .isEqualTo(409);
    }

    @Test
    void httpRouteApiRequiresAuthentication() throws Exception {
        // /api/admin/http-routes 走同一套 Spring Security 规则——确保新加的 HttpRouteResource
        // 没有被意外标记为 permitAll
        assertThat(get("/api/admin/http-routes", null).statusCode()).isEqualTo(401);
    }

    @Test
    void publicHttpProxyIgnoresForeignBearerToken() throws Exception {
        HttpResponse<String> response = get("/http/missing-client/nacos/", "nacos-owned-token");

        assertThat(response.statusCode())
                .as("foreign upstream bearer token must reach HTTP proxy instead of resource-server validation")
                .isEqualTo(502);
        assertThat(response.body()).contains("客户端不在线");
    }

    @Test
    void oidcConfigIsPublic() throws Exception {
        assertThat(get("/oidc-config", null).statusCode()).isEqualTo(200);
    }

    @Test
    void passwordLoginIssuesTokenThatAccessesAdminApi() throws Exception {
        HttpResponse<String> login = postJson("/auth/login", "{\"username\":\"admin\",\"password\":\"admin\"}");
        assertThat(login.statusCode()).isEqualTo(200);

        JsonNode body = JsonUtil.readString(login.body());
        String token = body.path("accessToken").asText(null);
        assertThat(token).isNotBlank();

        HttpResponse<String> overview = get("/api/admin/overview", token);
        assertThat(overview.statusCode())
                .as("overview response body: %s", overview.body())
                .isEqualTo(200);
    }

    @Test
    void authenticatedAccountCanManageItsCloudDiagram() throws Exception {
        HttpResponse<String> login = postJson("/auth/login", "{\"username\":\"admin\",\"password\":\"admin\"}");
        String token = JsonUtil.readString(login.body()).path("accessToken").asText();

        HttpResponse<String> created = sendJson(
                "POST",
                "/api/admin/diagrams",
                "{\"name\":\"云端架构图\",\"update\":\"AQID\"}",
                token
        );
        assertThat(created.statusCode()).isEqualTo(201);
        JsonNode createdBody = JsonUtil.readString(created.body());
        long id = createdBody.path("id").asLong();
        long revision = createdBody.path("revision").asLong();

        HttpResponse<String> listed = get("/api/admin/diagrams", token);
        assertThat(listed.statusCode()).isEqualTo(200);
        assertThat(listed.body()).contains("云端架构图");

        HttpResponse<String> detail = get("/api/admin/diagrams/" + id, token);
        assertThat(detail.statusCode()).isEqualTo(200);
        assertThat(detail.body()).contains("\"update\":\"AQID\"");

        HttpResponse<String> updated = sendJson(
                "PUT",
                "/api/admin/diagrams/" + id,
                "{\"name\":\"云端架构图 v2\",\"update\":\"BAUG\",\"revision\":" + revision + "}",
                token
        );
        assertThat(updated.statusCode()).isEqualTo(200);
        assertThat(JsonUtil.readString(updated.body()).path("revision").asLong()).isGreaterThan(revision);

        assertThat(delete("/api/admin/diagrams/" + id, token).statusCode()).isEqualTo(204);
    }

    @Test
    void wrongPasswordIsRejected() throws Exception {
        assertThat(postJson("/auth/login", "{\"username\":\"admin\",\"password\":\"nope\"}").statusCode()).isEqualTo(401);
    }

    private HttpResponse<String> get(String path, String bearer) throws Exception {
        HttpRequest.Builder builder = HttpRequest.newBuilder(URI.create("http://localhost:" + port + path)).GET();
        if (bearer != null) {
            builder.header("Authorization", "Bearer " + bearer);
        }
        return httpClient.send(builder.build(), HttpResponse.BodyHandlers.ofString());
    }

    private HttpResponse<String> postJson(String path, String json) throws Exception {
        return sendJson("POST", path, json, null);
    }

    private HttpResponse<String> sendJson(String method, String path, String json, String bearer) throws Exception {
        HttpRequest.Builder builder = HttpRequest.newBuilder(URI.create("http://localhost:" + port + path))
                .header("Content-Type", "application/json")
                .method(method, HttpRequest.BodyPublishers.ofString(json));
        if (bearer != null) {
            builder.header("Authorization", "Bearer " + bearer);
        }
        return httpClient.send(builder.build(), HttpResponse.BodyHandlers.ofString());
    }

    private HttpResponse<String> head(String path) throws Exception {
        HttpRequest request = HttpRequest.newBuilder(URI.create("http://localhost:" + port + path))
                .method("HEAD", HttpRequest.BodyPublishers.noBody())
                .build();
        return httpClient.send(request, HttpResponse.BodyHandlers.ofString());
    }

    private HttpResponse<String> delete(String path, String bearer) throws Exception {
        HttpRequest.Builder builder = HttpRequest.newBuilder(URI.create("http://localhost:" + port + path)).DELETE();
        if (bearer != null) {
            builder.header("Authorization", "Bearer " + bearer);
        }
        return httpClient.send(builder.build(), HttpResponse.BodyHandlers.ofString());
    }
}
