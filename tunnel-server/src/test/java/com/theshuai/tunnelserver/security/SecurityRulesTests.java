package com.theshuai.tunnelserver.security;

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
                "tunnel.netty.port=0",
                "tunnel.database.seed-demo-client=false",
                "tunnel.auth.username=admin",
                "tunnel.auth.password=admin"
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
    void httpRouteApiRequiresAuthentication() throws Exception {
        // /api/admin/http-routes 走同一套 Spring Security 规则——确保新加的 HttpRouteResource
        // 没有被意外标记为 permitAll
        assertThat(get("/api/admin/http-routes", null).statusCode()).isEqualTo(401);
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
        HttpRequest request = HttpRequest.newBuilder(URI.create("http://localhost:" + port + path))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(json))
                .build();
        return httpClient.send(request, HttpResponse.BodyHandlers.ofString());
    }
}
