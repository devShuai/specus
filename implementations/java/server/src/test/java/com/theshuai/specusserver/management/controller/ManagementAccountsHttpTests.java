package com.theshuai.specusserver.management.controller;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.jwk.source.ImmutableSecret;
import com.theshuai.specusserver.management.model.ManagementRole;
import com.theshuai.specusserver.management.model.ManagementUser;
import com.theshuai.specusserver.management.model.ManagementUserEmail;
import com.theshuai.specusserver.management.repository.ManagementUserEmailRepository;
import com.theshuai.specusserver.management.repository.ManagementUserRepository;
import com.theshuai.specusserver.security.LocalTokenService;
import com.theshuai.specusserver.security.PasswordService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Account lifecycle through the real routes (protocol/spec/management-accounts.md sections 5-7,
 * issue #199): replays {@code protocol/test-vectors/management-accounts-v1.json} and walks the
 * delete-then-recreate path with tokens that {@code /auth/login} really issued.
 */
@SpringBootTest(
        webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        properties = {
                "spring.datasource.url=jdbc:sqlite::memory:",
                "spring.jpa.database-platform=org.hibernate.community.dialect.SQLiteDialect",
                "spring.jpa.hibernate.ddl-auto=create-drop",
                "specus.netty.port=0",
                "specus.database.seed-demo-client=false",
                "specus.client-packages.github-release-fallback-enabled=false",
                "specus.auth.username=admin",
                "specus.auth.password=admin-accounts-password",
                "specus.auth.tenant-id=default"
        })
class ManagementAccountsHttpTests {
    private static final String VECTOR = "protocol/test-vectors/management-accounts-v1.json";
    private static final ObjectMapper JSON = new ObjectMapper();
    private static final String PASSWORD = "Accounts-test-password-1";

    @LocalServerPort private int port;
    @Autowired private LocalTokenService localTokenService;
    @Autowired private ManagementUserRepository userRepository;
    @Autowired private ManagementUserEmailRepository emailRepository;

    private final HttpClient httpClient = HttpClient.newHttpClient();

    @BeforeEach
    void emptyStore() {
        emailRepository.deleteAllInBatch();
        userRepository.deleteAllInBatch();
    }

    @Test
    void replaysTheTokenResolutionVector() throws IOException {
        JsonNode vector = readVector();
        seedAccounts(vector);
        for (JsonNode testCase : vector.get("tokenResolution")) {
            String name = testCase.get("name").asText();
            String token = sign(testCase.get("claims"));
            JsonNode expect = testCase.get("expect");
            HttpResponse<String> me = send("GET", "/api/admin/me", token, null);
            HttpResponse<String> refresh = send("POST", "/auth/refresh", token, null);
            if (expect.isNull()) {
                assertThat(me.statusCode()).as(name).isIn(401, 403);
                assertThat(refresh.statusCode()).as(name).isEqualTo(401);
                continue;
            }
            assertThat(me.statusCode()).as(name + " " + me.body()).isEqualTo(200);
            JsonNode view = JSON.readTree(me.body());
            assertThat(view.get("username").asText()).as(name).isEqualTo(expect.get("username").asText());
            assertThat(view.get("tenantId").asText()).as(name).isEqualTo(expect.get("tenantId").asText());
            assertThat(view.get("builtIn").asBoolean()).as(name).isEqualTo(expect.get("builtIn").asBoolean());
            assertThat(refresh.statusCode()).as(name + " " + refresh.body()).isEqualTo(200);
            JsonNode refreshed = payload(JSON.readTree(refresh.body()).get("accessToken").asText());
            assertThat(refreshed.get("sub").asText()).as(name).isEqualTo(expect.get("username").asText());
            assertThat(refreshed.get("tenant_id").asText()).as(name).isEqualTo(expect.get("tenantId").asText());
            JsonNode uid = refreshed.get(LocalTokenService.ACCOUNT_KEY_CLAIM);
            if (expect.get("uid").isNull()) {
                assertThat(uid).as(name).isNull();
            } else {
                assertThat(uid).as(name).isNotNull();
                assertThat(uid.asText()).as(name).isEqualTo(expect.get("uid").asText());
            }
        }
    }

    @Test
    void replaysTheUserListVector() throws IOException {
        JsonNode vector = readVector();
        seedAccounts(vector);
        for (JsonNode testCase : vector.get("userLists")) {
            String name = testCase.get("name").asText();
            HttpResponse<String> response = send("GET", "/api/admin/users", sign(testCase.get("caller")), null);
            assertThat(response.statusCode()).as(name + " " + response.body()).isEqualTo(200);
            List<String> actual = new ArrayList<>();
            for (JsonNode view : JSON.readTree(response.body())) {
                actual.add(view.get("username").asText() + "@" + view.get("tenantId").asText()
                        + (view.get("builtIn").asBoolean() ? " built-in" : ""));
            }
            List<String> expected = new ArrayList<>();
            for (JsonNode view : testCase.get("expect")) {
                expected.add(view.get("username").asText() + "@" + view.get("tenantId").asText()
                        + (view.get("builtIn").asBoolean() ? " built-in" : ""));
            }
            assertThat(actual).as(name).containsExactlyElementsOf(expected);
        }
    }

    @Test
    void deletedAccountTokensDoNotResolveToARecreatedAccountOfTheSameName() throws IOException {
        String admin = login("admin", "admin-accounts-password", null);
        assertThat(payload(admin).get(LocalTokenService.ACCOUNT_KEY_CLAIM)).as("built-in admin").isNull();
        String tenantAdmin = sign(Map.of("sub", "erin", "tenant_id", "tenant-a", "role", "ADMIN"));
        seed("5a4b3c2d-1e0f-4a9b-8c7d-6e5f4a3b2c1d", "erin", "tenant-a", ManagementRole.ADMIN);
        String create = "{\"username\":\"alice\",\"password\":\"" + PASSWORD + "\",\"role\":\"USER\"}";
        assertThat(send("POST", "/api/admin/users", tenantAdmin, create).statusCode()).isEqualTo(201);

        String first = login("alice", PASSWORD, "tenant-a");
        String firstKey = userRepository.findByTenantIdAndLoginNameNormalized("tenant-a", "alice")
                .orElseThrow().getUsername();
        assertThat(payload(first).get(LocalTokenService.ACCOUNT_KEY_CLAIM).asText()).isEqualTo(firstKey);
        assertThat(send("GET", "/api/admin/me", first, null).statusCode()).isEqualTo(200);

        assertThat(send("DELETE", "/api/admin/users/alice", tenantAdmin, null).statusCode()).isEqualTo(204);
        assertThat(send("POST", "/api/admin/users", tenantAdmin, create).statusCode()).isEqualTo(201);
        String secondKey = userRepository.findByTenantIdAndLoginNameNormalized("tenant-a", "alice")
                .orElseThrow().getUsername();
        assertThat(secondKey).isNotEqualTo(firstKey);

        // The first alice's token names an account row that is gone; it does not pass to the second.
        assertThat(send("GET", "/api/admin/me", first, null).statusCode()).isIn(401, 403);
        assertThat(send("POST", "/auth/refresh", first, null).statusCode()).isEqualTo(401);

        String second = login("alice", PASSWORD, "tenant-a");
        assertThat(payload(second).get(LocalTokenService.ACCOUNT_KEY_CLAIM).asText()).isEqualTo(secondKey);
        assertThat(send("GET", "/api/admin/me", second, null).statusCode()).isEqualTo(200);
        HttpResponse<String> refreshed = send("POST", "/auth/refresh", second, null);
        assertThat(refreshed.statusCode()).isEqualTo(200);
        assertThat(payload(JSON.readTree(refreshed.body()).get("accessToken").asText())
                .get(LocalTokenService.ACCOUNT_KEY_CLAIM).asText()).isEqualTo(secondKey);
    }

    @Test
    void deletingAnAccountReleasesItsEmail() {
        seed("9e8d7c6b-5a4f-4e3d-a2c1-b0a9f8e7d6c5", "dora", "default", ManagementRole.ADMIN);
        seed("0f1e2d3c-4b5a-4968-8776-655443322110", "frank", "default", ManagementRole.USER);
        seed("1a2b3c4d-5e6f-4a7b-8c9d-0e1f2a3b4c5d", "grace", "default", ManagementRole.USER);
        email("0f1e2d3c-4b5a-4968-8776-655443322110", "frank@example.com");
        email("1a2b3c4d-5e6f-4a7b-8c9d-0e1f2a3b4c5d", "grace@example.com");
        String dora = sign(Map.of("sub", "dora", "tenant_id", "default", "role", "ADMIN",
                LocalTokenService.ACCOUNT_KEY_CLAIM, "9e8d7c6b-5a4f-4e3d-a2c1-b0a9f8e7d6c5"));

        assertThat(send("DELETE", "/api/admin/users/FRANK", dora, null).statusCode()).isEqualTo(204);

        assertThat(emailRepository.existsByEmailIgnoreCase("frank@example.com")).isFalse();
        assertThat(emailRepository.existsByEmailIgnoreCase("grace@example.com")).isTrue();
        assertThat(userRepository.findById("0f1e2d3c-4b5a-4968-8776-655443322110")).isEmpty();
    }

    // -- fixture ----------------------------------------------------------------------------------

    private void seedAccounts(JsonNode vector) {
        for (JsonNode account : vector.get("accounts")) {
            ManagementUser user = seed(account.get("accountKey").asText(), account.get("loginName").asText(),
                    account.get("tenantId").asText(), ManagementRole.valueOf(account.get("role").asText()));
            if (!account.get("enabled").asBoolean()) {
                user.setEnabled(false);
                userRepository.saveAndFlush(user);
            }
        }
    }

    private ManagementUser seed(String accountKey, String loginName, String tenantId, ManagementRole role) {
        String now = Instant.now().toString();
        ManagementUser user = new ManagementUser();
        user.setUsername(accountKey);
        user.setLoginName(loginName);
        user.setLoginNameNormalized(loginName.toLowerCase(java.util.Locale.ROOT));
        user.setTenantId(tenantId);
        user.setPasswordHash(PasswordService.hash(PASSWORD));
        user.setRole(role);
        user.setEnabled(true);
        user.setCreatedAt(now);
        user.setUpdatedAt(now);
        return userRepository.saveAndFlush(user);
    }

    private void email(String accountKey, String address) {
        String now = Instant.now().toString();
        ManagementUserEmail email = new ManagementUserEmail();
        email.setUsername(accountKey);
        email.setEmail(address);
        email.setVerifiedAt(now);
        email.setCreatedAt(now);
        email.setUpdatedAt(now);
        emailRepository.saveAndFlush(email);
    }

    /** Signs the claims as the server's own local token, with iss, iat and exp added. */
    private String sign(JsonNode claims) {
        Map<String, Object> values = new java.util.LinkedHashMap<>();
        Iterator<Map.Entry<String, JsonNode>> fields = claims.fields();
        while (fields.hasNext()) {
            Map.Entry<String, JsonNode> field = fields.next();
            values.put(field.getKey(), field.getValue().asText());
        }
        return sign(values);
    }

    private String sign(Map<String, Object> claims) {
        Instant now = Instant.now();
        JwtClaimsSet.Builder builder = JwtClaimsSet.builder()
                .issuer(LocalTokenService.ISSUER)
                .issuedAt(now)
                .expiresAt(now.plusSeconds(600));
        claims.forEach(builder::claim);
        NimbusJwtEncoder encoder = new NimbusJwtEncoder(new ImmutableSecret<>(localTokenService.getSecretKey()));
        return encoder.encode(JwtEncoderParameters.from(JwsHeader.with(MacAlgorithm.HS256).build(), builder.build()))
                .getTokenValue();
    }

    private String login(String username, String password, String tenantId) throws IOException {
        String body = "{\"username\":\"" + username + "\",\"password\":\"" + password + "\""
                + (tenantId == null ? "" : ",\"tenantId\":\"" + tenantId + "\"") + "}";
        HttpResponse<String> response = send("POST", "/auth/login", null, body);
        assertThat(response.statusCode()).as(response.body()).isEqualTo(200);
        return JSON.readTree(response.body()).get("accessToken").asText();
    }

    private static JsonNode payload(String token) throws IOException {
        String[] parts = token.split("\\.");
        return JSON.readTree(new String(Base64.getUrlDecoder().decode(parts[1]), StandardCharsets.UTF_8));
    }

    private HttpResponse<String> send(String method, String path, String token, String body) {
        HttpRequest.BodyPublisher publisher = body == null
                ? HttpRequest.BodyPublishers.noBody()
                : HttpRequest.BodyPublishers.ofString(body);
        HttpRequest.Builder request = HttpRequest.newBuilder(URI.create("http://localhost:" + port + path))
                .method(method, publisher);
        if (body != null) {
            request.header("Content-Type", "application/json");
        }
        if (token != null) {
            request.header("Authorization", "Bearer " + token);
        }
        try {
            return httpClient.send(request.build(), HttpResponse.BodyHandlers.ofString());
        } catch (IOException e) {
            throw new IllegalStateException(e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException(e);
        }
    }

    private static JsonNode readVector() throws IOException {
        Path current = Path.of("").toAbsolutePath();
        for (int depth = 0; current != null && depth < 8; depth++, current = current.getParent()) {
            Path candidate = current.resolve(VECTOR);
            if (Files.isRegularFile(candidate)) {
                return JSON.readTree(Files.readString(candidate));
            }
        }
        throw new IllegalStateException("cannot locate " + VECTOR);
    }
}
