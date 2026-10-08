package com.theshuai.specusserver.management.controller;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.jwk.source.ImmutableSecret;
import com.theshuai.specusserver.management.model.ClientAccount;
import com.theshuai.specusserver.management.model.ClientCredential;
import com.theshuai.specusserver.management.model.ManagementRole;
import com.theshuai.specusserver.management.model.ManagementUser;
import com.theshuai.specusserver.management.model.ManagementUserEmail;
import com.theshuai.specusserver.management.model.PeerMeshAcl;
import com.theshuai.specusserver.management.model.PeerMeshDevice;
import com.theshuai.specusserver.management.model.PeerMeshEgressPolicy;
import com.theshuai.specusserver.management.model.SortableInstant;
import com.theshuai.specusserver.management.model.TransferAttachment;
import com.theshuai.specusserver.management.model.TransferAttachmentDownloadGrant;
import com.theshuai.specusserver.management.model.TransferAttachmentDownloadUsage;
import com.theshuai.specusserver.management.model.UserDiagramDocument;
import com.theshuai.specusserver.management.repository.ClientAccountRepository;
import com.theshuai.specusserver.management.repository.ClientCredentialRepository;
import com.theshuai.specusserver.management.repository.ManagementUserEmailRepository;
import com.theshuai.specusserver.management.repository.ManagementUserRepository;
import com.theshuai.specusserver.management.repository.PeerMeshAclRepository;
import com.theshuai.specusserver.management.repository.PeerMeshDeviceRepository;
import com.theshuai.specusserver.management.repository.PeerMeshEgressPolicyRepository;
import com.theshuai.specusserver.management.repository.TransferAttachmentDownloadGrantRepository;
import com.theshuai.specusserver.management.repository.TransferAttachmentDownloadUsageRepository;
import com.theshuai.specusserver.management.repository.TransferAttachmentRepository;
import com.theshuai.specusserver.management.repository.UserDiagramDocumentRepository;
import com.theshuai.specusserver.management.service.TransferAttachmentService;
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
    @Autowired private ClientAccountRepository clients;
    @Autowired private ClientCredentialRepository credentials;
    @Autowired private UserDiagramDocumentRepository diagrams;
    @Autowired private TransferAttachmentRepository attachments;
    @Autowired private TransferAttachmentDownloadGrantRepository grants;
    @Autowired private TransferAttachmentDownloadUsageRepository usage;
    @Autowired private PeerMeshAclRepository acls;
    @Autowired private PeerMeshEgressPolicyRepository policies;
    @Autowired private PeerMeshDeviceRepository devices;

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

    @Test
    void replaysTheAccountDeletionVector() throws IOException {
        JsonNode deletion = readVector().get("accountDeletion");
        for (JsonNode account : deletion.get("accounts")) {
            seed(account.get("accountKey").asText(), account.get("loginName").asText(),
                    account.get("tenantId").asText(), ManagementRole.valueOf(account.get("role").asText()));
        }
        JsonNode rows = deletion.get("seed");
        seedDeletionRows(rows);
        String actor = sign(deletion.get("actor"));
        int index = 0;
        for (JsonNode step : deletion.get("steps")) {
            String name = "step " + index++ + " " + step;
            JsonNode expect = step.get("expect");
            if (step.has("deleteUser")) {
                HttpResponse<String> response =
                        send("DELETE", "/api/admin/users/" + step.get("deleteUser").asText(), actor, null);
                assertThat(response.statusCode()).as(name + " " + response.body())
                        .isEqualTo(expect.get("status").asInt());
                if (response.statusCode() == 409) {
                    JsonNode body = JSON.readTree(response.body());
                    assertThat(body.path("error").asText()).as(name).isNotBlank();
                    assertThat(body.path("clients").asLong(-1)).as(name).isEqualTo(expect.get("clients").asLong());
                    assertThat(body.path("credentials").asLong(-1)).as(name)
                            .isEqualTo(expect.get("credentials").asLong());
                }
            } else if (step.has("get")) {
                HttpResponse<String> response = send("GET", step.get("get").asText(), sign(step.get("as")), null);
                assertThat(response.statusCode()).as(name + " " + response.body())
                        .isEqualTo(expect.get("status").asInt());
                assertThat(JSON.readTree(response.body())).as(name).isEqualTo(expect.get("body"));
            } else {
                applyDeletionFixture(step);
            }
        }

        JsonNode after = deletion.get("rowsAfter");
        assertRows(rows, after, "clients", id -> clients.findById(id).map(ClientAccount::getOwnerUsername));
        assertRows(rows, after, "credentials",
                id -> credentials.findById(id).map(ClientCredential::getOwnerUsername));
        assertRows(rows, after, "diagrams", id -> diagrams.findById(id).map(UserDiagramDocument::getOwnerUsername));
        assertRows(rows, after, "downloadGrants",
                id -> grants.findById(id).map(TransferAttachmentDownloadGrant::getUsername));
        assertRows(rows, after, "downloadUsage",
                id -> usage.findById(id).map(TransferAttachmentDownloadUsage::getUsername));
        assertRows(rows, after, "acls", id -> acls.findById(id).map(PeerMeshAcl::getOwnerUsername));
        assertRows(rows, after, "egressPolicies",
                id -> policies.findById(id).map(PeerMeshEgressPolicy::getOwnerUsername));
        assertRows(rows, after, "devices", id -> devices.findById(id).map(PeerMeshDevice::getOwnerUsername));
        String now = SortableInstant.format(Instant.now());
        assertRows(rows, after, "attachments", id -> attachments.findById(id).map(attachment -> {
            boolean active = attachment.getExpiresAt().compareTo(now) > 0
                    && (!"PENDING".equals(attachment.getStatus()) || attachment.getUploadExpiresAt().compareTo(now) > 0);
            return attachment.getOwnerUsername() + (active ? " active" : " inactive");
        }));

        Map<String, List<String>> accounts = new java.util.TreeMap<>();
        Map<String, List<String>> expectedAccounts = new java.util.TreeMap<>();
        for (JsonNode account : deletion.get("accountsAfter")) {
            expectedAccounts.computeIfAbsent(account.get("tenantId").asText(), tenant -> new ArrayList<>())
                    .add(account.get("loginName").asText() + "=" + account.get("accountKey").asText());
        }
        for (String tenant : expectedAccounts.keySet()) {
            for (ManagementUser user : userRepository.findByTenantIdOrderByLoginNameAsc(tenant)) {
                accounts.computeIfAbsent(tenant, ignored -> new ArrayList<>())
                        .add(user.getLoginName() + "=" + user.getUsername());
            }
        }
        expectedAccounts.values().forEach(java.util.Collections::sort);
        accounts.values().forEach(java.util.Collections::sort);
        assertThat(accounts).isEqualTo(expectedAccounts);
    }

    @Test
    void deletingAnAccountClosesItsManagementWebSockets() throws Exception {
        seed("6b1e2f3a-4c5d-4e6f-8a7b-9c0d1e2f3a4b", "hana", "tenant-d", ManagementRole.ADMIN);
        seed("7c2f3a4b-5d6e-4f70-9b8c-0d1e2f3a4b5c", "bob", "tenant-d", ManagementRole.USER);
        String hana = sign(Map.of("sub", "hana", "tenant_id", "tenant-d", "role", "ADMIN",
                LocalTokenService.ACCOUNT_KEY_CLAIM, "6b1e2f3a-4c5d-4e6f-8a7b-9c0d1e2f3a4b"));
        String bob = sign(Map.of("sub", "bob", "tenant_id", "tenant-d", "role", "USER",
                LocalTokenService.ACCOUNT_KEY_CLAIM, "7c2f3a4b-5d6e-4f70-9b8c-0d1e2f3a4b5c"));
        Socket bobMessages = openManagementSocket(bob, "client-messages");
        Socket bobEvents = openManagementSocket(bob, "connections");
        Socket hanaMessages = openManagementSocket(hana, "client-messages");

        assertThat(send("DELETE", "/api/admin/users/bob", hana, null).statusCode()).isEqualTo(204);

        assertThat(bobMessages.closed().get(10, java.util.concurrent.TimeUnit.SECONDS)).isNotNull();
        assertThat(bobEvents.closed().get(10, java.util.concurrent.TimeUnit.SECONDS)).isNotNull();
        // Another identity's connection stays open: it still answers a ping.
        hanaMessages.ping().get(10, java.util.concurrent.TimeUnit.SECONDS);
        assertThat(hanaMessages.closed()).isNotDone();
        hanaMessages.socket().abort();
    }

    // -- fixture ----------------------------------------------------------------------------------

    /** An open management WebSocket whose server side is known to be registered. */
    private record Socket(java.net.http.WebSocket socket,
                          java.util.concurrent.CompletableFuture<Integer> closed,
                          java.util.concurrent.atomic.AtomicReference<java.util.concurrent.CompletableFuture<Void>> pong) {
        java.util.concurrent.CompletableFuture<Void> ping() {
            java.util.concurrent.CompletableFuture<Void> next = new java.util.concurrent.CompletableFuture<>();
            pong.set(next);
            socket.sendPing(java.nio.ByteBuffer.allocate(0));
            return next;
        }
    }

    private Socket openManagementSocket(String token, String endpoint) throws Exception {
        HttpResponse<String> issued = send("POST", "/api/admin/ws-tickets", token,
                "{\"endpoint\":\"" + endpoint + "\"}");
        assertThat(issued.statusCode()).as(issued.body()).isEqualTo(200);
        String ticket = JSON.readTree(issued.body()).get("ticket").asText();
        java.util.concurrent.CompletableFuture<Integer> closed = new java.util.concurrent.CompletableFuture<>();
        java.util.concurrent.atomic.AtomicReference<java.util.concurrent.CompletableFuture<Void>> pong =
                new java.util.concurrent.atomic.AtomicReference<>(new java.util.concurrent.CompletableFuture<>());
        java.net.http.WebSocket socket = httpClient.newWebSocketBuilder()
                .buildAsync(URI.create("ws://localhost:" + port + "/ws/" + endpoint + "?ticket=" + ticket),
                        new java.net.http.WebSocket.Listener() {
                            @Override
                            public java.util.concurrent.CompletionStage<?> onPong(java.net.http.WebSocket webSocket,
                                                                                 java.nio.ByteBuffer message) {
                                pong.get().complete(null);
                                webSocket.request(1);
                                return null;
                            }

                            @Override
                            public java.util.concurrent.CompletionStage<?> onClose(java.net.http.WebSocket webSocket,
                                                                                  int statusCode, String reason) {
                                closed.complete(statusCode);
                                return null;
                            }

                            @Override
                            public void onError(java.net.http.WebSocket webSocket, Throwable error) {
                                closed.complete(-1);
                            }
                        })
                .get(10, java.util.concurrent.TimeUnit.SECONDS);
        Socket opened = new Socket(socket, closed, pong);
        // The container answers a ping only once the handler has registered the session.
        opened.ping().get(10, java.util.concurrent.TimeUnit.SECONDS);
        return opened;
    }

    private void seedDeletionRows(JsonNode rows) {
        Instant now = Instant.now();
        String later = SortableInstant.format(now.plusSeconds(3600));
        for (JsonNode row : rows.get("clients")) {
            ClientAccount client = new ClientAccount();
            client.setId(row.get("id").asLong());
            client.setTenantId(row.get("tenantId").asText());
            client.setOwnerUsername(row.get("owner").asText());
            client.setClientName(row.get("clientName").asText());
            client.setPasswordHash("0".repeat(64));
            client.setCreatedAt(now.toString());
            client.setUpdatedAt(now.toString());
            clients.saveAndFlush(client);
        }
        for (JsonNode row : rows.get("credentials")) {
            ClientCredential credential = new ClientCredential();
            credential.setId(row.get("id").asLong());
            credential.setTenantId(row.get("tenantId").asText());
            credential.setOwnerUsername(row.get("owner").asText());
            credential.setApiKey("acct-del-" + row.get("id").asLong());
            credential.setSecretHash("0".repeat(64));
            credential.setCreatedAt(now.toString());
            credential.setUpdatedAt(now.toString());
            credentials.saveAndFlush(credential);
        }
        for (JsonNode row : rows.get("diagrams")) {
            UserDiagramDocument document = new UserDiagramDocument();
            document.setId(row.get("id").asLong());
            document.setTenantId(row.get("tenantId").asText());
            document.setOwnerUsername(row.get("owner").asText());
            document.setName("acct-del-" + row.get("id").asLong());
            document.setSnapshotData(new byte[] {1});
            document.setSizeBytes(1);
            document.setRevision(1);
            document.setCreatedAt(now.toString());
            document.setUpdatedAt(now.toString());
            diagrams.saveAndFlush(document);
        }
        for (JsonNode row : rows.get("attachments")) {
            TransferAttachment attachment = new TransferAttachment();
            attachment.setId(row.get("id").asLong());
            attachment.setTenantId(row.get("tenantId").asText());
            attachment.setScope(TransferAttachmentService.SCOPE_ADMIN_CLIENT_MESSAGE);
            attachment.setOwnerUsername(row.get("owner").asText());
            attachment.setObjectKey("acct-del/" + row.get("id").asLong());
            attachment.setFileName("file.bin");
            attachment.setMimeType("application/octet-stream");
            attachment.setSizeBytes(1);
            attachment.setStatus(row.get("status").asText());
            attachment.setCreatedAt(now.toString());
            attachment.setUpdatedAt(now.toString());
            attachment.setUploadExpiresAt(later);
            attachment.setExpiresAt(later);
            attachments.saveAndFlush(attachment);
        }
        for (JsonNode row : rows.get("downloadGrants")) {
            TransferAttachmentDownloadGrant grant = new TransferAttachmentDownloadGrant();
            grant.setId(row.get("id").asLong());
            grant.setTokenHash(String.format("%064d", row.get("id").asLong()));
            grant.setTenantId(row.get("tenantId").asText());
            grant.setUsername(row.get("username").asText());
            grant.setAttachmentId(row.get("attachmentId").asLong());
            grant.setCreatedAt(now.toString());
            grant.setExpiresAt(later);
            grants.saveAndFlush(grant);
        }
        for (JsonNode row : rows.get("downloadUsage")) {
            TransferAttachmentDownloadUsage used = new TransferAttachmentDownloadUsage();
            used.setId(row.get("id").asLong());
            used.setTenantId(row.get("tenantId").asText());
            used.setUsername(row.get("username").asText());
            used.setAttachmentId(row.get("attachmentId").asLong());
            used.setSizeBytes(1);
            used.setUsageMonth(java.time.YearMonth.now(java.time.ZoneOffset.UTC).toString());
            used.setCreatedAt(now.toString());
            usage.saveAndFlush(used);
        }
        for (JsonNode row : rows.get("acls")) {
            PeerMeshAcl acl = new PeerMeshAcl();
            acl.setId(row.get("id").asLong());
            acl.setTenantId(row.get("tenantId").asText());
            acl.setOwnerUsername(row.get("owner").asText());
            acl.setSourceClientId(row.get("sourceClientId").asLong());
            acl.setSourceClientName("acct-del-" + row.get("sourceClientId").asLong());
            acl.setTargetClientId(row.get("targetClientId").asLong());
            acl.setTargetClientName("acct-del-" + row.get("targetClientId").asLong());
            acl.setCreatedAt(now.toString());
            acl.setUpdatedAt(now.toString());
            acls.saveAndFlush(acl);
        }
        for (JsonNode row : rows.get("egressPolicies")) {
            PeerMeshEgressPolicy policy = new PeerMeshEgressPolicy();
            policy.setId(row.get("id").asLong());
            policy.setTenantId(row.get("tenantId").asText());
            policy.setOwnerUsername(row.get("owner").asText());
            policy.setEgressClientId(row.get("egressClientId").asLong());
            policy.setEgressClientName("acct-del-" + row.get("egressClientId").asLong());
            policy.setCreatedAt(now.toString());
            policy.setUpdatedAt(now.toString());
            policies.saveAndFlush(policy);
        }
        for (JsonNode row : rows.get("devices")) {
            PeerMeshDevice device = new PeerMeshDevice();
            device.setId(row.get("id").asLong());
            device.setTenantId(row.get("tenantId").asText());
            device.setOwnerUsername(row.get("owner").asText());
            device.setClientId(row.get("clientId").asLong());
            device.setClientName("acct-del-" + row.get("clientId").asLong());
            device.setVirtualIp("10.77.0." + (row.get("id").asLong() % 250));
            device.setCidr("10.77.0.0/16");
            device.setCreatedAt(now.toString());
            device.setUpdatedAt(now.toString());
            devices.saveAndFlush(device);
        }
    }

    private void applyDeletionFixture(JsonNode step) {
        switch (step.get("fixture").asText()) {
            case "transfer-client" -> {
                ClientAccount client = clients.findById(step.get("id").asLong()).orElseThrow();
                client.setOwnerUsername(step.get("owner").asText());
                clients.saveAndFlush(client);
                devices.findByTenantIdAndClientId(client.getTenantId(), client.getId()).ifPresent(device -> {
                    device.setOwnerUsername(step.get("owner").asText());
                    devices.saveAndFlush(device);
                });
            }
            case "delete-client" -> clients.deleteById(step.get("id").asLong());
            case "delete-credential" -> credentials.deleteById(step.get("id").asLong());
            case "create-account" -> seed(step.get("accountKey").asText(), step.get("loginName").asText(),
                    step.get("tenantId").asText(), ManagementRole.valueOf(step.get("role").asText()));
            default -> throw new IllegalArgumentException("unknown fixture " + step);
        }
    }

    /** Of the seeded ids of {@code table}, exactly those of rowsAfter remain, with their owners. */
    private static void assertRows(JsonNode seed, JsonNode after, String table,
                                   java.util.function.LongFunction<java.util.Optional<String>> owner) {
        Map<Long, String> expected = new java.util.TreeMap<>();
        for (JsonNode row : after.get(table)) {
            String value = row.has("owner") ? row.get("owner").asText() : row.get("username").asText();
            if (row.has("active")) {
                value += row.get("active").asBoolean() ? " active" : " inactive";
            }
            expected.put(row.get("id").asLong(), value);
        }
        Map<Long, String> actual = new java.util.TreeMap<>();
        for (JsonNode row : seed.get(table)) {
            long id = row.get("id").asLong();
            owner.apply(id).ifPresent(value -> actual.put(id, value));
        }
        assertThat(actual).as(table).isEqualTo(expected);
    }

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
