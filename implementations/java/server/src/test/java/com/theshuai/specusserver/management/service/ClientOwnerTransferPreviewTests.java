package com.theshuai.specusserver.management.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.theshuai.specusserver.management.controller.ClientOwnerTransferResource;
import com.theshuai.specusserver.management.controller.GlobalExceptionHandler;
import com.theshuai.specusserver.management.model.ManagementRole;
import com.theshuai.specusserver.management.repository.ManagementUserRepository;
import com.theshuai.specusserver.management.security.ManagementContext;
import com.theshuai.specusserver.management.security.ManagementContextResolver;
import com.theshuai.specusserver.management.tenant.TenantContext;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.web.method.annotation.AuthenticationPrincipalArgumentResolver;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import javax.sql.DataSource;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.setup.MockMvcBuilders.standaloneSetup;

/** Real SQLite and production service/controller; only management identity resolution is stubbed. */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.NONE, properties = {
        "spring.datasource.url=jdbc:sqlite:file:target/test-owner-preview?mode=memory&cache=shared",
        "spring.jpa.database-platform=org.hibernate.community.dialect.SQLiteDialect",
        "spring.jpa.hibernate.ddl-auto=create-drop",
        "specus.netty.port=0", "specus.database.seed-demo-client=false"
})
class ClientOwnerTransferPreviewTests {
    private static final String STAMP = "2026-10-14T00:00:00Z";
    private static final ObjectMapper JSON = new ObjectMapper();
    private static final ManagementContext ADMIN = new ManagementContext(new TenantContext("tenant-a"), "admin", true);
    private static final List<String> TABLES = List.of("specus_client_account", "specus_client_credential",
            "specus_client_identity", "peer_mesh_device");
    @Autowired private ClientOwnerTransferService transfers;
    @Autowired private DataSource dataSource;
    @Autowired private ManagementContextResolver actualIdentityResolver;
    @Autowired private ManagementUserService users;
    @Autowired private ManagementUserRepository managementUsers;
    private JdbcTemplate jdbc;
    private ManagementContextResolver identities;
    private MockMvc mvc;

    @BeforeEach
    void setUp() {
        jdbc = new JdbcTemplate(dataSource);
        identities = mock(ManagementContextResolver.class);
        when(identities.resolve(any())).thenReturn(ADMIN);
        mvc = standaloneSetup(new ClientOwnerTransferResource(transfers, identities))
                .setControllerAdvice(new GlobalExceptionHandler())
                .setCustomArgumentResolvers(new AuthenticationPrincipalArgumentResolver()).build();
    }

    @TestFactory
    Stream<DynamicTest> sharedGetVectorsThroughActualDatabase() throws Exception {
        JsonNode vector = vector();
        List<DynamicTest> tests = new ArrayList<>();
        for (JsonNode scenario : vector.path("cases")) {
            if (scenario.has("request")) continue;
            // The physical unique constraint forbids this corrupt peer fixture. The pure plan
            // vector still verifies fail-closed behavior instead of disabling a real constraint.
            if (scenario.path("snapshot").asText().equals("duplicate-peer")) continue;
            tests.add(DynamicTest.dynamicTest(scenario.path("name").asText(), () -> {
                seed(snapshot(vector, scenario.path("snapshot").asText()));
                List<List<Map<String, Object>>> before = rows();
                MvcResult response = mvc.perform(get(route(scenario.path("scope").asText(), scenario.path("id").asText())))
                        .andExpect(header().string("Cache-Control", "no-store")).andReturn();
                JsonNode body = JSON.readTree(response.getResponse().getContentAsString(StandardCharsets.UTF_8));
                if (scenario.has("error")) {
                    assertThat(response.getResponse().getStatus()).isEqualTo(scenario.path("error").path("status").asInt());
                    assertThat(body.path("code")).isEqualTo(scenario.path("error").path("code"));
                    assertThat(body.path("error").asText()).isEqualTo(body.path("code").asText());
                } else {
                    assertThat(response.getResponse().getStatus()).isEqualTo(200);
                    JsonNode expected = scenario.path("preview");
                    for (String field : List.of("clientId", "credentialId", "canTransfer", "conflictCode")) {
                        assertThat(body.get(field)).as(field).isEqualTo(expected.get(field));
                    }
                    ArrayNode actualIds = JSON.createArrayNode();
                    body.path("affectedClients").forEach(client -> actualIds.add(client.path("id").longValue()));
                    assertThat(actualIds.toString()).isEqualTo(expected.path("affectedClientIds").toString());
                    assertThat(body.path("affectedClientCount").asInt()).isEqualTo(actualIds.size());
                    assertThat(!body.path("revision").isNull()).isEqualTo(expected.path("hasRevision").asBoolean());
                    assertThat(body.path("accessRetained").asBoolean()).isTrue();
                    assertThat(body.toString()).doesNotContain("sensitive-", "secretHash", "passwordHash", "machineFingerprint");
                }
                assertThat(rows()).isEqualTo(before);
            }));
        }
        assertThat(tests).isNotEmpty();
        return tests.stream();
    }

    @Test
    void nonAdminRejectedBeforeParsingOrLookingUpPath() throws Exception {
        seed(snapshot(vector(), "shared"));
        when(identities.resolve(any())).thenReturn(new ManagementContext(ADMIN.tenant(), "alice", false));
        for (String id : List.of("1001", "999", "not-a-number", "0", "9007199254740992")) {
            mvc.perform(get(route("single", id))).andExpect(status().isForbidden())
                    .andExpect(jsonPath("$.code").value("FORBIDDEN"));
        }
    }

    @Test
    void actualIdentityResolverRechecksCurrentRoleAndEnabledStateForEveryPreview() throws Exception {
        seed(snapshot(vector(), "shared"));
        users.createUser(ADMIN, new ManagementUserService.UserMutation(
                "preview-admin", "preview-test-password", ManagementRole.ADMIN, true));
        String accountKey = managementUsers.findByTenantIdAndLoginNameNormalized("tenant-a", "preview-admin")
                .orElseThrow().getUsername();
        MockMvc realIdentityMvc = standaloneSetup(new ClientOwnerTransferResource(transfers, actualIdentityResolver))
                .setControllerAdvice(new GlobalExceptionHandler())
                .setCustomArgumentResolvers(new AuthenticationPrincipalArgumentResolver()).build();
        Jwt jwt = Jwt.withTokenValue("fixture-already-validated-token").header("alg", "HS256")
                .issuer("specus").subject("preview-admin").claim("tenant_id", "tenant-a")
                .claim("uid", accountKey).build();
        try {
            SecurityContextHolder.clearContext();
            realIdentityMvc.perform(get(route("single", "1001"))).andExpect(status().isUnauthorized());
            SecurityContextHolder.getContext().setAuthentication(new JwtAuthenticationToken(jwt));
            realIdentityMvc.perform(get(route("single", "1001"))).andExpect(status().isOk());
            users.updateUser(ADMIN, "preview-admin", new ManagementUserService.UserMutation(
                    null, null, ManagementRole.USER, null));
            realIdentityMvc.perform(get(route("single", "not-a-number"))).andExpect(status().isForbidden())
                    .andExpect(jsonPath("$.code").value("FORBIDDEN"));
            users.updateUser(ADMIN, "preview-admin", new ManagementUserService.UserMutation(
                    null, null, ManagementRole.ADMIN, false));
            realIdentityMvc.perform(get(route("single", "1001"))).andExpect(status().isForbidden());
        } finally {
            SecurityContextHolder.clearContext();
            users.deleteUser(ADMIN, "preview-admin");
        }
        // Token signature verification belongs to the existing security filter chain; this
        // test covers the production resolver/current database authorization after that stage.
    }

    @Test
    void absentAndForeignPathResourcesAreIndistinguishable() throws Exception {
        seed(snapshot(vector(), "foreign-client"));
        for (String id : List.of("1002", "999")) {
            mvc.perform(get(route("single", id))).andExpect(status().isNotFound())
                    .andExpect(jsonPath("$.code").value("RESOURCE_NOT_FOUND"));
        }
        when(identities.resolve(any())).thenReturn(new ManagementContext(new TenantContext("tenant-b"), "admin", true));
        mvc.perform(get(route("credential-group", "501"))).andExpect(status().isNotFound())
                .andExpect(jsonPath("$.code").value("RESOURCE_NOT_FOUND"));
    }

    @Test
    void invalidIdShapesHaveStableErrors() throws Exception {
        seed(snapshot(vector(), "shared"));
        for (String id : List.of("-1", "1.0", "1e3", "9223372036854775808", "abc")) {
            mvc.perform(get(route("single", id))).andExpect(status().isBadRequest())
                    .andExpect(jsonPath("$.code").value("INVALID_TRANSFER_REQUEST"));
        }
    }

    @Test
    void sqlSnapshotIncludesReverseEdgesAndDoesNotFilterForeignCorruption() throws Exception {
        seed(snapshot(vector(), "multiple-credentials"));
        mvc.perform(get(route("single", "1001"))).andExpect(status().isConflict())
                .andExpect(jsonPath("$.code").value("INCONSISTENT_CREDENTIAL_GROUP"));
        seed(snapshot(vector(), "foreign-identity"));
        mvc.perform(get(route("single", "1001"))).andExpect(status().isConflict())
                .andExpect(jsonPath("$.code").value("INCONSISTENT_CREDENTIAL_GROUP"));
    }

    @Test
    void heartbeatAndRuntimeMetadataAreExcludedButNameChangesInvalidatePreview() throws Exception {
        seed(snapshot(vector(), "shared"));
        String revision = readGroupRevision();
        jdbc.update("UPDATE specus_client_identity SET last_seen_at=?, hostname=? WHERE id=701",
                "2026-10-15T00:00:00Z", "updated-hostname");
        jdbc.update("UPDATE peer_mesh_device SET last_seen_at=?, last_endpoint=?, updated_at=? WHERE id=801",
                "2026-10-15T00:00:00Z", "192.0.2.1:5000", "2026-10-15T00:00:00Z");
        assertThat(readGroupRevision()).isEqualTo(revision);
        jdbc.update("UPDATE specus_client_account SET client_name='renamed' WHERE id=1002");
        assertThat(readGroupRevision()).isNotEqualTo(revision);
    }

    @Test
    void freshServiceInstanceCanValidateTheSamePreview() throws Exception {
        seed(snapshot(vector(), "shared"));
        String revision = readGroupRevision();
        assertThat(new ClientOwnerTransferService(dataSource).previewCredential(ADMIN, "501").revision()).isEqualTo(revision);
        // This verifies the stateless revision only, not multi-instance coordinated transfer.
    }

    @Test
    void completeDatabaseGroupHasNoParameterOrPagingTruncation() throws Exception {
        ObjectNode input = snapshot(vector(), "shared");
        ArrayNode clients = JSON.createArrayNode();
        ArrayNode identityRows = JSON.createArrayNode();
        for (int n = 0; n < 1050; n++) {
            ObjectNode client = input.path("clients").get(0).deepCopy();
            client.put("id", 1001 + n).put("clientName", "device-" + n).put("enabled", n % 2 == 0);
            clients.add(client);
            ObjectNode identity = input.path("identities").get(0).deepCopy();
            identity.put("id", 10001 + n).put("clientId", 1001 + n);
            identityRows.add(identity);
        }
        input.set("clients", clients);
        input.set("identities", identityRows);
        seed(input);
        mvc.perform(get(route("credential-group", "501"))).andExpect(status().isOk())
                .andExpect(jsonPath("$.affectedClientCount").value(1050))
                .andExpect(jsonPath("$.affectedClients[1049].id").value(2050));
    }

    @Test
    void postIsNotExposedBeforeMutationCoordinationIsImplemented() throws Exception {
        seed(snapshot(vector(), "shared"));
        List<List<Map<String, Object>>> before = rows();
        for (String route : List.of(route("single", "1001"), route("credential-group", "501"))) {
            mvc.perform(post(route).contentType("application/json")
                    .content("{\"scope\":\"credential-group\",\"targetUsername\":\"bob\",\"expectedRevision\":\"stale\"}"))
                    .andExpect(status().isMethodNotAllowed());
        }
        assertThat(rows()).isEqualTo(before);
    }

    private String readGroupRevision() throws Exception {
        MvcResult result = mvc.perform(get(route("credential-group", "501"))).andExpect(status().isOk()).andReturn();
        return JSON.readTree(result.getResponse().getContentAsString(StandardCharsets.UTF_8)).path("revision").asText();
    }

    private List<List<Map<String, Object>>> rows() {
        return TABLES.stream().map(table -> jdbc.queryForList("SELECT * FROM " + table + " ORDER BY id")).toList();
    }

    private void seed(ObjectNode data) {
        for (String table : List.of("peer_mesh_device", "specus_client_identity", "specus_client_credential", "specus_client_account")) {
            jdbc.execute("DELETE FROM " + table);
        }
        for (JsonNode row : data.path("clients")) {
            jdbc.update("INSERT INTO specus_client_account(id,tenant_id,client_name,owner_username,enabled,password_hash,connection_rate_limit_per_minute,created_at,updated_at) VALUES (?,?,?,?,?,?,30,?,?)",
                    row.path("id").asLong(), row.path("tenantId").asText(), row.path("clientName").asText(),
                    row.path("ownerUsername").asText(), row.path("enabled").asBoolean(), "sensitive-password", STAMP, STAMP);
        }
        for (JsonNode row : data.path("credentials")) {
            jdbc.update("INSERT INTO specus_client_credential(id,tenant_id,owner_username,enabled,api_key,secret_hash,max_online_instances,created_at,updated_at) VALUES (?,?,?,?,?,?,10,?,?)",
                    row.path("id").asLong(), row.path("tenantId").asText(), row.path("ownerUsername").asText(),
                    row.path("enabled").asBoolean(), "ck-" + row.path("id").asLong(), "sensitive-secret", STAMP, STAMP);
        }
        for (JsonNode row : data.path("identities")) {
            jdbc.update("INSERT INTO specus_client_identity(id,tenant_id,credential_id,client_id,client_name,machine_fingerprint,os_user,first_seen_at,last_seen_at) VALUES (?,?,?,?,?,?,?,?,?)",
                    row.path("id").asLong(), row.path("tenantId").asText(), row.path("credentialId").asLong(),
                    row.path("clientId").asLong(), "fixture", "sensitive-fingerprint-" + row.path("id").asLong(),
                    "sensitive-os-user", STAMP, STAMP);
        }
        for (JsonNode row : data.path("peers")) {
            jdbc.update("INSERT INTO peer_mesh_device(id,tenant_id,client_id,client_name,owner_username,enabled,virtual_ip,cidr,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?)",
                    row.path("id").asLong(), row.path("tenantId").asText(), row.path("clientId").asLong(),
                    row.path("clientName").asText(), row.path("ownerUsername").asText(), row.path("enabled").asBoolean(),
                    "100.96.0." + (row.path("id").asLong() - 800), "100.96.0.0/16", STAMP, STAMP);
        }
    }

    private static String route(String scope, String id) {
        return "/api/admin/" + (scope.equals("single") ? "clients/" : "client-credentials/") + id + "/owner-transfer";
    }

    private static ObjectNode snapshot(JsonNode vector, String name) {
        ObjectNode input = vector.path("base").deepCopy();
        vector.path("snapshots").path(name).fields().forEachRemaining(entry -> input.set(entry.getKey(), entry.getValue().deepCopy()));
        return input;
    }

    private static JsonNode vector() throws Exception {
        Path root = Path.of("").toAbsolutePath();
        while (root != null && !Files.exists(root.resolve("protocol/test-vectors/client-owner-transfer-plan-v1.json"))) root = root.getParent();
        assertThat(root).as("repository shared ownership vectors").isNotNull();
        return JSON.readTree(Files.readString(root.resolve("protocol/test-vectors/client-owner-transfer-plan-v1.json")));
    }
}
