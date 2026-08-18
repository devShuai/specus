package com.theshuai.specusserver.database;

import com.theshuai.specusserver.config.ClientAuthProperties;
import com.theshuai.specusserver.config.DeploymentEnvironment;
import com.theshuai.specusserver.management.model.ClientAccount;
import com.theshuai.specusserver.management.model.ClientCredential;
import com.theshuai.specusserver.management.repository.ClientAccountRepository;
import com.theshuai.specusserver.management.repository.ClientCredentialRepository;
import com.theshuai.specusserver.management.service.ClientIdGenerator;
import com.theshuai.specusserver.management.tenant.TenantContext;
import com.theshuai.specusserver.security.PasswordService;
import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;
import org.springframework.dao.DataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

@Component
@Slf4j
public class DatabaseInitializer {
    private final ClientAccountRepository clientAccountRepository;
    private final ClientCredentialRepository clientCredentialRepository;
    private final ClientAuthProperties clientAuthProperties;
    private final JdbcTemplate jdbcTemplate;
    private final ManagementUserSchemaMigrator managementUserSchemaMigrator;
    private final boolean seedDemoClient;
    private final String databasePlatform;
    private final String defaultTenantId;
    private final String adminUsername;

    public DatabaseInitializer(ClientAccountRepository clientAccountRepository,
                               ClientCredentialRepository clientCredentialRepository,
                               ClientAuthProperties clientAuthProperties,
                               JdbcTemplate jdbcTemplate,
                               ManagementUserSchemaMigrator managementUserSchemaMigrator,
                               @Value("${specus.database.seed-demo-client:true}") boolean seedDemoClient,
                               @Value("${specus.env:}") String environmentName,
                               @Value("${spring.jpa.database-platform:auto}") String databasePlatform,
                               @Value("${specus.auth.tenant-id:default}") String defaultTenantId,
                               @Value("${specus.auth.username:admin}") String adminUsername) {
        this.clientAccountRepository = clientAccountRepository;
        this.clientCredentialRepository = clientCredentialRepository;
        this.clientAuthProperties = clientAuthProperties;
        this.jdbcTemplate = jdbcTemplate;
        this.managementUserSchemaMigrator = managementUserSchemaMigrator;
        // Demo data is convenience-only; prod never seeds it regardless of the requested flag.
        this.seedDemoClient = seedDemoClient && DeploymentEnvironment.parse(environmentName).allowsDemoData();
        this.databasePlatform = databasePlatform;
        this.defaultTenantId = TenantContext.normalize(defaultTenantId);
        this.adminUsername = normalizeAdminUsername(adminUsername);
    }

    @PostConstruct
    public void initializeAtStartup() {
        initialize();
    }

    @Transactional
    public synchronized Map<String, Object> initialize() {
        return initialize(new TenantContext(defaultTenantId));
    }

    @Transactional
    public synchronized Map<String, Object> initialize(TenantContext tenant) {
        backfillDefaultTenant();
        managementUserSchemaMigrator.migrate();
        widenHttpBodyTextColumns();
        ensureHttpBinaryBodyColumns();
        backfillDefaultOwner();
        if (seedDemoClient && clientAccountRepository
                .findByTenantIdAndClientName(tenant.tenantId(), "Demo client").isEmpty()) {
            String now = Instant.now().toString();
            ClientAccount client = new ClientAccount();
            client.setId(ClientIdGenerator.newId());
            client.setTenantId(tenant.tenantId());
            client.setOwnerUsername(adminUsername);
            client.setClientName("Demo client");
            client.setPasswordHash(PasswordService.hash("test1234"));
            client.setEnabled(true);
            client.setConnectionRateLimitPerMinute(30);
            client.setCreatedAt(now);
            client.setUpdatedAt(now);
            clientAccountRepository.save(client);
        }
        if (seedDemoClient && clientCredentialRepository.findByApiKey("demo-client").isEmpty()) {
            String now = Instant.now().toString();
            ClientCredential credential = new ClientCredential();
            credential.setId(ClientIdGenerator.newId());
            credential.setTenantId(tenant.tenantId());
            credential.setOwnerUsername(adminUsername);
            credential.setApiKey("demo-client");
            credential.setSecretHash(PasswordService.hash("test1234"));
            credential.setEnabled(true);
            credential.setMaxOnlineInstances(clientAuthProperties.getDefaultMaxOnlineInstances());
            credential.setCreatedAt(now);
            credential.setUpdatedAt(now);
            clientCredentialRepository.save(credential);
        }

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("initialized", true);
        result.put("tenantId", tenant.tenantId());
        result.put("orm", "spring-data-jpa");
        result.put("dialect", databasePlatform);
        result.put("clients", clientAccountRepository.countByTenantId(tenant.tenantId()));
        return result;
    }

    private void backfillDefaultTenant() {
        for (String table : List.of(
                "specus_client_account",
                "specus_client_credential",
                "specus_management_user",
                "specus_client_identity",
                "specus_client_session",
                "specus_mapping",
                "http_route_mapping",
                "specus_http_media_capture",
                "specus_http_media_reference",
                "specus_connection_record",
                "specus_connection_stat",
                "specus_traffic_usage",
                "peer_mesh_device",
                "peer_mesh_acl",
                "peer_mesh_session")) {
            try {
                int rows = jdbcTemplate.update(
                        "update " + table + " set tenant_id = ? where tenant_id is null or tenant_id = ''",
                        defaultTenantId);
                if (rows > 0) {
                    log.info("[tenant] backfilled {} row(s) in {} to tenant '{}'", rows, table, defaultTenantId);
                }
            } catch (DataAccessException e) {
                log.debug("[tenant] skip backfill for {}: {}", table, e.getMessage());
            }
        }
    }

    private void backfillDefaultOwner() {
        for (String table : List.of(
                "specus_client_account",
                "specus_client_credential",
                "peer_mesh_device",
                "peer_mesh_acl")) {
            try {
                int rows = jdbcTemplate.update(
                        "update " + table + " set owner_username = ? where owner_username is null or owner_username = ''",
                        adminUsername);
                if (rows > 0) {
                    log.info("[tenant] backfilled {} row(s) in {} to owner '{}'", rows, table, adminUsername);
                }
            } catch (DataAccessException e) {
                log.debug("[tenant] skip owner backfill for {}: {}", table, e.getMessage());
            }
        }
    }

    private void widenHttpBodyTextColumns() {
        String normalizedPlatform = databasePlatform == null ? "" : databasePlatform.toLowerCase();
        List<String> sql = List.of();
        if (normalizedPlatform.contains("mysql") || normalizedPlatform.contains("mariadb")) {
            sql = List.of(
                    "alter table specus_http_traffic_exchange modify column request_preview_text longtext",
                    "alter table specus_http_traffic_exchange modify column response_preview_text longtext"
            );
        } else if (normalizedPlatform.contains("postgres")) {
            sql = List.of(
                    "alter table specus_http_traffic_exchange alter column request_preview_text type text",
                    "alter table specus_http_traffic_exchange alter column response_preview_text type text"
            );
        }
        for (String statement : sql) {
            try {
                jdbcTemplate.execute(statement);
            } catch (DataAccessException e) {
                log.debug("[schema] skip widening HTTP body text column with '{}': {}", statement, e.getMessage());
            }
        }
    }

    private void ensureHttpBinaryBodyColumns() {
        String normalizedPlatform = databasePlatform == null ? "" : databasePlatform.toLowerCase();
        List<String> sql = List.of();
        if (normalizedPlatform.contains("mysql") || normalizedPlatform.contains("mariadb")) {
            sql = List.of(
                    "alter table specus_http_traffic_exchange add column request_body_data longblob",
                    "alter table specus_http_traffic_exchange add column response_body_data longblob"
            );
        } else if (normalizedPlatform.contains("postgres")) {
            sql = List.of(
                    "alter table specus_http_traffic_exchange add column request_body_data bytea",
                    "alter table specus_http_traffic_exchange add column response_body_data bytea"
            );
        }
        for (String statement : sql) {
            try {
                jdbcTemplate.execute(statement);
            } catch (DataAccessException e) {
                log.debug("[schema] skip adding HTTP binary body column with '{}': {}", statement, e.getMessage());
            }
        }
    }

    private String normalizeAdminUsername(String username) {
        if (username == null || username.isBlank()) {
            return "admin";
        }
        return username.trim();
    }

}
