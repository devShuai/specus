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

/**
 * Startup runs {@link #initialize()} without a transaction, from {@code @PostConstruct}; the admin
 * initialize endpoint runs it through the proxy, inside one. Each step reads the schema from
 * {@link SchemaMetadata} before touching it, because on PostgreSQL a statement that fails, even
 * one caught here, aborts that transaction and every statement after it.
 */
@Component
@Slf4j
public class DatabaseInitializer {
    private static final String HTTP_EXCHANGE_TABLE = "specus_http_traffic_exchange";

    private final ClientAccountRepository clientAccountRepository;
    private final ClientCredentialRepository clientCredentialRepository;
    private final ClientAuthProperties clientAuthProperties;
    private final JdbcTemplate jdbcTemplate;
    private final ManagementUserSchemaMigrator managementUserSchemaMigrator;
    private final ClientDownloadSchemaMigrator clientDownloadSchemaMigrator;
    private final PeerServiceDiscoverySchemaMigrator peerServiceDiscoverySchemaMigrator;
    private final TransferTimestampMigrator transferTimestampMigrator;
    private final HttpExchangeLargeObjectMigrator httpExchangeLargeObjectMigrator;
    private final LegacyDemoCredentialSanitizer legacyDemoCredentialSanitizer;
    private final SqliteUniqueIndexMigrator sqliteUniqueIndexMigrator;
    private final boolean seedDemoClient;
    private final String databasePlatform;
    private final String defaultTenantId;
    private final String adminUsername;

    public DatabaseInitializer(ClientAccountRepository clientAccountRepository,
                               ClientCredentialRepository clientCredentialRepository,
                               ClientAuthProperties clientAuthProperties,
                               JdbcTemplate jdbcTemplate,
                               ManagementUserSchemaMigrator managementUserSchemaMigrator,
                               ClientDownloadSchemaMigrator clientDownloadSchemaMigrator,
                               PeerServiceDiscoverySchemaMigrator peerServiceDiscoverySchemaMigrator,
                               TransferTimestampMigrator transferTimestampMigrator,
                               HttpExchangeLargeObjectMigrator httpExchangeLargeObjectMigrator,
                               LegacyDemoCredentialSanitizer legacyDemoCredentialSanitizer,
                               SqliteUniqueIndexMigrator sqliteUniqueIndexMigrator,
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
        this.clientDownloadSchemaMigrator = clientDownloadSchemaMigrator;
        this.peerServiceDiscoverySchemaMigrator = peerServiceDiscoverySchemaMigrator;
        this.transferTimestampMigrator = transferTimestampMigrator;
        this.httpExchangeLargeObjectMigrator = httpExchangeLargeObjectMigrator;
        this.legacyDemoCredentialSanitizer = legacyDemoCredentialSanitizer;
        this.sqliteUniqueIndexMigrator = sqliteUniqueIndexMigrator;
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
        clientDownloadSchemaMigrator.migrate();
        peerServiceDiscoverySchemaMigrator.migrate();
        transferTimestampMigrator.migrate();
        httpExchangeLargeObjectMigrator.migrate();
        widenHttpBodyTextColumns();
        ensureHttpBinaryBodyColumns();
        backfillDefaultOwner();
        legacyDemoCredentialSanitizer.sanitize();
        // After the backfills: a NULL tenant never collides in a unique index, 'default' can.
        sqliteUniqueIndexMigrator.migrate();
        if (seedDemoClient && clientAccountRepository
                .findByTenantIdAndClientName(tenant.tenantId(), "Demo client").isEmpty()) {
            String now = Instant.now().toString();
            ClientAccount client = new ClientAccount();
            client.setId(ClientIdGenerator.newId());
            client.setTenantId(tenant.tenantId());
            client.setOwnerUsername(adminUsername);
            client.setClientName("Demo client");
            client.setPasswordHash(PasswordService.hashToken("test1234"));
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
            credential.setSecretHash(PasswordService.hashToken("test1234"));
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
                "peer_mesh_session",
                "peer_mesh_service_sharing",
                "peer_mesh_shared_service")) {
            if (!SchemaMetadata.hasColumn(jdbcTemplate, table, "tenant_id")) {
                log.debug("[tenant] skip backfill for {}: no tenant_id column", table);
                continue;
            }
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
            if (!SchemaMetadata.hasColumn(jdbcTemplate, table, "owner_username")) {
                log.debug("[tenant] skip owner backfill for {}: no owner_username column", table);
                continue;
            }
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
        // On MySQL and MariaDB MySqlLobColumnMigrator widens them, and only while they are narrow.
        String normalizedPlatform = databasePlatform == null ? "" : databasePlatform.toLowerCase();
        if (!normalizedPlatform.contains("postgres")) {
            return;
        }
        String statement = "alter table " + HTTP_EXCHANGE_TABLE + " alter column %s type text";
        SchemaMetadata.Table table = SchemaMetadata.table(jdbcTemplate, HTTP_EXCHANGE_TABLE);
        for (String column : List.of("request_preview_text", "response_preview_text")) {
            if (table == null || !table.hasColumn(column)) {
                continue;
            }
            try {
                jdbcTemplate.execute(statement.formatted(column));
            } catch (DataAccessException e) {
                log.debug("[schema] skip widening HTTP body text column {}: {}", column, e.getMessage());
            }
        }
    }

    private void ensureHttpBinaryBodyColumns() {
        String normalizedPlatform = databasePlatform == null ? "" : databasePlatform.toLowerCase();
        String type;
        if (normalizedPlatform.contains("mysql") || normalizedPlatform.contains("mariadb")) {
            type = "longblob";
        } else if (normalizedPlatform.contains("postgres")) {
            type = "bytea";
        } else {
            return;
        }
        SchemaMetadata.Table table = SchemaMetadata.table(jdbcTemplate, HTTP_EXCHANGE_TABLE);
        if (table == null) {
            return;
        }
        for (String column : List.of("request_body_data", "response_body_data")) {
            if (table.hasColumn(column)) {
                continue;
            }
            try {
                jdbcTemplate.execute("alter table " + HTTP_EXCHANGE_TABLE + " add column " + column + " " + type);
            } catch (DataAccessException e) {
                log.debug("[schema] skip adding HTTP binary body column {}: {}", column, e.getMessage());
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
