package com.theshuai.tunnelserver.database;

import com.theshuai.tunnelserver.management.model.ClientAccount;
import com.theshuai.tunnelserver.management.repository.ClientAccountRepository;
import com.theshuai.tunnelserver.management.service.ClientIdGenerator;
import com.theshuai.tunnelserver.management.tenant.TenantContext;
import com.theshuai.tunnelserver.security.PasswordService;
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
    private final JdbcTemplate jdbcTemplate;
    private final boolean seedDemoClient;
    private final String databasePlatform;
    private final String defaultTenantId;

    public DatabaseInitializer(ClientAccountRepository clientAccountRepository,
                               JdbcTemplate jdbcTemplate,
                               @Value("${tunnel.database.seed-demo-client:true}") boolean seedDemoClient,
                               @Value("${spring.jpa.database-platform:auto}") String databasePlatform,
                               @Value("${tunnel.auth.tenant-id:default}") String defaultTenantId) {
        this.clientAccountRepository = clientAccountRepository;
        this.jdbcTemplate = jdbcTemplate;
        this.seedDemoClient = seedDemoClient;
        this.databasePlatform = databasePlatform;
        this.defaultTenantId = TenantContext.normalize(defaultTenantId);
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
        widenHttpRequestPreviewText();
        backfillDefaultTenant();
        if (seedDemoClient && clientAccountRepository
                .findByTenantIdAndClientName(tenant.tenantId(), "Demo client").isEmpty()) {
            String now = Instant.now().toString();
            ClientAccount client = new ClientAccount();
            client.setId(ClientIdGenerator.newId());
            client.setTenantId(tenant.tenantId());
            client.setClientName("Demo client");
            client.setPasswordHash(PasswordService.hash("test1234"));
            client.setEnabled(true);
            client.setConnectionRateLimitPerMinute(30);
            client.setCreatedAt(now);
            client.setUpdatedAt(now);
            clientAccountRepository.save(client);
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
                "tunnel_client_account",
                "tunnel_mapping",
                "http_route_mapping",
                "tunnel_connection_record",
                "tunnel_connection_stat",
                "tunnel_traffic_usage")) {
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

    private void widenHttpRequestPreviewText() {
        String normalizedPlatform = databasePlatform == null ? "" : databasePlatform.toLowerCase();
        String sql = null;
        if (normalizedPlatform.contains("mysql") || normalizedPlatform.contains("mariadb")) {
            sql = "alter table tunnel_http_traffic_exchange modify column request_preview_text longtext";
        } else if (normalizedPlatform.contains("postgres")) {
            sql = "alter table tunnel_http_traffic_exchange alter column request_preview_text type text";
        }
        if (sql == null) {
            return;
        }
        try {
            jdbcTemplate.execute(sql);
        } catch (DataAccessException e) {
            log.debug("[schema] skip widening tunnel_http_traffic_exchange.request_preview_text: {}", e.getMessage());
        }
    }

}
