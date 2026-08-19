package com.theshuai.specusserver.database;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.dao.DataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Locale;

/**
 * Idempotent upgrade that keeps Peer service sharing off for existing databases.
 * Missing tables are created with {@code enabled=false}; existing rows are never flipped on.
 */
@Component
@Slf4j
public class PeerServiceDiscoverySchemaMigrator {
    private final JdbcTemplate jdbcTemplate;
    private final String databasePlatform;

    public PeerServiceDiscoverySchemaMigrator(JdbcTemplate jdbcTemplate,
                                              @Value("${spring.jpa.database-platform:auto}") String databasePlatform) {
        this.jdbcTemplate = jdbcTemplate;
        this.databasePlatform = databasePlatform == null ? "" : databasePlatform;
    }

    @Transactional
    public void migrate() {
        Dialect dialect = dialect();
        for (String statement : createStatements(dialect)) {
            try {
                jdbcTemplate.execute(statement);
            } catch (DataAccessException e) {
                log.debug("[peer-service] skip schema statement: {}", e.getMessage());
            }
        }
        ensureColumn("specus_client_session", "peer_service_discovery_version", dialect.intDefaultZero());
        ensureColumn("specus_client_session", "peer_service_applications", dialect.varchar(160));
        ensureColumn("peer_mesh_shared_service", "allowed_client_ids", dialect.varchar(512));
        ensureColumn("peer_mesh_service_sharing", "mdns_import_enabled", dialect.boolNotNullFalse());
        int sharingForcedOff = 0;
        try {
            sharingForcedOff = jdbcTemplate.update(
                    "update peer_mesh_service_sharing set enabled = " + dialect.falseLiteral()
                            + " where enabled is null");
        } catch (DataAccessException e) {
            log.debug("[peer-service] skip sharing null backfill: {}", e.getMessage());
        }
        int servicesForcedOff = 0;
        try {
            servicesForcedOff = jdbcTemplate.update(
                    "update peer_mesh_shared_service set enabled = " + dialect.falseLiteral()
                            + " where enabled is null");
        } catch (DataAccessException e) {
            log.debug("[peer-service] skip service null backfill: {}", e.getMessage());
        }
        if (sharingForcedOff > 0 || servicesForcedOff > 0) {
            log.info("[peer-service] default-off backfill sharing={} services={}",
                    sharingForcedOff, servicesForcedOff);
        }
    }

    private void ensureColumn(String table, String column, String definition) {
        try {
            jdbcTemplate.query("select " + column + " from " + table + " where 1 = 0", rs -> null);
        } catch (DataAccessException missing) {
            jdbcTemplate.execute("alter table " + table + " add column " + column + " " + definition);
            log.info("[peer-service] added {}.{}", table, column);
        }
    }

    private List<String> createStatements(Dialect dialect) {
        return List.of(
                """
                create table if not exists peer_mesh_service_sharing (
                    tenant_id %s not null,
                    enabled %s not null,
                    updated_by %s,
                    updated_at %s not null,
                    primary key (tenant_id)
                )
                """.formatted(dialect.varchar(80), dialect.boolNotNullFalse(), dialect.varchar(80), dialect.varchar(40)),
                """
                create table if not exists peer_mesh_shared_service (
                    id %s not null,
                    tenant_id %s not null,
                    client_id %s not null,
                    client_name %s not null,
                    service_id %s not null,
                    name %s not null,
                    description %s,
                    transport %s not null,
                    application %s not null,
                    target_host %s not null,
                    target_port %s not null,
                    published_port %s not null,
                    path %s,
                    enabled %s not null,
                    visibility %s not null,
                    created_at %s not null,
                    updated_at %s not null,
                    primary key (id)
                )
                """.formatted(
                        dialect.bigint(),
                        dialect.varchar(80),
                        dialect.bigint(),
                        dialect.varchar(120),
                        dialect.varchar(64),
                        dialect.varchar(80),
                        dialect.varchar(200),
                        dialect.varchar(16),
                        dialect.varchar(16),
                        dialect.varchar(64),
                        dialect.intType(),
                        dialect.intType(),
                        dialect.varchar(128),
                        dialect.boolNotNullFalse(),
                        dialect.varchar(16),
                        dialect.varchar(40),
                        dialect.varchar(40)),
                "create unique index if not exists uk_peer_shared_service_id on peer_mesh_shared_service (tenant_id, client_id, service_id)",
                "create index if not exists idx_peer_shared_service_tenant_client on peer_mesh_shared_service (tenant_id, client_id)"
        );
    }

    private Dialect dialect() {
        String platform = databasePlatform.toLowerCase(Locale.ROOT);
        if (platform.contains("mysql") || platform.contains("mariadb")) {
            return Dialect.MYSQL;
        }
        if (platform.contains("postgres")) {
            return Dialect.POSTGRES;
        }
        return Dialect.SQLITE;
    }

    private enum Dialect {
        SQLITE, MYSQL, POSTGRES;

        private String varchar(int length) {
            return this == SQLITE ? "TEXT" : "varchar(" + length + ")";
        }

        private String bigint() {
            return this == SQLITE ? "INTEGER" : "bigint";
        }

        private String intType() {
            return this == SQLITE ? "INTEGER" : "integer";
        }

        private String boolNotNullFalse() {
            return switch (this) {
                case POSTGRES -> "boolean not null default false";
                case MYSQL -> "tinyint(1) not null default 0";
                case SQLITE -> "INTEGER not null default 0";
            };
        }

        private String intDefaultZero() {
            return switch (this) {
                case POSTGRES -> "integer not null default 0";
                case MYSQL -> "int not null default 0";
                case SQLITE -> "INTEGER not null default 0";
            };
        }

        private String falseLiteral() {
            return this == POSTGRES ? "false" : "0";
        }
    }
}
