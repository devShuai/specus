package com.theshuai.specusserver.database;

import lombok.extern.slf4j.Slf4j;
import org.springframework.dao.DataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * Idempotent upgrade for installations that already have the legacy external-link-only table.
 * Hibernate creates the nullable columns for new deployments; this migrator backfills legacy rows
 * before portable unique catalogue/latest keys are enforced.
 */
@Component
@Slf4j
public class ClientDownloadSchemaMigrator {
    private final JdbcTemplate jdbcTemplate;

    public ClientDownloadSchemaMigrator(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    public void migrate() {
        for (String definition : List.of(
                "version varchar(32)",
                "sha256 varchar(64)",
                "file_size bigint",
                "is_latest boolean",
                "changelog_url varchar(1024)",
                "min_supported_version varchar(32)",
                "hosted boolean",
                "catalog_key varchar(160)",
                "latest_slot varchar(100)")) {
            try {
                jdbcTemplate.execute("alter table client_download_link add column " + definition);
            } catch (DataAccessException exception) {
                log.debug("[client-package] column already present or table unavailable ({}): {}",
                        definition, exception.getMessage());
            }
        }

        List<Map<String, Object>> rows;
        try {
            rows = jdbcTemplate.queryForList("""
                    select id, implementation, platform, arch, version, is_latest, hosted
                      from client_download_link
                     order by id desc
                    """);
        } catch (DataAccessException exception) {
            log.debug("[client-package] legacy table not ready for migration: {}", exception.getMessage());
            return;
        }

        Set<String> catalogKeys = new HashSet<>();
        Set<String> latestSlots = new HashSet<>();
        for (Map<String, Object> row : rows) {
            long id = ((Number) row.get("id")).longValue();
            String implementation = normalized(row.get("implementation"));
            String platform = normalized(row.get("platform"));
            String arch = normalized(row.get("arch"));
            String version = text(row.get("version"));
            if (!StringUtils.hasText(version)) {
                version = legacyVersion(id);
            }
            String catalogKey = catalogueKey(implementation, platform, arch, version);
            if (!catalogKeys.add(catalogKey)) {
                version = legacyVersion(id);
                catalogKey = catalogueKey(implementation, platform, arch, version);
                catalogKeys.add(catalogKey);
            }

            boolean latest = truthy(row.get("is_latest"));
            String latestSlot = targetKey(implementation, platform, arch);
            if (latest && !latestSlots.add(latestSlot)) {
                latest = false;
            }
            boolean hosted = truthy(row.get("hosted"));
            jdbcTemplate.update("""
                    update client_download_link
                       set version = ?, file_size = coalesce(file_size, 0), is_latest = ?,
                           hosted = ?, catalog_key = ?, latest_slot = ?
                     where id = ?
                    """, version, latest, hosted, catalogKey, latest ? latestSlot : null, id);
        }

        createUniqueIndex("ux_client_download_catalog_key", "catalog_key");
        createUniqueIndex("ux_client_download_latest_slot", "latest_slot");
    }

    private void createUniqueIndex(String name, String column) {
        try {
            jdbcTemplate.execute("create unique index " + name
                    + " on client_download_link (" + column + ")");
        } catch (DataAccessException exception) {
            log.debug("[client-package] unique index {} already present: {}", name, exception.getMessage());
        }
    }

    public static String legacyVersion(long id) {
        return "0.0.0-legacy." + Long.toUnsignedString(id);
    }

    public static String catalogueKey(String implementation, String platform, String arch, String version) {
        return targetKey(implementation, platform, arch) + "|" + version;
    }

    public static String targetKey(String implementation, String platform, String arch) {
        return implementation + "|" + platform + "|" + arch;
    }

    private static String normalized(Object value) {
        return text(value).toLowerCase(Locale.ROOT);
    }

    private static String text(Object value) {
        return value == null ? "" : value.toString().trim();
    }

    private static boolean truthy(Object value) {
        if (value instanceof Boolean bool) {
            return bool;
        }
        if (value instanceof Number number) {
            return number.intValue() != 0;
        }
        return value != null && ("true".equalsIgnoreCase(value.toString()) || "1".equals(value.toString()));
    }
}
