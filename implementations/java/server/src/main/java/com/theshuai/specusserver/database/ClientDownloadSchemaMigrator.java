package com.theshuai.specusserver.database;

import lombok.extern.slf4j.Slf4j;
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
    private static final String TABLE_NAME = "client_download_link";
    private static final List<ColumnDefinition> COLUMNS = List.of(
            new ColumnDefinition("version", "version varchar(32)"),
            new ColumnDefinition("sha256", "sha256 varchar(64)"),
            new ColumnDefinition("file_size", "file_size bigint"),
            new ColumnDefinition("is_latest", "is_latest boolean"),
            new ColumnDefinition("changelog_url", "changelog_url varchar(1024)"),
            new ColumnDefinition("min_supported_version", "min_supported_version varchar(32)"),
            new ColumnDefinition("hosted", "hosted boolean"),
            new ColumnDefinition("catalog_key", "catalog_key varchar(160)"),
            new ColumnDefinition("latest_slot", "latest_slot varchar(100)"));

    private final JdbcTemplate jdbcTemplate;

    public ClientDownloadSchemaMigrator(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    public void migrate() {
        SchemaMetadata.Table table = SchemaMetadata.table(jdbcTemplate, TABLE_NAME);
        if (table == null) {
            log.debug("[client-package] table {} does not exist; no legacy rows to migrate", TABLE_NAME);
            return;
        }
        for (ColumnDefinition column : COLUMNS) {
            if (!table.hasColumn(column.name())) {
                // Metadata distinguishes an expected idempotent restart from a genuine DDL error.
                // Never swallow a permission, syntax or storage failure: running without the two
                // unique keys would make the catalogue's invariants only best-effort.
                jdbcTemplate.execute("alter table " + TABLE_NAME + " add column " + column.ddl());
            }
        }

        List<Map<String, Object>> rows = jdbcTemplate.queryForList("""
                select id, implementation, platform, arch, version, min_supported_version,
                       is_latest, hosted, enabled
                  from client_download_link
                 order by id desc
                """);

        Set<String> catalogKeys = new HashSet<>();
        Set<String> latestSlots = new HashSet<>();
        for (Map<String, Object> row : rows) {
            long id = ((Number) row.get("id")).longValue();
            String implementation = normalized(row.get("implementation"));
            String platform = normalized(row.get("platform"));
            String arch = normalized(row.get("arch"));
            String version = canonicalVersion(row.get("version"));
            String minSupportedVersion = canonicalVersion(row.get("min_supported_version"));
            String catalogKey = catalogueKey(implementation, platform, arch, version, id);
            if (!catalogKeys.add(catalogKey)) {
                // Preserve every duplicate legacy row, but never fabricate a version visible to
                // update clients. An administrator can later assign it an explicit SemVer.
                version = null;
                catalogKey = catalogueKey(implementation, platform, arch, null, id);
                catalogKeys.add(catalogKey);
            }
            if (version == null) {
                minSupportedVersion = null;
            }

            boolean latest = StringUtils.hasText(version)
                    && truthy(row.get("is_latest"))
                    && truthy(row.get("enabled"));
            String latestSlot = targetKey(implementation, platform, arch);
            if (latest && !latestSlots.add(latestSlot)) {
                latest = false;
            }
            boolean hosted = truthy(row.get("hosted"));
            jdbcTemplate.update("""
                    update client_download_link
                       set implementation = ?, platform = ?, arch = ?, version = ?,
                           min_supported_version = ?, file_size = coalesce(file_size, 0),
                           is_latest = ?, hosted = ?,
                           catalog_key = ?, latest_slot = ?
                     where id = ?
                    """, implementation, platform, arch, version, minSupportedVersion, latest, hosted,
                    catalogKey, latest ? latestSlot : null, id);
        }

        SchemaMetadata.Table migrated = SchemaMetadata.table(jdbcTemplate, TABLE_NAME);
        createUniqueIndex(migrated, "ux_client_download_catalog_key", "catalog_key");
        createUniqueIndex(migrated, "ux_client_download_latest_slot", "latest_slot");
    }

    private void createUniqueIndex(SchemaMetadata.Table table, String name, String column) {
        if (table.index(name) == null) {
            jdbcTemplate.execute("create unique index " + name
                    + " on " + TABLE_NAME + " (" + column + ")");
        }
    }

    public static String catalogueKey(String implementation, String platform, String arch,
                                      String version, long id) {
        return targetKey(implementation, platform, arch) + "|"
                + (StringUtils.hasText(version) ? version : "legacy:" + Long.toUnsignedString(id));
    }

    public static String targetKey(String implementation, String platform, String arch) {
        return implementation + "|" + platform + "|" + arch;
    }

    private static String normalized(Object value) {
        return text(value).toLowerCase(Locale.ROOT);
    }

    private static String canonicalVersion(Object value) {
        String version = text(value);
        if (version.startsWith("v")) {
            version = version.substring(1);
        }
        return StringUtils.hasText(version) ? version : null;
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

    private record ColumnDefinition(String name, String ddl) { }
}
