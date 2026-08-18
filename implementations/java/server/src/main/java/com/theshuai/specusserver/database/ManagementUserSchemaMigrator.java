package com.theshuai.specusserver.database;

import lombok.extern.slf4j.Slf4j;
import org.springframework.dao.DataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.ConnectionCallback;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.TreeMap;

/** Compatibility migration for tenant-scoped management login names. */
@Component
@Slf4j
public class ManagementUserSchemaMigrator {
    static final String TABLE = "specus_management_user";
    static final String UNIQUE_INDEX = "uq_management_user_tenant_login_name";

    private final JdbcTemplate jdbcTemplate;

    public ManagementUserSchemaMigrator(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    /**
     * Runs through a separate Spring bean so the backfill is actually transactional when invoked
     * by {@link DatabaseInitializer}'s startup callback.
     */
    @Transactional
    public void migrate() {
        ensureColumn("login_name", "varchar(80)");
        ensureColumn("login_name_normalized", "varchar(80)");

        List<LoginNameRow> rows = jdbcTemplate.query(
                "select username, tenant_id, login_name from " + TABLE,
                (rs, rowNum) -> new LoginNameRow(
                        rs.getString("username"),
                        rs.getString("tenant_id"),
                        rs.getString("login_name")));
        Set<String> tenantNames = new HashSet<>();
        for (LoginNameRow row : rows) {
            String loginName = hasText(row.loginName()) ? row.loginName().trim() : row.accountKey();
            if (!hasText(loginName) || loginName.length() > 80) {
                throw new IllegalStateException("management user has an invalid login name");
            }
            String tenantId = hasText(row.tenantId()) ? row.tenantId().trim() : "default";
            String normalized = normalize(loginName);
            if (!tenantNames.add(tenantId + '\u0000' + normalized)) {
                throw new IllegalStateException(
                        "duplicate management login name in tenant '" + tenantId + "'");
            }
        }
        for (LoginNameRow row : rows) {
            String loginName = hasText(row.loginName()) ? row.loginName().trim() : row.accountKey();
            jdbcTemplate.update(
                    "update " + TABLE
                            + " set login_name = ?, login_name_normalized = ? where username = ?",
                    loginName,
                    normalize(loginName),
                    row.accountKey());
        }
        ensureUniqueIndex();
        log.info("[schema] management login-name migration verified for {} row(s)", rows.size());
    }

    private void ensureColumn(String name, String type) {
        try {
            jdbcTemplate.query("select " + name + " from " + TABLE + " where 1 = 0", rs -> null);
        } catch (DataAccessException missingColumn) {
            jdbcTemplate.execute("alter table " + TABLE + " add column " + name + " " + type);
            log.info("[schema] added {}.{}", TABLE, name);
        }
    }

    private void ensureUniqueIndex() {
        try {
            jdbcTemplate.execute("create unique index " + UNIQUE_INDEX + " on " + TABLE
                    + " (tenant_id, login_name_normalized)");
        } catch (DataAccessException exception) {
            String message = fullMessage(exception).toLowerCase(Locale.ROOT);
            if (message.contains("already exists")
                    || message.contains("duplicate key name")
                    || message.contains("relation \"" + UNIQUE_INDEX.toLowerCase(Locale.ROOT) + "\" already exists")) {
                verifyUniqueIndexDefinition();
                return;
            }
            throw exception;
        }
        verifyUniqueIndexDefinition();
    }

    private void verifyUniqueIndexDefinition() {
        IndexDefinition definition = jdbcTemplate.execute((ConnectionCallback<IndexDefinition>) connection -> {
            TreeMap<Short, String> columns = new TreeMap<>();
            Boolean unique = null;
            try (var indexes = connection.getMetaData().getIndexInfo(
                    connection.getCatalog(), null, TABLE, false, false)) {
                while (indexes.next()) {
                    String indexName = indexes.getString("INDEX_NAME");
                    if (indexName == null || !UNIQUE_INDEX.equalsIgnoreCase(indexName)) {
                        continue;
                    }
                    unique = !indexes.getBoolean("NON_UNIQUE");
                    String columnName = indexes.getString("COLUMN_NAME");
                    short ordinal = indexes.getShort("ORDINAL_POSITION");
                    if (columnName != null && ordinal > 0) {
                        columns.put(ordinal, columnName.toLowerCase(Locale.ROOT));
                    }
                }
            }
            return unique == null ? null : new IndexDefinition(unique, List.copyOf(columns.values()));
        });
        if (definition == null
                || !definition.unique()
                || !definition.columns().equals(List.of("tenant_id", "login_name_normalized"))) {
            throw new IllegalStateException(
                    "index " + UNIQUE_INDEX + " must be unique on (tenant_id, login_name_normalized)");
        }
    }

    static String normalize(String value) {
        return value.trim().toLowerCase(Locale.ROOT);
    }

    private static boolean hasText(String value) {
        return value != null && !value.trim().isEmpty();
    }

    private static String fullMessage(Throwable throwable) {
        StringBuilder result = new StringBuilder();
        for (Throwable current = throwable; current != null; current = current.getCause()) {
            if (current.getMessage() != null) {
                result.append(' ').append(current.getMessage());
            }
        }
        return result.toString();
    }

    private record LoginNameRow(String accountKey, String tenantId, String loginName) {
    }

    private record IndexDefinition(boolean unique, List<String> columns) {
    }
}
