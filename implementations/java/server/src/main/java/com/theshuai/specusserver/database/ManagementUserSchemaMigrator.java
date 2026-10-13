package com.theshuai.specusserver.database;

import lombok.extern.slf4j.Slf4j;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/** Compatibility migration for tenant-scoped management login names. */
@Component
@Slf4j
public class ManagementUserSchemaMigrator {
    static final String TABLE = "specus_management_user";
    static final String UNIQUE_INDEX = "uq_management_user_tenant_login_name";
    static final String EMAIL_TABLE = "specus_management_user_email";
    private static final List<String> UNIQUE_INDEX_COLUMNS = List.of("tenant_id", "login_name_normalized");

    private final JdbcTemplate jdbcTemplate;

    public ManagementUserSchemaMigrator(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    /**
     * Runs through a separate Spring bean so the backfill is actually transactional when invoked
     * by {@link DatabaseInitializer}'s startup callback. Every statement in it is expected to
     * succeed: the schema is read from {@link SchemaMetadata}, never probed with a statement that
     * may fail, because on PostgreSQL that failure aborts the transaction.
     */
    @Transactional
    public void migrate() {
        SchemaMetadata.Table table = SchemaMetadata.table(jdbcTemplate, TABLE);
        if (table == null) {
            throw new IllegalStateException("table " + TABLE + " does not exist");
        }
        ensureColumn(table, "login_name", "varchar(80)");
        ensureColumn(table, "login_name_normalized", "varchar(80)");

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
        ensureUniqueIndex(table);
        removeOrphanedEmails();
        log.info("[schema] management login-name migration verified for {} row(s)", rows.size());
    }

    /**
     * Accounts deleted before the delete took their email record along left that record behind,
     * keyed by an account key no account has any more, and the address could never register
     * again. Those records are released here; every other record is left alone.
     */
    private void removeOrphanedEmails() {
        if (SchemaMetadata.table(jdbcTemplate, EMAIL_TABLE) == null) {
            return;
        }
        int removed = jdbcTemplate.update("delete from " + EMAIL_TABLE
                + " where username not in (select username from " + TABLE + ")");
        if (removed > 0) {
            log.info("[schema] removed {} email record(s) of deleted management accounts", removed);
        }
    }

    private void ensureColumn(SchemaMetadata.Table table, String name, String type) {
        if (!table.hasColumn(name)) {
            jdbcTemplate.execute("alter table " + TABLE + " add column " + name + " " + type);
            log.info("[schema] added {}.{}", TABLE, name);
        }
    }

    /**
     * On MySQL and PostgreSQL Hibernate has already created the index from the {@code @Index} of
     * {@code ManagementUser}; the SQLite dialect leaves unique indexes out, so there it is created
     * here on the first start.
     */
    private void ensureUniqueIndex(SchemaMetadata.Table table) {
        if (table.index(UNIQUE_INDEX) == null) {
            jdbcTemplate.execute("create unique index " + UNIQUE_INDEX + " on " + TABLE
                    + " (" + String.join(", ", UNIQUE_INDEX_COLUMNS) + ")");
        }
        verifyUniqueIndexDefinition();
    }

    private void verifyUniqueIndexDefinition() {
        SchemaMetadata.Table table = SchemaMetadata.table(jdbcTemplate, TABLE);
        SchemaMetadata.Index index = table == null ? null : table.index(UNIQUE_INDEX);
        if (index == null || !index.unique() || !index.columns().equals(UNIQUE_INDEX_COLUMNS)) {
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

    private record LoginNameRow(String accountKey, String tenantId, String loginName) {
    }
}
