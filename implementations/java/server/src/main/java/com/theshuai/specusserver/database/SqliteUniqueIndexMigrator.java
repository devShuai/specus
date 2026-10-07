package com.theshuai.specusserver.database;

import lombok.extern.slf4j.Slf4j;
import org.springframework.dao.DataAccessException;
import org.springframework.jdbc.core.ConnectionCallback;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Idempotent upgrade that creates on SQLite the unique keys the JPA mapping declares at table level.
 *
 * <p>Hibernate's SQLite dialect renders a column's own {@code unique} inline, but leaves out every
 * {@code @UniqueConstraint} and {@code @Index(unique = true)}: its unique delegate returns an empty
 * create-table fragment and an empty alter-table command, under {@code create} as well as
 * {@code update}, and nothing is logged. Without these indexes SQLite refuses the {@code ON CONFLICT}
 * upserts of the traffic counters, which fall back to find-then-save, and racing inserts store the
 * duplicate rows a constraint violation was meant to stop. MySQL and PostgreSQL get the constraints
 * from Hibernate, so this runs on SQLite only.
 *
 * <p>A database that ran without an index can already hold rows the index would reject. Each key
 * says what happens to them, and the default is to change nothing: the index is skipped and a
 * warning names the table and the query that lists the rows. Every start tries again, so the index
 * appears once an operator has resolved them. Only two kinds of key are resolved here, both
 * without losing information:
 * <ul>
 *   <li>Counters: rows sharing a key are increments of one counter split by a race, so the newest
 *       row takes their sum and the others are deleted.</li>
 *   <li>The media deduplication key: an optional shortcut the capture service clears itself
 *       whenever the keyed capture cannot be reused. The newest row keeps it; the older ones lose
 *       only the key and stay reachable through the attribute lookup.</li>
 * </ul>
 */
@Component
@Slf4j
public class SqliteUniqueIndexMigrator {
    private static final int LISTED_ROWS = 20;

    /**
     * Every table-level unique key of the mapping. {@code SqliteUniqueIndexMigratorTests} fails when
     * an entity declares one that is not listed here.
     */
    static final List<UniqueKey> UNIQUE_KEYS = List.of(
            // Credentials and accounts: which of two rows is the real one is the operator's call.
            UniqueKey.report("uk_client_credential_api_key", "specus_client_credential", "api_key"),
            // Each identity owns the client account it created, so two of them are two accounts.
            UniqueKey.report("uk_client_identity_machine_user", "specus_client_identity",
                    "credential_id", "machine_fingerprint", "os_user"),
            // Already enforced by ManagementUserSchemaMigrator, which refuses to start on duplicates.
            UniqueKey.report("uq_management_user_tenant_login_name", "specus_management_user",
                    "tenant_id", "login_name_normalized"),
            UniqueKey.report("uq_management_user_oidc_identity_key", "specus_management_user",
                    "oidc_identity_key"),
            // Pending sign-ups expire; RegistrationService deletes them hourly, a later start succeeds.
            UniqueKey.report("uq_registration_challenge_username", "specus_management_registration_challenge",
                    "username"),
            UniqueKey.report("uq_registration_challenge_email", "specus_management_registration_challenge",
                    "email"),
            // Routing and mesh configuration: two rows are two conflicting settings.
            UniqueKey.report("uk_specus_mapping_listen_port", "specus_mapping", "listen_port"),
            UniqueKey.report("uk_http_route_client_route", "http_route_mapping", "client_id", "route"),
            UniqueKey.report("uk_peer_mesh_acl_pair", "peer_mesh_acl",
                    "tenant_id", "source_client_id", "target_client_id"),
            UniqueKey.report("uk_peer_mesh_device_client", "peer_mesh_device", "tenant_id", "client_id"),
            UniqueKey.report("uk_peer_mesh_device_ip", "peer_mesh_device", "tenant_id", "virtual_ip"),
            UniqueKey.report("uk_peer_egress_policy_client", "peer_mesh_egress_policy",
                    "tenant_id", "egress_client_id"),
            UniqueKey.report("uk_peer_egress_activity_client", "peer_mesh_egress_activity",
                    "tenant_id", "egress_client_id"),
            // PeerServiceDiscoverySchemaMigrator creates it too, but only logs a failure at debug.
            UniqueKey.report("uk_peer_shared_service_id", "peer_mesh_shared_service",
                    "tenant_id", "client_id", "service_id"),
            // Rooms own their tokens, codes and attachments; tokens are secrets. Never merged.
            UniqueKey.report("uk_public_transfer_room_key", "public_transfer_room", "room_name", "owner_token_hash"),
            UniqueKey.report("uk_public_transfer_access_token", "public_transfer_room_access", "token_hash"),
            UniqueKey.report("uk_public_transfer_pairing_code_hash", "public_transfer_room_pairing_code",
                    "code_hash"),
            UniqueKey.report("uk_attachment_download_grant_token", "transfer_attachment_download_grant",
                    "token_hash"),
            UniqueKey.mergeCounters("uk_specus_traffic_client_date", "specus_traffic_usage",
                    List.of("client_id", "usage_date"),
                    List.of("upload_bytes", "download_bytes")),
            UniqueKey.mergeCounters("uk_resource_traffic_resource_date", "specus_resource_traffic_usage",
                    List.of("tenant_id", "client_id", "resource_type", "resource_key", "usage_date"),
                    List.of("upload_bytes", "download_bytes")),
            UniqueKey.mergeCounters("uk_specus_connection_stat", "specus_connection_stat",
                    List.of("tenant_id", "client_name", "stat_month"),
                    List.of("total_count", "success_count", "failure_count")),
            UniqueKey.keepNewestKey("uk_http_media_deduplication", "specus_http_media_capture",
                    "deduplication_key"));

    private final JdbcTemplate jdbcTemplate;

    public SqliteUniqueIndexMigrator(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    /**
     * Runs through a separate Spring bean so a merge and the index it clears the way for commit
     * together when invoked by {@link DatabaseInitializer}'s startup callback.
     */
    @Transactional
    public Result migrate() {
        if (!isSqlite()) {
            return new Result(List.of(), List.of());
        }
        List<String> created = new ArrayList<>();
        List<String> skipped = new ArrayList<>();
        for (UniqueKey key : UNIQUE_KEYS) {
            switch (migrate(key, inspect(key.table()))) {
                case CREATED -> created.add(key.name());
                case SKIPPED -> skipped.add(key.name());
                case UNCHANGED -> { }
            }
        }
        if (!created.isEmpty()) {
            log.info("[schema] created {} SQLite unique index(es): {}", created.size(), created);
        }
        return new Result(List.copyOf(created), List.copyOf(skipped));
    }

    private Outcome migrate(UniqueKey key, TableIndexes table) {
        if (table == null) {
            log.debug("[schema] table {} does not exist; skip unique index {}", key.table(), key.name());
            return Outcome.UNCHANGED;
        }
        List<String> missingColumns = key.columns().stream()
                .filter(column -> !table.columns().contains(column))
                .toList();
        if (!missingColumns.isEmpty()) {
            log.warn("[schema] unique index {} not created: {} has no column(s) {}",
                    key.name(), key.table(), missingColumns);
            return Outcome.SKIPPED;
        }
        if (table.enforces(key.columns())) {
            return Outcome.UNCHANGED;
        }
        if (table.indexNames().contains(key.name().toLowerCase(Locale.ROOT))) {
            log.warn("[schema] unique index {} not created: an index of that name on {} is not unique on ({})",
                    key.name(), key.table(), key.columnList());
            return Outcome.SKIPPED;
        }

        List<DuplicateGroup> duplicates = findDuplicates(key);
        if (!duplicates.isEmpty() && !resolve(key, duplicates)) {
            return Outcome.SKIPPED;
        }
        try {
            jdbcTemplate.execute("create unique index if not exists " + key.name()
                    + " on " + key.table() + " (" + key.columnList() + ")");
            return Outcome.CREATED;
        } catch (DataAccessException exception) {
            // The rows are as resolve() left them, which is consistent on its own; the server
            // keeps running as it did before this index existed, and the next start retries.
            log.warn("[schema] unique index {} on {} ({}) not created: {}",
                    key.name(), key.table(), key.columnList(), exception.getMessage());
            return Outcome.SKIPPED;
        }
    }

    private List<DuplicateGroup> findDuplicates(UniqueKey key) {
        StringBuilder sql = new StringBuilder("select group_concat(rowid)");
        for (String counter : key.counters()) {
            sql.append(", sum(").append(counter).append(')');
        }
        if (!key.counters().isEmpty()) {
            sql.append(", max(updated_at)");
        }
        // A unique index treats NULLs as distinct, so rows with a NULL key column never collide.
        sql.append(" from ").append(key.table())
                .append(" where ").append(key.columns().stream()
                        .map(column -> column + " is not null")
                        .collect(Collectors.joining(" and ")))
                .append(" group by ").append(key.columnList())
                .append(" having count(*) > 1");
        return jdbcTemplate.query(sql.toString(), (row, rowNumber) -> {
            List<Long> rowIds = Arrays.stream(row.getString(1).split(","))
                    .map(Long::valueOf)
                    .sorted()
                    .toList();
            List<Object> merged = new ArrayList<>();
            for (int index = 0; index < key.counters().size(); index++) {
                merged.add(row.getLong(2 + index));
            }
            if (!key.counters().isEmpty()) {
                merged.add(row.getString(2 + key.counters().size()));
            }
            return new DuplicateGroup(rowIds, merged);
        });
    }

    /** Returns whether the duplicates are gone and the index can be created. */
    private boolean resolve(UniqueKey key, List<DuplicateGroup> duplicates) {
        List<Long> older = duplicates.stream().flatMap(group -> group.older().stream()).toList();
        switch (key.duplicates()) {
            case REPORT -> {
                List<Long> rows = duplicates.stream().flatMap(group -> group.rowIds().stream()).toList();
                log.warn("[schema] unique index {} not created: {} holds {} group(s) of rows sharing ({}), "
                                + "{} row(s) in all, rowid {}. Nothing was changed; resolve them and restart. "
                                + "List them with: select {}, count(*) from {} group by {} having count(*) > 1",
                        key.name(), key.table(), duplicates.size(), key.columnList(), rows.size(), listed(rows),
                        key.columnList(), key.table(), key.columnList());
                return false;
            }
            case MERGE_COUNTERS -> {
                String assignments = key.counters().stream()
                        .map(counter -> counter + " = ?")
                        .collect(Collectors.joining(", ")) + ", updated_at = ?";
                List<Object[]> survivors = new ArrayList<>();
                for (DuplicateGroup group : duplicates) {
                    List<Object> values = new ArrayList<>(group.merged());
                    values.add(group.newest());
                    survivors.add(values.toArray());
                }
                // Both statements run in migrate()'s transaction: a sum is never kept without the
                // rows it came from being deleted, nor the other way round.
                jdbcTemplate.batchUpdate("update " + key.table() + " set " + assignments + " where rowid = ?",
                        survivors);
                jdbcTemplate.batchUpdate("delete from " + key.table() + " where rowid = ?", rowIdArguments(older));
                log.warn("[schema] merged {} group(s) of rows of {} sharing ({}) into their newest row by summing "
                                + "({}), before creating unique index {}; deleted the other {} row(s), rowid {}",
                        duplicates.size(), key.table(), key.columnList(), String.join(", ", key.counters()),
                        key.name(), older.size(), listed(older));
                return true;
            }
            case KEEP_NEWEST_KEY -> {
                String column = key.columns().getFirst();
                jdbcTemplate.batchUpdate("update " + key.table() + " set " + column + " = null where rowid = ?",
                        rowIdArguments(older));
                log.warn("[schema] cleared {} on {} row(s) of {} that shared it with a newer row, before creating "
                                + "unique index {}; the rows themselves are kept, rowid {}",
                        column, older.size(), key.table(), key.name(), listed(older));
                return true;
            }
        }
        throw new IllegalStateException("unhandled duplicate resolution " + key.duplicates());
    }

    private static List<Object[]> rowIdArguments(List<Long> rowIds) {
        return rowIds.stream().map(rowId -> new Object[]{rowId}).toList();
    }

    private static String listed(List<Long> rowIds) {
        if (rowIds.size() <= LISTED_ROWS) {
            return rowIds.toString();
        }
        return rowIds.subList(0, LISTED_ROWS) + " and " + (rowIds.size() - LISTED_ROWS) + " more";
    }

    private TableIndexes inspect(String table) {
        Set<String> columns = new HashSet<>();
        for (String column : jdbcTemplate.queryForList("select name from pragma_table_info(?)", String.class, table)) {
            columns.add(column.toLowerCase(Locale.ROOT));
        }
        if (columns.isEmpty()) {
            return null;
        }
        Map<String, IndexDefinition> indexes = new LinkedHashMap<>();
        jdbcTemplate.query("""
                select il.name, il."unique", il.partial, ii.name
                  from pragma_index_list(?) il
                  left join pragma_index_info(il.name) ii
                 order by il.name, ii.seqno
                """, row -> {
            String name = row.getString(1).toLowerCase(Locale.ROOT);
            // A partial index enforces nothing outside its WHERE clause.
            boolean unique = row.getInt(2) != 0 && row.getInt(3) == 0;
            IndexDefinition index = indexes.computeIfAbsent(name, ignored -> new IndexDefinition(unique, new HashSet<>()));
            String column = row.getString(4);
            // An expression column has no name; such an index never equals a list of columns.
            index.columns().add(column == null ? "" : column.toLowerCase(Locale.ROOT));
        }, table);
        return new TableIndexes(Set.copyOf(columns), indexes);
    }

    private boolean isSqlite() {
        String product = jdbcTemplate.execute((ConnectionCallback<String>) connection ->
                connection.getMetaData().getDatabaseProductName());
        return product != null && product.toLowerCase(Locale.ROOT).contains("sqlite");
    }

    enum Duplicates { REPORT, MERGE_COUNTERS, KEEP_NEWEST_KEY }

    private enum Outcome { CREATED, UNCHANGED, SKIPPED }

    /**
     * One unique key of the mapping and what to do with rows that already violate it.
     *
     * @param counters for {@link Duplicates#MERGE_COUNTERS}: the columns summed into the newest
     *                 row, whose {@code updated_at} becomes the latest of the group
     */
    record UniqueKey(String name, String table, List<String> columns, Duplicates duplicates,
                     List<String> counters) {
        static UniqueKey report(String name, String table, String... columns) {
            return new UniqueKey(name, table, List.of(columns), Duplicates.REPORT, List.of());
        }

        static UniqueKey mergeCounters(String name, String table, List<String> columns, List<String> counters) {
            return new UniqueKey(name, table, columns, Duplicates.MERGE_COUNTERS, counters);
        }

        static UniqueKey keepNewestKey(String name, String table, String column) {
            return new UniqueKey(name, table, List.of(column), Duplicates.KEEP_NEWEST_KEY, List.of());
        }

        String columnList() {
            return String.join(", ", columns);
        }
    }

    /** The indexes created by this run and the ones left out, by name. */
    public record Result(List<String> created, List<String> skipped) { }

    /** Rows sharing one key value, oldest first by rowid, and the merged counter values. */
    private record DuplicateGroup(List<Long> rowIds, List<Object> merged) {
        long newest() {
            return rowIds.getLast();
        }

        List<Long> older() {
            return rowIds.subList(0, rowIds.size() - 1);
        }
    }

    private record IndexDefinition(boolean unique, Set<String> columns) { }

    private record TableIndexes(Set<String> columns, Map<String, IndexDefinition> indexes) {
        Set<String> indexNames() {
            return indexes.keySet();
        }

        /** Whether a full unique index on exactly these columns exists, under whatever name. */
        boolean enforces(List<String> keyColumns) {
            Set<String> wanted = keyColumns.stream()
                    .map(column -> column.toLowerCase(Locale.ROOT))
                    .collect(Collectors.toSet());
            return indexes.values().stream()
                    .anyMatch(index -> index.unique() && index.columns().equals(wanted));
        }
    }
}
