package com.theshuai.specusserver.database;

import com.theshuai.specusserver.database.JpaUniqueKeys.Key;
import com.theshuai.specusserver.database.JpaUniqueKeys.Mapping;
import com.theshuai.specusserver.database.JpaUniqueKeys.SqliteUniqueIndex;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.jdbc.core.JdbcTemplate;
import org.sqlite.SQLiteDataSource;

import java.nio.file.Path;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class SqliteUniqueIndexMigratorTests {
    @TempDir
    Path temporaryDirectory;

    @Test
    void listsEveryTableLevelUniqueKeyOfTheMapping() {
        List<Key> declared;
        try (Mapping mapping = JpaUniqueKeys.bind()) {
            declared = mapping.tableLevel;
        }
        List<Key> listed = SqliteUniqueIndexMigrator.UNIQUE_KEYS.stream()
                .map(key -> new Key(key.table(), key.name(), key.columns()))
                .toList();

        assertThat(declared).as("@UniqueConstraint and @Index(unique = true) of the mapping").hasSize(22);
        assertThat(listed).containsExactlyInAnyOrderElementsOf(declared);
    }

    /**
     * What {@code ddl-auto} leaves on a fresh SQLite database: each column's own unique, and of the
     * table-level keys only one whose column happens to be unique on its own as well. The migrator
     * adds every other key under its declared name.
     */
    @ParameterizedTest
    @ValueSource(strings = {"update", "create-drop"})
    void hibernateLeavesTableLevelUniqueKeysOutAndTheMigratorAddsThem(String ddlAuto) {
        JdbcTemplate jdbc = sqlite(ddlAuto + ".db");
        try (Mapping mapping = JpaUniqueKeys.bind(jdbc.getDataSource(), ddlAuto)) {
            List<SqliteUniqueIndex> fromHibernate = JpaUniqueKeys.sqliteUniqueIndexes(jdbc);

            assertThat(mapping.columnLevel)
                    .as("@Column(unique = true) rendered inline")
                    .isNotEmpty()
                    .allMatch(key -> JpaUniqueKeys.enforced(fromHibernate, key));
            assertThat(mapping.tableLevel)
                    .as("table-level unique keys under their declared name after ddl-auto=%s", ddlAuto)
                    .noneMatch(key -> JpaUniqueKeys.named(fromHibernate, key));
            assertThat(mapping.tableLevel.stream().filter(key -> JpaUniqueKeys.enforced(fromHibernate, key)))
                    .as("table-level unique keys enforced at all after ddl-auto=%s", ddlAuto)
                    .extracting(Key::name)
                    .containsExactly("uk_attachment_download_grant_token");

            SqliteUniqueIndexMigrator.Result result = new SqliteUniqueIndexMigrator(jdbc).migrate();

            List<SqliteUniqueIndex> migrated = JpaUniqueKeys.sqliteUniqueIndexes(jdbc);
            assertThat(result.skipped()).isEmpty();
            assertThat(result.created()).hasSize(mapping.tableLevel.size() - 1)
                    .doesNotContain("uk_attachment_download_grant_token");
            assertThat(mapping.tableLevel).allMatch(key -> JpaUniqueKeys.enforced(migrated, key));
            assertThat(mapping.tableLevel.stream().filter(key -> result.created().contains(key.name())))
                    .allMatch(key -> JpaUniqueKeys.named(migrated, key));

            assertThat(new SqliteUniqueIndexMigrator(jdbc).migrate())
                    .isEqualTo(new SqliteUniqueIndexMigrator.Result(List.of(), List.of()));
        }
    }

    @Test
    void anUpdateOverAMigratedDatabaseKeepsTheIndexes() {
        JdbcTemplate jdbc = sqlite("restart.db");
        try (Mapping ignored = JpaUniqueKeys.bind(jdbc.getDataSource(), "update")) {
            new SqliteUniqueIndexMigrator(jdbc).migrate();
        }
        List<SqliteUniqueIndex> before = JpaUniqueKeys.sqliteUniqueIndexes(jdbc);

        try (Mapping ignored = JpaUniqueKeys.bind(jdbc.getDataSource(), "update")) {
            assertThat(JpaUniqueKeys.sqliteUniqueIndexes(jdbc)).containsExactlyInAnyOrderElementsOf(before);
            assertThat(new SqliteUniqueIndexMigrator(jdbc).migrate().created()).isEmpty();
        }
    }

    @Test
    void mergesSplitTrafficCountersIntoTheNewestRowAndEnablesTheUpsert() {
        JdbcTemplate jdbc = sqlite("counters.db");
        jdbc.execute("""
                create table specus_traffic_usage (
                    id integer primary key, tenant_id text, client_id integer not null,
                    client_name text not null, usage_date text not null,
                    upload_bytes integer not null, download_bytes integer not null, updated_at text not null)
                """);
        jdbc.update("insert into specus_traffic_usage values (1, 'default', 7, 'old-name', '2026-10-01', 10, 100, '2026-10-01T10:00:00Z')");
        jdbc.update("insert into specus_traffic_usage values (2, 'default', 7, 'new-name', '2026-10-01', 20, 200, '2026-10-01T09:00:00Z')");
        jdbc.update("insert into specus_traffic_usage values (3, 'default', 7, 'new-name', '2026-10-01', 30, 300, '2026-10-01T08:00:00Z')");
        jdbc.update("insert into specus_traffic_usage values (4, 'default', 7, 'new-name', '2026-10-02', 1, 2, '2026-10-02T08:00:00Z')");
        // TrafficUsageService's upsert names this conflict target; SQLite refuses it without the index.
        String upsert = """
                insert into specus_traffic_usage (tenant_id, client_id, client_name, usage_date,
                                                  upload_bytes, download_bytes, updated_at)
                values ('default', 7, 'new-name', '2026-10-01', 5, 50, '2026-10-01T11:00:00Z')
                on conflict (client_id, usage_date) do update set
                    upload_bytes = specus_traffic_usage.upload_bytes + excluded.upload_bytes,
                    download_bytes = specus_traffic_usage.download_bytes + excluded.download_bytes
                """;
        assertThatThrownBy(() -> jdbc.update(upsert))
                .hasRootCauseMessage("[SQLITE_ERROR] SQL error or missing database "
                        + "(ON CONFLICT clause does not match any PRIMARY KEY or UNIQUE constraint)");

        SqliteUniqueIndexMigrator.Result result = new SqliteUniqueIndexMigrator(jdbc).migrate();

        assertThat(result.created()).containsExactly("uk_specus_traffic_client_date");
        assertThat(jdbc.queryForList("select * from specus_traffic_usage order by id")).containsExactly(
                Map.of("id", 3, "tenant_id", "default", "client_id", 7, "client_name", "new-name",
                        "usage_date", "2026-10-01", "upload_bytes", 60, "download_bytes", 600,
                        "updated_at", "2026-10-01T10:00:00Z"),
                Map.of("id", 4, "tenant_id", "default", "client_id", 7, "client_name", "new-name",
                        "usage_date", "2026-10-02", "upload_bytes", 1, "download_bytes", 2,
                        "updated_at", "2026-10-02T08:00:00Z"));
        jdbc.update(upsert);
        assertThat(jdbc.queryForMap("select upload_bytes, download_bytes from specus_traffic_usage "
                + "where client_id = 7 and usage_date = '2026-10-01'"))
                .isEqualTo(Map.of("upload_bytes", 65, "download_bytes", 650));
    }

    @Test
    void keepsTheDeduplicationKeyOnTheNewestCaptureAndEveryCaptureRow() {
        JdbcTemplate jdbc = sqlite("media.db");
        jdbc.execute("""
                create table specus_http_media_capture (
                    id integer primary key, tenant_id text not null, deduplication_key text, state text not null)
                """);
        jdbc.update("insert into specus_http_media_capture values (1, 'default', 'range-a', 'COMPLETE')");
        jdbc.update("insert into specus_http_media_capture values (2, 'default', 'range-a', 'COMPLETE')");
        jdbc.update("insert into specus_http_media_capture values (3, 'default', null, 'FAILED')");
        jdbc.update("insert into specus_http_media_capture values (4, 'default', 'range-b', 'COMPLETE')");

        new SqliteUniqueIndexMigrator(jdbc).migrate();

        assertThat(jdbc.queryForList("select id, deduplication_key from specus_http_media_capture order by id"))
                .extracting(row -> row.get("deduplication_key"))
                .containsExactly(null, "range-a", null, "range-b");
        assertThatThrownBy(() -> jdbc.update(
                "insert into specus_http_media_capture values (5, 'default', 'range-a', 'STARTING')"))
                .hasRootCauseMessage("[SQLITE_CONSTRAINT_UNIQUE] A UNIQUE constraint failed "
                        + "(UNIQUE constraint failed: specus_http_media_capture.deduplication_key)");
    }

    @Test
    void leavesConflictingRowsAloneAndCreatesTheIndexOnceTheyAreResolved() {
        JdbcTemplate jdbc = sqlite("mappings.db");
        jdbc.execute("""
                create table specus_mapping (
                    id integer primary key, client_id integer not null, listen_port integer not null,
                    target_port integer not null)
                """);
        jdbc.update("insert into specus_mapping values (1, 10, 2222, 22)");
        jdbc.update("insert into specus_mapping values (2, 11, 2222, 2022)");
        List<Map<String, Object>> rows = jdbc.queryForList("select * from specus_mapping order by id");

        SqliteUniqueIndexMigrator.Result first = new SqliteUniqueIndexMigrator(jdbc).migrate();

        assertThat(first.skipped()).containsExactly("uk_specus_mapping_listen_port");
        assertThat(first.created()).isEmpty();
        assertThat(jdbc.queryForList("select * from specus_mapping order by id")).isEqualTo(rows);
        assertThat(JpaUniqueKeys.sqliteUniqueIndexes(jdbc)).isEmpty();

        jdbc.update("update specus_mapping set listen_port = 2223 where id = 2");
        SqliteUniqueIndexMigrator.Result second = new SqliteUniqueIndexMigrator(jdbc).migrate();

        assertThat(second.created()).containsExactly("uk_specus_mapping_listen_port");
        assertThat(second.skipped()).isEmpty();
    }

    @Test
    void rowsWithANullKeyColumnDoNotCollide() {
        JdbcTemplate jdbc = sqlite("connection-stats.db");
        jdbc.execute("""
                create table specus_connection_stat (
                    id integer primary key, tenant_id text, client_name text not null, stat_month text not null,
                    total_count integer not null, success_count integer not null, failure_count integer not null,
                    updated_at text not null)
                """);
        jdbc.update("insert into specus_connection_stat values (1, null, 'a', '2026-10', 1, 1, 0, 't1')");
        jdbc.update("insert into specus_connection_stat values (2, null, 'a', '2026-10', 2, 1, 1, 't2')");

        SqliteUniqueIndexMigrator.Result result = new SqliteUniqueIndexMigrator(jdbc).migrate();

        assertThat(result.created()).containsExactly("uk_specus_connection_stat");
        assertThat(jdbc.queryForObject("select count(*) from specus_connection_stat", Integer.class)).isEqualTo(2);
    }

    private JdbcTemplate sqlite(String fileName) {
        SQLiteDataSource dataSource = new SQLiteDataSource();
        dataSource.setUrl("jdbc:sqlite:" + temporaryDirectory.resolve(fileName));
        return new JdbcTemplate(dataSource);
    }
}
