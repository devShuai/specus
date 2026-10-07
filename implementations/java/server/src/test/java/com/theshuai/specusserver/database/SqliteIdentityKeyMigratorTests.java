package com.theshuai.specusserver.database;

import com.theshuai.specusserver.management.service.HttpMediaCaptureService;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.SingleConnectionDataSource;

import java.nio.file.Path;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class SqliteIdentityKeyMigratorTests {
    /** The media capture table as Hibernate created it under ddl-auto=create-drop. */
    private static final String UNTYPED_MEDIA_CAPTURE = """
            CREATE TABLE specus_http_media_capture (initialization_segment boolean not null,
                live_stream boolean not null, status_code integer not null, captured_bytes bigint not null,
                client_id bigint not null, content_range_end bigint, content_range_start bigint, id,
                resource_id bigint, segment_sequence bigint, total_bytes bigint, method varchar(16) not null,
                state varchar(24) not null, media_kind varchar(32) not null, captured_at varchar(40) not null,
                completed_at varchar(40), expires_at varchar(40) not null, deduplication_key varchar(64),
                resource_key varchar(64) not null, tenant_id varchar(80) not null,
                client_name varchar(120) not null, content_encoding varchar(128), last_modified varchar(128),
                route varchar(128) not null, entity_tag varchar(512), object_etag varchar(512),
                object_key varchar(1024) not null, upload_id varchar(1024), failure_reason varchar(2048),
                source_url varchar(3072) not null, content_type varchar(255), response_headers clob,
                primary key (id))
            """;
    private static final List<String> MEDIA_CAPTURE_INDEXES = List.of(
            "CREATE INDEX idx_http_media_tenant_id on specus_http_media_capture (tenant_id, id)",
            "CREATE INDEX idx_http_media_resource on specus_http_media_capture (tenant_id, resource_key, id)",
            "CREATE INDEX idx_http_media_expiry on specus_http_media_capture (state, expires_at)");

    @TempDir
    Path temporaryDirectory;

    private SingleConnectionDataSource dataSource;
    private JdbcTemplate jdbc;
    private SqliteIdentityKeyMigrator migrator;

    @BeforeEach
    void openDatabase() {
        dataSource = new SingleConnectionDataSource(
                "jdbc:sqlite:" + temporaryDirectory.resolve("untyped-identity.db"), true);
        jdbc = new JdbcTemplate(dataSource);
        migrator = new SqliteIdentityKeyMigrator(jdbc);
    }

    @AfterEach
    void closeDatabase() {
        dataSource.destroy();
    }

    @Test
    void rebuildsTheMediaCaptureTableAndNumbersTheRowsSavedWithoutAnId() {
        jdbc.execute(UNTYPED_MEDIA_CAPTURE);
        MEDIA_CAPTURE_INDEXES.forEach(jdbc::execute);
        // A row written with an explicit id, as a workaround might have.
        insertCapture(5L, "complete", HttpMediaCaptureService.STATE_COMPLETE, "key-complete");
        // Rows as JPA saved them: the id stays NULL and the capture never gets past STARTING. Repeats
        // of a range each add another such row under the same deduplication key.
        insertCapture(null, "first", HttpMediaCaptureService.STATE_STARTING, "key-stuck");
        insertCapture(null, "second", HttpMediaCaptureService.STATE_STARTING, "key-stuck");
        insertCapture(null, "third", HttpMediaCaptureService.STATE_STARTING, null);
        assertThat(jdbc.queryForObject(
                "select count(*) from specus_http_media_capture where id is null", Long.class)).isEqualTo(3);

        migrator.migrate();

        assertThat(idType("specus_http_media_capture")).isEqualToIgnoringCase("integer");
        assertThat(jdbc.queryForList("select id, rowid as row_id from specus_http_media_capture"))
                .allSatisfy(row -> assertThat(row.get("id")).isEqualTo(row.get("row_id")));
        assertThat(jdbc.queryForList("select id, route from specus_http_media_capture order by id"))
                .extracting(row -> ((Number) row.get("id")).longValue() + ":" + row.get("route"))
                .containsExactly("5:complete", "6:first", "7:second", "8:third");

        Map<String, Object> complete = capture(5);
        assertThat(complete.get("state")).isEqualTo(HttpMediaCaptureService.STATE_COMPLETE);
        assertThat(complete.get("deduplication_key")).isEqualTo("key-complete");
        assertThat(complete.get("failure_reason")).isNull();
        for (long id = 6; id <= 8; id++) {
            Map<String, Object> stuck = capture(id);
            assertThat(stuck.get("state")).isEqualTo(HttpMediaCaptureService.STATE_FAILED);
            assertThat(stuck.get("deduplication_key")).isNull();
            assertThat(stuck.get("failure_reason")).isEqualTo(SqliteIdentityKeyMigrator.UNNUMBERED_CAPTURE_FAILURE);
            assertThat(stuck.get("completed_at")).isNotNull();
        }
        assertThat(indexes("specus_http_media_capture")).containsExactlyInAnyOrder(
                "idx_http_media_tenant_id", "idx_http_media_resource", "idx_http_media_expiry");

        // The next row saved without an id gets one.
        insertCapture(null, "after", HttpMediaCaptureService.STATE_STARTING, "key-after");
        assertThat(jdbc.queryForObject(
                "select id from specus_http_media_capture where route = 'after'", Long.class)).isEqualTo(9L);

        String repaired = createSql("specus_http_media_capture");
        migrator.migrate();
        assertThat(createSql("specus_http_media_capture")).isEqualTo(repaired);
        assertThat(capture(9).get("state")).isEqualTo(HttpMediaCaptureService.STATE_STARTING);
    }

    @Test
    void rebuildsTheTrafficTables() {
        jdbc.execute("""
                CREATE TABLE specus_http_traffic_exchange (request_truncated boolean not null,
                    status_code integer not null, client_id bigint not null, id, route varchar(128) not null,
                    primary key (id))
                """);
        jdbc.execute("CREATE INDEX idx_http_traffic_route on specus_http_traffic_exchange (route, id)");
        jdbc.execute("""
                CREATE TABLE specus_tcp_traffic_frame (truncated boolean not null, destination_port integer,
                    listen_port integer not null, client_id bigint not null, frame_index bigint, id,
                    channel_id varchar(120) not null, primary key (id))
                """);
        for (String route : List.of("a", "b")) {
            jdbc.update("insert into specus_http_traffic_exchange(request_truncated, status_code, client_id, route) "
                    + "values (0, 200, 1, ?)", route);
            jdbc.update("insert into specus_tcp_traffic_frame(truncated, listen_port, client_id, channel_id) "
                    + "values (0, 2222, 1, ?)", route);
        }

        migrator.migrate();

        assertThat(idType("specus_http_traffic_exchange")).isEqualToIgnoringCase("integer");
        assertThat(idType("specus_tcp_traffic_frame")).isEqualToIgnoringCase("integer");
        assertThat(jdbc.queryForList("select id from specus_http_traffic_exchange order by route", Long.class))
                .containsExactly(1L, 2L);
        assertThat(jdbc.queryForList("select id from specus_tcp_traffic_frame order by channel_id", Long.class))
                .containsExactly(1L, 2L);
        assertThat(indexes("specus_http_traffic_exchange")).containsExactly("idx_http_traffic_route");
        assertThat(jdbc.queryForList("select name from sqlite_master where name like '%rebuild%'")).isEmpty();
    }

    /** As ddl-auto=update creates it: the id comes first, aliases the rowid, and nothing is touched. */
    @Test
    void leavesATableWithTheRowidAliasAlone() {
        jdbc.execute(UNTYPED_MEDIA_CAPTURE
                .replace(" id,", "")
                .replace("(initialization_segment", "(id integer, initialization_segment"));
        insertCapture(null, "capturing", HttpMediaCaptureService.STATE_STARTING, "key-live");
        String created = createSql("specus_http_media_capture");

        migrator.migrate();

        assertThat(createSql("specus_http_media_capture")).isEqualTo(created);
        assertThat(capture(1).get("state")).isEqualTo(HttpMediaCaptureService.STATE_STARTING);
        assertThat(capture(1).get("deduplication_key")).isEqualTo("key-live");
    }

    @Test
    void doesNothingWithoutTheTables() {
        migrator.migrate();

        assertThat(jdbc.queryForList("select name from sqlite_master")).isEmpty();
    }

    private void insertCapture(Long id, String route, String state, String deduplicationKey) {
        jdbc.update("""
                insert into specus_http_media_capture(
                    id, initialization_segment, live_stream, status_code, captured_bytes, client_id, method,
                    state, media_kind, captured_at, expires_at, deduplication_key, resource_key, tenant_id,
                    client_name, route, object_key, source_url)
                values (?, 0, 0, 200, 0, 7, 'GET', ?, 'MEDIA_FILE', '2026-10-01T00:00:00Z',
                        '2026-10-08T00:00:00Z', ?, 'resource', 'default', 'client-a', ?, ?, ?)
                """, id, state, deduplicationKey, route, "objects/" + route, "https://media.example.test/" + route);
    }

    private Map<String, Object> capture(long id) {
        return jdbc.queryForMap("select * from specus_http_media_capture where id = ?", id);
    }

    private String idType(String table) {
        return jdbc.queryForObject("select type from pragma_table_info(?) where name = 'id' and pk = 1",
                String.class, table);
    }

    private List<String> indexes(String table) {
        return jdbc.queryForList("select name from sqlite_master where type = 'index' and tbl_name = ?",
                String.class, table);
    }

    private String createSql(String table) {
        return jdbc.queryForObject("select sql from sqlite_master where type = 'table' and name = ?",
                String.class, table);
    }
}
