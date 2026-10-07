package com.theshuai.specusserver.database;

import com.theshuai.specusserver.management.service.HttpMediaCaptureService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.jdbc.core.ConnectionCallback;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.SingleConnectionDataSource;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * Idempotent repair of the SQLite tables whose IDENTITY id was created without a type. Hibernate
 * writes such an id when ddl-auto=create or create-drop orders an integer column before it (the
 * update default keeps the id first). SQLite then keeps the id apart from the rowid: a row saved
 * through JPA stores a NULL id while Hibernate reports {@code last_insert_rowid()}, so the row is
 * never found, updated or deleted by id, and queries map it to a null entity.
 *
 * <p>The table is rebuilt with an {@code integer} id, which aliases the rowid. Ids already stored
 * are kept; rows without one are numbered after them in the order they were inserted. A media
 * capture that had no id never got past {@code STARTING}, because every later write looked it up
 * by id: it is failed and gives up its deduplication key, as the capture would have done itself.
 * Without that, every request for its range would be skipped as already being captured, or fail
 * once two such rows share the key.
 */
@Component
@Slf4j
public class SqliteIdentityKeyMigrator {
    static final String MEDIA_CAPTURE_TABLE = "specus_http_media_capture";
    /** The IDENTITY tables that have an integer column Hibernate's create order puts before the id. */
    static final List<String> TABLES = List.of(
            MEDIA_CAPTURE_TABLE,
            "specus_http_traffic_exchange",
            "specus_tcp_traffic_frame");
    static final String UNNUMBERED_CAPTURE_FAILURE = "采集记录缺少主键，未能完成";

    private static final String SAVEPOINT = "specus_identity_key_repair";
    /** The id declared with no type: a whole column definition, never the primary key clause. */
    private static final Pattern UNTYPED_ID = Pattern.compile("([(,]\\s*)id(\\s*,)", Pattern.CASE_INSENSITIVE);

    private final JdbcTemplate jdbcTemplate;

    public SqliteIdentityKeyMigrator(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    public void migrate() {
        // One connection throughout: the savepoint, the rebuild and the rename must share it.
        jdbcTemplate.execute((ConnectionCallback<Void>) connection -> {
            if (!"SQLite".equalsIgnoreCase(connection.getMetaData().getDatabaseProductName())) {
                return null;
            }
            JdbcTemplate sqlite = new JdbcTemplate(new SingleConnectionDataSource(connection, true));
            for (String table : TABLES) {
                repair(sqlite, table);
            }
            return null;
        });
    }

    private void repair(JdbcTemplate sqlite, String table) {
        List<Map<String, Object>> columns = sqlite.queryForList(
                "select name, type, pk from pragma_table_info(?) order by cid", table);
        if (!hasUntypedIdentity(columns)) {
            return;
        }
        String createSql = sqlite.queryForObject(
                "select sql from sqlite_master where type = 'table' and name = ?", String.class, table);
        String rebuiltColumns = typedColumns(createSql);
        if (rebuiltColumns == null) {
            log.warn("[schema] {} has an id without a type, but its definition is not one this repair rewrites: {}",
                    table, createSql);
            return;
        }
        List<String> dependents = sqlite.queryForList("""
                select sql from sqlite_master
                 where tbl_name = ? and type in ('index', 'trigger') and sql is not null
                """, String.class, table);
        List<String> names = columns.stream().map(column -> (String) column.get("name")).toList();
        String rebuilt = table + "__rebuild";

        // Atomic per table, inside or outside a surrounding transaction.
        sqlite.execute("savepoint " + SAVEPOINT);
        try {
            if (MEDIA_CAPTURE_TABLE.equals(table)) {
                failUnnumberedCaptures(sqlite);
            }
            long rows = count(sqlite, table);
            long unnumbered = sqlite.queryForObject(
                    "select count(*) from " + table + " where id is null", Long.class);
            sqlite.execute("create table " + rebuilt + " " + rebuiltColumns);
            sqlite.execute("insert into " + rebuilt + " (" + quoted(names) + ") select " + quoted(names)
                    + " from " + table + " where id is not null order by id");
            // Leaving the id out lets SQLite number each row after the largest id so far.
            List<String> withoutId = names.stream().filter(name -> !"id".equalsIgnoreCase(name)).toList();
            sqlite.execute("insert into " + rebuilt + " (" + quoted(withoutId) + ") select " + quoted(withoutId)
                    + " from " + table + " where id is null order by rowid");
            if (count(sqlite, rebuilt) != rows) {
                throw new IllegalStateException("row count changed while rebuilding " + table);
            }
            sqlite.execute("drop table " + table);
            sqlite.execute("alter table " + rebuilt + " rename to " + table);
            dependents.forEach(sqlite::execute);
            sqlite.execute("release " + SAVEPOINT);
            log.info("[schema] rebuilt {} with an integer id: {} row(s), {} of them numbered",
                    table, rows, unnumbered);
        } catch (RuntimeException exception) {
            sqlite.execute("rollback to " + SAVEPOINT);
            sqlite.execute("release " + SAVEPOINT);
            log.warn("[schema] failed to rebuild {} with an integer id; rows saved to it keep a NULL id",
                    table, exception);
        }
    }

    private static boolean hasUntypedIdentity(List<Map<String, Object>> columns) {
        List<Map<String, Object>> key = columns.stream()
                .filter(column -> ((Number) column.get("pk")).intValue() > 0)
                .toList();
        return key.size() == 1
                && "id".equalsIgnoreCase((String) key.getFirst().get("name"))
                && ((String) key.getFirst().get("type")).isBlank();
    }

    /** The column list of {@code createSql} with the id typed {@code integer}, or null. */
    private static String typedColumns(String createSql) {
        int open = createSql == null ? -1 : createSql.indexOf('(');
        if (open < 0) {
            return null;
        }
        String columns = createSql.substring(open);
        if (UNTYPED_ID.matcher(columns).results().count() != 1) {
            return null;
        }
        return UNTYPED_ID.matcher(columns).replaceFirst("$1id integer$2");
    }

    private static void failUnnumberedCaptures(JdbcTemplate sqlite) {
        int failed = sqlite.update("""
                update specus_http_media_capture
                   set state = ?, deduplication_key = null, failure_reason = ?, completed_at = ?
                 where id is null and state in (?, ?)
                """,
                HttpMediaCaptureService.STATE_FAILED,
                UNNUMBERED_CAPTURE_FAILURE,
                Instant.now().toString(),
                HttpMediaCaptureService.STATE_STARTING,
                HttpMediaCaptureService.STATE_CAPTURING);
        if (failed > 0) {
            log.info("[media-capture] failed {} capture(s) that were stored without an id", failed);
        }
    }

    private static long count(JdbcTemplate sqlite, String table) {
        return sqlite.queryForObject("select count(*) from " + table, Long.class);
    }

    private static String quoted(List<String> names) {
        return names.stream().map(name -> '"' + name + '"').collect(Collectors.joining(", "));
    }
}
