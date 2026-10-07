package com.theshuai.specusserver.database;

import lombok.extern.slf4j.Slf4j;
import org.springframework.jdbc.core.ConnectionCallback;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowCallbackHandler;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Moves the HTTP exchange bodies and previews of a PostgreSQL database out of large objects.
 *
 * <p>They used to be {@code @Lob}: Hibernate made the four columns {@code oid} and wrote each value
 * as a large object, a preview in UTF-8. {@link DatabaseInitializer} then altered the two preview
 * columns to {@code text}, which turned each large object's number into its text, and every preview
 * written since is such a number too. The mapping now makes the columns {@code bytea} and
 * {@code text}; this copies each large object into its row and unlinks it. A number with no large
 * object behind it is left as it is in a preview and cleared in a body.
 *
 * <p>With ddl-auto=update Hibernate has already altered each column whose type differs from the
 * mapping: an {@code oid} preview column to {@code text}, as the widening did, while an {@code oid}
 * body column stays, as nothing casts oid to bytea, with the failure only logged. So an {@code oid}
 * column marks such a table. All four columns change in one transaction, so a later start finds none and leaves
 * the previews alone, where a body of digits is only text. A failure rolls the whole conversion back
 * and fails the start, rather than run on columns the mapping can no longer write.
 */
@Component
@Slf4j
public class HttpExchangeLargeObjectMigrator {
    private static final String TABLE = "specus_http_traffic_exchange";
    private static final List<Column> COLUMNS = List.of(
            new Column("request_body_data", "bytea"),
            new Column("response_body_data", "bytea"),
            new Column("request_preview_text", "text"),
            new Column("response_preview_text", "text"));
    /** What {@code regtype} calls the types a preview column has had. */
    private static final Set<String> TEXT_TYPES = Set.of("text", "character varying");
    private static final String MIGRATED = "specus_migrated_large_object";

    private final JdbcTemplate jdbcTemplate;

    public HttpExchangeLargeObjectMigrator(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    @Transactional
    public void migrate() {
        if (!isPostgres()) {
            return;
        }
        Map<String, String> types = columnTypes();
        if (!types.containsValue("oid")) {
            return;
        }
        // The large objects to unlink once copied, when no column holds their numbers any more.
        jdbcTemplate.execute("create temporary table " + MIGRATED + " (lo oid primary key) on commit drop");
        List<String> alterations = new ArrayList<>();
        for (Column column : COLUMNS) {
            String type = types.get(column.name());
            if ("oid".equals(type)) {
                remember(column.name());
                // lo_get fails on a number with no large object behind it.
                jdbcTemplate.update("update " + TABLE + " set " + column.name() + " = null"
                        + " where " + column.name() + " is not null and not " + isLargeObject(column.name()));
                alterations.add("alter column " + column.name() + " type " + column.type()
                        + " using " + content(column.name(), column.type()));
            } else if (column.type().equals("text") && TEXT_TYPES.contains(type)) {
                String reference = reference(column.name());
                remember(reference);
                jdbcTemplate.update("update " + TABLE + " set " + column.name() + " = " + content(reference, "text")
                        + " where " + isLargeObject(reference));
            }
        }
        if (!alterations.isEmpty()) {
            jdbcTemplate.execute("alter table " + TABLE + " " + String.join(", ", alterations));
        }
        Long unlinked = jdbcTemplate.queryForObject("select count(lo_unlink(lo)) from " + MIGRATED, Long.class);
        log.info("[schema] moved {} large object(s) into the bytea and text columns of {}, which were {}",
                unlinked, TABLE, types);
    }

    private void remember(String largeObject) {
        jdbcTemplate.update("insert into " + MIGRATED + " select " + largeObject + " from " + TABLE
                + " where " + isLargeObject(largeObject) + " on conflict do nothing");
    }

    private static String isLargeObject(String number) {
        return "exists (select 1 from pg_largeobject_metadata m where m.oid = " + number + ")";
    }

    /** The number the old mapping wrote into a text column, as an oid; null for any other text. */
    private static String reference(String column) {
        // CASE keeps the casts off other text; 4294967295 is the largest oid.
        return "(case when " + column + " !~ '^[1-9][0-9]{0,9}$' then null"
                + " when " + column + "::bigint > 4294967295 then null"
                + " else " + column + "::bigint::oid end)";
    }

    /** The large object as the column's new type; pgjdbc wrote a string into one in UTF-8. */
    private static String content(String largeObject, String type) {
        return type.equals("bytea")
                ? "lo_get(" + largeObject + ")"
                : "convert_from(lo_get(" + largeObject + "), 'UTF8')";
    }

    private boolean isPostgres() {
        return Boolean.TRUE.equals(jdbcTemplate.execute((ConnectionCallback<Boolean>) connection ->
                "PostgreSQL".equalsIgnoreCase(connection.getMetaData().getDatabaseProductName())));
    }

    /** The types of the four columns in the table unqualified SQL sees; none when there is no table. */
    private Map<String, String> columnTypes() {
        Map<String, String> types = new LinkedHashMap<>();
        jdbcTemplate.query("""
                        select attname, atttypid::regtype::text from pg_attribute
                         where attrelid = to_regclass(?) and attnum > 0 and not attisdropped
                         order by attnum
                        """,
                (RowCallbackHandler) row -> {
                    String name = row.getString(1);
                    if (COLUMNS.stream().anyMatch(column -> column.name().equals(name))) {
                        types.put(name, row.getString(2));
                    }
                },
                TABLE);
        return types;
    }

    private record Column(String name, String type) {
    }
}
