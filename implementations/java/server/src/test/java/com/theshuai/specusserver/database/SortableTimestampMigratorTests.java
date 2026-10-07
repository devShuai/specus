package com.theshuai.specusserver.database;

import com.theshuai.specusserver.management.model.SortableInstant;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.SingleConnectionDataSource;

import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class SortableTimestampMigratorTests {
    private static final String UNPARSEABLE = "not-an-instant";

    /**
     * Legacy values of every {@code Instant.toString()} width, more than two batches of them, under
     * numeric and text keys. Unparseable values stay as they are and do not stop the paging; tables
     * that do not exist yet are skipped.
     */
    @Test
    void rewritesLegacyValuesInBatchesUnderNumericAndTextKeys() {
        JdbcTemplate jdbc = new JdbcTemplate(new SingleConnectionDataSource("jdbc:sqlite::memory:", true));
        jdbc.execute("create table specus_connection_record (id integer primary key, connected_at varchar(40) not null)");
        jdbc.execute("create table specus_websocket_ticket (token_hash varchar(64) primary key, expires_at varchar(40) not null)");
        int rows = 2 * SortableTimestampMigrator.BATCH_SIZE + 7;
        Map<Object, String> records = new LinkedHashMap<>();
        Map<Object, String> tickets = new LinkedHashMap<>();
        for (int i = 1; i <= rows; i++) {
            records.put(i, legacy(i));
            tickets.put("t%05d".formatted(i), legacy(i));
        }
        jdbc.batchUpdate("insert into specus_connection_record(id, connected_at) values (?, ?)", arguments(records));
        jdbc.batchUpdate("insert into specus_websocket_ticket(token_hash, expires_at) values (?, ?)", arguments(tickets));

        SortableTimestampMigrator migrator = new SortableTimestampMigrator(jdbc);
        migrator.migrate();

        Map<Object, String> migratedRecords = read(jdbc, "select id, connected_at from specus_connection_record");
        Map<Object, String> migratedTickets = read(jdbc, "select token_hash, expires_at from specus_websocket_ticket");
        assertThat(migratedRecords).isEqualTo(expected(records));
        assertThat(migratedTickets).isEqualTo(expected(tickets));

        migrator.migrate();

        assertThat(read(jdbc, "select id, connected_at from specus_connection_record")).isEqualTo(migratedRecords);
        assertThat(read(jdbc, "select token_hash, expires_at from specus_websocket_ticket")).isEqualTo(migratedTickets);
    }

    /** Whole seconds, then 3, 6 and 9 fraction digits in turn, with an unparseable value every 97th row. */
    private static String legacy(int i) {
        if (i % 97 == 0) {
            return UNPARSEABLE;
        }
        Instant second = Instant.parse("2026-09-15T12:00:00Z").plusSeconds(i);
        return switch (i % 4) {
            case 0 -> second.toString();
            case 1 -> second.plusMillis(i % 1000 + 1).toString();
            case 2 -> second.plusNanos(1_000L * (i % 1000 + 1)).toString();
            default -> second.plusNanos(i % 1000 + 1).toString();
        };
    }

    private static Map<Object, String> expected(Map<Object, String> legacy) {
        Map<Object, String> expected = new LinkedHashMap<>();
        legacy.forEach((key, value) -> {
            String migrated = UNPARSEABLE.equals(value) ? value : SortableInstant.normalize(value);
            assertThat(migrated.length()).isIn(UNPARSEABLE.length(), SortableInstant.LENGTH);
            expected.put(key, migrated);
        });
        return expected;
    }

    private static List<Object[]> arguments(Map<Object, String> values) {
        List<Object[]> arguments = new ArrayList<>();
        values.forEach((key, value) -> arguments.add(new Object[]{key, value}));
        return arguments;
    }

    private static Map<Object, String> read(JdbcTemplate jdbc, String sql) {
        Map<Object, String> values = new LinkedHashMap<>();
        jdbc.query(sql + " order by 1", row -> {
            values.put(row.getObject(1), row.getString(2));
        });
        return values;
    }
}
