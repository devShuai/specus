package com.theshuai.specusserver.database;

import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.jpa.autoconfigure.EntityManagerFactoryDependsOnPostProcessor;
import org.springframework.context.annotation.Bean;
import org.springframework.dao.DataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowCallbackHandler;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * Widens the LOB columns Hibernate's MySQLDialect created too narrow before their mappings declared
 * {@code Length.LONG32}: a {@code @Lob} column kept {@code @Column}'s default length of 255 and
 * became tinyblob or tinytext, and a LONGVARBINARY one became varbinary(32600), which rejects a
 * diagram snapshot past 32,600 bytes.
 *
 * <p>Runs before Hibernate's schema update. That update takes varbinary for the same type as
 * LONGVARBINARY and so never widens the diagram snapshot; it does alter a tinyblob or tinytext
 * column, but one statement per column. Changing a column's type rebuilds the table, which on a
 * large traffic table takes long and holds up its writes, so this widens all of a table's narrow
 * columns in one statement, and only while information_schema still reports a narrow type; the
 * update then finds them matching, and a later start alters nothing.
 */
@Component
@Slf4j
public class MySqlLobColumnMigrator {
    private static final List<LobColumn> COLUMNS = List.of(
            new LobColumn("public_transfer_diagram_version", "snapshot_data", "longblob", true),
            new LobColumn("specus_http_media_capture", "response_headers", "longtext", false),
            new LobColumn("specus_http_traffic_exchange", "request_body_data", "longblob", false),
            new LobColumn("specus_http_traffic_exchange", "response_body_data", "longblob", false),
            new LobColumn("specus_http_traffic_exchange", "request_preview_text", "longtext", false),
            new LobColumn("specus_http_traffic_exchange", "response_preview_text", "longtext", false),
            new LobColumn("specus_tcp_traffic_frame", "payload_data", "longblob", false),
            new LobColumn("specus_websocket_ticket", "attributes_json", "longtext", true),
            new LobColumn("user_diagram_document", "snapshot_data", "longblob", true));

    private final JdbcTemplate jdbcTemplate;
    private final boolean mySql;

    public MySqlLobColumnMigrator(JdbcTemplate jdbcTemplate,
                                  @Value("${spring.jpa.database-platform:auto}") String databasePlatform) {
        this.jdbcTemplate = jdbcTemplate;
        String platform = databasePlatform == null ? "" : databasePlatform.toLowerCase(Locale.ROOT);
        this.mySql = platform.contains("mysql") || platform.contains("mariadb");
    }

    /** Hibernate updates the schema while it builds the entity manager factory. */
    @Bean
    static EntityManagerFactoryDependsOnPostProcessor lobColumnsWidenedBeforeSchemaUpdate() {
        return new EntityManagerFactoryDependsOnPostProcessor(MySqlLobColumnMigrator.class);
    }

    @PostConstruct
    public void migrate() {
        if (!mySql) {
            return;
        }
        // The HTTP exchange headers may still be varchar(8192); the capture cap keeps them within it.
        Set<String> narrowColumns = new HashSet<>();
        jdbcTemplate.query("""
                select table_name, column_name
                  from information_schema.columns
                 where table_schema = database()
                   and data_type in ('tinyblob', 'tinytext', 'blob', 'text', 'varbinary')
                """, (RowCallbackHandler) row -> narrowColumns.add(key(row.getString(1), row.getString(2))));
        Map<String, List<String>> modifications = new LinkedHashMap<>();
        for (LobColumn column : COLUMNS) {
            if (narrowColumns.contains(key(column.table(), column.name()))) {
                // MODIFY drops what it does not restate, NOT NULL included.
                modifications.computeIfAbsent(column.table(), table -> new ArrayList<>())
                        .add("modify column " + column.name() + " " + column.type()
                                + (column.notNull() ? " not null" : ""));
            }
        }
        modifications.forEach((table, columns) -> {
            String statement = "alter table " + table + " " + String.join(", ", columns);
            log.info("[schema] widening the LOB columns of {}, which rebuilds the table: {}", table, statement);
            try {
                jdbcTemplate.execute(statement);
            } catch (DataAccessException e) {
                log.warn("[schema] could not widen the LOB columns of {}, so values past their old width keep"
                        + " failing until '{}' runs: {}", table, statement, e.getMessage());
            }
        });
    }

    private static String key(String table, String column) {
        return (table + "." + column).toLowerCase(Locale.ROOT);
    }

    private record LobColumn(String table, String name, String type, boolean notNull) {
    }
}
