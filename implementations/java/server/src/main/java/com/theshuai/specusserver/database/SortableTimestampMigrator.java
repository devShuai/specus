package com.theshuai.specusserver.database;

import com.theshuai.specusserver.management.model.SortableInstant;
import lombok.extern.slf4j.Slf4j;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowCallbackHandler;
import org.springframework.stereotype.Component;

import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.List;

/**
 * Idempotent rewrite of the timestamp columns that queries compare as strings to the
 * {@link SortableInstant} width. Rows written before it hold {@code Instant.toString()} text (20, 24,
 * 27 or 30 characters, never 28), which those comparisons get up to a second wrong. Every write path
 * stores the fixed width now, so a later start finds nothing to rewrite.
 */
@Component
@Slf4j
public class SortableTimestampMigrator {
    /** Rows read per query, so a long connection log is never held in memory at once. */
    static final int BATCH_SIZE = 500;

    static final List<TimestampColumn> COLUMNS = List.of(
            new TimestampColumn("transfer_attachment", "id", "upload_expires_at"),
            new TimestampColumn("transfer_attachment", "id", "expires_at"),
            new TimestampColumn("transfer_attachment_download_grant", "id", "expires_at"),
            new TimestampColumn("specus_client_auth_nonce", "id", "expires_at"),
            new TimestampColumn("specus_websocket_ticket", "token_hash", "expires_at"),
            new TimestampColumn("peer_mesh_session", "id", "expires_at"),
            new TimestampColumn("public_transfer_room_pairing_code", "id", "expires_at"),
            new TimestampColumn("specus_management_registration_challenge", "registration_id", "expires_at"),
            new TimestampColumn("specus_connection_record", "id", "connected_at"),
            new TimestampColumn("specus_http_media_capture", "id", "expires_at"));

    private final JdbcTemplate jdbcTemplate;

    public SortableTimestampMigrator(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    public void migrate() {
        for (TimestampColumn column : COLUMNS) {
            if (!tableExists(column.table())) {
                log.debug("[schema] table {} does not exist; no timestamps to rewrite", column.table());
                continue;
            }
            int rewritten = rewrite(column);
            if (rewritten > 0) {
                log.info("[schema] rewrote {} {}.{} value(s) to the sortable instant form",
                        rewritten, column.table(), column.name());
            }
        }
    }

    private int rewrite(TimestampColumn column) {
        String table = column.table();
        String key = column.key();
        String name = column.name();
        String legacy = "select " + key + ", " + name + " from " + table
                + " where " + name + " is not null and length(" + name + ") <> " + SortableInstant.LENGTH;
        String page = " order by " + key + " limit " + BATCH_SIZE;
        String update = "update " + table + " set " + name + " = ? where " + key + " = ? and " + name + " = ?";
        int rewritten = 0;
        Object after = null;
        while (true) {
            // Read a whole batch first: SQLite's single connection cannot update while the cursor is open.
            List<Object[]> rows = new ArrayList<>();
            RowCallbackHandler collect = row -> rows.add(new Object[]{row.getObject(1), row.getString(2)});
            if (after == null) {
                jdbcTemplate.query(legacy + page, collect);
            } else {
                // Keyset paging steps past rows left unchanged because they do not parse.
                jdbcTemplate.query(legacy + " and " + key + " > ?" + page, collect, after);
            }
            List<Object[]> updates = new ArrayList<>();
            for (Object[] row : rows) {
                String stored = (String) row[1];
                try {
                    updates.add(new Object[]{SortableInstant.normalize(stored), row[0], stored});
                } catch (DateTimeParseException exception) {
                    log.warn("[schema] leaving unparseable {}.{} of row {} unchanged: '{}'",
                            table, name, row[0], stored);
                }
            }
            if (!updates.isEmpty()) {
                jdbcTemplate.batchUpdate(update, updates);
                rewritten += updates.size();
            }
            if (rows.size() < BATCH_SIZE) {
                return rewritten;
            }
            after = rows.get(rows.size() - 1)[0];
        }
    }

    /**
     * From the metadata: the admin initialize endpoint runs this inside a transaction, which a
     * failed probe would abort on PostgreSQL.
     */
    private boolean tableExists(String table) {
        return SchemaMetadata.table(jdbcTemplate, table) != null;
    }

    /** A string-compared timestamp column, with the primary key that addresses its rows. */
    record TimestampColumn(String table, String key, String name) { }
}
