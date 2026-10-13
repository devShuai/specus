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
 * Idempotent rewrite of the transfer expiry columns to the {@link SortableInstant} width.
 * Rows written before it hold {@code Instant.toString()} text (20, 24, 27 or 30 characters, never
 * 28), which the storage-quota, expiry-scan and download-grant queries compare up to a second
 * wrong. Every write path stores the fixed width now, so a later start finds nothing to rewrite.
 */
@Component
@Slf4j
public class TransferTimestampMigrator {
    private static final List<TimestampColumn> COLUMNS = List.of(
            new TimestampColumn("transfer_attachment", "upload_expires_at"),
            new TimestampColumn("transfer_attachment", "expires_at"),
            new TimestampColumn("transfer_attachment_download_grant", "expires_at"));

    private final JdbcTemplate jdbcTemplate;

    public TransferTimestampMigrator(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    public void migrate() {
        for (TimestampColumn column : COLUMNS) {
            if (!tableExists(column.table())) {
                log.debug("[transfer] table {} does not exist; no timestamps to rewrite", column.table());
                continue;
            }
            int rewritten = rewrite(column);
            if (rewritten > 0) {
                log.info("[transfer] rewrote {} {}.{} value(s) to the sortable instant form",
                        rewritten, column.table(), column.name());
            }
        }
    }

    private int rewrite(TimestampColumn column) {
        String table = column.table();
        String name = column.name();
        List<Object[]> updates = new ArrayList<>();
        // Collect first: SQLite's single connection cannot update while the cursor is open.
        jdbcTemplate.query("select id, " + name + " from " + table
                        + " where " + name + " is not null and length(" + name + ") <> " + SortableInstant.LENGTH,
                (RowCallbackHandler) row -> {
                    long id = row.getLong(1);
                    String stored = row.getString(2);
                    try {
                        updates.add(new Object[]{SortableInstant.normalize(stored), id, stored});
                    } catch (DateTimeParseException exception) {
                        log.warn("[transfer] leaving unparseable {}.{} of row {} unchanged: '{}'",
                                table, name, id, stored);
                    }
                });
        if (!updates.isEmpty()) {
            jdbcTemplate.batchUpdate("update " + table + " set " + name + " = ?"
                    + " where id = ? and " + name + " = ?", updates);
        }
        return updates.size();
    }

    /**
     * From the metadata: the admin initialize endpoint runs this inside a transaction, which a
     * failed probe would abort on PostgreSQL.
     */
    private boolean tableExists(String table) {
        return SchemaMetadata.table(jdbcTemplate, table) != null;
    }

    private record TimestampColumn(String table, String name) { }
}
