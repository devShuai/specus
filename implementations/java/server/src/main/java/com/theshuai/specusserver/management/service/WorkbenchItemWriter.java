package com.theshuai.specusserver.management.service;

import lombok.extern.slf4j.Slf4j;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;

import javax.sql.DataSource;
import java.sql.Connection;
import java.sql.SQLException;
import java.util.Locale;

import static com.theshuai.specusserver.management.model.ManagementWorkbenchItem.FAVORITE;
import static com.theshuai.specusserver.management.model.ManagementWorkbenchItem.RECENT;

/**
 * Writes new workbench rows with one atomic statement per dialect (protocol/spec/service-workbench.md
 * section 8): two instances adding the same reference at once both succeed instead of one of them
 * failing on the primary key. A favourite that is already there keeps its addedAt; a recent open
 * keeps the later of the two times. Runs inside the service's transaction and shares its connection.
 */
@Component
@Slf4j
public class WorkbenchItemWriter {
    private static final String COLUMNS = "(tenant_id, username, list, kind, object_id, at_ms)";

    private final JdbcTemplate jdbc;
    private final String favoriteSql;
    private final String recentSql;

    public WorkbenchItemWriter(JdbcTemplate jdbc, DataSource dataSource) {
        this.jdbc = jdbc;
        String product = databaseProduct(dataSource);
        String insert = "INSERT INTO management_workbench_item " + COLUMNS + " VALUES (?, ?, ?, ?, ?, ?)";
        if (product.contains("mysql") || product.contains("mariadb")) {
            favoriteSql = insert + " ON DUPLICATE KEY UPDATE at_ms = at_ms";
            recentSql = insert + " ON DUPLICATE KEY UPDATE at_ms = GREATEST(at_ms, VALUES(at_ms))";
        } else {
            // SQLite's two-argument max() and PostgreSQL's GREATEST() are the same scalar maximum.
            String greatest = product.contains("postgres") ? "GREATEST" : "max";
            String conflict = " ON CONFLICT (tenant_id, username, list, kind, object_id) DO ";
            favoriteSql = insert + conflict + "NOTHING";
            recentSql = insert + conflict + "UPDATE SET at_ms = " + greatest
                    + "(management_workbench_item.at_ms, excluded.at_ms)";
        }
    }

    private static String databaseProduct(DataSource dataSource) {
        try (Connection connection = dataSource.getConnection()) {
            String product = connection.getMetaData().getDatabaseProductName();
            return product == null ? "" : product.toLowerCase(Locale.ROOT);
        } catch (SQLException e) {
            log.warn("[workbench] database product detection failed: {}", e.getMessage());
            return "";
        }
    }

    /** Adds a favourite unless it is already there. */
    public void addFavorite(String tenantId, String username, String kind, long objectId, long atMs) {
        jdbc.update(favoriteSql, tenantId, username, FAVORITE, kind, objectId, atMs);
    }

    /** Records a recent open, keeping the later time when the row appeared meanwhile. */
    public void recordRecent(String tenantId, String username, String kind, long objectId, long atMs) {
        jdbc.update(recentSql, tenantId, username, RECENT, kind, objectId, atMs);
    }
}
