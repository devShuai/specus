package com.theshuai.specusserver.management.service;

import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.JdbcTemplate;

import javax.sql.DataSource;
import java.sql.Connection;
import java.sql.DatabaseMetaData;
import java.sql.SQLException;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/** The upsert each dialect gets; SQLite runs for real in the workbench HTTP tests. */
class WorkbenchItemWriterTests {

    private static WorkbenchItemWriter writer(String product, JdbcTemplate jdbc) throws SQLException {
        DataSource dataSource = mock(DataSource.class);
        Connection connection = mock(Connection.class);
        DatabaseMetaData metaData = mock(DatabaseMetaData.class);
        when(dataSource.getConnection()).thenReturn(connection);
        when(connection.getMetaData()).thenReturn(metaData);
        when(metaData.getDatabaseProductName()).thenReturn(product);
        return new WorkbenchItemWriter(jdbc, dataSource);
    }

    @Test
    void mysqlKeepsTheFirstFavouriteAndTheLaterRecent() throws SQLException {
        JdbcTemplate jdbc = mock(JdbcTemplate.class);
        WorkbenchItemWriter writer = writer("MySQL", jdbc);
        writer.addFavorite("t1", "alice", "http-route", 11L, 100L);
        writer.recordRecent("t1", "alice", "http-route", 11L, 200L);
        verify(jdbc).update(eq("INSERT INTO management_workbench_item (tenant_id, username, list, kind, object_id, at_ms)"
                + " VALUES (?, ?, ?, ?, ?, ?) ON DUPLICATE KEY UPDATE at_ms = at_ms"), any(Object[].class));
        verify(jdbc).update(eq("INSERT INTO management_workbench_item (tenant_id, username, list, kind, object_id, at_ms)"
                + " VALUES (?, ?, ?, ?, ?, ?) ON DUPLICATE KEY UPDATE at_ms = GREATEST(at_ms, VALUES(at_ms))"),
                any(Object[].class));
    }

    @Test
    void postgresUsesOnConflictWithGreatest() throws SQLException {
        JdbcTemplate jdbc = mock(JdbcTemplate.class);
        WorkbenchItemWriter writer = writer("PostgreSQL", jdbc);
        writer.addFavorite("t1", "alice", "http-route", 11L, 100L);
        writer.recordRecent("t1", "alice", "http-route", 11L, 200L);
        String insert = "INSERT INTO management_workbench_item (tenant_id, username, list, kind, object_id, at_ms)"
                + " VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT (tenant_id, username, list, kind, object_id) DO ";
        verify(jdbc).update(eq(insert + "NOTHING"), any(Object[].class));
        verify(jdbc).update(eq(insert + "UPDATE SET at_ms = GREATEST(management_workbench_item.at_ms, excluded.at_ms)"),
                any(Object[].class));
    }

    @Test
    void anUnknownProductFallsBackToTheSqliteForm() throws SQLException {
        JdbcTemplate jdbc = mock(JdbcTemplate.class);
        DataSource dataSource = mock(DataSource.class);
        when(dataSource.getConnection()).thenThrow(new SQLException("down"));
        new WorkbenchItemWriter(jdbc, dataSource).recordRecent("t1", "alice", "http-route", 11L, 200L);
        verify(jdbc).update(eq("INSERT INTO management_workbench_item"
                + " (tenant_id, username, list, kind, object_id, at_ms) VALUES (?, ?, ?, ?, ?, ?)"
                + " ON CONFLICT (tenant_id, username, list, kind, object_id) DO UPDATE SET at_ms ="
                + " max(management_workbench_item.at_ms, excluded.at_ms)"), any(Object[].class));
    }
}
