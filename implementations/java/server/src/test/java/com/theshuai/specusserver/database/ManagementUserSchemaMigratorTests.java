package com.theshuai.specusserver.database;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.dao.DataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.SingleConnectionDataSource;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class ManagementUserSchemaMigratorTests {
    private SingleConnectionDataSource dataSource;

    @AfterEach
    void closeConnection() {
        if (dataSource != null) {
            dataSource.destroy();
        }
    }

    @Test
    void backfillsLegacyRowsAndEnforcesTenantScopedUniqueness() {
        JdbcTemplate jdbc = legacyDatabase();
        jdbc.update("insert into specus_management_user(username, tenant_id) values (?, ?)", "Alice", "tenant-a");
        jdbc.update("insert into specus_management_user(username, tenant_id) values (?, ?)", "alice", "tenant-b");

        ManagementUserSchemaMigrator migrator = new ManagementUserSchemaMigrator(jdbc);
        migrator.migrate();
        migrator.migrate();

        assertThat(jdbc.queryForMap(
                "select login_name, login_name_normalized from specus_management_user where username = 'Alice'"))
                .containsEntry("login_name", "Alice")
                .containsEntry("login_name_normalized", "alice");
        assertThatThrownBy(() -> jdbc.update(
                "insert into specus_management_user(username, tenant_id, login_name, login_name_normalized)"
                        + " values (?, ?, ?, ?)",
                "new-key", "tenant-a", "ALICE", "alice"))
                .isInstanceOf(DataAccessException.class);
    }

    @Test
    void failsBeforeBackfillWhenLegacyRowsCollideInsideTenant() {
        JdbcTemplate jdbc = legacyDatabase();
        jdbc.update("insert into specus_management_user(username, tenant_id) values (?, ?)", "Alice", "tenant-a");
        jdbc.update("insert into specus_management_user(username, tenant_id) values (?, ?)", "alice", "tenant-a");

        assertThatThrownBy(() -> new ManagementUserSchemaMigrator(jdbc).migrate())
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("duplicate management login name")
                .hasMessageContaining("tenant-a");
        assertThat(jdbc.queryForObject(
                "select count(*) from specus_management_user where login_name is not null", Integer.class))
                .isZero();
    }

    @Test
    void rejectsAnExistingIndexWithTheExpectedNameButWrongDefinition() {
        JdbcTemplate jdbc = legacyDatabase();
        jdbc.execute("create unique index uq_management_user_tenant_login_name "
                + "on specus_management_user (username)");

        assertThatThrownBy(() -> new ManagementUserSchemaMigrator(jdbc).migrate())
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("must be unique on (tenant_id, login_name_normalized)");
    }

    private JdbcTemplate legacyDatabase() {
        dataSource = new SingleConnectionDataSource("jdbc:sqlite::memory:", true);
        JdbcTemplate jdbc = new JdbcTemplate(dataSource);
        jdbc.execute("create table specus_management_user ("
                + "username varchar(80) primary key, tenant_id varchar(80) not null)");
        return jdbc;
    }
}
