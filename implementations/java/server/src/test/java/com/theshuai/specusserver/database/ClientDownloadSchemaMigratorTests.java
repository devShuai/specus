package com.theshuai.specusserver.database;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.dao.DataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.sqlite.SQLiteDataSource;

import java.nio.file.Path;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class ClientDownloadSchemaMigratorTests {
    @TempDir
    Path temporaryDirectory;

    @Test
    void upgradesLegacyRowsWithoutInventingVisibleVersionsAndEnforcesPortableSlots() {
        SQLiteDataSource dataSource = new SQLiteDataSource();
        dataSource.setUrl("jdbc:sqlite:" + temporaryDirectory.resolve("legacy.db"));
        JdbcTemplate jdbc = new JdbcTemplate(dataSource);
        jdbc.execute("""
                create table client_download_link (
                    id bigint primary key,
                    implementation varchar(32) not null,
                    platform varchar(32) not null,
                    arch varchar(32) not null,
                    enabled boolean not null default true
                )
                """);
        jdbc.update("insert into client_download_link(id, implementation, platform, arch) values (1,'go','windows','x64')");
        jdbc.update("insert into client_download_link(id, implementation, platform, arch) values (2,'go','windows','x64')");

        ClientDownloadSchemaMigrator migrator = new ClientDownloadSchemaMigrator(jdbc);
        migrator.migrate();

        List<Map<String, Object>> legacy = jdbc.queryForList(
                "select id, version, is_latest, hosted, catalog_key, latest_slot from client_download_link order by id");
        assertThat(legacy).allSatisfy(row -> {
            assertThat(row.get("version")).isNull();
            assertThat(((Number) row.get("is_latest")).intValue()).isZero();
            assertThat(((Number) row.get("hosted")).intValue()).isZero();
            assertThat(row.get("latest_slot")).isNull();
        });
        assertThat(legacy).extracting(row -> row.get("catalog_key")).doesNotHaveDuplicates();

        // Simulate a partially upgraded database containing duplicate version/latest declarations.
        jdbc.update("update client_download_link set version='v1.2.3', min_supported_version='v1.0.0', is_latest=1");
        migrator.migrate();
        List<Map<String, Object>> upgraded = jdbc.queryForList(
                "select id, version, min_supported_version, is_latest, catalog_key, latest_slot "
                        + "from client_download_link order by id desc");
        assertThat(upgraded.stream().filter(row -> row.get("version") != null)).hasSize(1);
        assertThat(upgraded.stream().filter(row -> row.get("version") == null))
                .allSatisfy(row -> assertThat(row.get("min_supported_version")).isNull());
        assertThat(upgraded.stream().filter(row -> row.get("version") != null).findFirst().orElseThrow())
                .satisfies(row -> {
                    assertThat(row.get("version")).isEqualTo("1.2.3");
                    assertThat(row.get("min_supported_version")).isEqualTo("1.0.0");
                });
        assertThat(upgraded.stream().filter(row -> ((Number) row.get("is_latest")).intValue() == 1)).hasSize(1);
        assertThat(upgraded).extracting(row -> row.get("catalog_key")).doesNotHaveDuplicates();

        String occupied = upgraded.getFirst().get("catalog_key").toString();
        assertThatThrownBy(() -> jdbc.update(
                "insert into client_download_link(id,implementation,platform,arch,catalog_key) values (3,'go','windows','x64',?)",
                occupied)).isInstanceOf(DataAccessException.class)
                .hasRootCauseMessage("[SQLITE_CONSTRAINT_UNIQUE] A UNIQUE constraint failed "
                        + "(UNIQUE constraint failed: client_download_link.catalog_key)");

        jdbc.update("""
                update client_download_link
                   set enabled=0, is_latest=1, latest_slot='go|windows|x64'
                 where id=2
                """);
        migrator.migrate();
        Map<String, Object> disabled = jdbc.queryForMap(
                "select is_latest, latest_slot from client_download_link where id=2");
        assertThat(((Number) disabled.get("is_latest")).intValue()).isZero();
        assertThat(disabled.get("latest_slot")).isNull();

        // A third run is a no-op, which is essential for every server restart.
        migrator.migrate();
        assertThat(jdbc.queryForObject("select count(*) from client_download_link", Long.class)).isEqualTo(2L);
    }
}
