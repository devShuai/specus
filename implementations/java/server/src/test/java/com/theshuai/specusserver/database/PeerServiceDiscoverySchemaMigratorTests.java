package com.theshuai.specusserver.database;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.jdbc.core.JdbcTemplate;
import org.sqlite.SQLiteDataSource;

import java.nio.file.Path;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class PeerServiceDiscoverySchemaMigratorTests {
    @TempDir
    Path temporaryDirectory;

    @Test
    void createsTablesDisabledByDefaultAndAddsSessionCapabilityColumns() {
        SQLiteDataSource dataSource = new SQLiteDataSource();
        dataSource.setUrl("jdbc:sqlite:" + temporaryDirectory.resolve("legacy.db"));
        JdbcTemplate jdbc = new JdbcTemplate(dataSource);
        jdbc.execute("""
                create table specus_client_session (
                    id integer primary key,
                    tenant_id text not null,
                    status text not null
                )
                """);
        // A session that was already there when the server was upgraded.
        jdbc.execute("insert into specus_client_session(id, tenant_id, status) values (2, 'default', 'DISCONNECTED')");

        PeerServiceDiscoverySchemaMigrator migrator = new PeerServiceDiscoverySchemaMigrator(
                jdbc, "org.hibernate.community.dialect.SQLiteDialect");
        migrator.migrate();
        migrator.migrate();

        jdbc.update("insert into peer_mesh_service_sharing(tenant_id, enabled, updated_at) values ('default', 1, 'now')");
        jdbc.update("""
                insert into peer_mesh_shared_service(
                    id, tenant_id, client_id, client_name, service_id, name, transport, application,
                    target_host, target_port, published_port, enabled, visibility, created_at, updated_at)
                values (1, 'default', 1, 'a', 'svc-ssh001', 'ssh', 'tcp', 'ssh', '127.0.0.1', 22, 2222, 0, 'OWNER', 'now', 'now')
                """);

        Map<String, Object> sharing = jdbc.queryForMap(
                "select enabled, mdns_import_enabled from peer_mesh_service_sharing where tenant_id='default'");
        assertThat(((Number) sharing.get("mdns_import_enabled")).intValue()).isZero();
        jdbc.queryForMap("select allowed_client_ids from peer_mesh_shared_service where id=1");
        Map<String, Object> service = jdbc.queryForMap("select enabled from peer_mesh_shared_service where id=1");
        assertThat(((Number) service.get("enabled")).intValue()).isZero();

        jdbc.execute("insert into specus_client_session(id, tenant_id, status) values (1, 'default', 'HTTP_AUTHENTICATED')");
        Map<String, Object> session = jdbc.queryForMap(
                "select peer_service_discovery_version, peer_service_applications from specus_client_session where id=1");
        assertThat(((Number) session.get("peer_service_discovery_version")).intValue()).isZero();
        // Sessions from before the egress columns, and new rows that do not set them, announce no
        // egress and no domain targets.
        for (int id : new int[] {1, 2}) {
            Map<String, Object> egress = jdbc.queryForMap(
                    "select client_egress_version, client_egress_domain_targets from specus_client_session where id=?", id);
            assertThat(((Number) egress.get("client_egress_version")).intValue()).isZero();
            assertThat(((Number) egress.get("client_egress_domain_targets")).intValue()).isZero();
        }
        assertThat(sharing).isNotEmpty();
    }

    /**
     * An egress policy table from before domain rules gains the column with an empty list, so a
     * policy saved before them grants no name and a row written without it reads the same way.
     */
    @Test
    void addsTheEgressDomainRulesColumnToAnExistingPolicyTable() {
        SQLiteDataSource dataSource = new SQLiteDataSource();
        dataSource.setUrl("jdbc:sqlite:" + temporaryDirectory.resolve("legacy-egress.db"));
        JdbcTemplate jdbc = new JdbcTemplate(dataSource);
        jdbc.execute("create table specus_client_session (id integer primary key, tenant_id text not null)");
        jdbc.execute("""
                create table peer_mesh_egress_policy (
                    id integer primary key,
                    tenant_id text not null,
                    egress_client_id integer not null,
                    destination_rules text
                )
                """);
        jdbc.execute("""
                insert into peer_mesh_egress_policy(id, tenant_id, egress_client_id, destination_rules)
                values (1, 'default', 2, '[{"cidr":"203.0.113.0/24","protocols":["tcp"],"portRanges":[[443,443]]}]')
                """);

        PeerServiceDiscoverySchemaMigrator migrator = new PeerServiceDiscoverySchemaMigrator(
                jdbc, "org.hibernate.community.dialect.SQLiteDialect");
        migrator.migrate();
        migrator.migrate();

        jdbc.execute("insert into peer_mesh_egress_policy(id, tenant_id, egress_client_id) values (3, 'default', 4)");
        for (int id : new int[] {1, 3}) {
            assertThat(jdbc.queryForObject(
                    "select domain_rules from peer_mesh_egress_policy where id=?", String.class, id))
                    .as("policy %d", id).isEqualTo("[]");
        }
        assertThat(jdbc.queryForObject(
                "select destination_rules from peer_mesh_egress_policy where id=1", String.class))
                .contains("203.0.113.0/24");
    }
}
