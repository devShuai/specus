package com.theshuai.specusserver.database;

import com.theshuai.specusserver.SpecusServerApplication;
import com.theshuai.specusserver.management.model.SortableInstant;
import io.zonky.test.db.postgres.embedded.EmbeddedPostgres;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.boot.WebApplicationType;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DataSourceTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

import javax.sql.DataSource;
import java.io.IOException;
import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * The schema migrations on a real PostgreSQL. Unlike SQLite and MySQL, PostgreSQL aborts the whole
 * transaction on the first failed statement, so a migration that probes the schema by running a
 * statement and catching its failure works on the other two and breaks here; and the failure's
 * message follows the server's {@code lc_messages}, so it cannot be recognised by its text.
 *
 * <p>Each migrator runs inside a transaction, as {@code @Transactional} and the admin initialize
 * endpoint run it, and twice, as two starts do.
 */
class PostgresSchemaMigrationTests {
    private static final AtomicInteger DATABASES = new AtomicInteger();
    private static EmbeddedPostgres postgres;

    @TempDir
    Path temporaryDirectory;

    @BeforeAll
    static void startPostgres() throws IOException {
        postgres = EmbeddedPostgres.start();
    }

    @AfterAll
    static void stopPostgres() throws IOException {
        if (postgres != null) {
            postgres.close();
        }
    }

    @Test
    void serverStartsRestartsAndReinitializesOnPostgres() {
        String database = createDatabase();
        List<Map<String, Object>> indexes;

        try (ConfigurableApplicationContext first = start(database)) {
            indexes = indexes(first);
            assertThat(indexes).extracting(index -> index.get("indexname"))
                    .contains(ManagementUserSchemaMigrator.UNIQUE_INDEX);
        }

        try (ConfigurableApplicationContext second = start(database)) {
            assertThat(indexes(second)).isEqualTo(indexes);
            // POST /api/admin/database/initialize: every step inside one transaction.
            assertThat(second.getBean(DatabaseInitializer.class).initialize())
                    .containsEntry("initialized", true);
            assertThat(indexes(second)).isEqualTo(indexes);
        }
    }

    /** The reported failure: Hibernate's update has already created the index. */
    @Test
    void managementUserMigrationAcceptsTheIndexHibernateCreated() {
        DataSource dataSource = newDatabase();
        JdbcTemplate jdbc = new JdbcTemplate(dataSource);
        jdbc.execute("create table specus_management_user (username varchar(80) primary key,"
                + " tenant_id varchar(80) not null, login_name varchar(80), login_name_normalized varchar(80))");
        jdbc.execute("create unique index uq_management_user_tenant_login_name"
                + " on specus_management_user (tenant_id, login_name_normalized)");
        jdbc.update("insert into specus_management_user(username, tenant_id) values ('Alice', 'tenant-a')");

        migrateTwice(dataSource, () -> new ManagementUserSchemaMigrator(jdbc).migrate());

        assertThat(jdbc.queryForObject(
                "select login_name_normalized from specus_management_user where username = 'Alice'", String.class))
                .isEqualTo("alice");
    }

    @Test
    void managementUserMigrationUpgradesALegacyTable() {
        DataSource dataSource = newDatabase();
        JdbcTemplate jdbc = new JdbcTemplate(dataSource);
        jdbc.execute("create table specus_management_user ("
                + "username varchar(80) primary key, tenant_id varchar(80) not null)");
        jdbc.update("insert into specus_management_user(username, tenant_id) values ('Alice', 'tenant-a')");
        jdbc.update("insert into specus_management_user(username, tenant_id) values ('alice', 'tenant-b')");

        migrateTwice(dataSource, () -> new ManagementUserSchemaMigrator(jdbc).migrate());

        assertThat(jdbc.queryForMap(
                "select login_name, login_name_normalized from specus_management_user where username = 'Alice'"))
                .containsEntry("login_name", "Alice")
                .containsEntry("login_name_normalized", "alice");
        assertThat(jdbc.queryForObject("""
                select indexdef from pg_indexes
                 where schemaname = current_schema() and indexname = 'uq_management_user_tenant_login_name'
                """, String.class))
                .contains("UNIQUE", "(tenant_id, login_name_normalized)");
    }

    @Test
    void managementUserMigrationRejectsAnIndexOfThatNameOnOtherColumns() {
        DataSource dataSource = newDatabase();
        JdbcTemplate jdbc = new JdbcTemplate(dataSource);
        jdbc.execute("create table specus_management_user (username varchar(80) primary key,"
                + " tenant_id varchar(80) not null, login_name varchar(80), login_name_normalized varchar(80))");
        jdbc.execute("create unique index uq_management_user_tenant_login_name on specus_management_user (username)");

        assertThatThrownBy(() -> inTransaction(dataSource, () -> new ManagementUserSchemaMigrator(jdbc).migrate()))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("must be unique on (tenant_id, login_name_normalized)");
    }

    @Test
    void peerServiceMigrationAddsColumnsToALegacySessionTable() {
        DataSource dataSource = newDatabase();
        JdbcTemplate jdbc = new JdbcTemplate(dataSource);
        jdbc.execute("create table specus_client_session ("
                + "id bigint primary key, tenant_id varchar(80) not null, status varchar(40) not null)");
        jdbc.update("insert into specus_client_session(id, tenant_id, status) values (1, 'default', 'DISCONNECTED')");

        migrateTwice(dataSource, () -> new PeerServiceDiscoverySchemaMigrator(
                jdbc, "org.hibernate.dialect.PostgreSQLDialect").migrate());

        assertThat(jdbc.queryForMap("""
                select peer_service_discovery_version, client_egress_version, client_egress_domain_targets
                  from specus_client_session where id = 1
                """))
                .containsEntry("peer_service_discovery_version", 0)
                .containsEntry("client_egress_version", 0)
                .containsEntry("client_egress_domain_targets", false);
        assertThat(jdbc.queryForList(
                "select indexname from pg_indexes where tablename = 'peer_mesh_shared_service'", String.class))
                .contains("uk_peer_shared_service_id", "idx_peer_shared_service_tenant_client");
    }

    @Test
    void sortableTimestampMigrationSkipsMissingTablesWithoutAbortingTheTransaction() {
        DataSource dataSource = newDatabase();
        JdbcTemplate jdbc = new JdbcTemplate(dataSource);

        inTransaction(dataSource, () -> {
            new SortableTimestampMigrator(jdbc).migrate();
            assertThat(jdbc.queryForObject("select 1", Integer.class)).isEqualTo(1);
        });
    }

    /** Legacy values under a numeric and a text key, more than one batch of them, rewritten in place. */
    @Test
    void sortableTimestampMigrationRewritesLegacyRowsOnPostgres() {
        DataSource dataSource = newDatabase();
        JdbcTemplate jdbc = new JdbcTemplate(dataSource);
        jdbc.execute("create table specus_connection_record (id bigint primary key, connected_at varchar(40) not null)");
        jdbc.execute("""
                create table specus_websocket_ticket (
                    token_hash varchar(64) primary key, expires_at varchar(40) not null)
                """);
        // Whole seconds and 3, 6 or 9 fraction digits, as Instant.toString() writes them.
        long[] fractionNanos = {0L, 7_000_000L, 7_000L, 7L};
        List<Object[]> records = new ArrayList<>();
        List<Object[]> tickets = new ArrayList<>();
        for (int i = 1; i <= SortableTimestampMigrator.BATCH_SIZE + 3; i++) {
            String legacy = Instant.parse("2026-09-15T12:00:00Z")
                    .plusSeconds(i).plusNanos(fractionNanos[i % 4]).toString();
            records.add(new Object[]{(long) i, legacy});
            tickets.add(new Object[]{"t%04d".formatted(i), legacy});
        }
        jdbc.batchUpdate("insert into specus_connection_record(id, connected_at) values (?, ?)", records);
        jdbc.batchUpdate("insert into specus_websocket_ticket(token_hash, expires_at) values (?, ?)", tickets);

        migrateTwice(dataSource, () -> new SortableTimestampMigrator(jdbc).migrate());

        assertThat(jdbc.queryForObject("select count(*) from specus_connection_record where length(connected_at) <> ?",
                Integer.class, SortableInstant.LENGTH)).isZero();
        assertThat(jdbc.queryForObject("select count(*) from specus_websocket_ticket where length(expires_at) <> ?",
                Integer.class, SortableInstant.LENGTH)).isZero();
        assertThat(jdbc.queryForObject("select connected_at from specus_connection_record where id = 2", String.class))
                .isEqualTo("2026-09-15T12:00:02.0000070Z");
        // In the second batch.
        assertThat(jdbc.queryForObject(
                "select expires_at from specus_websocket_ticket where token_hash = 't0501'", String.class))
                .isEqualTo("2026-09-15T12:08:21.0070000Z");
    }

    private String createDatabase() {
        String name = "specus_" + DATABASES.incrementAndGet();
        new JdbcTemplate(postgres.getPostgresDatabase()).execute("create database " + name);
        return name;
    }

    private DataSource newDatabase() {
        return postgres.getDatabase("postgres", createDatabase());
    }

    private ConfigurableApplicationContext start(String database) {
        // Command-line arguments, because builder properties are defaults that application.yml
        // overrides: the datasource would silently fall back to ./specus.db.
        return new SpringApplicationBuilder(SpecusServerApplication.class)
                .web(WebApplicationType.NONE)
                .run(
                        "--spring.datasource.url=" + postgres.getJdbcUrl("postgres", database),
                        "--spring.datasource.driver-class-name=org.postgresql.Driver",
                        "--spring.datasource.username=postgres",
                        "--spring.datasource.password=",
                        "--spring.datasource.hikari.maximum-pool-size=4",
                        "--spring.jpa.database-platform=org.hibernate.dialect.PostgreSQLDialect",
                        "--spring.jpa.hibernate.ddl-auto=update",
                        "--specus.netty.port=0",
                        "--specus.client-packages.data-directory=" + temporaryDirectory.resolve("data"),
                        "--specus.client-packages.github-release-fallback-enabled=false");
    }

    private static List<Map<String, Object>> indexes(ConfigurableApplicationContext context) {
        return context.getBean(JdbcTemplate.class).queryForList("""
                select tablename, indexname, indexdef
                  from pg_indexes
                 where schemaname = current_schema()
                 order by tablename, indexname
                """);
    }

    private static void migrateTwice(DataSource dataSource, Runnable migration) {
        inTransaction(dataSource, migration);
        inTransaction(dataSource, migration);
    }

    private static void inTransaction(DataSource dataSource, Runnable work) {
        new TransactionTemplate(new DataSourceTransactionManager(dataSource))
                .executeWithoutResult(status -> work.run());
    }
}
