package com.theshuai.specusserver.database;

import com.theshuai.specusserver.SpecusServerApplication;
import com.theshuai.specusserver.management.model.HttpBodyDataCodec;
import com.theshuai.specusserver.management.model.HttpTrafficExchange;
import com.theshuai.specusserver.management.model.HttpTrafficExchangeView;
import com.theshuai.specusserver.management.repository.HttpTrafficExchangeRepository;
import com.theshuai.specusserver.management.service.TrafficViewService;
import com.theshuai.specusserver.management.storage.HttpTrafficExchangeStore;
import com.theshuai.specusserver.management.storage.HttpTrafficSearchField;
import com.theshuai.specusserver.management.tenant.TenantContext;
import io.zonky.test.db.postgres.embedded.EmbeddedPostgres;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.boot.WebApplicationType;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.data.domain.PageRequest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowCallbackHandler;
import org.springframework.jdbc.datasource.DataSourceTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

import javax.sql.DataSource;
import java.io.IOException;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
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
    private static final Map<String, String> BYTES_AND_TEXT = Map.of(
            "request_body_data", "bytea",
            "response_body_data", "bytea",
            "request_preview_text", "text",
            "response_preview_text", "text");
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

    /** Update never changes a column's type, so a database the old varchar(8192) headers created keeps them. */
    @Test
    void httpHeaderColumnsTheOldMappingCreatedKeepWorking() {
        String database = createDatabase();

        try (ConfigurableApplicationContext first = start(database)) {
            JdbcTemplate jdbc = first.getBean(JdbcTemplate.class);
            assertThat(httpHeaderColumnTypes(jdbc)).containsOnly("text");
            for (String column : List.of("request_headers", "response_headers")) {
                jdbc.execute("alter table specus_http_traffic_exchange alter column " + column + " type varchar(8192)");
            }
        }

        try (ConfigurableApplicationContext second = start(database)) {
            assertThat(httpHeaderColumnTypes(second.getBean(JdbcTemplate.class)))
                    .containsOnly("character varying(8192)");
            HttpTrafficExchangeRepository repository = second.getBean(HttpTrafficExchangeRepository.class);
            HttpTrafficExchange exchange = repository.save(WidestHttpTrafficExchange.create());

            assertThat(repository.findById(exchange.getId()).orElseThrow())
                    .usingRecursiveComparison()
                    .isEqualTo(exchange);
            assertThat(second.getBean(HttpTrafficExchangeStore.class)
                    .search(TenantContext.defaultTenant(), null, null, null, null,
                            HttpTrafficSearchField.RESPONSE_HEADERS, "x-response", PageRequest.of(0, 20))
                    .getContent())
                    .extracting(HttpTrafficExchangeView::id)
                    .containsExactly(exchange.getId().toString());
        }
    }

    /** The search and the detail were called without a transaction when they failed. */
    @Test
    void httpExchangeBodiesAreBytesAndTextSearchedAndReadWithoutATransaction() {
        try (ConfigurableApplicationContext context = start(createDatabase())) {
            JdbcTemplate jdbc = context.getBean(JdbcTemplate.class);
            assertThat(httpBodyColumnTypes(jdbc)).isEqualTo(BYTES_AND_TEXT);
            HttpTrafficExchange exchange = context.getBean(HttpTrafficExchangeRepository.class)
                    .save(widestExchangeWithBodyWords());

            // The search that failed: ALL takes in the previews.
            assertThat(context.getBean(HttpTrafficExchangeStore.class)
                    .search(TenantContext.defaultTenant(), null, null, null, null,
                            HttpTrafficSearchField.ALL, "x-request", PageRequest.of(0, 20))
                    .getContent())
                    .extracting(HttpTrafficExchangeView::id)
                    .containsExactly(exchange.getId().toString());
            assertBodiesSearchableAndReadable(context, exchange);
            assertThat(largeObjects(jdbc)).isEmpty();
        }
    }

    /**
     * The @Lob mapping made all four columns oid and wrote each body and preview as a large object,
     * a preview in UTF-8. The widening of the preview columns then made them text, which turned the
     * large objects' numbers into their text, and wrote the previews that way from then on.
     */
    @Test
    void httpExchangeLargeObjectsTheLobMappingWroteMoveIntoTheirRows() {
        String database = createDatabase();
        HttpTrafficExchange exchange;
        HttpTrafficExchange empty;
        HttpTrafficExchange vacuumed;
        long unrelated;

        try (ConfigurableApplicationContext first = start(database)) {
            HttpTrafficExchangeRepository repository = first.getBean(HttpTrafficExchangeRepository.class);
            exchange = repository.save(widestExchangeWithBodyWords());
            empty = WidestHttpTrafficExchange.create();
            empty.setRequestBodyData(null);
            empty.setResponseBodyData(null);
            empty.setRequestPreviewText(null);
            empty.setResponsePreviewText(null);
            empty = repository.save(empty);
            vacuumed = repository.save(WidestHttpTrafficExchange.create());

            JdbcTemplate jdbc = first.getBean(JdbcTemplate.class);
            // The request preview column stays oid, as before the widening ran.
            jdbc.execute("""
                    alter table specus_http_traffic_exchange
                      alter column request_body_data type oid using lo_from_bytea(0, request_body_data),
                      alter column response_body_data type oid using lo_from_bytea(0, response_body_data),
                      alter column request_preview_text type oid
                            using lo_from_bytea(0, convert_to(request_preview_text, 'UTF8'))
                    """);
            jdbc.update("""
                    update specus_http_traffic_exchange
                       set response_preview_text = lo_from_bytea(0, convert_to(response_preview_text, 'UTF8'))::text
                    """);
            // vacuumlo removes the large objects no oid column holds, a text column's among them.
            jdbc.queryForMap("""
                    select lo_unlink(request_body_data), lo_unlink(response_preview_text::oid)
                      from specus_http_traffic_exchange where id = ?
                    """, vacuumed.getId());
            unrelated = jdbc.queryForObject("select lo_from_bytea(0, '\\x01'::bytea)", Long.class);
        }

        HttpTrafficExchange digits;
        try (ConfigurableApplicationContext second = start(database)) {
            JdbcTemplate jdbc = second.getBean(JdbcTemplate.class);
            assertThat(httpBodyColumnTypes(jdbc)).isEqualTo(BYTES_AND_TEXT);
            assertThat(largeObjects(jdbc)).containsExactly(unrelated);
            HttpTrafficExchangeRepository repository = second.getBean(HttpTrafficExchangeRepository.class);
            assertThat(read(repository, empty)).usingRecursiveComparison().isEqualTo(empty);
            // A body number with nothing behind it is gone; a preview one may be text, so it stays.
            HttpTrafficExchange vacuumedRead = read(repository, vacuumed);
            assertThat(vacuumedRead.getRequestBodyData()).isNull();
            assertThat(vacuumedRead.getResponsePreviewText()).matches("[1-9][0-9]*");
            assertThat(vacuumedRead).usingRecursiveComparison()
                    .ignoringFields("requestBodyData", "responsePreviewText")
                    .isEqualTo(vacuumed);
            assertBodiesSearchableAndReadable(second, exchange);

            digits = WidestHttpTrafficExchange.create();
            digits.setRequestPreviewText(Long.toString(unrelated));
            digits = repository.save(digits);
        }

        // No oid column is left to mark the table, so the next start converts nothing.
        try (ConfigurableApplicationContext third = start(database)) {
            assertThat(read(third.getBean(HttpTrafficExchangeRepository.class), digits))
                    .usingRecursiveComparison()
                    .isEqualTo(digits);
            assertThat(largeObjects(third.getBean(JdbcTemplate.class))).containsExactly(unrelated);
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
    void transferTimestampMigrationSkipsMissingTablesWithoutAbortingTheTransaction() {
        DataSource dataSource = newDatabase();
        JdbcTemplate jdbc = new JdbcTemplate(dataSource);

        inTransaction(dataSource, () -> {
            new TransferTimestampMigrator(jdbc).migrate();
            assertThat(jdbc.queryForObject("select 1", Integer.class)).isEqualTo(1);
        });
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

    private static List<String> httpHeaderColumnTypes(JdbcTemplate jdbc) {
        return jdbc.queryForList("""
                select data_type || coalesce('(' || character_maximum_length || ')', '')
                  from information_schema.columns
                 where table_schema = current_schema() and table_name = 'specus_http_traffic_exchange'
                   and column_name in ('request_headers', 'response_headers')
                """, String.class);
    }

    private static HttpTrafficExchange widestExchangeWithBodyWords() {
        HttpTrafficExchange exchange = WidestHttpTrafficExchange.create();
        exchange.setRequestPreviewText(exchange.getRequestPreviewText() + " Request-Body");
        exchange.setResponsePreviewText(exchange.getResponsePreviewText() + " Response-Body");
        return exchange;
    }

    /** The store's search and detail without a transaction, and the admin console's search in its own. */
    private static void assertBodiesSearchableAndReadable(ConfigurableApplicationContext context,
                                                          HttpTrafficExchange exchange) {
        HttpTrafficExchangeStore store = context.getBean(HttpTrafficExchangeStore.class);
        String id = exchange.getId().toString();
        // The keyword is lower-cased, and the previews now are too, as every other field is.
        for (Map.Entry<HttpTrafficSearchField, String> search : List.of(
                Map.entry(HttpTrafficSearchField.ALL, "request-body"),
                Map.entry(HttpTrafficSearchField.REQUEST_BODY, "request-body"),
                Map.entry(HttpTrafficSearchField.RESPONSE_BODY, "RESPONSE-BODY"))) {
            assertThat(store.search(TenantContext.defaultTenant(), null, null, null, null,
                            search.getKey(), search.getValue(), PageRequest.of(0, 20))
                    .getContent())
                    .as("search %s", search)
                    .extracting(HttpTrafficExchangeView::id)
                    .containsExactly(id);
        }
        // The admin console's, in a read-only transaction.
        assertThat(context.getBean(TrafficViewService.class)
                .listHttpExchanges(TenantContext.defaultTenant(), null, null, null,
                        HttpTrafficSearchField.ALL, "response-body", PageRequest.of(0, 20))
                .getContent())
                .extracting(HttpTrafficExchangeView::id)
                .containsExactly(id);
        assertThat(store.findById(TenantContext.defaultTenant(), exchange.getId(), null))
                .hasValueSatisfying(view -> {
                    assertThat(view.requestPreviewText()).isEqualTo(HttpBodyDataCodec.toDisplayText(
                            exchange.getRequestBodyData(), exchange.getRequestContentType(),
                            exchange.getRequestHeaders(), exchange.getRequestPreviewText()));
                    assertThat(view.responsePreviewText()).isEqualTo(HttpBodyDataCodec.toDisplayText(
                            exchange.getResponseBodyData(), exchange.getResponseContentType(),
                            exchange.getResponseHeaders(), exchange.getResponsePreviewText()));
                });
        assertThat(read(context.getBean(HttpTrafficExchangeRepository.class), exchange))
                .usingRecursiveComparison()
                .isEqualTo(exchange);
    }

    /** Through a query method, which has no transaction of its own as findById does. */
    private static HttpTrafficExchange read(HttpTrafficExchangeRepository repository, HttpTrafficExchange exchange) {
        return repository.findByTenantIdAndId(exchange.getTenantId(), exchange.getId()).orElseThrow();
    }

    private static Map<String, String> httpBodyColumnTypes(JdbcTemplate jdbc) {
        Map<String, String> types = new TreeMap<>();
        jdbc.query("""
                select column_name, data_type
                  from information_schema.columns
                 where table_schema = current_schema() and table_name = 'specus_http_traffic_exchange'
                   and column_name in ('request_body_data', 'response_body_data',
                                       'request_preview_text', 'response_preview_text')
                """, (RowCallbackHandler) row -> types.put(row.getString(1), row.getString(2)));
        return types;
    }

    private static List<Long> largeObjects(JdbcTemplate jdbc) {
        return jdbc.queryForList("select oid::bigint from pg_largeobject_metadata order by oid", Long.class);
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
