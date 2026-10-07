package com.theshuai.specusserver.database;

import ch.vorburger.exec.ManagedProcessException;
import ch.vorburger.mariadb4j.DB;
import ch.vorburger.mariadb4j.DBConfigurationBuilder;
import com.theshuai.specusserver.SpecusServerApplication;
import com.theshuai.specusserver.management.model.HttpTrafficExchange;
import com.theshuai.specusserver.management.model.HttpTrafficExchangeView;
import com.theshuai.specusserver.management.repository.HttpTrafficExchangeRepository;
import com.theshuai.specusserver.management.storage.HttpTrafficExchangeStore;
import com.theshuai.specusserver.management.storage.HttpTrafficSearchField;
import com.theshuai.specusserver.management.tenant.TenantContext;
import jakarta.persistence.EntityManagerFactory;
import org.hibernate.engine.spi.SessionFactoryImplementor;
import org.hibernate.persister.entity.AbstractEntityPersister;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIf;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.boot.WebApplicationType;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.data.domain.PageRequest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowCallbackHandler;
import org.springframework.jdbc.datasource.DriverManagerDataSource;

import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Boots the server with Hibernate's MySQLDialect on an embedded MariaDB. MySQL and MariaDB cap the
 * non-LOB columns of a row at 65,535 bytes, counting each varchar(n) at its utf8mb4 worst case of
 * 4n bytes, and the dialect picks a LOB column's type by its declared length, down to the 255 bytes
 * of tinyblob; SQLite and PostgreSQL have neither limit. ddl-auto=update only logs a create table
 * that fails, so production starts with the table missing; this test halts on any failed DDL instead.
 *
 * <p>Runs where a MariaDB4j server binary for this OS is on the test classpath (the
 * {@code windows-mariadb4j} profile); skipped elsewhere. {@link MySqlColumnTypeTests} checks the
 * same limits on every platform without a database.
 */
@EnabledIf("mariaDbBinaryAvailable")
class MariaDbSchemaTests {
    private static final String DATABASE = "specus";
    /** Each LOB column as Hibernate's MySQLDialect made it before its mapping declared a length. */
    private static final Map<String, String> NARROW_LOB_COLUMNS = Map.of(
            "public_transfer_diagram_version.snapshot_data", "tinyblob",
            "specus_http_media_capture.response_headers", "tinytext",
            "specus_http_traffic_exchange.request_body_data", "tinyblob",
            "specus_http_traffic_exchange.request_preview_text", "tinytext",
            // As a length of up to 65,535 would have made them.
            "specus_http_traffic_exchange.response_body_data", "blob",
            "specus_http_traffic_exchange.response_preview_text", "text",
            "specus_tcp_traffic_frame.payload_data", "tinyblob",
            "specus_websocket_ticket.attributes_json", "tinytext",
            "user_diagram_document.snapshot_data", "varbinary(32600)");

    @TempDir
    static Path temporaryDirectory;

    private static DB mariaDb;
    private static ConfigurableApplicationContext context;

    @BeforeAll
    static void start() throws ManagedProcessException {
        mariaDb = DB.newEmbeddedDB(DBConfigurationBuilder.newBuilder().setPort(0).build());
        mariaDb.start();
        context = boot(createDatabase(DATABASE));
    }

    @AfterAll
    static void stop() throws ManagedProcessException {
        if (context != null) {
            context.close();
        }
        if (mariaDb != null) {
            mariaDb.stop();
        }
    }

    @Test
    void everyEntityTableIsCreated() {
        assertThat(databaseTables()).containsAll(entityTables());
    }

    @Test
    void noLargeObjectColumnStopsAt64KiB() {
        // The binary and text columns of this schema hold bodies, payloads and snapshots.
        assertThat(jdbc().queryForList("""
                select concat(table_name, '.', column_name, ' ', data_type)
                  from information_schema.columns
                 where table_schema = ? and data_type in ('tinytext', 'text', 'tinyblob', 'blob', 'varbinary')
                """, String.class, DATABASE)).isEmpty();
    }

    @Test
    void theWidestHttpExchangeRoundTripsAndItsHeadersAndBodiesAreSearchable() {
        HttpTrafficExchangeRepository repository = context.getBean(HttpTrafficExchangeRepository.class);
        HttpTrafficExchange exchange = WidestHttpTrafficExchange.create();
        exchange.setResponsePreviewText(exchange.getResponsePreviewText() + " Response-Body");
        exchange = repository.save(exchange);

        assertThat(repository.findById(exchange.getId()).orElseThrow())
                .usingRecursiveComparison()
                .isEqualTo(exchange);
        HttpTrafficExchangeStore store = context.getBean(HttpTrafficExchangeStore.class);
        assertThat(store.search(TenantContext.defaultTenant(), null, null, null, null,
                        HttpTrafficSearchField.REQUEST_HEADERS, "x-request", PageRequest.of(0, 20))
                .getContent())
                .extracting(HttpTrafficExchangeView::id)
                .containsExactly(exchange.getId().toString());
        // A preview is searched lower-cased, as every other field is.
        assertThat(store.search(TenantContext.defaultTenant(), null, null, null, null,
                        HttpTrafficSearchField.RESPONSE_BODY, "response-body", PageRequest.of(0, 20))
                .getContent())
                .extracting(HttpTrafficExchangeView::id)
                .containsExactly(exchange.getId().toString());
    }

    /**
     * ddl-auto=update widens a narrow tinyblob or tinytext column one statement at a time, each of
     * which rebuilds the table, and a varbinary one never. The migration widens them before that
     * update runs, one statement a table, and alters nothing on a later start.
     */
    @Test
    void lobColumnsAnOlderMappingMadeNarrowAreWidenedInOneStatementATable() throws ManagedProcessException {
        Map<String, String> mapped = lobColumns(jdbc(), DATABASE);
        assertThat(mapped).containsOnlyKeys(NARROW_LOB_COLUMNS.keySet());
        String database = createDatabase("specus_narrow_lobs");
        try (ConfigurableApplicationContext first = boot(database)) {
            JdbcTemplate jdbc = first.getBean(JdbcTemplate.class);
            NARROW_LOB_COLUMNS.forEach((column, narrowType) -> {
                String[] tableAndName = column.split("\\.");
                jdbc.execute("alter table " + tableAndName[0] + " modify column " + tableAndName[1] + " " + narrowType
                        + (mapped.get(column).endsWith(" not null") ? " not null" : ""));
            });
        }
        JdbcTemplate server = new JdbcTemplate(new DriverManagerDataSource(url(database), "root", ""));
        assertThat(lobColumns(server, database).values()).noneMatch(type -> type.startsWith("long"));

        server.execute("set global log_output = 'TABLE'");
        server.execute("set global general_log = 'ON'");
        try {
            server.execute("truncate table mysql.general_log");
            try (ConfigurableApplicationContext second = boot(database)) {
                assertThat(lobColumns(server, database)).isEqualTo(mapped);
            }
            assertThat(lobTablesAltered(server)).containsExactlyInAnyOrderElementsOf(lobTables());

            server.execute("truncate table mysql.general_log");
            try (ConfigurableApplicationContext third = boot(database)) {
                assertThat(lobTablesAltered(server)).isEmpty();
            }
        } finally {
            server.execute("set global general_log = 'OFF'");
        }
    }

    /** The type of each column {@link #NARROW_LOB_COLUMNS} names, with " not null" when it is. */
    private static Map<String, String> lobColumns(JdbcTemplate jdbc, String database) {
        Map<String, String> columns = new TreeMap<>();
        jdbc.query("""
                select concat(table_name, '.', column_name), column_type, is_nullable
                  from information_schema.columns
                 where table_schema = ?
                """, (RowCallbackHandler) row -> {
            if (NARROW_LOB_COLUMNS.containsKey(row.getString(1))) {
                columns.put(row.getString(1), row.getString(2) + ("NO".equals(row.getString(3)) ? " not null" : ""));
            }
        }, database);
        return columns;
    }

    /**
     * The table of each ALTER the general log holds, from any connection, among {@link #lobTables()}:
     * Hibernate's update alters specus_management_user's enum column on every start.
     */
    private static List<String> lobTablesAltered(JdbcTemplate server) {
        Set<String> lobTables = lobTables();
        return server.queryForList("""
                select convert(argument using utf8mb4)
                  from mysql.general_log
                 where command_type = 'Query' and convert(argument using utf8mb4) like 'alter table %'
                """, String.class).stream()
                .map(statement -> statement.split("\\s+")[2])
                .filter(lobTables::contains)
                .toList();
    }

    private static Set<String> lobTables() {
        Set<String> tables = new TreeSet<>();
        NARROW_LOB_COLUMNS.keySet().forEach(column -> tables.add(column.substring(0, column.indexOf('.'))));
        return tables;
    }

    private static String createDatabase(String database) throws ManagedProcessException {
        // MySQL 8's default character set, in which a varchar costs 4 bytes a character.
        mariaDb.run("create database " + database + " character set utf8mb4 collate utf8mb4_unicode_ci");
        return database;
    }

    private static ConfigurableApplicationContext boot(String database) {
        // Command-line arguments, because builder properties are defaults that application.yml overrides.
        return new SpringApplicationBuilder(SpecusServerApplication.class)
                .web(WebApplicationType.NONE)
                .run(
                        "--spring.datasource.url=" + url(database),
                        "--spring.datasource.driver-class-name=com.mysql.cj.jdbc.Driver",
                        "--spring.datasource.username=root",
                        "--spring.jpa.database-platform=org.hibernate.dialect.MySQLDialect",
                        "--spring.jpa.hibernate.ddl-auto=update",
                        // A create table that fails would otherwise only be logged.
                        "--spring.jpa.properties.hibernate.hbm2ddl.halt_on_error=true",
                        // HTTP exchange detail goes to the database only without Elasticsearch.
                        "--specus.elasticsearch.uris=",
                        "--specus.netty.port=0",
                        "--specus.client-packages.data-directory=" + temporaryDirectory.resolve(database),
                        "--specus.client-packages.github-release-fallback-enabled=false");
    }

    private static String url(String database) {
        // MySQL's driver cannot read MariaDB's keyword list (HHH100045), so Hibernate never learns the
        // current database and would take another test database's tables for this one's.
        return "jdbc:mysql://localhost:" + mariaDb.getConfiguration().getPort() + "/" + database
                + "?nullDatabaseMeansCurrent=true";
    }

    private static Set<String> entityTables() {
        Set<String> tables = new TreeSet<>();
        context.getBean(EntityManagerFactory.class).unwrap(SessionFactoryImplementor.class)
                .getMappingMetamodel()
                .forEachEntityDescriptor(entity -> tables.add(((AbstractEntityPersister) entity).getTableName()));
        return tables;
    }

    private static Set<String> databaseTables() {
        return new TreeSet<>(jdbc().queryForList(
                "select table_name from information_schema.tables where table_schema = ?",
                String.class, DATABASE));
    }

    private static JdbcTemplate jdbc() {
        return context.getBean(JdbcTemplate.class);
    }

    static boolean mariaDbBinaryAvailable() {
        try {
            String binaries = DBConfigurationBuilder.newBuilder().build().getBinariesClassPathLocation();
            return MariaDbSchemaTests.class.getClassLoader().getResource(binaries + "/bin/") != null;
        } catch (RuntimeException unsupportedPlatform) {
            return false;
        }
    }
}
