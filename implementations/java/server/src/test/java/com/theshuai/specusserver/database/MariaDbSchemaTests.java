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

import java.nio.file.Path;
import java.util.Set;
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

    @TempDir
    static Path temporaryDirectory;

    private static DB mariaDb;
    private static ConfigurableApplicationContext context;

    @BeforeAll
    static void start() throws ManagedProcessException {
        mariaDb = DB.newEmbeddedDB(DBConfigurationBuilder.newBuilder().setPort(0).build());
        mariaDb.start();
        // MySQL 8's default character set, in which a varchar costs 4 bytes a character.
        mariaDb.run("create database " + DATABASE + " character set utf8mb4 collate utf8mb4_unicode_ci");
        // Command-line arguments, because builder properties are defaults that application.yml overrides.
        context = new SpringApplicationBuilder(SpecusServerApplication.class)
                .web(WebApplicationType.NONE)
                .run(
                        "--spring.datasource.url=jdbc:mysql://localhost:"
                                + mariaDb.getConfiguration().getPort() + "/" + DATABASE,
                        "--spring.datasource.driver-class-name=com.mysql.cj.jdbc.Driver",
                        "--spring.datasource.username=root",
                        "--spring.jpa.database-platform=org.hibernate.dialect.MySQLDialect",
                        "--spring.jpa.hibernate.ddl-auto=update",
                        // A create table that fails would otherwise only be logged.
                        "--spring.jpa.properties.hibernate.hbm2ddl.halt_on_error=true",
                        // HTTP exchange detail goes to the database only without Elasticsearch.
                        "--specus.elasticsearch.uris=",
                        "--specus.netty.port=0",
                        "--specus.client-packages.data-directory=" + temporaryDirectory.resolve("data"),
                        "--specus.client-packages.github-release-fallback-enabled=false");
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
    void theWidestHttpExchangeRoundTripsAndItsHeadersAreSearchable() {
        HttpTrafficExchangeRepository repository = context.getBean(HttpTrafficExchangeRepository.class);
        HttpTrafficExchange exchange = repository.save(WidestHttpTrafficExchange.create());

        assertThat(repository.findById(exchange.getId()).orElseThrow())
                .usingRecursiveComparison()
                .isEqualTo(exchange);
        assertThat(context.getBean(HttpTrafficExchangeStore.class)
                .search(TenantContext.defaultTenant(), null, null, null, null,
                        HttpTrafficSearchField.REQUEST_HEADERS, "x-request", PageRequest.of(0, 20))
                .getContent())
                .extracting(HttpTrafficExchangeView::id)
                .containsExactly(exchange.getId().toString());
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
