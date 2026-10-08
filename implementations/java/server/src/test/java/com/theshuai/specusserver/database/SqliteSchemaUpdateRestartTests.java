package com.theshuai.specusserver.database;

import com.theshuai.specusserver.SpecusServerApplication;
import com.theshuai.specusserver.management.model.HttpTrafficExchange;
import com.theshuai.specusserver.management.model.HttpTrafficExchangeView;
import com.theshuai.specusserver.management.repository.HttpTrafficExchangeRepository;
import com.theshuai.specusserver.management.storage.HttpTrafficExchangeStore;
import com.theshuai.specusserver.management.storage.HttpTrafficSearchField;
import com.theshuai.specusserver.management.tenant.TenantContext;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.boot.WebApplicationType;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.data.domain.PageRequest;
import org.springframework.jdbc.core.JdbcTemplate;

import java.nio.file.Path;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Every other context test runs create-drop on a fresh database, so none of them exercises the
 * production path: ddl-auto=update against a SQLite file that already holds the full schema.
 */
class SqliteSchemaUpdateRestartTests {
    // SQLITE_MAX_COMPOUND_SELECT; sqlite-jdbc's getColumns spends one compound term per column.
    private static final int COMPOUND_SELECT_LIMIT = 500;

    @TempDir
    Path temporaryDirectory;

    @Test
    void serverRestartsOnAnExistingSqliteDatabase() {
        Path database = temporaryDirectory.resolve("specus.db");
        List<Map<String, Object>> schema;

        try (ConfigurableApplicationContext first = start(database)) {
            assertThat(database).isNotEmptyFile();
            assertThat(columnCount(first))
                    .as("the schema must outgrow one compound SELECT for this test to cover the restart")
                    .isGreaterThan(COMPOUND_SELECT_LIMIT);
            schema = schema(first);
        }

        // The second start reads the existing schema's metadata before deciding what to migrate,
        // and must leave every table, index and constraint as the first start created them.
        try (ConfigurableApplicationContext second = start(database)) {
            assertThat(schema(second)).isEqualTo(schema);
        }
    }

    /** The @Lob mapping made these blob and clob; written and read as bytes and text, they still work. */
    @Test
    void httpExchangeColumnsTheLobMappingCreatedKeepWorking() {
        Path database = temporaryDirectory.resolve("specus.db");
        Map<String, String> lobTypes = Map.of(
                "request_body_data", "blob",
                "response_body_data", "blob",
                "request_preview_text", "clob",
                "response_preview_text", "clob");

        try (ConfigurableApplicationContext first = start(database)) {
            JdbcTemplate jdbc = first.getBean(JdbcTemplate.class);
            lobTypes.forEach((column, type) -> {
                jdbc.execute("alter table specus_http_traffic_exchange drop column " + column);
                jdbc.execute("alter table specus_http_traffic_exchange add column " + column + " " + type);
            });
        }

        try (ConfigurableApplicationContext second = start(database)) {
            assertThat(second.getBean(JdbcTemplate.class).queryForList("""
                    select lower(type) from pragma_table_info('specus_http_traffic_exchange')
                     where name in ('request_body_data', 'response_body_data',
                                    'request_preview_text', 'response_preview_text')
                    """, String.class))
                    .containsExactlyInAnyOrderElementsOf(lobTypes.values());
            HttpTrafficExchangeRepository repository = second.getBean(HttpTrafficExchangeRepository.class);
            HttpTrafficExchange exchange = WidestHttpTrafficExchange.create();
            exchange.setRequestPreviewText(exchange.getRequestPreviewText() + " Request-Body");
            exchange = repository.save(exchange);

            assertThat(repository.findByTenantIdAndId(exchange.getTenantId(), exchange.getId()).orElseThrow())
                    .usingRecursiveComparison()
                    .isEqualTo(exchange);
            assertThat(second.getBean(HttpTrafficExchangeStore.class)
                    .search(TenantContext.defaultTenant(), null, null, null, null,
                            HttpTrafficSearchField.ALL, "request-body", PageRequest.of(0, 20))
                    .getContent())
                    .extracting(HttpTrafficExchangeView::id)
                    .containsExactly(exchange.getId().toString());
        }
    }

    private ConfigurableApplicationContext start(Path database) {
        // Command-line arguments, because builder properties are defaults that application.yml
        // overrides: the datasource would silently fall back to ./specus.db.
        return new SpringApplicationBuilder(SpecusServerApplication.class)
                .web(WebApplicationType.NONE)
                .run(
                        "--spring.datasource.url=jdbc:sqlite:" + database,
                        "--spring.jpa.hibernate.ddl-auto=update",
                        // A migration DDL that fails would otherwise only be logged.
                        "--spring.jpa.properties.hibernate.hbm2ddl.halt_on_error=true",
                        "--specus.netty.port=0",
                        "--specus.client-packages.data-directory=" + temporaryDirectory.resolve("data"),
                        "--specus.client-packages.github-release-fallback-enabled=false");
    }

    private static int columnCount(ConfigurableApplicationContext context) {
        Integer count = context.getBean(JdbcTemplate.class).queryForObject("""
                select count(*)
                  from sqlite_master m join pragma_table_info(m.name)
                 where m.type = 'table' and m.name not like 'sqlite\\_%' escape '\\'
                """, Integer.class);
        return count == null ? 0 : count;
    }

    private static List<Map<String, Object>> schema(ConfigurableApplicationContext context) {
        return context.getBean(JdbcTemplate.class).queryForList(
                "select type, name, tbl_name, sql from sqlite_master order by type, name");
    }
}
