package com.theshuai.specusserver.database;

import org.hibernate.cfg.SchemaToolingSettings;
import org.hibernate.tool.schema.JdbcMetadataAccessStrategy;
import org.junit.jupiter.api.Test;
import org.springframework.mock.env.MockEnvironment;

import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class SqliteSchemaMetadataConfigurationTests {
    private static final String STRATEGY = SchemaToolingSettings.HBM2DDL_JDBC_METADATA_EXTRACTOR_STRATEGY;

    @Test
    void sqliteReadsMetadataTableByTable() {
        Map<String, Object> properties = customize("jdbc:sqlite:./specus.db", new HashMap<>());

        assertThat(JdbcMetadataAccessStrategy.interpretSetting(properties))
                .isEqualTo(JdbcMetadataAccessStrategy.INDIVIDUALLY);
    }

    @Test
    void mysqlAndPostgresKeepHibernatesNamespaceScopedDefault() {
        for (String url : new String[] {
                "jdbc:mysql://127.0.0.1:3306/specus", "jdbc:postgresql://127.0.0.1:5432/specus", ""}) {
            Map<String, Object> properties = customize(url, new HashMap<>());

            assertThat(properties).as(url).doesNotContainKey(STRATEGY);
            assertThat(JdbcMetadataAccessStrategy.interpretSetting(properties))
                    .isEqualTo(JdbcMetadataAccessStrategy.GROUPED);
        }
    }

    @Test
    void explicitStrategyWins() {
        Map<String, Object> properties = customize("JDBC:SQLITE:specus.db", new HashMap<>(Map.of(STRATEGY, "grouped")));

        assertThat(properties).containsEntry(STRATEGY, "grouped");
    }

    private static Map<String, Object> customize(String url, Map<String, Object> properties) {
        MockEnvironment environment = new MockEnvironment();
        if (!url.isEmpty()) {
            environment.setProperty("spring.datasource.url", url);
        }
        new SqliteSchemaMetadataConfiguration().sqliteSchemaMetadataCustomizer(environment).customize(properties);
        return properties;
    }
}
