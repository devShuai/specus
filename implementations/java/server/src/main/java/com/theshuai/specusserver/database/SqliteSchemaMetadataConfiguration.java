package com.theshuai.specusserver.database;

import org.hibernate.cfg.SchemaToolingSettings;
import org.hibernate.tool.schema.JdbcMetadataAccessStrategy;
import org.springframework.boot.hibernate.autoconfigure.HibernatePropertiesCustomizer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;

/**
 * ddl-auto=update reads the existing schema at startup. Hibernate's default (grouped) strategy
 * calls getColumns for every table at once, which sqlite-jdbc builds as one compound SELECT with a
 * term per column; SQLite caps those at 500 terms, so a restart fails once the schema outgrows
 * that. On SQLite, read the metadata table by table instead.
 *
 * <p>Only on SQLite: when a table is missing from the current namespace, the per-table strategy
 * searches every namespace, so on MySQL/PostgreSQL a same-named table in another database or
 * schema would be taken for it and the table never created.
 */
@Configuration(proxyBeanMethods = false)
public class SqliteSchemaMetadataConfiguration {
    private static final String SQLITE_URL_PREFIX = "jdbc:sqlite:";

    @Bean
    public HibernatePropertiesCustomizer sqliteSchemaMetadataCustomizer(Environment environment) {
        String url = environment.getProperty("spring.datasource.url", "");
        return hibernateProperties -> {
            if (isSqlite(url)) {
                // An explicit spring.jpa.properties setting still wins.
                hibernateProperties.putIfAbsent(
                        SchemaToolingSettings.HBM2DDL_JDBC_METADATA_EXTRACTOR_STRATEGY,
                        JdbcMetadataAccessStrategy.INDIVIDUALLY);
            }
        };
    }

    static boolean isSqlite(String url) {
        return url.regionMatches(true, 0, SQLITE_URL_PREFIX, 0, SQLITE_URL_PREFIX.length());
    }
}
