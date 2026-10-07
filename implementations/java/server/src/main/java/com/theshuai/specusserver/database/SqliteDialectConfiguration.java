package com.theshuai.specusserver.database;

import lombok.extern.slf4j.Slf4j;
import org.hibernate.cfg.AvailableSettings;
import org.hibernate.community.dialect.SQLiteDialect;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.beans.factory.config.BeanPostProcessor;
import org.springframework.boot.hibernate.autoconfigure.HibernatePropertiesCustomizer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.core.JdbcTemplate;

import java.util.Map;

/**
 * Makes a violated constraint on SQLite a {@code DataIntegrityViolationException}, through JPA and
 * {@code JdbcTemplate} alike, as it already is on MySQL and PostgreSQL.
 */
@Configuration(proxyBeanMethods = false)
@Slf4j
public class SqliteDialectConfiguration {

    /**
     * Puts {@link SpecusSqliteDialect} in place of the community dialect it extends, whether named by
     * {@code spring.jpa.database-platform} or by {@code hibernate.dialect}. The README told SQLite
     * deployments to set {@code SPECUS_DB_DIALECT} to the community class, and those would otherwise
     * keep the untranslated violations; the subclass changes nothing else.
     */
    @Bean
    public HibernatePropertiesCustomizer sqliteDialectUpgrade(
            @Value("${spring.jpa.database-platform:}") String databasePlatform) {
        return properties -> upgradeCommunityDialect(properties, databasePlatform);
    }

    /**
     * Puts the SQLite translation in front of each {@code JdbcTemplate}'s own translator. It is not
     * declared as an {@code SQLExceptionTranslator} bean: Spring Boot also hands such a bean to the
     * JPA dialect, where it would replace Hibernate's translation of every JDBC exception on every
     * database.
     */
    @Bean
    public static BeanPostProcessor sqliteJdbcTemplateTranslation() {
        return new BeanPostProcessor() {
            @Override
            public Object postProcessAfterInitialization(Object bean, String beanName) {
                if (bean instanceof JdbcTemplate jdbcTemplate) {
                    jdbcTemplate.setExceptionTranslator(
                            new SqliteSqlExceptionTranslator(jdbcTemplate.getExceptionTranslator()));
                }
                return bean;
            }
        };
    }

    /**
     * An explicit {@code hibernate.dialect} property wins over the platform, as it does when Spring
     * merges the two; the replacement is written there so that it wins as well.
     */
    static void upgradeCommunityDialect(Map<String, Object> properties, String databasePlatform) {
        Object configured = properties.getOrDefault(AvailableSettings.DIALECT, databasePlatform);
        if (configured instanceof String name && name.trim().equals(SQLiteDialect.class.getName())) {
            properties.put(AvailableSettings.DIALECT, SpecusSqliteDialect.class.getName());
            log.info("[schema] {} is configured; using {}, which also translates SQLite constraint violations",
                    SQLiteDialect.class.getName(), SpecusSqliteDialect.class.getName());
        }
    }
}
