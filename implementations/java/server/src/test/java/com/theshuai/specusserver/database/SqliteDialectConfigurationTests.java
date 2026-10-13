package com.theshuai.specusserver.database;

import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class SqliteDialectConfigurationTests {
    private static final String COMMUNITY = "org.hibernate.community.dialect.SQLiteDialect";
    private static final String SPECUS = "com.theshuai.specusserver.database.SpecusSqliteDialect";

    @Test
    void theCommunityDialectAsPlatformIsReplaced() {
        Map<String, Object> properties = new HashMap<>();

        SqliteDialectConfiguration.upgradeCommunityDialect(properties, COMMUNITY);

        assertThat(properties).containsEntry("hibernate.dialect", SPECUS);
    }

    @Test
    void theCommunityDialectAsHibernatePropertyIsReplaced() {
        Map<String, Object> properties = new HashMap<>(Map.of("hibernate.dialect", " " + COMMUNITY + " "));

        SqliteDialectConfiguration.upgradeCommunityDialect(properties, "");

        assertThat(properties).containsEntry("hibernate.dialect", SPECUS);
    }

    @Test
    void anExplicitHibernatePropertyWinsOverThePlatform() {
        Map<String, Object> properties = new HashMap<>(Map.of("hibernate.dialect", "org.hibernate.dialect.MySQLDialect"));

        SqliteDialectConfiguration.upgradeCommunityDialect(properties, COMMUNITY);

        assertThat(properties).containsExactlyEntriesOf(Map.of("hibernate.dialect", "org.hibernate.dialect.MySQLDialect"));
    }

    @Test
    void otherDialectsAreLeftAlone() {
        for (String platform : new String[]{SPECUS, "org.hibernate.dialect.PostgreSQLDialect", "", "auto"}) {
            Map<String, Object> properties = new HashMap<>();

            SqliteDialectConfiguration.upgradeCommunityDialect(properties, platform);

            assertThat(properties).as(platform).isEmpty();
        }
    }
}
