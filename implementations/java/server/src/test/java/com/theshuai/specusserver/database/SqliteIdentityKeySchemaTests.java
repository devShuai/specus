package com.theshuai.specusserver.database;

import jakarta.persistence.EntityManagerFactory;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import jakarta.persistence.metamodel.EntityType;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.bean.override.mockito.MockitoBean;

import java.lang.reflect.Field;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Every IDENTITY id Hibernate creates on SQLite is declared {@code integer}, so it aliases the
 * rowid and holds the value Hibernate reads back from {@code last_insert_rowid()}. Created with
 * create-drop, the action whose column order used to put an integer column first, and checked as
 * Hibernate created it: the startup repair is replaced by a mock.
 */
@SpringBootTest(properties = {
        "spring.datasource.url=jdbc:sqlite::memory:",
        "spring.jpa.database-platform=org.hibernate.community.dialect.SQLiteDialect",
        "spring.jpa.hibernate.ddl-auto=create-drop",
        "specus.netty.port=0",
        "specus.database.seed-demo-client=false"
})
class SqliteIdentityKeySchemaTests {
    @Autowired
    private EntityManagerFactory entityManagerFactory;

    @Autowired
    private JdbcTemplate jdbcTemplate;

    @MockitoBean
    private SqliteIdentityKeyMigrator startupRepair;

    @Test
    void everyIdentityIdAliasesTheRowid() {
        List<String> tables = identityTables(entityManagerFactory);
        assertThat(tables).containsAll(SqliteIdentityKeyMigrator.TABLES).hasSizeGreaterThan(3);

        for (String table : tables) {
            List<Map<String, Object>> key = jdbcTemplate.queryForList(
                    "select name, type from pragma_table_info(?) where pk > 0", table);
            assertThat(key).as(table).hasSize(1);
            assertThat(key.getFirst().get("name")).as(table).isEqualTo("id");
            assertThat((String) key.getFirst().get("type")).as(table).isEqualToIgnoringCase("integer");
        }
    }

    @Test
    void theRepairLeavesACreatedSchemaAlone() {
        Map<String, String> created = createStatements(jdbcTemplate, identityTables(entityManagerFactory));

        new SqliteIdentityKeyMigrator(jdbcTemplate).migrate();

        assertThat(createStatements(jdbcTemplate, identityTables(entityManagerFactory))).isEqualTo(created);
    }

    /** The tables of the entities whose id is {@code GenerationType.IDENTITY}. */
    static List<String> identityTables(EntityManagerFactory entityManagerFactory) {
        return entityManagerFactory.getMetamodel().getEntities().stream()
                .map(EntityType::getJavaType)
                .filter(type -> Arrays.stream(type.getDeclaredFields())
                        .anyMatch(SqliteIdentityKeySchemaTests::isIdentity))
                .map(type -> type.getAnnotation(Table.class).name())
                .sorted()
                .toList();
    }

    static Map<String, String> createStatements(JdbcTemplate jdbcTemplate, List<String> tables) {
        return tables.stream().collect(Collectors.toMap(Function.identity(), table ->
                jdbcTemplate.queryForObject(
                        "select sql from sqlite_master where type = 'table' and name = ?", String.class, table)));
    }

    private static boolean isIdentity(Field field) {
        GeneratedValue generated = field.getAnnotation(GeneratedValue.class);
        return field.isAnnotationPresent(Id.class)
                && generated != null
                && generated.strategy() == GenerationType.IDENTITY;
    }
}
