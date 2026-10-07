package com.theshuai.specusserver.database;

import jakarta.persistence.Entity;
import org.hibernate.boot.Metadata;
import org.hibernate.boot.MetadataSources;
import org.hibernate.boot.registry.StandardServiceRegistry;
import org.hibernate.boot.registry.StandardServiceRegistryBuilder;
import org.hibernate.dialect.MySQLDialect;
import org.hibernate.mapping.Column;
import org.hibernate.mapping.Table;
import org.hibernate.type.SqlTypes;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.context.annotation.ClassPathScanningCandidateComponentProvider;
import org.springframework.core.type.filter.AnnotationTypeFilter;

import java.sql.Types;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Renders every entity's columns with Hibernate's MySQLDialect, without a database, so the limits
 * {@link MariaDbSchemaTests} meets on a real server are checked on every platform.
 */
class MySqlColumnTypeTests {
    /** MySQL's row limit, against which a TEXT or BLOB column counts only its pointer. */
    private static final int MAX_ROW_BYTES = 65_535;
    /** utf8mb4, MySQL 8's default: a varchar(n) costs 4n bytes. */
    private static final int BYTES_PER_CHAR = 4;
    /** The widest TEXT or BLOB pointer; the schema's other unsized types are no wider. */
    private static final int LOB_OR_FIXED_BYTES = 12;
    private static final Pattern SIZED_TYPE = Pattern.compile("(var)?(char|binary)\\((\\d+)\\)");
    private static final Set<Integer> LOB_TYPE_CODES = Set.of(
            Types.BLOB, Types.CLOB, Types.NCLOB,
            Types.LONGVARBINARY, Types.LONGVARCHAR, Types.LONGNVARCHAR,
            SqlTypes.LONG32VARBINARY, SqlTypes.LONG32VARCHAR, SqlTypes.LONG32NVARCHAR,
            SqlTypes.MATERIALIZED_BLOB, SqlTypes.MATERIALIZED_CLOB, SqlTypes.MATERIALIZED_NCLOB);
    /** MySQL's TEXT and BLOB hold 64 KiB, short of a 3 MiB diagram snapshot or a captured body. */
    private static final Pattern UNBOUNDED_LOB = Pattern.compile("(medium|long)(text|blob)");

    private static StandardServiceRegistry registry;
    private static Metadata metadata;

    @BeforeAll
    static void buildMetadata() throws ClassNotFoundException {
        registry = new StandardServiceRegistryBuilder()
                .applySetting("hibernate.dialect", MySQLDialect.class.getName())
                .applySetting("hibernate.boot.allow_jdbc_metadata_access", false)
                .build();
        MetadataSources sources = new MetadataSources(registry);
        // The packages Spring Boot's entity scan covers: the application's own.
        ClassPathScanningCandidateComponentProvider scanner = new ClassPathScanningCandidateComponentProvider(false);
        scanner.addIncludeFilter(new AnnotationTypeFilter(Entity.class));
        for (BeanDefinition entity : scanner.findCandidateComponents("com.theshuai.specusserver")) {
            sources.addAnnotatedClass(Class.forName(entity.getBeanClassName()));
        }
        metadata = sources.buildMetadata();
    }

    @AfterAll
    static void destroyRegistry() {
        StandardServiceRegistryBuilder.destroy(registry);
    }

    @Test
    void everyTableFitsMySqlsRowLimitInUtf8mb4() {
        Map<String, Integer> rowBytes = new TreeMap<>();
        for (Table table : metadata.collectTableMappings()) {
            rowBytes.put(table.getName(), table.getColumns().stream()
                    .mapToInt(column -> rowBytes(column.getSqlType(metadata)))
                    .sum());
        }

        assertThat(rowBytes).isNotEmpty().allSatisfy((table, bytes) ->
                assertThat(bytes).as("worst-case bytes of a %s row", table).isLessThanOrEqualTo(MAX_ROW_BYTES));
    }

    @Test
    void lobColumnsGetMySqlsUnboundedTypes() {
        // Without a length of its own, a @Lob column keeps @Column's default of 255 and becomes
        // tinyblob or tinytext, and a LONGVARBINARY one becomes varbinary(32600).
        List<String> bounded = new ArrayList<>();
        for (Table table : metadata.collectTableMappings()) {
            for (Column column : table.getColumns()) {
                String sqlType = column.getSqlType(metadata);
                if (LOB_TYPE_CODES.contains(column.getSqlTypeCode(metadata)) && !UNBOUNDED_LOB.matcher(sqlType).matches()) {
                    bounded.add(table.getName() + "." + column.getName() + " " + sqlType);
                }
            }
        }

        assertThat(bounded).isEmpty();
    }

    private static int rowBytes(String sqlType) {
        Matcher sized = SIZED_TYPE.matcher(sqlType);
        if (!sized.matches()) {
            return LOB_OR_FIXED_BYTES;
        }
        int bytes = Integer.parseInt(sized.group(3)) * (sized.group(2).equals("char") ? BYTES_PER_CHAR : 1);
        // The length prefix of a variable-width column.
        return bytes + (sized.group(1) == null ? 0 : bytes > 255 ? 2 : 1);
    }
}
