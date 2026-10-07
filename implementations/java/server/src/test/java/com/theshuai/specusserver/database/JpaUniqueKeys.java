package com.theshuai.specusserver.database;

import com.theshuai.specusserver.SpecusServerApplication;
import jakarta.persistence.Entity;
import org.hibernate.SessionFactory;
import org.hibernate.boot.Metadata;
import org.hibernate.boot.MetadataSources;
import org.hibernate.boot.model.naming.CamelCaseToUnderscoresNamingStrategy;
import org.hibernate.boot.registry.StandardServiceRegistry;
import org.hibernate.boot.registry.StandardServiceRegistryBuilder;
import org.hibernate.cfg.AvailableSettings;
import org.hibernate.community.dialect.SQLiteDialect;
import org.hibernate.mapping.Column;
import org.hibernate.mapping.Table;
import org.hibernate.mapping.UniqueKey;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.boot.hibernate.SpringImplicitNamingStrategy;
import org.springframework.context.annotation.ClassPathScanningCandidateComponentProvider;
import org.springframework.core.type.filter.AnnotationTypeFilter;
import org.springframework.jdbc.core.JdbcTemplate;

import javax.sql.DataSource;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * The unique keys of the JPA mapping as Hibernate binds them, and the SQLite indexes that enforce
 * them. The mapping is bound with Spring Boot's naming strategies, so table and column names are
 * the ones the server uses.
 */
final class JpaUniqueKeys {
    private JpaUniqueKeys() {
    }

    /** A unique key: a table, its name and its columns in declared order. */
    record Key(String table, String name, List<String> columns) {
        @Override
        public String toString() {
            return name + " on " + table + " (" + String.join(", ", columns) + ")";
        }
    }

    /** A full (not partial) unique index as SQLite reports it, whatever created it. */
    record SqliteUniqueIndex(String table, String name, Set<String> columns) { }

    /**
     * The bound mapping and, when built with a data source, a session factory that ran
     * {@code hibernate.hbm2ddl.auto} on it, the setting Spring Boot's {@code ddl-auto} becomes.
     */
    static final class Mapping implements AutoCloseable {
        private final StandardServiceRegistry registry;
        private final SessionFactory sessionFactory;
        /** {@code @UniqueConstraint} and {@code @Index(unique = true)}. */
        final List<Key> tableLevel;
        /** {@code @Column(unique = true)}, which SQLite gets inline in the column definition. */
        final List<Key> columnLevel;

        private Mapping(StandardServiceRegistry registry, SessionFactory sessionFactory,
                        List<Key> tableLevel, List<Key> columnLevel) {
            this.registry = registry;
            this.sessionFactory = sessionFactory;
            this.tableLevel = tableLevel;
            this.columnLevel = columnLevel;
        }

        @Override
        public void close() {
            if (sessionFactory != null) {
                sessionFactory.close();
            }
            StandardServiceRegistryBuilder.destroy(registry);
        }
    }

    /** Binds the mapping without touching a database. */
    static Mapping bind() {
        return bind(null, null);
    }

    /** Binds the mapping and lets Hibernate create or update the schema in {@code dataSource}. */
    static Mapping bind(DataSource dataSource, String ddlAuto) {
        StandardServiceRegistryBuilder settings = new StandardServiceRegistryBuilder()
                .applySetting(AvailableSettings.DIALECT, SQLiteDialect.class.getName())
                .applySetting(AvailableSettings.ALLOW_METADATA_ON_BOOT, false);
        if (dataSource != null) {
            settings.applySetting(AvailableSettings.DATASOURCE, dataSource)
                    .applySetting(AvailableSettings.HBM2DDL_AUTO, ddlAuto)
                    // The default grouped extraction lists every column of an existing database in
                    // one getColumns call, which sqlite-jdbc turns into a compound SELECT of more
                    // than the 500 terms SQLite allows for this schema.
                    .applySetting(AvailableSettings.HBM2DDL_JDBC_METADATA_EXTRACTOR_STRATEGY, "individually");
        }
        StandardServiceRegistry registry = settings.build();
        try {
            MetadataSources sources = new MetadataSources(registry);
            ClassPathScanningCandidateComponentProvider scanner = new ClassPathScanningCandidateComponentProvider(false);
            scanner.addIncludeFilter(new AnnotationTypeFilter(Entity.class));
            for (BeanDefinition entity : scanner.findCandidateComponents(SpecusServerApplication.class.getPackageName())) {
                sources.addAnnotatedClassName(entity.getBeanClassName());
            }
            Metadata metadata = sources.getMetadataBuilder()
                    .applyPhysicalNamingStrategy(new CamelCaseToUnderscoresNamingStrategy())
                    .applyImplicitNamingStrategy(new SpringImplicitNamingStrategy())
                    .build();
            // Read before the schema tool runs: rendering a column's inline unique adds a unique
            // key for it to the table model.
            List<Key> tableLevel = new ArrayList<>();
            List<Key> columnLevel = new ArrayList<>();
            for (Table table : metadata.collectTableMappings()) {
                for (UniqueKey key : table.getUniqueKeys().values()) {
                    tableLevel.add(new Key(table.getName(), key.getName(),
                            key.getColumns().stream().map(Column::getName).toList()));
                }
                for (Column column : table.getColumns()) {
                    if (column.isUnique() && !table.isPrimaryKey(column)) {
                        columnLevel.add(new Key(table.getName(), column.getUniqueKeyName(), List.of(column.getName())));
                    }
                }
            }
            SessionFactory sessionFactory = dataSource == null ? null : metadata.buildSessionFactory();
            return new Mapping(registry, sessionFactory, List.copyOf(tableLevel), List.copyOf(columnLevel));
        } catch (RuntimeException exception) {
            StandardServiceRegistryBuilder.destroy(registry);
            throw exception;
        }
    }

    static List<SqliteUniqueIndex> sqliteUniqueIndexes(JdbcTemplate jdbc) {
        Map<String, SqliteUniqueIndex> indexes = new LinkedHashMap<>();
        jdbc.query("""
                select t.name, il.name, ii.name
                  from sqlite_master t
                  join pragma_index_list(t.name) il
                  join pragma_index_info(il.name) ii
                 where t.type = 'table' and il."unique" = 1 and il.partial = 0
                 order by t.name, il.name, ii.seqno
                """, row -> {
            String table = row.getString(1).toLowerCase(Locale.ROOT);
            String name = row.getString(2).toLowerCase(Locale.ROOT);
            String column = row.getString(3);
            indexes.computeIfAbsent(name, ignored -> new SqliteUniqueIndex(table, name, new HashSet<>()))
                    .columns().add(column == null ? "" : column.toLowerCase(Locale.ROOT));
        });
        return List.copyOf(indexes.values());
    }

    /** Whether a unique index on exactly the key's columns exists, under whatever name. */
    static boolean enforced(List<SqliteUniqueIndex> indexes, Key key) {
        return indexes.stream().anyMatch(index -> covers(index, key));
    }

    /** Whether the unique index on the key's columns carries the key's declared name. */
    static boolean named(List<SqliteUniqueIndex> indexes, Key key) {
        return indexes.stream().anyMatch(index -> index.name().equalsIgnoreCase(key.name()) && covers(index, key));
    }

    private static boolean covers(SqliteUniqueIndex index, Key key) {
        Set<String> columns = new HashSet<>();
        key.columns().forEach(column -> columns.add(column.toLowerCase(Locale.ROOT)));
        return index.table().equalsIgnoreCase(key.table()) && index.columns().equals(columns);
    }
}
