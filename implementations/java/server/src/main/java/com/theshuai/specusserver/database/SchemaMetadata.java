package com.theshuai.specusserver.database;

import org.springframework.jdbc.core.ConnectionCallback;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.util.StringUtils;

import java.sql.Connection;
import java.sql.DatabaseMetaData;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;

/**
 * The tables, columns and indexes a startup migration needs, read from JDBC metadata.
 *
 * <p>A migration asks here instead of running a statement and catching its failure. PostgreSQL
 * aborts the whole transaction on the first failed statement, so a probe that fails there makes
 * every later statement of the migration fail too, and the failure's message is in the server's
 * {@code lc_messages} language, so it cannot be told apart by its text either.
 */
final class SchemaMetadata {
    private SchemaMetadata() {
    }

    /**
     * The table as unqualified SQL in the current catalog and schema sees it, or {@code null}
     * when there is none. Names are lower case.
     */
    static Table table(JdbcTemplate jdbcTemplate, String name) {
        return jdbcTemplate.execute((ConnectionCallback<Table>) connection -> {
            DatabaseMetaData metadata = connection.getMetaData();
            Location location = locate(metadata, connection.getCatalog(), currentSchema(connection), name);
            if (location == null) {
                return null;
            }
            return new Table(columns(metadata, location), indexes(metadata, location));
        });
    }

    /** Whether the table exists and has the column. */
    static boolean hasColumn(JdbcTemplate jdbcTemplate, String table, String column) {
        Boolean present = jdbcTemplate.execute((ConnectionCallback<Boolean>) connection -> {
            DatabaseMetaData metadata = connection.getMetaData();
            Location location = locate(metadata, connection.getCatalog(), currentSchema(connection), table);
            return location != null && columns(metadata, location).contains(column.toLowerCase(Locale.ROOT));
        });
        return Boolean.TRUE.equals(present);
    }

    private static Location locate(DatabaseMetaData metadata, String catalog, String currentSchema, String name)
            throws SQLException {
        Location fallback = null;
        try (ResultSet result = metadata.getTables(catalog, null, "%", new String[]{"TABLE"})) {
            while (result.next()) {
                String tableName = result.getString("TABLE_NAME");
                if (!name.equalsIgnoreCase(tableName)) {
                    continue;
                }
                Location candidate = new Location(
                        result.getString("TABLE_CAT"), result.getString("TABLE_SCHEM"), tableName);
                if (currentSchema != null && currentSchema.equalsIgnoreCase(candidate.schema())) {
                    return candidate;
                }
                fallback = candidate;
            }
        }
        return fallback;
    }

    private static Set<String> columns(DatabaseMetaData metadata, Location location) throws SQLException {
        Set<String> columns = new LinkedHashSet<>();
        try (ResultSet result = metadata.getColumns(
                location.catalog(), location.schema(), location.name(), "%")) {
            while (result.next()) {
                // The table name is a LIKE pattern, in which '_' matches any character.
                if (location.name().equalsIgnoreCase(result.getString("TABLE_NAME"))) {
                    columns.add(result.getString("COLUMN_NAME").toLowerCase(Locale.ROOT));
                }
            }
        }
        return Set.copyOf(columns);
    }

    private static Map<String, Index> indexes(DatabaseMetaData metadata, Location location) throws SQLException {
        Map<String, Boolean> unique = new LinkedHashMap<>();
        Map<String, TreeMap<Short, String>> columns = new LinkedHashMap<>();
        try (ResultSet result = metadata.getIndexInfo(
                location.catalog(), location.schema(), location.name(), false, false)) {
            while (result.next()) {
                String indexName = result.getString("INDEX_NAME");
                short ordinal = result.getShort("ORDINAL_POSITION");
                if (!StringUtils.hasText(indexName) || ordinal <= 0) {
                    continue;
                }
                String key = indexName.toLowerCase(Locale.ROOT);
                unique.put(key, !result.getBoolean("NON_UNIQUE"));
                String column = result.getString("COLUMN_NAME");
                // An expression has no column name; such an index never equals a list of columns.
                columns.computeIfAbsent(key, ignored -> new TreeMap<>())
                        .put(ordinal, column == null ? "" : column.toLowerCase(Locale.ROOT));
            }
        }
        Map<String, Index> indexes = new LinkedHashMap<>();
        unique.forEach((key, isUnique) ->
                indexes.put(key, new Index(isUnique, List.copyOf(columns.get(key).values()))));
        return Map.copyOf(indexes);
    }

    private static String currentSchema(Connection connection) {
        try {
            return connection.getSchema();
        } catch (SQLException | AbstractMethodError exception) {
            return null;
        }
    }

    private record Location(String catalog, String schema, String name) {
    }

    /** One table's columns and its indexes by name. */
    record Table(Set<String> columns, Map<String, Index> indexes) {
        boolean hasColumn(String column) {
            return columns.contains(column.toLowerCase(Locale.ROOT));
        }

        /** The index of that name, or {@code null}. */
        Index index(String name) {
            return indexes.get(name.toLowerCase(Locale.ROOT));
        }
    }

    /** Whether an index is unique, and its columns in key order. */
    record Index(boolean unique, List<String> columns) {
    }
}
