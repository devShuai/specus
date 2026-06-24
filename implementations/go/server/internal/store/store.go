package store

import (
	"database/sql"
	"embed"
	"fmt"
	"strconv"
	"strings"
	"time"

	_ "github.com/go-sql-driver/mysql"
	_ "github.com/jackc/pgx/v5/stdlib"
	_ "modernc.org/sqlite"
)

//go:embed schema/*.sql
var schemaFS embed.FS

// isoLayout matches the C# server's "yyyy-MM-ddTHH:mm:ss.fffffffZ" so string ordering equals
// time ordering across SQLite TEXT and Postgres/MySQL VARCHAR columns.
const isoLayout = "2006-01-02T15:04:05.0000000Z"

// Dialect identifies the active SQL dialect.
type Dialect string

const (
	DialectSQLite   Dialect = "sqlite"
	DialectPostgres Dialect = "postgresql"
	DialectMySQL    Dialect = "mysql"
)

// DB is the persistence layer over a multi-dialect database/sql connection.
type DB struct {
	sql     *sql.DB
	dialect Dialect
}

// Open connects using the given provider (sqlite|postgres|mysql) and connection string,
// then applies the embedded schema for that dialect.
func Open(provider, connectionString string) (*DB, error) {
	driver, dialect, err := resolveDriver(provider)
	if err != nil {
		return nil, err
	}
	handle, err := sql.Open(driver, connectionString)
	if err != nil {
		return nil, fmt.Errorf("open %s database: %w", dialect, err)
	}
	if dialect == DialectSQLite {
		// SQLite is single-writer; one connection avoids "database is locked".
		handle.SetMaxOpenConns(1)
	}
	if err := handle.Ping(); err != nil {
		handle.Close()
		return nil, fmt.Errorf("ping %s database: %w", dialect, err)
	}
	db := &DB{sql: handle, dialect: dialect}
	if err := db.migrate(); err != nil {
		handle.Close()
		return nil, err
	}
	return db, nil
}

// Dialect returns the active dialect (also surfaced as the API "dialect" field).
func (db *DB) Dialect() Dialect { return db.dialect }

// Close releases the underlying connection pool.
func (db *DB) Close() error { return db.sql.Close() }

func resolveDriver(provider string) (driver string, dialect Dialect, err error) {
	switch strings.ToLower(strings.TrimSpace(provider)) {
	case "", "sqlite", "sqlite3":
		return "sqlite", DialectSQLite, nil
	case "postgres", "postgresql", "npgsql", "pgx":
		return "pgx", DialectPostgres, nil
	case "mysql", "mariadb":
		return "mysql", DialectMySQL, nil
	default:
		return "", "", fmt.Errorf("unknown database provider %q (use sqlite, postgres, or mysql)", provider)
	}
}

func (db *DB) migrate() error {
	name := map[Dialect]string{
		DialectSQLite:   "schema/sqlite.sql",
		DialectPostgres: "schema/postgres.sql",
		DialectMySQL:    "schema/mysql.sql",
	}[db.dialect]
	data, err := schemaFS.ReadFile(name)
	if err != nil {
		return fmt.Errorf("read schema %s: %w", name, err)
	}
	for _, stmt := range splitStatements(string(data)) {
		if _, err := db.sql.Exec(stmt); err != nil {
			return fmt.Errorf("apply schema statement: %w\n%s", err, stmt)
		}
	}
	return nil
}

// splitStatements splits a schema file into individual statements on ';' boundaries,
// dropping comments and blank statements (safe for drivers that exec one statement at a time).
func splitStatements(script string) []string {
	var statements []string
	for _, raw := range strings.Split(script, ";") {
		var lines []string
		for _, line := range strings.Split(raw, "\n") {
			trimmed := strings.TrimSpace(line)
			if trimmed == "" || strings.HasPrefix(trimmed, "--") {
				continue
			}
			lines = append(lines, line)
		}
		stmt := strings.TrimSpace(strings.Join(lines, "\n"))
		if stmt != "" {
			statements = append(statements, stmt)
		}
	}
	return statements
}

// rebind converts '?' placeholders to the dialect's positional form ($1.. for Postgres).
func (db *DB) rebind(query string) string {
	if db.dialect != DialectPostgres {
		return query
	}
	var builder strings.Builder
	n := 0
	for i := 0; i < len(query); i++ {
		if query[i] == '?' {
			n++
			builder.WriteByte('$')
			builder.WriteString(strconv.Itoa(n))
			continue
		}
		builder.WriteByte(query[i])
	}
	return builder.String()
}

// formatTime renders a timestamp in the canonical ISO-8601 UTC string.
func formatTime(value time.Time) string {
	return value.UTC().Format(isoLayout)
}

// parseTime parses a stored ISO-8601 timestamp, tolerating fractional-width variants.
func parseTime(value string) time.Time {
	for _, layout := range []string{isoLayout, time.RFC3339Nano, time.RFC3339} {
		if parsed, err := time.Parse(layout, value); err == nil {
			return parsed.UTC()
		}
	}
	return time.Time{}
}
