package store

import (
	"database/sql"
	"fmt"
	"strings"
	"unicode/utf8"
)

const (
	managementUserTable        = "specus_management_user"
	managementLoginNameIndex   = "uq_management_user_tenant_login_name"
	managementLoginNameMaxRune = 80
)

var managementLoginNameIndexColumns = []string{"tenant_id", "login_name_normalized"}

// migrateManagementLoginNames is Java's ManagementUserSchemaMigrator. Accounts that predate
// tenant-scoped login names keep their username as the account key and get it as their login
// name, so every column that records a username (client owners, shares, workbench rows, product
// metrics progress) still names the same account. It runs on every start and is idempotent:
//
//  1. adds login_name and login_name_normalized when missing;
//  2. refuses to start, before writing anything, when a login name is blank or too long, or two
//     accounts of one tenant would share a normalized login name;
//  3. backfills both columns;
//  4. creates the unique index on (tenant_id, login_name_normalized) and refuses to start when an
//     index of that name exists with another definition.
func (db *DB) migrateManagementLoginNames() error {
	if err := db.ensureColumn(managementUserTable, "login_name", "VARCHAR(80)"); err != nil {
		return err
	}
	if err := db.ensureColumn(managementUserTable, "login_name_normalized", "VARCHAR(80)"); err != nil {
		return err
	}
	type loginNameRow struct {
		accountKey, loginName, normalized string
		storedName, storedNormalized      sql.NullString
	}
	rows, err := db.sql.Query(`SELECT username, tenant_id, login_name, login_name_normalized FROM ` +
		managementUserTable)
	if err != nil {
		return fmt.Errorf("read management login names: %w", err)
	}
	var all []loginNameRow
	seen := make(map[string]struct{})
	for rows.Next() {
		var (
			row    loginNameRow
			tenant sql.NullString
		)
		if err := rows.Scan(&row.accountKey, &tenant, &row.storedName, &row.storedNormalized); err != nil {
			rows.Close()
			return fmt.Errorf("read management login names: %w", err)
		}
		row.loginName = strings.TrimSpace(row.storedName.String)
		if row.loginName == "" {
			row.loginName = row.accountKey
		}
		if strings.TrimSpace(row.loginName) == "" || utf8.RuneCountInString(row.loginName) > managementLoginNameMaxRune {
			rows.Close()
			return fmt.Errorf("management user has an invalid login name")
		}
		tenantID := defaultTenant(strings.TrimSpace(tenant.String))
		row.normalized = NormalizeLoginName(row.loginName)
		key := tenantID + "\x00" + row.normalized
		if _, duplicate := seen[key]; duplicate {
			rows.Close()
			return fmt.Errorf("duplicate management login name in tenant '%s'", tenantID)
		}
		seen[key] = struct{}{}
		all = append(all, row)
	}
	if err := rows.Close(); err != nil {
		return fmt.Errorf("read management login names: %w", err)
	}
	tx, err := db.sql.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	update := db.rebind(`UPDATE ` + managementUserTable +
		` SET login_name = ?, login_name_normalized = ? WHERE username = ?`)
	for _, row := range all {
		if row.storedName.Valid && row.storedName.String == row.loginName &&
			row.storedNormalized.Valid && row.storedNormalized.String == row.normalized {
			continue
		}
		if _, err := tx.Exec(update, row.loginName, row.normalized, row.accountKey); err != nil {
			return fmt.Errorf("backfill management login names: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("backfill management login names: %w", err)
	}
	if err := db.ensureUniqueIndex(managementLoginNameIndex, managementUserTable,
		strings.Join(managementLoginNameIndexColumns, ", ")); err != nil {
		return err
	}
	return db.verifyManagementLoginNameIndex()
}

// verifyManagementLoginNameIndex reads the index back: "CREATE ... IF NOT EXISTS" keeps an index of
// that name whatever its columns, and such an index would not enforce per-tenant uniqueness.
func (db *DB) verifyManagementLoginNameIndex() error {
	unique, columns, err := db.indexDefinition(managementUserTable, managementLoginNameIndex)
	if err != nil {
		return fmt.Errorf("inspect index %s: %w", managementLoginNameIndex, err)
	}
	if !unique || strings.Join(columns, ",") != strings.Join(managementLoginNameIndexColumns, ",") {
		return fmt.Errorf("index %s must be unique on (tenant_id, login_name_normalized)", managementLoginNameIndex)
	}
	return nil
}

// indexDefinition returns whether the named index of table is unique and its key columns in order.
// A missing index reads as not unique and without columns.
func (db *DB) indexDefinition(table, index string) (bool, []string, error) {
	var (
		unique  bool
		columns []string
	)
	switch db.dialect {
	case DialectSQLite:
		list, err := db.sql.Query(fmt.Sprintf("PRAGMA index_list(%s)", table))
		if err != nil {
			return false, nil, err
		}
		found := false
		for list.Next() {
			values, err := scanPragmaRow(list)
			if err != nil {
				list.Close()
				return false, nil, err
			}
			if strings.EqualFold(fmt.Sprint(values["name"]), index) {
				found = true
				unique = fmt.Sprint(values["unique"]) == "1"
			}
		}
		if err := list.Close(); err != nil {
			return false, nil, err
		}
		if !found {
			return false, nil, nil
		}
		info, err := db.sql.Query(fmt.Sprintf("PRAGMA index_info(%s)", index))
		if err != nil {
			return false, nil, err
		}
		defer info.Close()
		for info.Next() {
			values, err := scanPragmaRow(info)
			if err != nil {
				return false, nil, err
			}
			columns = append(columns, strings.ToLower(fmt.Sprint(values["name"])))
		}
		return unique, columns, info.Err()
	case DialectPostgres:
		rows, err := db.sql.Query(`SELECT ix.indisunique, a.attname
			FROM pg_class t
			JOIN pg_namespace n ON n.oid = t.relnamespace
			JOIN pg_index ix ON ix.indrelid = t.oid
			JOIN pg_class i ON i.oid = ix.indexrelid
			JOIN LATERAL unnest(ix.indkey) WITH ORDINALITY AS k(attnum, position) ON TRUE
			LEFT JOIN pg_attribute a ON a.attrelid = t.oid AND a.attnum = k.attnum
			WHERE n.nspname = current_schema() AND t.relname = $1 AND i.relname = $2
			ORDER BY k.position`, table, index)
		if err != nil {
			return false, nil, err
		}
		defer rows.Close()
		for rows.Next() {
			var column sql.NullString
			if err := rows.Scan(&unique, &column); err != nil {
				return false, nil, err
			}
			// An expression column has no attribute and never matches a plain column name.
			columns = append(columns, strings.ToLower(column.String))
		}
		return unique, columns, rows.Err()
	case DialectMySQL:
		rows, err := db.sql.Query(`SELECT non_unique, column_name FROM information_schema.statistics
			WHERE table_schema = DATABASE() AND table_name = ? AND index_name = ?
			ORDER BY seq_in_index`, table, index)
		if err != nil {
			return false, nil, err
		}
		defer rows.Close()
		unique = true
		for rows.Next() {
			var (
				nonUnique int
				column    sql.NullString
			)
			if err := rows.Scan(&nonUnique, &column); err != nil {
				return false, nil, err
			}
			unique = unique && nonUnique == 0
			columns = append(columns, strings.ToLower(column.String))
		}
		return unique && len(columns) > 0, columns, rows.Err()
	default:
		return false, nil, fmt.Errorf("unsupported database dialect %q", db.dialect)
	}
}

// scanPragmaRow reads one PRAGMA row by column name, since the column set differs between SQLite
// versions (index_list gained origin and partial).
func scanPragmaRow(rows *sql.Rows) (map[string]any, error) {
	names, err := rows.Columns()
	if err != nil {
		return nil, err
	}
	values := make([]any, len(names))
	pointers := make([]any, len(names))
	for i := range values {
		pointers[i] = &values[i]
	}
	if err := rows.Scan(pointers...); err != nil {
		return nil, err
	}
	row := make(map[string]any, len(names))
	for i, name := range names {
		if bytes, ok := values[i].([]byte); ok {
			row[name] = string(bytes)
		} else {
			row[name] = values[i]
		}
	}
	return row, nil
}
