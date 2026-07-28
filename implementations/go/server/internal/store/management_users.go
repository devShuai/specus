package store

import (
	"context"
	"database/sql"
	"errors"
	"strings"
)

// FindManagementUserByUsername returns a management user by username, ignoring case.
func (db *DB) FindManagementUserByUsername(ctx context.Context, username string) (*ManagementUser, error) {
	query := db.rebind(`SELECT username, tenant_id, password_hash, role, enabled, created_at, updated_at
		FROM specus_management_user WHERE LOWER(username) = LOWER(?)`)
	row := db.sql.QueryRowContext(ctx, query, username)
	user, err := scanManagementUser(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &user, nil
}

// ListManagementUsersByTenant returns DB-backed management users in one tenant.
func (db *DB) ListManagementUsersByTenant(ctx context.Context, tenantID string) ([]ManagementUser, error) {
	query := db.rebind(`SELECT username, tenant_id, password_hash, role, enabled, created_at, updated_at
		FROM specus_management_user WHERE tenant_id = ? ORDER BY LOWER(username)`)
	rows, err := db.sql.QueryContext(ctx, query, defaultTenant(tenantID))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var users []ManagementUser
	for rows.Next() {
		user, err := scanManagementUser(rows)
		if err != nil {
			return nil, err
		}
		users = append(users, user)
	}
	return users, rows.Err()
}

// InsertManagementUser persists a new DB-backed management user.
func (db *DB) InsertManagementUser(ctx context.Context, user ManagementUser) error {
	query := db.rebind(`INSERT INTO specus_management_user
		(username, tenant_id, password_hash, role, enabled, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)`)
	_, err := db.sql.ExecContext(ctx, query, user.Username, defaultTenant(user.TenantID),
		user.PasswordHash, normalizeManagementRole(user.Role), boolToInt(user.Enabled),
		formatTime(user.CreatedAt), formatTime(user.UpdatedAt))
	return err
}

// UpdateManagementUser updates mutable fields of a DB-backed management user.
func (db *DB) UpdateManagementUser(ctx context.Context, user ManagementUser) error {
	query := db.rebind(`UPDATE specus_management_user SET password_hash = ?, role = ?,
		enabled = ?, updated_at = ? WHERE LOWER(username) = LOWER(?)`)
	_, err := db.sql.ExecContext(ctx, query, user.PasswordHash, normalizeManagementRole(user.Role),
		boolToInt(user.Enabled), formatTime(user.UpdatedAt), user.Username)
	return err
}

// DeleteManagementUser removes a DB-backed management user.
func (db *DB) DeleteManagementUser(ctx context.Context, username string) error {
	_, err := db.sql.ExecContext(ctx,
		db.rebind(`DELETE FROM specus_management_user WHERE LOWER(username) = LOWER(?)`), username)
	return err
}

type managementUserScanner interface {
	Scan(dest ...any) error
}

func scanManagementUser(scanner managementUserScanner) (ManagementUser, error) {
	var (
		user               ManagementUser
		enabled            databaseBoolean
		createdAt, updated string
	)
	err := scanner.Scan(&user.Username, &user.TenantID, &user.PasswordHash, &user.Role,
		&enabled, &createdAt, &updated)
	if err != nil {
		return ManagementUser{}, err
	}
	user.Role = normalizeManagementRole(user.Role)
	user.Enabled = bool(enabled)
	user.CreatedAt = parseTime(createdAt)
	user.UpdatedAt = parseTime(updated)
	return user, nil
}

func normalizeManagementRole(value string) string {
	if strings.EqualFold(strings.TrimSpace(value), ManagementRoleAdmin) {
		return ManagementRoleAdmin
	}
	return ManagementRoleUser
}
