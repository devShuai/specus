package store

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"
)

var (
	ErrOIDCIdentityConflict   = errors.New("OIDC identity conflicts with an existing user binding")
	ErrManagementUserDisabled = errors.New("management user is disabled")
)

// FindManagementUserByUsername returns a management user by username, ignoring case.
func (db *DB) FindManagementUserByUsername(ctx context.Context, username string) (*ManagementUser, error) {
	query := db.rebind(`SELECT username, tenant_id, password_hash,
		COALESCE(oidc_issuer, ''), COALESCE(oidc_subject, ''), COALESCE(oidc_identity_key, ''),
		role, enabled, created_at, updated_at
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

// FindManagementUserByOIDCIdentity returns the enabled-state-bearing local account bound to one
// immutable issuer/subject pair. The hash is only an index key; the original pair is compared as
// well so a collision or corrupted row fails closed.
func (db *DB) FindManagementUserByOIDCIdentity(ctx context.Context, issuer, subject,
	identityKey string) (*ManagementUser, error) {
	query := db.rebind(`SELECT username, tenant_id, password_hash,
		COALESCE(oidc_issuer, ''), COALESCE(oidc_subject, ''), COALESCE(oidc_identity_key, ''),
		role, enabled, created_at, updated_at
		FROM specus_management_user WHERE oidc_identity_key = ?`)
	user, err := scanManagementUser(db.sql.QueryRowContext(ctx, query, identityKey))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if !sameOIDCBinding(user, issuer, subject, identityKey) {
		return nil, ErrOIDCIdentityConflict
	}
	return &user, nil
}

// ListManagementUsersByTenant returns DB-backed management users in one tenant.
func (db *DB) ListManagementUsersByTenant(ctx context.Context, tenantID string) ([]ManagementUser, error) {
	query := db.rebind(`SELECT username, tenant_id, password_hash,
		COALESCE(oidc_issuer, ''), COALESCE(oidc_subject, ''), COALESCE(oidc_identity_key, ''),
		role, enabled, created_at, updated_at
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
		(username, tenant_id, password_hash, oidc_issuer, oidc_subject, oidc_identity_key,
		 role, enabled, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	_, err := db.sql.ExecContext(ctx, query, user.Username, defaultTenant(user.TenantID),
		user.PasswordHash, nullIfBlank(user.OIDCIssuer), nullIfBlank(user.OIDCSubject),
		nullIfBlank(user.OIDCIdentityKey), normalizeManagementRole(user.Role), boolToInt(user.Enabled),
		formatTime(user.CreatedAt), formatTime(user.UpdatedAt))
	return err
}

// UpdateManagementUser updates mutable fields of a DB-backed management user.
func (db *DB) UpdateManagementUser(ctx context.Context, user ManagementUser) error {
	query := db.rebind(`UPDATE specus_management_user SET password_hash = ?, oidc_issuer = ?,
		oidc_subject = ?, oidc_identity_key = ?, role = ?, enabled = ?, updated_at = ?
		WHERE LOWER(username) = LOWER(?)`)
	_, err := db.sql.ExecContext(ctx, query, user.PasswordHash, nullIfBlank(user.OIDCIssuer),
		nullIfBlank(user.OIDCSubject), nullIfBlank(user.OIDCIdentityKey), normalizeManagementRole(user.Role),
		boolToInt(user.Enabled), formatTime(user.UpdatedAt), user.Username)
	return err
}

// DeleteManagementUser removes a DB-backed management user.
func (db *DB) DeleteManagementUser(ctx context.Context, username string) error {
	_, err := db.sql.ExecContext(ctx,
		db.rebind(`DELETE FROM specus_management_user WHERE LOWER(username) = LOWER(?)`), username)
	return err
}

// ResolveOrProvisionOIDCUser atomically resolves an issuer/subject binding, links an enabled
// unbound user with the imported username, or creates a least-privilege USER.  The immutable
// identity key has a database unique index, so concurrent first logins cannot bind one external
// identity to multiple local accounts.
func (db *DB) ResolveOrProvisionOIDCUser(ctx context.Context, issuer, subject, identityKey,
	username, tenantID, passwordHash string, now time.Time) (*ManagementUser, error) {
	tx, err := db.sql.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	columns := `username, tenant_id, password_hash,
		COALESCE(oidc_issuer, ''), COALESCE(oidc_subject, ''), COALESCE(oidc_identity_key, ''),
		role, enabled, created_at, updated_at`
	byIdentity := db.rebind(`SELECT ` + columns + ` FROM specus_management_user WHERE oidc_identity_key = ?`)
	bound, scanErr := scanManagementUser(tx.QueryRowContext(ctx, byIdentity, identityKey))
	if scanErr == nil {
		if bound.OIDCIssuer != issuer || bound.OIDCSubject != subject || bound.OIDCIdentityKey != identityKey {
			return nil, ErrOIDCIdentityConflict
		}
		if !bound.Enabled {
			return nil, ErrManagementUserDisabled
		}
		if err := tx.Commit(); err != nil {
			return nil, err
		}
		return &bound, nil
	}
	if !errors.Is(scanErr, sql.ErrNoRows) {
		return nil, scanErr
	}

	byUsername := db.rebind(`SELECT ` + columns + ` FROM specus_management_user
		WHERE LOWER(username) = LOWER(?)`)
	existing, scanErr := scanManagementUser(tx.QueryRowContext(ctx, byUsername, username))
	if scanErr == nil {
		if !existing.Enabled {
			return nil, ErrManagementUserDisabled
		}
		hasIssuer := strings.TrimSpace(existing.OIDCIssuer) != ""
		hasSubject := strings.TrimSpace(existing.OIDCSubject) != ""
		hasIdentityKey := strings.TrimSpace(existing.OIDCIdentityKey) != ""
		if hasIssuer || hasSubject || hasIdentityKey {
			if existing.OIDCIssuer != issuer || existing.OIDCSubject != subject ||
				(hasIdentityKey && existing.OIDCIdentityKey != identityKey) {
				return nil, ErrOIDCIdentityConflict
			}
			if hasIdentityKey {
				if err := tx.Commit(); err != nil {
					return nil, err
				}
				return &existing, nil
			}
		}

		// The WHERE clause is the first-bind compare-and-swap. A concurrent login can no
		// longer overwrite a binding selected just before this update.
		whereBinding := `COALESCE(oidc_issuer, '') = '' AND COALESCE(oidc_subject, '') = ''`
		args := []any{issuer, subject, identityKey, formatTime(now), username}
		if hasIssuer || hasSubject {
			// Compatibility path for a legacy exact issuer/subject row that predates identity_key.
			whereBinding = `oidc_issuer = ? AND oidc_subject = ?`
			args = append(args, issuer, subject)
		}
		query := db.rebind(`UPDATE specus_management_user SET oidc_issuer = ?, oidc_subject = ?,
			oidc_identity_key = ?, updated_at = ? WHERE LOWER(username) = LOWER(?) AND ` +
			whereBinding + ` AND COALESCE(oidc_identity_key, '') = ''`)
		result, err := tx.ExecContext(ctx, query, args...)
		if err != nil {
			if isUniqueConstraintError(err) {
				if rollbackErr := tx.Rollback(); rollbackErr != nil && !errors.Is(rollbackErr, sql.ErrTxDone) {
					return nil, rollbackErr
				}
				return db.resolveExactOIDCUsernameBinding(ctx, username, issuer, subject, identityKey)
			}
			return nil, err
		}
		updated, err := result.RowsAffected()
		if err != nil {
			return nil, err
		}
		if updated != 1 {
			// Another first-login request won the compare-and-swap. End this transaction so
			// MySQL's repeatable-read snapshot cannot hide the committed winner, then accept
			// only the exact immutable binding selected by this request.
			if rollbackErr := tx.Rollback(); rollbackErr != nil && !errors.Is(rollbackErr, sql.ErrTxDone) {
				return nil, rollbackErr
			}
			return db.resolveExactOIDCUsernameBinding(ctx, username, issuer, subject, identityKey)
		}
		existing.OIDCIssuer = issuer
		existing.OIDCSubject = subject
		existing.OIDCIdentityKey = identityKey
		existing.UpdatedAt = now
		if err := tx.Commit(); err != nil {
			return nil, err
		}
		return &existing, nil
	}
	if !errors.Is(scanErr, sql.ErrNoRows) {
		return nil, scanErr
	}

	created := ManagementUser{
		Username: username, TenantID: defaultTenant(tenantID), PasswordHash: passwordHash,
		OIDCIssuer: issuer, OIDCSubject: subject, OIDCIdentityKey: identityKey,
		Role: ManagementRoleUser, Enabled: true, CreatedAt: now, UpdatedAt: now,
	}
	insert := db.rebind(`INSERT INTO specus_management_user
		(username, tenant_id, password_hash, oidc_issuer, oidc_subject, oidc_identity_key,
		 role, enabled, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	if _, err := tx.ExecContext(ctx, insert, created.Username, created.TenantID, created.PasswordHash,
		created.OIDCIssuer, created.OIDCSubject, created.OIDCIdentityKey, created.Role,
		boolToInt(created.Enabled), formatTime(now), formatTime(now)); err != nil {
		if isUniqueConstraintError(err) {
			return nil, ErrOIDCIdentityConflict
		}
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return &created, nil
}

func (db *DB) resolveExactOIDCUsernameBinding(ctx context.Context, username, issuer, subject,
	identityKey string) (*ManagementUser, error) {
	current, err := db.FindManagementUserByUsername(ctx, username)
	if err != nil {
		return nil, err
	}
	if current == nil || !sameOIDCBinding(*current, issuer, subject, identityKey) {
		return nil, ErrOIDCIdentityConflict
	}
	if !current.Enabled {
		return nil, ErrManagementUserDisabled
	}
	return current, nil
}

func sameOIDCBinding(user ManagementUser, issuer, subject, identityKey string) bool {
	return user.OIDCIssuer == issuer && user.OIDCSubject == subject && user.OIDCIdentityKey == identityKey
}

func isUniqueConstraintError(err error) bool {
	if err == nil {
		return false
	}
	message := strings.ToLower(err.Error())
	return strings.Contains(message, "unique constraint") ||
		strings.Contains(message, "duplicate key") || strings.Contains(message, "duplicate entry")
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
	err := scanner.Scan(&user.Username, &user.TenantID, &user.PasswordHash,
		&user.OIDCIssuer, &user.OIDCSubject, &user.OIDCIdentityKey, &user.Role,
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

func nullIfBlank(value string) any {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	return value
}

func normalizeManagementRole(value string) string {
	if strings.EqualFold(strings.TrimSpace(value), ManagementRoleAdmin) {
		return ManagementRoleAdmin
	}
	return ManagementRoleUser
}
