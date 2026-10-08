package store

import (
	"context"
	"crypto/rand"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

var (
	ErrOIDCIdentityConflict   = errors.New("OIDC identity conflicts with an existing user binding")
	ErrManagementUserDisabled = errors.New("management user is disabled")
)

// managementUserColumns selects a row for scanManagementUser. The login name falls back to the
// account key for a row the login-name migration has not reached.
const managementUserColumns = `username, COALESCE(NULLIF(login_name, ''), username), tenant_id, password_hash,
		COALESCE(oidc_issuer, ''), COALESCE(oidc_subject, ''), COALESCE(oidc_identity_key, ''),
		role, enabled, created_at, updated_at`

// NormalizeLoginName is the comparison form of a login name (Java
// ManagementUserService.loginNameKey): trimmed and lower-cased. Login names are unique per tenant
// in this form.
func NormalizeLoginName(loginName string) string {
	return strings.ToLower(strings.TrimSpace(loginName))
}

// newAccountKey returns a random UUID (version 4) for the primary key of a new account, as Java's
// ManagementUserService.newAccountKey does. The key is opaque: it is never shown nor used to log in.
func newAccountKey() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(fmt.Sprintf("read random account key: %v", err))
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// FindManagementUserByLogin returns the user of one tenant with this login name, ignoring case.
// Login names are unique per tenant, so this is the lookup for login, token resolution and every
// administrator action; a user of another tenant is simply not found.
func (db *DB) FindManagementUserByLogin(ctx context.Context, tenantID, loginName string) (*ManagementUser, error) {
	return db.findManagementUserByLogin(ctx, db.sql, tenantID, loginName)
}

func (db *DB) findManagementUserByLogin(ctx context.Context, runner sqlRunner, tenantID,
	loginName string) (*ManagementUser, error) {
	query := db.rebind(`SELECT ` + managementUserColumns + ` FROM specus_management_user
		WHERE tenant_id = ? AND login_name_normalized = ?`)
	user, err := scanManagementUser(runner.QueryRowContext(ctx, query,
		defaultTenant(strings.TrimSpace(tenantID)), NormalizeLoginName(loginName)))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &user, nil
}

// FindManagementUserByAccountKey returns the user whose primary key is exactly accountKey. Only a
// local token without a tenant claim, issued before tenant-scoped login names, is resolved this way.
func (db *DB) FindManagementUserByAccountKey(ctx context.Context, accountKey string) (*ManagementUser, error) {
	query := db.rebind(`SELECT ` + managementUserColumns + ` FROM specus_management_user WHERE username = ?`)
	user, err := scanManagementUser(db.sql.QueryRowContext(ctx, query, accountKey))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &user, nil
}

// FindLegacyManagementUser is the bare-login fallback of Java's ManagementUserService.authenticate:
// an account that predates tenant-scoped login names kept its username as the account key, so a
// login without a tenant may still find it by that key, ignoring case. Two or more matches (in one
// tenant or several) resolve to no one rather than to whichever row comes first.
func (db *DB) FindLegacyManagementUser(ctx context.Context, name string) (*ManagementUser, error) {
	query := db.rebind(`SELECT ` + managementUserColumns + ` FROM specus_management_user
		WHERE LOWER(username) = LOWER(?)`)
	rows, err := db.sql.QueryContext(ctx, query, strings.TrimSpace(name))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var found []ManagementUser
	for len(found) < 2 && rows.Next() {
		user, err := scanManagementUser(rows)
		if err != nil {
			return nil, err
		}
		found = append(found, user)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(found) != 1 {
		return nil, nil
	}
	return &found[0], nil
}

// FindManagementUserByOIDCIdentity returns the enabled-state-bearing local account bound to one
// immutable issuer/subject pair. The hash is only an index key; the original pair is compared as
// well so a collision or corrupted row fails closed.
func (db *DB) FindManagementUserByOIDCIdentity(ctx context.Context, issuer, subject,
	identityKey string) (*ManagementUser, error) {
	query := db.rebind(`SELECT ` + managementUserColumns + ` FROM specus_management_user WHERE oidc_identity_key = ?`)
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
	query := db.rebind(`SELECT ` + managementUserColumns + ` FROM specus_management_user
		WHERE tenant_id = ? ORDER BY login_name_normalized, username`)
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

// InsertManagementUser persists a new DB-backed management user and returns it as stored. Without
// an AccountKey the row gets a fresh random one, so a login name never doubles as a global key.
func (db *DB) InsertManagementUser(ctx context.Context, user ManagementUser) (ManagementUser, error) {
	if err := db.insertManagementUserOn(ctx, db.sql, &user); err != nil {
		return ManagementUser{}, err
	}
	return user, nil
}

func (db *DB) insertManagementUserOn(ctx context.Context, runner sqlRunner, user *ManagementUser) error {
	if strings.TrimSpace(user.AccountKey) == "" {
		user.AccountKey = newAccountKey()
	}
	user.Username = strings.TrimSpace(user.Username)
	user.TenantID = defaultTenant(user.TenantID)
	user.Role = normalizeManagementRole(user.Role)
	query := db.rebind(`INSERT INTO specus_management_user
		(username, login_name, login_name_normalized, tenant_id, password_hash, oidc_issuer, oidc_subject,
		 oidc_identity_key, role, enabled, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	_, err := runner.ExecContext(ctx, query, user.AccountKey, user.Username, NormalizeLoginName(user.Username),
		user.TenantID, user.PasswordHash, nullIfBlank(user.OIDCIssuer), nullIfBlank(user.OIDCSubject),
		nullIfBlank(user.OIDCIdentityKey), user.Role, boolToInt(user.Enabled),
		formatTime(user.CreatedAt), formatTime(user.UpdatedAt))
	return err
}

// UpdateManagementUser updates mutable fields of a DB-backed management user, found by its key.
func (db *DB) UpdateManagementUser(ctx context.Context, user ManagementUser) error {
	return db.updateManagementUserOn(ctx, db.sql, user)
}

func (db *DB) updateManagementUserOn(ctx context.Context, runner sqlRunner, user ManagementUser) error {
	query := db.rebind(`UPDATE specus_management_user SET password_hash = ?, oidc_issuer = ?,
		oidc_subject = ?, oidc_identity_key = ?, role = ?, enabled = ?, updated_at = ?
		WHERE username = ?`)
	_, err := runner.ExecContext(ctx, query, user.PasswordHash, nullIfBlank(user.OIDCIssuer),
		nullIfBlank(user.OIDCSubject), nullIfBlank(user.OIDCIdentityKey), normalizeManagementRole(user.Role),
		boolToInt(user.Enabled), formatTime(user.UpdatedAt), user.AccountKey)
	return err
}

// DeleteManagementUser removes a DB-backed management user together with the account's workbench
// lists, in one transaction: a recreated account with the same name must start with empty lists.
func (db *DB) DeleteManagementUser(ctx context.Context, user ManagementUser) error {
	tx, err := db.sql.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := db.deleteManagementUserOn(ctx, tx, user); err != nil {
		return err
	}
	return tx.Commit()
}

// deleteManagementUserOn deletes the account row by its key and the workbench rows of its identity:
// the tenant and the login name as the account record spells it (Java WorkbenchReferences.forgetIdentity).
// The registered email points at the account key and goes with the account, so the address can
// register again once the transaction commits.
func (db *DB) deleteManagementUserOn(ctx context.Context, runner sqlRunner, user ManagementUser) error {
	if _, err := runner.ExecContext(ctx, db.rebind(`DELETE FROM management_workbench_item
		WHERE tenant_id = ? AND username = ?`), defaultTenant(user.TenantID), user.Username); err != nil {
		return err
	}
	if _, err := runner.ExecContext(ctx, db.rebind(`DELETE FROM specus_management_user_email WHERE username = ?`),
		user.AccountKey); err != nil {
		return err
	}
	_, err := runner.ExecContext(ctx, db.rebind(`DELETE FROM specus_management_user WHERE username = ?`),
		user.AccountKey)
	return err
}

// AccountStillOwnsError refuses to delete an account that still owns clients or access credentials
// (management-accounts.md section 7.1): they carry tunnels in use, and a later account of the same
// name would own them. The administrator deletes or hands them over first.
type AccountStillOwnsError struct {
	Clients     int64
	Credentials int64
}

func (e *AccountStillOwnsError) Error() string {
	return fmt.Sprintf("该账号仍拥有 %d 个客户端、%d 个接入凭证，需先转移或删除", e.Clients, e.Credentials)
}

// forgetAccountDataOn deals, in the deletion's transaction, with the rows the account's identity
// (tenant, login name) owns besides the account row (management-accounts.md section 7.1). It refuses
// with *AccountStillOwnsError while clients or credentials remain. Otherwise diagram documents,
// download grants and download usage go; attachments expire now, so nothing can complete, download
// or count them any more and the expiry scan deletes their objects (the row is the only record of
// the object); Peer device rows of clients that no longer exist go; Peer ACLs and egress policies,
// which decide how other people's clients connect, stay and are owned by actor from now on.
func (db *DB) forgetAccountDataOn(ctx context.Context, runner sqlRunner, user ManagementUser, actor string) error {
	tenantID := defaultTenant(user.TenantID)
	owned := &AccountStillOwnsError{}
	if err := runner.QueryRowContext(ctx, db.rebind(`SELECT COUNT(*) FROM specus_client_account
		WHERE COALESCE(tenant_id, 'default') = ? AND owner_username = ?`), tenantID, user.Username).
		Scan(&owned.Clients); err != nil {
		return err
	}
	if err := runner.QueryRowContext(ctx, db.rebind(`SELECT COUNT(*) FROM specus_client_credential
		WHERE tenant_id = ? AND owner_username = ?`), tenantID, user.Username).Scan(&owned.Credentials); err != nil {
		return err
	}
	if owned.Clients > 0 || owned.Credentials > 0 {
		return owned
	}
	now := time.Now()
	cutoff := formatTime(now)
	statements := []struct {
		query string
		args  []any
	}{
		{`DELETE FROM user_diagram_document WHERE tenant_id = ? AND owner_username = ?`, nil},
		{`UPDATE transfer_attachment SET expires_at = ?, upload_expires_at = ?, updated_at = ?
			WHERE tenant_id = ? AND owner_username = ? AND status <> 'EXPIRED' AND expires_at > ?`,
			[]any{cutoff, cutoff, cutoff, tenantID, user.Username, cutoff}},
		{`DELETE FROM transfer_attachment_download_grant WHERE tenant_id = ? AND username = ?`, nil},
		{`DELETE FROM transfer_attachment_download_usage WHERE tenant_id = ? AND username = ?`, nil},
		{`DELETE FROM peer_mesh_device WHERE tenant_id = ? AND owner_username = ?
			AND NOT EXISTS (SELECT 1 FROM specus_client_account c WHERE c.id = peer_mesh_device.client_id)`, nil},
		{`UPDATE peer_mesh_acl SET owner_username = ? WHERE tenant_id = ? AND owner_username = ?`,
			[]any{actor, tenantID, user.Username}},
		{`UPDATE peer_mesh_egress_policy SET owner_username = ? WHERE tenant_id = ? AND owner_username = ?`,
			[]any{actor, tenantID, user.Username}},
	}
	for _, statement := range statements {
		args := statement.args
		if args == nil {
			args = []any{tenantID, user.Username}
		}
		if _, err := runner.ExecContext(ctx, db.rebind(statement.query), args...); err != nil {
			return err
		}
	}
	return nil
}

// ResolveOrProvisionOIDCUser atomically resolves an issuer/subject binding, links an enabled
// unbound user of tenantID with the imported login name, or creates a least-privilege USER there.
// Users of other tenants never take part: a same-named user elsewhere neither binds nor blocks the
// new account. The immutable identity key has a database unique index, so concurrent first logins
// cannot bind one external identity to multiple local accounts.
func (db *DB) ResolveOrProvisionOIDCUser(ctx context.Context, issuer, subject, identityKey,
	username, tenantID, passwordHash string, now time.Time) (*ManagementUser, error) {
	tx, err := db.sql.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	byIdentity := db.rebind(`SELECT ` + managementUserColumns + ` FROM specus_management_user WHERE oidc_identity_key = ?`)
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

	tenantID = defaultTenant(strings.TrimSpace(tenantID))
	existing, findErr := db.findManagementUserByLogin(ctx, tx, tenantID, username)
	if findErr != nil {
		return nil, findErr
	}
	if existing != nil {
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
				return existing, nil
			}
		}

		// The WHERE clause is the first-bind compare-and-swap, keyed by the account key. A
		// concurrent login can no longer overwrite a binding selected just before this update.
		whereBinding := `COALESCE(oidc_issuer, '') = '' AND COALESCE(oidc_subject, '') = ''`
		args := []any{issuer, subject, identityKey, formatTime(now), existing.AccountKey}
		if hasIssuer || hasSubject {
			// Compatibility path for a legacy exact issuer/subject row that predates identity_key.
			whereBinding = `oidc_issuer = ? AND oidc_subject = ?`
			args = append(args, issuer, subject)
		}
		query := db.rebind(`UPDATE specus_management_user SET oidc_issuer = ?, oidc_subject = ?,
			oidc_identity_key = ?, updated_at = ? WHERE username = ? AND ` +
			whereBinding + ` AND COALESCE(oidc_identity_key, '') = ''`)
		result, err := tx.ExecContext(ctx, query, args...)
		if err != nil {
			if isUniqueConstraintError(err) {
				if rollbackErr := tx.Rollback(); rollbackErr != nil && !errors.Is(rollbackErr, sql.ErrTxDone) {
					return nil, rollbackErr
				}
				return db.resolveExactOIDCAccountBinding(ctx, existing.AccountKey, issuer, subject, identityKey)
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
			return db.resolveExactOIDCAccountBinding(ctx, existing.AccountKey, issuer, subject, identityKey)
		}
		existing.OIDCIssuer = issuer
		existing.OIDCSubject = subject
		existing.OIDCIdentityKey = identityKey
		existing.UpdatedAt = now
		if err := tx.Commit(); err != nil {
			return nil, err
		}
		return existing, nil
	}

	created := ManagementUser{
		Username: strings.TrimSpace(username), TenantID: tenantID, PasswordHash: passwordHash,
		OIDCIssuer: issuer, OIDCSubject: subject, OIDCIdentityKey: identityKey,
		Role: ManagementRoleUser, Enabled: true, CreatedAt: now, UpdatedAt: now,
	}
	if err := db.insertManagementUserOn(ctx, tx, &created); err != nil {
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

func (db *DB) resolveExactOIDCAccountBinding(ctx context.Context, accountKey, issuer, subject,
	identityKey string) (*ManagementUser, error) {
	current, err := db.FindManagementUserByAccountKey(ctx, accountKey)
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

// IsUniqueConstraintError reports whether err is a unique-index violation in any supported dialect.
func IsUniqueConstraintError(err error) bool {
	return isUniqueConstraintError(err)
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
	err := scanner.Scan(&user.AccountKey, &user.Username, &user.TenantID, &user.PasswordHash,
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
