package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
)

// Temporary HTTP shares (protocol/spec/temporary-http-share.md). Times are integer epoch seconds:
// share expiry is compared as an instant, never as a string.

var (
	// ErrShareLimitReached is returned when a route already has the maximum of active shares.
	ErrShareLimitReached = errors.New("the route already has the maximum number of active shares")
	// ErrShareIDTaken is returned when a freshly drawn share id collides with an existing row.
	ErrShareIDTaken = errors.New("share id already exists")
)

// HTTPShare mirrors http_share. The token itself is never stored, only its SHA-256.
type HTTPShare struct {
	ShareID        string
	TenantID       string
	RouteID        int64
	TokenSHA256    string
	Access         string
	PathPrefix     string
	Label          *string
	CreatedBy      string
	CreatedAt      int64
	ExpiresAt      int64
	RevokedAt      *int64
	RevokedBy      *string
	RevokeReason   *string
	ExpiryRecorded bool
}

// Active reports a share that is neither revoked nor expired at now.
func (s HTTPShare) Active(now int64) bool { return s.RevokedAt == nil && now < s.ExpiresAt }

// HTTPAccessAuditEntry mirrors http_access_audit.
type HTTPAccessAuditEntry struct {
	ID       int64
	TenantID string
	At       int64
	Actor    *string
	Action   string
	RouteID  int64
	ShareID  *string
	Detail   string
}

// HTTPShareSnapshot is a share with the current state of everything that may end it.
type HTTPShareSnapshot struct {
	Share   HTTPShare
	Route   *HTTPRouteMapping
	Client  *ClientAccount
	Creator *ManagementUser
}

// ShareLapseFunc returns why a snapshot's share can no longer be honoured, or "".
type ShareLapseFunc func(HTTPShareSnapshot) string

type sqlRunner interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

// AuditDetail renders an audit detail object from key/value pairs, keeping their order.
func AuditDetail(pairs ...string) string {
	var builder strings.Builder
	builder.WriteByte('{')
	for i := 0; i+1 < len(pairs); i += 2 {
		if i > 0 {
			builder.WriteByte(',')
		}
		key, _ := json.Marshal(pairs[i])
		value, _ := json.Marshal(pairs[i+1])
		builder.Write(key)
		builder.WriteByte(':')
		builder.Write(value)
	}
	builder.WriteByte('}')
	return builder.String()
}

const httpShareColumns = `share_id, tenant_id, route_id, token_sha256, access, path_prefix, label, created_by,
	created_at, expires_at, revoked_at, revoked_by, revoke_reason, expiry_recorded`

func scanHTTPShare(scanner rowScanner) (HTTPShare, error) {
	var (
		share          HTTPShare
		label          sql.NullString
		revokedAt      sql.NullInt64
		revokedBy      sql.NullString
		revokeReason   sql.NullString
		expiryRecorded int64
	)
	if err := scanner.Scan(&share.ShareID, &share.TenantID, &share.RouteID, &share.TokenSHA256, &share.Access,
		&share.PathPrefix, &label, &share.CreatedBy, &share.CreatedAt, &share.ExpiresAt, &revokedAt,
		&revokedBy, &revokeReason, &expiryRecorded); err != nil {
		return HTTPShare{}, err
	}
	if label.Valid {
		share.Label = &label.String
	}
	if revokedAt.Valid {
		share.RevokedAt = &revokedAt.Int64
	}
	if revokedBy.Valid {
		share.RevokedBy = &revokedBy.String
	}
	if revokeReason.Valid {
		share.RevokeReason = &revokeReason.String
	}
	share.ExpiryRecorded = expiryRecorded != 0
	return share, nil
}

func (db *DB) queryHTTPShares(ctx context.Context, runner sqlRunner, where string, args ...any) ([]HTTPShare, error) {
	rows, err := runner.QueryContext(ctx, db.rebind(`SELECT `+httpShareColumns+` FROM http_share `+where), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var shares []HTTPShare
	for rows.Next() {
		share, err := scanHTTPShare(rows)
		if err != nil {
			return nil, err
		}
		shares = append(shares, share)
	}
	return shares, rows.Err()
}

func (db *DB) getHTTPShare(ctx context.Context, runner sqlRunner, shareID string) (*HTTPShare, error) {
	shares, err := db.queryHTTPShares(ctx, runner, `WHERE share_id = ?`, shareID)
	if err != nil {
		return nil, err
	}
	// Share ids are case-sensitive; MySQL's default collation is not.
	for i := range shares {
		if shares[i].ShareID == shareID {
			return &shares[i], nil
		}
	}
	return nil, nil
}

// GetHTTPShare returns a share by id, or nil when there is none.
func (db *DB) GetHTTPShare(ctx context.Context, shareID string) (*HTTPShare, error) {
	return db.getHTTPShare(ctx, db.sql, shareID)
}

// ListHTTPSharesByRoute returns every stored share of a route, newest first.
func (db *DB) ListHTTPSharesByRoute(ctx context.Context, routeID int64) ([]HTTPShare, error) {
	return db.queryHTTPShares(ctx, db.sql, `WHERE route_id = ? ORDER BY created_at DESC, share_id DESC`, routeID)
}

func (db *DB) getHTTPRouteByID(ctx context.Context, runner sqlRunner, id int64) (*HTTPRouteMapping, error) {
	query := db.rebind(`SELECT id, COALESCE(tenant_id, 'default'), client_id, client_name, route, target_base_url,
		enabled, detail_capture_enabled, media_capture_enabled, path_rewrite_enabled, auth_enabled,
		COALESCE(auth_username, ''), COALESCE(auth_password_hash, ''), created_at, updated_at
		FROM http_route_mapping WHERE id = ?`)
	var (
		r                  HTTPRouteMapping
		enabled            databaseBoolean
		detailCapture      databaseBoolean
		mediaCapture       databaseBoolean
		pathRewrite        databaseBoolean
		authEnabled        databaseBoolean
		createdAt, updated string
	)
	err := runner.QueryRowContext(ctx, query, id).Scan(&r.ID, &r.TenantID, &r.ClientID, &r.ClientName, &r.Route,
		&r.TargetBaseURL, &enabled, &detailCapture, &mediaCapture, &pathRewrite, &authEnabled, &r.AuthUsername,
		&r.AuthPasswordHash, &createdAt, &updated)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	r.Enabled = bool(enabled)
	r.DetailCaptureEnabled = bool(detailCapture)
	r.MediaCaptureEnabled = bool(mediaCapture)
	r.PathRewriteEnabled = bool(pathRewrite)
	r.AuthEnabled = bool(authEnabled)
	r.CreatedAt = parseTime(createdAt)
	r.UpdatedAt = parseTime(updated)
	return &r, nil
}

// GetHTTPRouteByID returns one route, or nil when there is none.
func (db *DB) GetHTTPRouteByID(ctx context.Context, id int64) (*HTTPRouteMapping, error) {
	return db.getHTTPRouteByID(ctx, db.sql, id)
}

func (db *DB) getClientByID(ctx context.Context, runner sqlRunner, id int64) (*ClientAccount, error) {
	query := db.rebind(`SELECT id, COALESCE(tenant_id, 'default'), COALESCE(owner_username, ''),
		client_name, password_hash, enabled,
		connection_rate_limit_per_minute, created_at, updated_at FROM specus_client_account WHERE id = ?`)
	var (
		account            ClientAccount
		enabled            databaseBoolean
		createdAt, updated string
	)
	err := runner.QueryRowContext(ctx, query, id).Scan(&account.ID, &account.TenantID,
		&account.OwnerUsername, &account.ClientName, &account.PasswordHash, &enabled,
		&account.ConnectionRateLimitPerMinute, &createdAt, &updated)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	account.Enabled = bool(enabled)
	account.CreatedAt = parseTime(createdAt)
	account.UpdatedAt = parseTime(updated)
	return &account, nil
}

func (db *DB) findManagementUser(ctx context.Context, runner sqlRunner, username string) (*ManagementUser, error) {
	query := db.rebind(`SELECT username, tenant_id, password_hash,
		COALESCE(oidc_issuer, ''), COALESCE(oidc_subject, ''), COALESCE(oidc_identity_key, ''),
		role, enabled, created_at, updated_at
		FROM specus_management_user WHERE LOWER(username) = LOWER(?)`)
	user, err := scanManagementUser(runner.QueryRowContext(ctx, query, username))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &user, nil
}

func (db *DB) snapshotFor(ctx context.Context, runner sqlRunner, share HTTPShare) (HTTPShareSnapshot, error) {
	snapshot := HTTPShareSnapshot{Share: share}
	route, err := db.getHTTPRouteByID(ctx, runner, share.RouteID)
	if err != nil {
		return snapshot, err
	}
	snapshot.Route = route
	if route != nil {
		if snapshot.Client, err = db.getClientByID(ctx, runner, route.ClientID); err != nil {
			return snapshot, err
		}
	}
	snapshot.Creator, err = db.findManagementUser(ctx, runner, share.CreatedBy)
	return snapshot, err
}

// LoadHTTPShareSnapshot reads a share and the current state of its route, client and creator, or
// returns nil when the share does not exist. Nothing here is cached: revocation and every change
// that ends a share must be visible to the very next request on every instance.
func (db *DB) LoadHTTPShareSnapshot(ctx context.Context, shareID string) (*HTTPShareSnapshot, error) {
	share, err := db.GetHTTPShare(ctx, shareID)
	if err != nil || share == nil {
		return nil, err
	}
	snapshot, err := db.snapshotFor(ctx, db.sql, *share)
	if err != nil {
		return nil, err
	}
	return &snapshot, nil
}

// SnapshotHTTPShare reads the current state of everything that may end an already loaded share.
func (db *DB) SnapshotHTTPShare(ctx context.Context, share HTTPShare) (HTTPShareSnapshot, error) {
	return db.snapshotFor(ctx, db.sql, share)
}

func (db *DB) insertAudit(ctx context.Context, runner sqlRunner, entry HTTPAccessAuditEntry) error {
	_, err := runner.ExecContext(ctx, db.rebind(`INSERT INTO http_access_audit
		(tenant_id, occurred_at, actor, action, route_id, share_id, detail_json) VALUES (?, ?, ?, ?, ?, ?, ?)`),
		defaultTenant(entry.TenantID), entry.At, entry.Actor, entry.Action, entry.RouteID, entry.ShareID,
		entry.Detail)
	return err
}

// httpRouteShareLockQuery holds a route row until the end of the transaction, or is "" where no
// lock is needed: SQLite has no SELECT ... FOR UPDATE, and its single writer already serializes
// the creation.
func (db *DB) httpRouteShareLockQuery() string {
	if db.dialect == DialectSQLite {
		return ""
	}
	return db.rebind(`SELECT id FROM http_route_mapping WHERE id = ? FOR UPDATE`)
}

// lockHTTPRouteForShares serializes the share creations of one route, on every instance. It must
// be the transaction's first statement: MySQL's REPEATABLE READ snapshot then starts only after
// the lock is granted, so the count sees the share committed by the creation that held it. A
// route that is gone has no row to lock, and the creation goes on as it would without the lock.
func (db *DB) lockHTTPRouteForShares(ctx context.Context, tx *sql.Tx, routeID int64) error {
	query := db.httpRouteShareLockQuery()
	if query == "" {
		return nil
	}
	var locked int64
	if err := tx.QueryRowContext(ctx, query, routeID).Scan(&locked); err != nil &&
		!errors.Is(err, sql.ErrNoRows) {
		return err
	}
	return nil
}

// InsertHTTPShare stores a new share with its share.created audit entry, unless the route already
// has maxActive active shares at now. The count, the insert and the audit share one transaction,
// which first locks the route row so that concurrent creations cannot all count the same total.
func (db *DB) InsertHTTPShare(ctx context.Context, share HTTPShare, maxActive int, now int64,
	audit HTTPAccessAuditEntry) error {
	tx, err := db.sql.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := db.lockHTTPRouteForShares(ctx, tx, share.RouteID); err != nil {
		return err
	}
	var active int
	if err := tx.QueryRowContext(ctx, db.rebind(`SELECT COUNT(*) FROM http_share
		WHERE route_id = ? AND revoked_at IS NULL AND expires_at > ?`), share.RouteID, now).Scan(&active); err != nil {
		return err
	}
	if active >= maxActive {
		return ErrShareLimitReached
	}
	existing, err := db.getHTTPShare(ctx, tx, share.ShareID)
	if err != nil {
		return err
	}
	if existing != nil {
		return ErrShareIDTaken
	}
	if _, err := tx.ExecContext(ctx, db.rebind(`INSERT INTO http_share (`+httpShareColumns+`)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL, NULL, 0)`),
		share.ShareID, defaultTenant(share.TenantID), share.RouteID, share.TokenSHA256, share.Access,
		share.PathPrefix, share.Label, share.CreatedBy, share.CreatedAt, share.ExpiresAt); err != nil {
		if isUniqueConstraintError(err) {
			return ErrShareIDTaken
		}
		return err
	}
	if err := db.insertAudit(ctx, tx, audit); err != nil {
		return err
	}
	return tx.Commit()
}

func (db *DB) revokeShareTx(ctx context.Context, runner sqlRunner, share HTTPShare, now int64, actor *string,
	reason string) (bool, error) {
	result, err := runner.ExecContext(ctx, db.rebind(`UPDATE http_share SET revoked_at = ?, revoked_by = ?,
		revoke_reason = ? WHERE share_id = ? AND revoked_at IS NULL AND expires_at > ?`),
		now, actor, reason, share.ShareID, now)
	if err != nil {
		return false, err
	}
	changed, err := result.RowsAffected()
	if err != nil || changed != 1 {
		return false, err
	}
	shareID := share.ShareID
	return true, db.insertAudit(ctx, runner, HTTPAccessAuditEntry{TenantID: share.TenantID, At: now,
		Actor: actor, Action: "share.revoked", RouteID: share.RouteID, ShareID: &shareID,
		Detail: AuditDetail("reason", reason)})
}

// RevokeHTTPShare ends an active share with a conditional update and, only when this call changed
// the row, writes its share.revoked entry in the same transaction. Concurrent instances therefore
// record each end once. actor is nil for the system (read-time revocation, sweep).
func (db *DB) RevokeHTTPShare(ctx context.Context, share HTTPShare, now int64, actor *string,
	reason string) (bool, error) {
	tx, err := db.sql.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	changed, err := db.revokeShareTx(ctx, tx, share, now, actor, reason)
	if err != nil || !changed {
		return false, err
	}
	return true, tx.Commit()
}

func (db *DB) revokeActiveShares(ctx context.Context, tx sqlRunner, where string, args []any, now int64,
	actor *string, reason string, lapse ShareLapseFunc) ([]string, error) {
	shares, err := db.queryHTTPShares(ctx, tx, `WHERE revoked_at IS NULL AND expires_at > ? AND `+where+
		` ORDER BY created_at, share_id`, append([]any{now}, args...)...)
	if err != nil {
		return nil, err
	}
	var revoked []string
	for _, share := range shares {
		if lapse != nil {
			snapshot, err := db.snapshotFor(ctx, tx, share)
			if err != nil {
				return nil, err
			}
			if lapse(snapshot) != reason {
				continue
			}
		}
		changed, err := db.revokeShareTx(ctx, tx, share, now, actor, reason)
		if err != nil {
			return nil, err
		}
		if changed {
			revoked = append(revoked, share.ShareID)
		}
	}
	return revoked, nil
}

func nullableActor(actor string) *string {
	if actor == "" {
		return nil
	}
	return &actor
}

// InsertHTTPRouteAudited creates a route and records its exposure in the same transaction.
func (db *DB) InsertHTTPRouteAudited(ctx context.Context, r HTTPRouteMapping, actor string, now int64,
	exposure string) error {
	tx, err := db.sql.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := db.insertHTTPRoute(ctx, tx, r); err != nil {
		return err
	}
	if err := db.insertAudit(ctx, tx, HTTPAccessAuditEntry{TenantID: r.TenantID, At: now,
		Actor: nullableActor(actor), Action: "route.created", RouteID: r.ID,
		Detail: AuditDetail("exposure", exposure)}); err != nil {
		return err
	}
	return tx.Commit()
}

// RouteChange describes the access-relevant part of a route update.
type RouteChange struct {
	ExposureBefore     string
	ExposureAfter      string
	CredentialsChanged bool
	// RevokeReason is set when the route is no longer protected: its active shares end.
	RevokeReason string
}

// UpdateHTTPRouteAudited updates a route, records exposure and credential changes, and revokes the
// route's active shares when it stops being protected, all in one transaction. It returns the ids
// of the revoked shares.
func (db *DB) UpdateHTTPRouteAudited(ctx context.Context, r HTTPRouteMapping, change RouteChange, actor string,
	now int64) ([]string, error) {
	tx, err := db.sql.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if err := db.updateHTTPRoute(ctx, tx, r); err != nil {
		return nil, err
	}
	who := nullableActor(actor)
	if change.ExposureBefore != change.ExposureAfter {
		if err := db.insertAudit(ctx, tx, HTTPAccessAuditEntry{TenantID: r.TenantID, At: now, Actor: who,
			Action: "route.exposure-changed", RouteID: r.ID,
			Detail: AuditDetail("from", change.ExposureBefore, "to", change.ExposureAfter)}); err != nil {
			return nil, err
		}
	}
	if change.CredentialsChanged {
		if err := db.insertAudit(ctx, tx, HTTPAccessAuditEntry{TenantID: r.TenantID, At: now, Actor: who,
			Action: "route.credentials-changed", RouteID: r.ID, Detail: "{}"}); err != nil {
			return nil, err
		}
	}
	var revoked []string
	if change.RevokeReason != "" {
		if revoked, err = db.revokeActiveShares(ctx, tx, `route_id = ?`, []any{r.ID}, now, who,
			change.RevokeReason, nil); err != nil {
			return nil, err
		}
	}
	return revoked, tx.Commit()
}

// DeleteHTTPRouteAudited deletes a route, records it and revokes its active shares in one
// transaction.
func (db *DB) DeleteHTTPRouteAudited(ctx context.Context, r HTTPRouteMapping, exposure, actor string,
	now int64) ([]string, error) {
	tx, err := db.sql.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if err := deleteWorkbenchReferences(ctx, db, tx, WorkbenchKindHTTPRoute, r.ID); err != nil {
		return nil, err
	}
	if _, err := tx.ExecContext(ctx, db.rebind(`DELETE FROM http_route_mapping WHERE id = ?`), r.ID); err != nil {
		return nil, err
	}
	who := nullableActor(actor)
	if err := db.insertAudit(ctx, tx, HTTPAccessAuditEntry{TenantID: r.TenantID, At: now, Actor: who,
		Action: "route.deleted", RouteID: r.ID, Detail: AuditDetail("exposure", exposure)}); err != nil {
		return nil, err
	}
	revoked, err := db.revokeActiveShares(ctx, tx, `route_id = ?`, []any{r.ID}, now, who, "route-deleted", nil)
	if err != nil {
		return nil, err
	}
	return revoked, tx.Commit()
}

// UpdateClientAudited updates a client like UpdateClientAndRenameReferences and, when the update
// disables it, revokes the active shares of all its routes in the same transaction.
func (db *DB) UpdateClientAudited(ctx context.Context, account ClientAccount, oldName string, wasEnabled bool,
	actor string, now int64) ([]string, error) {
	tx, err := db.sql.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if err := db.updateClientAndRenameReferences(ctx, tx, account, oldName); err != nil {
		return nil, err
	}
	var revoked []string
	if wasEnabled && !account.Enabled {
		if revoked, err = db.revokeActiveShares(ctx, tx,
			`route_id IN (SELECT id FROM http_route_mapping WHERE client_id = ?)`, []any{account.ID}, now,
			nullableActor(actor), "client-disabled", nil); err != nil {
			return nil, err
		}
	}
	return revoked, tx.Commit()
}

// DeleteClientAudited deletes a client with its routes, records every deleted route and revokes
// the routes' active shares, all in one transaction.
func (db *DB) DeleteClientAudited(ctx context.Context, id int64, actor string, now int64,
	exposure func(HTTPRouteMapping) string) ([]string, error) {
	tx, err := db.sql.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	rows, err := tx.QueryContext(ctx, db.rebind(`SELECT id FROM http_route_mapping WHERE client_id = ? ORDER BY id`), id)
	if err != nil {
		return nil, err
	}
	var routeIDs []int64
	for rows.Next() {
		var routeID int64
		if err := rows.Scan(&routeID); err != nil {
			rows.Close()
			return nil, err
		}
		routeIDs = append(routeIDs, routeID)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	who := nullableActor(actor)
	for _, routeID := range routeIDs {
		route, err := db.getHTTPRouteByID(ctx, tx, routeID)
		if err != nil {
			return nil, err
		}
		if route == nil {
			continue
		}
		if err := db.insertAudit(ctx, tx, HTTPAccessAuditEntry{TenantID: route.TenantID, At: now, Actor: who,
			Action: "route.deleted", RouteID: route.ID, Detail: AuditDetail("exposure", exposure(*route))}); err != nil {
			return nil, err
		}
	}
	var revoked []string
	if len(routeIDs) > 0 {
		args := make([]any, 0, len(routeIDs))
		for _, routeID := range routeIDs {
			args = append(args, routeID)
		}
		if revoked, err = db.revokeActiveShares(ctx, tx, `route_id IN (`+placeholders(len(routeIDs))+`)`, args,
			now, who, "client-deleted", nil); err != nil {
			return nil, err
		}
	}
	// Every workbench reference to a service the client carries goes while its rows still exist.
	if err := deleteClientWorkbenchReferences(ctx, db, tx, id); err != nil {
		return nil, err
	}
	for _, table := range []string{"specus_mapping", "http_route_mapping"} {
		if _, err := tx.ExecContext(ctx, db.rebind(`DELETE FROM `+table+` WHERE client_id = ?`), id); err != nil {
			return nil, err
		}
	}
	if _, err := tx.ExecContext(ctx, db.rebind(`DELETE FROM specus_client_account WHERE id = ?`), id); err != nil {
		return nil, err
	}
	return revoked, tx.Commit()
}

// UpdateManagementUserAudited updates a user and, in the same transaction, revokes the user's own
// active shares that the change leaves without a creator who may manage the route.
func (db *DB) UpdateManagementUserAudited(ctx context.Context, user ManagementUser, actor string, now int64,
	lapse ShareLapseFunc) ([]string, error) {
	tx, err := db.sql.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, db.rebind(`UPDATE specus_management_user SET password_hash = ?, oidc_issuer = ?,
		oidc_subject = ?, oidc_identity_key = ?, role = ?, enabled = ?, updated_at = ?
		WHERE LOWER(username) = LOWER(?)`), user.PasswordHash, nullIfBlank(user.OIDCIssuer),
		nullIfBlank(user.OIDCSubject), nullIfBlank(user.OIDCIdentityKey), normalizeManagementRole(user.Role),
		boolToInt(user.Enabled), formatTime(user.UpdatedAt), user.Username); err != nil {
		return nil, err
	}
	revoked, err := db.revokeActiveShares(ctx, tx, `LOWER(created_by) = LOWER(?)`, []any{user.Username}, now,
		nullableActor(actor), "creator-lost-access", lapse)
	if err != nil {
		return nil, err
	}
	return revoked, tx.Commit()
}

// DeleteManagementUserAudited deletes a user and revokes the user's active shares in the same
// transaction, so a later user of the same name never inherits them.
func (db *DB) DeleteManagementUserAudited(ctx context.Context, username, actor string, now int64,
	lapse ShareLapseFunc) ([]string, error) {
	tx, err := db.sql.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	// The account's workbench lists are personal history and go with it.
	if _, err := tx.ExecContext(ctx, db.rebind(`DELETE FROM management_workbench_item WHERE username IN
		(SELECT username FROM specus_management_user WHERE LOWER(username) = LOWER(?))`), username); err != nil {
		return nil, err
	}
	if _, err := tx.ExecContext(ctx,
		db.rebind(`DELETE FROM specus_management_user WHERE LOWER(username) = LOWER(?)`), username); err != nil {
		return nil, err
	}
	revoked, err := db.revokeActiveShares(ctx, tx, `LOWER(created_by) = LOWER(?)`, []any{username}, now,
		nullableActor(actor), "creator-lost-access", lapse)
	if err != nil {
		return nil, err
	}
	return revoked, tx.Commit()
}

// SweepHTTPShares records each expiry once (stamped with expiresAt, in expiry order), revokes
// active shares that lapsed without any hook or request noticing, and drops share rows ended for
// more than shareRetention seconds and audit rows older than auditRetention seconds. It returns the
// shares it revoked. Running it on several instances at once is safe: every write is conditional.
func (db *DB) SweepHTTPShares(ctx context.Context, now, shareRetention, auditRetention int64,
	lapse ShareLapseFunc) ([]string, error) {
	expired, err := db.queryHTTPShares(ctx, db.sql, `WHERE revoked_at IS NULL AND expiry_recorded = 0
		AND expires_at <= ? ORDER BY expires_at, share_id`, now)
	if err != nil {
		return nil, err
	}
	for _, share := range expired {
		if err := db.recordExpiry(ctx, share); err != nil {
			return nil, err
		}
	}
	active, err := db.queryHTTPShares(ctx, db.sql, `WHERE revoked_at IS NULL AND expires_at > ?
		ORDER BY created_at, share_id`, now)
	if err != nil {
		return nil, err
	}
	var revoked []string
	for _, share := range active {
		snapshot, err := db.snapshotFor(ctx, db.sql, share)
		if err != nil {
			return revoked, err
		}
		reason := lapse(snapshot)
		if reason == "" {
			continue
		}
		changed, err := db.RevokeHTTPShare(ctx, share, now, nil, reason)
		if err != nil {
			return revoked, err
		}
		if changed {
			revoked = append(revoked, share.ShareID)
		}
	}
	cutoff := now - shareRetention
	if _, err := db.sql.ExecContext(ctx, db.rebind(`DELETE FROM http_share
		WHERE (revoked_at IS NOT NULL AND revoked_at < ?) OR (revoked_at IS NULL AND expires_at < ?)`),
		cutoff, cutoff); err != nil {
		return revoked, err
	}
	if _, err := db.sql.ExecContext(ctx, db.rebind(`DELETE FROM http_access_audit WHERE occurred_at < ?`),
		now-auditRetention); err != nil {
		return revoked, err
	}
	return revoked, nil
}

func (db *DB) recordExpiry(ctx context.Context, share HTTPShare) error {
	tx, err := db.sql.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, db.rebind(`UPDATE http_share SET expiry_recorded = 1
		WHERE share_id = ? AND revoked_at IS NULL AND expiry_recorded = 0`), share.ShareID)
	if err != nil {
		return err
	}
	if changed, err := result.RowsAffected(); err != nil || changed != 1 {
		return err
	}
	shareID := share.ShareID
	if err := db.insertAudit(ctx, tx, HTTPAccessAuditEntry{TenantID: share.TenantID, At: share.ExpiresAt,
		Action: "share.expired", RouteID: share.RouteID, ShareID: &shareID, Detail: "{}"}); err != nil {
		return err
	}
	return tx.Commit()
}

// ExecStatement runs one statement with '?' placeholders and returns the rows it changed. It
// exists for tests and maintenance that must change rows without the management hooks, the way
// a direct database edit or an older instance would.
func (db *DB) ExecStatement(ctx context.Context, query string, args ...any) (int64, error) {
	result, err := db.sql.ExecContext(ctx, db.rebind(query), args...)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}

// ListHTTPAccessAudit pages a tenant's audit entries newest first, optionally for one route and
// before an audit id.
func (db *DB) ListHTTPAccessAudit(ctx context.Context, tenantID string, routeID, before *int64,
	limit int) ([]HTTPAccessAuditEntry, error) {
	query := `SELECT id, tenant_id, occurred_at, actor, action, route_id, share_id, detail_json
		FROM http_access_audit WHERE tenant_id = ?`
	args := []any{defaultTenant(tenantID)}
	if routeID != nil {
		query += ` AND route_id = ?`
		args = append(args, *routeID)
	}
	if before != nil {
		query += ` AND id < ?`
		args = append(args, *before)
	}
	query += ` ORDER BY id DESC LIMIT ?`
	args = append(args, limit)
	rows, err := db.sql.QueryContext(ctx, db.rebind(query), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var entries []HTTPAccessAuditEntry
	for rows.Next() {
		var (
			entry   HTTPAccessAuditEntry
			actor   sql.NullString
			shareID sql.NullString
		)
		if err := rows.Scan(&entry.ID, &entry.TenantID, &entry.At, &actor, &entry.Action, &entry.RouteID,
			&shareID, &entry.Detail); err != nil {
			return nil, err
		}
		if actor.Valid {
			entry.Actor = &actor.String
		}
		if shareID.Valid {
			entry.ShareID = &shareID.String
		}
		entries = append(entries, entry)
	}
	return entries, rows.Err()
}
