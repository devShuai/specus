package store

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"
)

// ErrNotFound is returned when a requested row does not exist.
var ErrNotFound = errors.New("not found")

// ErrClientDownloadDisabled is returned when a disabled catalog row is raced or selected for the
// latest marker. Keeping this check in the transaction prevents a stale API read from publishing
// a row that another administrator just disabled or retargeted.
var ErrClientDownloadDisabled = errors.New("client download is disabled or changed")

// ---- clients -------------------------------------------------------------------------

// ListClients returns all client accounts ordered by id.
func (db *DB) ListClients(ctx context.Context) ([]ClientAccount, error) {
	rows, err := db.sql.QueryContext(ctx, `SELECT id, COALESCE(tenant_id, 'default'), COALESCE(owner_username, ''),
		client_name, password_hash, enabled,
		connection_rate_limit_per_minute, created_at, updated_at FROM specus_client_account ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var clients []ClientAccount
	for rows.Next() {
		var (
			account            ClientAccount
			enabled            databaseBoolean
			createdAt, updated string
		)
		if err := rows.Scan(&account.ID, &account.TenantID, &account.OwnerUsername,
			&account.ClientName, &account.PasswordHash, &enabled,
			&account.ConnectionRateLimitPerMinute, &createdAt, &updated); err != nil {
			return nil, err
		}
		account.Enabled = bool(enabled)
		account.CreatedAt = parseTime(createdAt)
		account.UpdatedAt = parseTime(updated)
		clients = append(clients, account)
	}
	return clients, rows.Err()
}

// GetClient returns the client account by id, or ErrNotFound.
func (db *DB) GetClient(ctx context.Context, id int64) (*ClientAccount, error) {
	query := db.rebind(`SELECT id, COALESCE(tenant_id, 'default'), COALESCE(owner_username, ''),
		client_name, password_hash, enabled,
		connection_rate_limit_per_minute, created_at, updated_at FROM specus_client_account WHERE id = ?`)
	var (
		account            ClientAccount
		enabled            databaseBoolean
		createdAt, updated string
	)
	err := db.sql.QueryRowContext(ctx, query, id).Scan(&account.ID, &account.TenantID,
		&account.OwnerUsername, &account.ClientName, &account.PasswordHash, &enabled,
		&account.ConnectionRateLimitPerMinute, &createdAt, &updated)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	account.Enabled = bool(enabled)
	account.CreatedAt = parseTime(createdAt)
	account.UpdatedAt = parseTime(updated)
	return &account, nil
}

// InsertClient persists a new client account (id is caller-assigned).
func (db *DB) InsertClient(ctx context.Context, account ClientAccount) error {
	query := db.rebind(`INSERT INTO specus_client_account
		(id, tenant_id, owner_username, client_name, password_hash, enabled,
		 connection_rate_limit_per_minute, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	_, err := db.sql.ExecContext(ctx, query, account.ID, defaultTenant(account.TenantID),
		defaultOwner(account.OwnerUsername), account.ClientName, account.PasswordHash,
		boolToInt(account.Enabled), account.ConnectionRateLimitPerMinute,
		formatTime(account.CreatedAt), formatTime(account.UpdatedAt))
	return err
}

// UpdateClient updates a client account's mutable fields.
func (db *DB) UpdateClient(ctx context.Context, account ClientAccount) error {
	query := db.rebind(`UPDATE specus_client_account SET owner_username = ?, client_name = ?, password_hash = ?,
		enabled = ?, connection_rate_limit_per_minute = ?, updated_at = ? WHERE id = ?`)
	_, err := db.sql.ExecContext(ctx, query, defaultOwner(account.OwnerUsername), account.ClientName, account.PasswordHash,
		boolToInt(account.Enabled), account.ConnectionRateLimitPerMinute,
		formatTime(account.UpdatedAt), account.ID)
	return err
}

// UpdateClientAndRenameReferences updates the account and every mutable denormalized client_name
// in one database transaction. Historical connection/detail rows intentionally retain the name
// captured at event time, matching Java ClientNameReferenceRepository.
func (db *DB) UpdateClientAndRenameReferences(ctx context.Context, account ClientAccount, oldName string) error {
	tx, err := db.sql.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	accountUpdate := db.rebind(`UPDATE specus_client_account SET owner_username = ?, client_name = ?,
		password_hash = ?, enabled = ?, connection_rate_limit_per_minute = ?, updated_at = ? WHERE id = ?`)
	if _, err := tx.ExecContext(ctx, accountUpdate, defaultOwner(account.OwnerUsername), account.ClientName,
		account.PasswordHash, boolToInt(account.Enabled), account.ConnectionRateLimitPerMinute,
		formatTime(account.UpdatedAt), account.ID); err != nil {
		return err
	}
	if account.ClientName != oldName {
		updates := []struct {
			query string
			args  []any
		}{
			{`UPDATE specus_client_identity SET client_name = ? WHERE client_id = ?`, []any{account.ClientName, account.ID}},
			{`UPDATE specus_mapping SET client_name = ?, updated_at = ? WHERE client_id = ?`, []any{account.ClientName, formatTime(account.UpdatedAt), account.ID}},
			{`UPDATE http_route_mapping SET client_name = ?, updated_at = ? WHERE client_id = ?`, []any{account.ClientName, formatTime(account.UpdatedAt), account.ID}},
			{`UPDATE peer_mesh_device SET client_name = ?, updated_at = ? WHERE client_id = ?`, []any{account.ClientName, formatTime(account.UpdatedAt), account.ID}},
			{`UPDATE peer_mesh_acl SET source_client_name = ?, updated_at = ? WHERE source_client_id = ?`, []any{account.ClientName, formatTime(account.UpdatedAt), account.ID}},
			{`UPDATE peer_mesh_acl SET target_client_name = ?, updated_at = ? WHERE target_client_id = ?`, []any{account.ClientName, formatTime(account.UpdatedAt), account.ID}},
			{`UPDATE specus_traffic_usage SET client_name = ? WHERE client_id = ?`, []any{account.ClientName, account.ID}},
			{`UPDATE specus_resource_traffic_usage SET client_name = ? WHERE client_id = ?`, []any{account.ClientName, account.ID}},
		}
		for _, update := range updates {
			if _, err := tx.ExecContext(ctx, db.rebind(update.query), update.args...); err != nil {
				return err
			}
		}
	}
	return tx.Commit()
}

// DeleteClient removes a client account and its specus/http-route mappings.
func (db *DB) DeleteClient(ctx context.Context, id int64) error {
	for _, table := range []string{"specus_mapping", "http_route_mapping"} {
		if _, err := db.sql.ExecContext(ctx, db.rebind(`DELETE FROM `+table+` WHERE client_id = ?`), id); err != nil {
			return err
		}
	}
	_, err := db.sql.ExecContext(ctx, db.rebind(`DELETE FROM specus_client_account WHERE id = ?`), id)
	return err
}

// ---- client credentials --------------------------------------------------------------

func (db *DB) ListCredentials(ctx context.Context) ([]ClientCredential, error) {
	rows, err := db.sql.QueryContext(ctx, `SELECT id, tenant_id, COALESCE(owner_username, ''),
		api_key, secret_hash, enabled, max_online_instances, created_at, updated_at
		FROM specus_client_credential ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var credentials []ClientCredential
	for rows.Next() {
		credential, err := scanCredential(rows)
		if err != nil {
			return nil, err
		}
		credentials = append(credentials, credential)
	}
	return credentials, rows.Err()
}

func (db *DB) GetCredential(ctx context.Context, id int64) (*ClientCredential, error) {
	query := db.rebind(`SELECT id, tenant_id, COALESCE(owner_username, ''),
		api_key, secret_hash, enabled, max_online_instances, created_at, updated_at
		FROM specus_client_credential WHERE id = ?`)
	row := db.sql.QueryRowContext(ctx, query, id)
	credential, err := scanCredential(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &credential, nil
}

func (db *DB) InsertCredential(ctx context.Context, credential ClientCredential) error {
	query := db.rebind(`INSERT INTO specus_client_credential
		(id, tenant_id, owner_username, api_key, secret_hash, enabled,
		 max_online_instances, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	_, err := db.sql.ExecContext(ctx, query, credential.ID, defaultTenant(credential.TenantID),
		defaultOwner(credential.OwnerUsername), credential.APIKey, credential.SecretHash,
		boolToInt(credential.Enabled), credential.MaxOnlineInstances,
		formatTime(credential.CreatedAt), formatTime(credential.UpdatedAt))
	return err
}

func (db *DB) UpdateCredential(ctx context.Context, credential ClientCredential) error {
	query := db.rebind(`UPDATE specus_client_credential SET owner_username = ?, api_key = ?,
		secret_hash = ?, enabled = ?, max_online_instances = ?, updated_at = ? WHERE id = ?`)
	_, err := db.sql.ExecContext(ctx, query, defaultOwner(credential.OwnerUsername),
		credential.APIKey, credential.SecretHash, boolToInt(credential.Enabled),
		credential.MaxOnlineInstances, formatTime(credential.UpdatedAt), credential.ID)
	return err
}

func (db *DB) DeleteCredential(ctx context.Context, id int64) error {
	_, err := db.sql.ExecContext(ctx, db.rebind(`DELETE FROM specus_client_credential WHERE id = ?`), id)
	return err
}

type credentialScanner interface {
	Scan(dest ...any) error
}

func scanCredential(scanner credentialScanner) (ClientCredential, error) {
	var (
		credential         ClientCredential
		enabled            databaseBoolean
		createdAt, updated string
	)
	err := scanner.Scan(&credential.ID, &credential.TenantID, &credential.OwnerUsername,
		&credential.APIKey, &credential.SecretHash, &enabled, &credential.MaxOnlineInstances,
		&createdAt, &updated)
	if err != nil {
		return ClientCredential{}, err
	}
	credential.Enabled = bool(enabled)
	credential.CreatedAt = parseTime(createdAt)
	credential.UpdatedAt = parseTime(updated)
	return credential, nil
}

// ---- client download links ----------------------------------------------------------

func (db *DB) ListClientDownloadLinks(ctx context.Context, enabledOnly bool) ([]ClientDownloadLink, error) {
	query := `SELECT id, implementation, platform, arch, version, display_name, download_url, description,
		sha256, file_size, is_latest, changelog_url, min_supported_version,
		display_order, enabled, created_at, updated_at FROM client_download_link`
	if enabledOnly {
		query += ` WHERE enabled <> 0 ORDER BY implementation, display_order, id`
	} else {
		query += ` ORDER BY display_order, id`
	}
	rows, err := db.sql.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var links []ClientDownloadLink
	for rows.Next() {
		link, err := scanClientDownloadLink(rows)
		if err != nil {
			return nil, err
		}
		links = append(links, link)
	}
	return links, rows.Err()
}

func (db *DB) GetClientDownloadLink(ctx context.Context, id int64) (*ClientDownloadLink, error) {
	query := db.rebind(`SELECT id, implementation, platform, arch, version, display_name, download_url, description,
		sha256, file_size, is_latest, changelog_url, min_supported_version,
		display_order, enabled, created_at, updated_at FROM client_download_link WHERE id = ?`)
	link, err := scanClientDownloadLink(db.sql.QueryRowContext(ctx, query, id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &link, nil
}

func (db *DB) InsertClientDownloadLink(ctx context.Context, link ClientDownloadLink) error {
	if link.IsLatest && !link.Enabled {
		return ErrClientDownloadDisabled
	}
	tx, err := db.sql.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if link.IsLatest {
		if err := db.clearLatestClientDownloadTx(ctx, tx, link.Implementation, link.Platform, link.Arch); err != nil {
			return err
		}
	}
	query := db.rebind(`INSERT INTO client_download_link
		(id, implementation, platform, arch, version, display_name, download_url, description,
		 sha256, file_size, is_latest, latest_slot, changelog_url, min_supported_version,
		 display_order, enabled, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	latestSlot := any(nil)
	if link.IsLatest {
		latestSlot = clientDownloadLatestSlot(link.Implementation, link.Platform, link.Arch)
	}
	if _, err := tx.ExecContext(ctx, query, link.ID, link.Implementation, link.Platform, link.Arch,
		clientDownloadDatabaseVersion(link), link.DisplayName, link.DownloadURL, link.Description, link.SHA256, link.FileSize,
		boolToInt(link.IsLatest), latestSlot, link.ChangelogURL, link.MinSupportedVersion, link.DisplayOrder,
		boolToInt(link.Enabled), formatTime(link.CreatedAt), formatTime(link.UpdatedAt)); err != nil {
		return err
	}
	return tx.Commit()
}

func (db *DB) UpdateClientDownloadLink(ctx context.Context, link ClientDownloadLink) error {
	if link.IsLatest && !link.Enabled {
		return ErrClientDownloadDisabled
	}
	tx, err := db.sql.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if link.IsLatest {
		if err := db.clearLatestClientDownloadTx(ctx, tx, link.Implementation, link.Platform, link.Arch); err != nil {
			return err
		}
	}
	query := db.rebind(`UPDATE client_download_link SET implementation = ?, platform = ?, arch = ?,
		version = ?, display_name = ?, download_url = ?, description = ?, sha256 = ?, file_size = ?,
		is_latest = ?, latest_slot = ?, changelog_url = ?, min_supported_version = ?, display_order = ?, enabled = ?,
		updated_at = ? WHERE id = ?`)
	latestSlot := any(nil)
	if link.IsLatest {
		latestSlot = clientDownloadLatestSlot(link.Implementation, link.Platform, link.Arch)
	}
	result, err := tx.ExecContext(ctx, query, link.Implementation, link.Platform, link.Arch,
		clientDownloadDatabaseVersion(link), link.DisplayName, link.DownloadURL, link.Description, link.SHA256, link.FileSize,
		boolToInt(link.IsLatest), latestSlot, link.ChangelogURL, link.MinSupportedVersion, link.DisplayOrder,
		boolToInt(link.Enabled), formatTime(link.UpdatedAt), link.ID)
	if err != nil {
		return err
	}
	if affected, err := result.RowsAffected(); err == nil && affected == 0 {
		return ErrNotFound
	}
	return tx.Commit()
}

// SetClientDownloadLinkLatest atomically clears the previous latest entry for one target and marks
// the requested enabled entry as latest. It is safe under concurrent admin requests on every
// supported database because the updates share one transaction.
func (db *DB) SetClientDownloadLinkLatest(ctx context.Context, id int64, updatedAt time.Time) (*ClientDownloadLink, error) {
	tx, err := db.sql.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()
	query := db.rebind(`SELECT id, implementation, platform, arch, version, display_name, download_url, description,
		sha256, file_size, is_latest, changelog_url, min_supported_version,
		display_order, enabled, created_at, updated_at FROM client_download_link WHERE id = ?`)
	link, err := scanClientDownloadLink(tx.QueryRowContext(ctx, query, id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if !link.Enabled {
		return nil, ErrClientDownloadDisabled
	}
	if err := db.clearLatestClientDownloadTx(ctx, tx, link.Implementation, link.Platform, link.Arch); err != nil {
		return nil, err
	}
	result, err := tx.ExecContext(ctx, db.rebind(`UPDATE client_download_link
		SET is_latest = ?, latest_slot = ?, updated_at = ?
		WHERE id = ? AND enabled <> ? AND implementation = ? AND platform = ? AND arch = ?
			AND version = ? AND download_url = ? AND sha256 = ? AND file_size = ?`), 1,
		clientDownloadLatestSlot(link.Implementation, link.Platform, link.Arch), formatTime(updatedAt), id, 0,
		link.Implementation, link.Platform, link.Arch, clientDownloadDatabaseVersion(link),
		link.DownloadURL, link.SHA256, link.FileSize)
	if err != nil {
		return nil, err
	}
	if affected, rowsErr := result.RowsAffected(); rowsErr != nil {
		return nil, rowsErr
	} else if affected == 0 {
		return nil, ErrClientDownloadDisabled
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	link.IsLatest = true
	link.UpdatedAt = updatedAt
	return &link, nil
}

func (db *DB) clearLatestClientDownloadTx(ctx context.Context, tx *sql.Tx,
	implementation, platform, arch string) error {
	_, err := tx.ExecContext(ctx, db.rebind(`UPDATE client_download_link SET is_latest = ?, latest_slot = NULL
		WHERE implementation = ? AND platform = ? AND arch = ? AND is_latest <> ?`),
		0, implementation, platform, arch, 0)
	return err
}

func (db *DB) DeleteClientDownloadLink(ctx context.Context, id int64) error {
	_, err := db.sql.ExecContext(ctx, db.rebind(`DELETE FROM client_download_link WHERE id = ?`), id)
	return err
}

func scanClientDownloadLink(scanner credentialScanner) (ClientDownloadLink, error) {
	var (
		link                                             ClientDownloadLink
		version, description, changelogURL, minSupported sql.NullString
		enabled, isLatest                                databaseBoolean
		createdAt, updated                               string
	)
	err := scanner.Scan(&link.ID, &link.Implementation, &link.Platform, &link.Arch, &version,
		&link.DisplayName, &link.DownloadURL, &description, &link.SHA256, &link.FileSize, &isLatest,
		&changelogURL, &minSupported, &link.DisplayOrder, &enabled, &createdAt, &updated)
	if err != nil {
		return ClientDownloadLink{}, err
	}
	if version.Valid && strings.TrimSpace(version.String) != "" {
		link.Version = &version.String
	}
	if description.Valid {
		link.Description = &description.String
	}
	if changelogURL.Valid {
		link.ChangelogURL = &changelogURL.String
	}
	if minSupported.Valid {
		link.MinSupportedVersion = &minSupported.String
	}
	link.Enabled = bool(enabled)
	link.IsLatest = bool(isLatest)
	link.CreatedAt = parseTime(createdAt)
	link.UpdatedAt = parseTime(updated)
	return link, nil
}

func clientDownloadDatabaseVersion(link ClientDownloadLink) any {
	if link.Version != nil {
		return strings.TrimSpace(*link.Version)
	}
	return nil
}

// ---- specusMappings -------------------------------------------------------------------------

// ListSpecusMappings returns specus mappings, optionally filtered by client id, ordered by id.
func (db *DB) ListSpecusMappings(ctx context.Context, clientID *int64) ([]SpecusMapping, error) {
	query := `SELECT id, COALESCE(tenant_id, 'default'), client_id, client_name, listen_port, target_address, target_port,
		enabled, detail_capture_enabled, created_at, updated_at FROM specus_mapping`
	var args []any
	if clientID != nil {
		query += ` WHERE client_id = ?`
		args = append(args, *clientID)
	}
	query += ` ORDER BY id`
	rows, err := db.sql.QueryContext(ctx, db.rebind(query), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var mappings []SpecusMapping
	for rows.Next() {
		var (
			m                  SpecusMapping
			enabled            databaseBoolean
			detailCapture      databaseBoolean
			createdAt, updated string
		)
		if err := rows.Scan(&m.ID, &m.TenantID, &m.ClientID, &m.ClientName, &m.ListenPort, &m.TargetAddress,
			&m.TargetPort, &enabled, &detailCapture, &createdAt, &updated); err != nil {
			return nil, err
		}
		m.Enabled = bool(enabled)
		m.DetailCaptureEnabled = bool(detailCapture)
		m.CreatedAt = parseTime(createdAt)
		m.UpdatedAt = parseTime(updated)
		mappings = append(mappings, m)
	}
	return mappings, rows.Err()
}

// GetSpecus returns a specus mapping by id, or ErrNotFound.
func (db *DB) GetSpecus(ctx context.Context, id int64) (*SpecusMapping, error) {
	mappings, err := db.ListSpecusMappings(ctx, nil)
	if err != nil {
		return nil, err
	}
	for i := range mappings {
		if mappings[i].ID == id {
			return &mappings[i], nil
		}
	}
	return nil, ErrNotFound
}

// ListenPortInUse reports whether a listen port is already mapped (optionally excluding a row).
func (db *DB) ListenPortInUse(ctx context.Context, listenPort int, excludeID int64) (bool, error) {
	query := db.rebind(`SELECT COUNT(*) FROM specus_mapping WHERE listen_port = ? AND id <> ?`)
	var count int
	err := db.sql.QueryRowContext(ctx, query, listenPort, excludeID).Scan(&count)
	return count > 0, err
}

// InsertSpecus persists a new specus mapping (id is caller-assigned).
func (db *DB) InsertSpecus(ctx context.Context, m SpecusMapping) error {
	query := db.rebind(`INSERT INTO specus_mapping
		(id, tenant_id, client_id, client_name, listen_port, target_address, target_port, enabled,
		 detail_capture_enabled, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	_, err := db.sql.ExecContext(ctx, query, m.ID, defaultTenant(m.TenantID), m.ClientID, m.ClientName, m.ListenPort,
		m.TargetAddress, m.TargetPort, boolToInt(m.Enabled), boolToInt(m.DetailCaptureEnabled),
		formatTime(m.CreatedAt), formatTime(m.UpdatedAt))
	return err
}

// UpdateSpecus updates a specus mapping's mutable fields.
func (db *DB) UpdateSpecus(ctx context.Context, m SpecusMapping) error {
	query := db.rebind(`UPDATE specus_mapping SET listen_port = ?, target_address = ?, target_port = ?,
		enabled = ?, detail_capture_enabled = ?, updated_at = ? WHERE id = ?`)
	_, err := db.sql.ExecContext(ctx, query, m.ListenPort, m.TargetAddress, m.TargetPort,
		boolToInt(m.Enabled), boolToInt(m.DetailCaptureEnabled), formatTime(m.UpdatedAt), m.ID)
	return err
}

// DeleteSpecus removes a specus mapping.
func (db *DB) DeleteSpecus(ctx context.Context, id int64) error {
	_, err := db.sql.ExecContext(ctx, db.rebind(`DELETE FROM specus_mapping WHERE id = ?`), id)
	return err
}

// ---- http routes ---------------------------------------------------------------------

// ListHTTPRoutes returns HTTP route mappings, optionally filtered by client id, ordered by id.
func (db *DB) ListHTTPRoutes(ctx context.Context, clientID *int64) ([]HTTPRouteMapping, error) {
	query := `SELECT id, COALESCE(tenant_id, 'default'), client_id, client_name, route, target_base_url, enabled,
		detail_capture_enabled, media_capture_enabled, path_rewrite_enabled, auth_enabled, COALESCE(auth_username, ''),
		COALESCE(auth_password_hash, ''), created_at, updated_at
		FROM http_route_mapping`
	var args []any
	if clientID != nil {
		query += ` WHERE client_id = ?`
		args = append(args, *clientID)
	}
	query += ` ORDER BY id`
	rows, err := db.sql.QueryContext(ctx, db.rebind(query), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var routes []HTTPRouteMapping
	for rows.Next() {
		var (
			r                  HTTPRouteMapping
			enabled            databaseBoolean
			detailCapture      databaseBoolean
			mediaCapture       databaseBoolean
			pathRewrite        databaseBoolean
			authEnabled        databaseBoolean
			createdAt, updated string
		)
		if err := rows.Scan(&r.ID, &r.TenantID, &r.ClientID, &r.ClientName, &r.Route, &r.TargetBaseURL,
			&enabled, &detailCapture, &mediaCapture, &pathRewrite, &authEnabled, &r.AuthUsername, &r.AuthPasswordHash,
			&createdAt, &updated); err != nil {
			return nil, err
		}
		r.Enabled = bool(enabled)
		r.DetailCaptureEnabled = bool(detailCapture)
		r.MediaCaptureEnabled = bool(mediaCapture)
		r.PathRewriteEnabled = bool(pathRewrite)
		r.AuthEnabled = bool(authEnabled)
		r.CreatedAt = parseTime(createdAt)
		r.UpdatedAt = parseTime(updated)
		routes = append(routes, r)
	}
	return routes, rows.Err()
}

// GetHTTPRoute returns an HTTP route mapping by id, or ErrNotFound.
func (db *DB) GetHTTPRoute(ctx context.Context, id int64) (*HTTPRouteMapping, error) {
	routes, err := db.ListHTTPRoutes(ctx, nil)
	if err != nil {
		return nil, err
	}
	for i := range routes {
		if routes[i].ID == id {
			return &routes[i], nil
		}
	}
	return nil, ErrNotFound
}

// RouteInUse reports whether (client_id, route) is taken (optionally excluding a row).
func (db *DB) RouteInUse(ctx context.Context, clientID int64, route string, excludeID int64) (bool, error) {
	query := db.rebind(`SELECT COUNT(*) FROM http_route_mapping WHERE client_id = ? AND route = ? AND id <> ?`)
	var count int
	err := db.sql.QueryRowContext(ctx, query, clientID, route, excludeID).Scan(&count)
	return count > 0, err
}

// InsertHTTPRoute persists a new HTTP route mapping (id is caller-assigned).
func (db *DB) InsertHTTPRoute(ctx context.Context, r HTTPRouteMapping) error {
	query := db.rebind(`INSERT INTO http_route_mapping
		(id, tenant_id, client_id, client_name, route, target_base_url, enabled, detail_capture_enabled,
		 media_capture_enabled, path_rewrite_enabled, auth_enabled, auth_username, auth_password_hash, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	_, err := db.sql.ExecContext(ctx, query, r.ID, defaultTenant(r.TenantID), r.ClientID, r.ClientName, r.Route,
		r.TargetBaseURL, boolToInt(r.Enabled), boolToInt(r.DetailCaptureEnabled),
		boolToInt(r.MediaCaptureEnabled), boolToInt(r.PathRewriteEnabled), boolToInt(r.AuthEnabled), r.AuthUsername, r.AuthPasswordHash,
		formatTime(r.CreatedAt), formatTime(r.UpdatedAt))
	return err
}

// UpdateHTTPRoute updates an HTTP route mapping's mutable fields.
func (db *DB) UpdateHTTPRoute(ctx context.Context, r HTTPRouteMapping) error {
	query := db.rebind(`UPDATE http_route_mapping SET route = ?, target_base_url = ?, enabled = ?,
		detail_capture_enabled = ?, media_capture_enabled = ?, path_rewrite_enabled = ?, auth_enabled = ?, auth_username = ?,
		auth_password_hash = ?, updated_at = ? WHERE id = ?`)
	_, err := db.sql.ExecContext(ctx, query, r.Route, r.TargetBaseURL, boolToInt(r.Enabled),
		boolToInt(r.DetailCaptureEnabled), boolToInt(r.MediaCaptureEnabled), boolToInt(r.PathRewriteEnabled), boolToInt(r.AuthEnabled),
		r.AuthUsername, r.AuthPasswordHash, formatTime(r.UpdatedAt), r.ID)
	return err
}

// DeleteHTTPRoute removes an HTTP route mapping.
func (db *DB) DeleteHTTPRoute(ctx context.Context, id int64) error {
	_, err := db.sql.ExecContext(ctx, db.rebind(`DELETE FROM http_route_mapping WHERE id = ?`), id)
	return err
}

// ---- connections / traffic / stats ---------------------------------------------------

// ConnectionFilter narrows a connection-record query.
type ConnectionFilter struct {
	TenantID  string
	ClientID  *int64
	ClientIDs []int64
	Success   *bool
	FromISO   string
	ToISO     string
	Page      int
	Size      int
}

// ListConnections returns a page of connection records (newest first) and the total count.
func (db *DB) ListConnections(ctx context.Context, filter ConnectionFilter) ([]ConnectionRecord, int, error) {
	where := ` WHERE 1=1`
	var args []any
	if filter.TenantID != "" {
		where += ` AND (tenant_id = ? OR tenant_id IS NULL OR tenant_id = '')`
		args = append(args, defaultTenant(filter.TenantID))
	}
	if filter.ClientID != nil {
		where += ` AND client_id = ?`
		args = append(args, *filter.ClientID)
	} else if len(filter.ClientIDs) > 0 {
		where += ` AND client_id IN (` + placeholders(len(filter.ClientIDs)) + `)`
		for _, id := range filter.ClientIDs {
			args = append(args, id)
		}
	}
	if filter.Success != nil {
		where += ` AND success = ?`
		args = append(args, boolToInt(*filter.Success))
	}
	if filter.FromISO != "" {
		where += ` AND connected_at >= ?`
		args = append(args, filter.FromISO)
	}
	if filter.ToISO != "" {
		where += ` AND connected_at <= ?`
		args = append(args, filter.ToISO)
	}

	var total int
	if err := db.sql.QueryRowContext(ctx, db.rebind(`SELECT COUNT(*) FROM specus_connection_record`+where), args...).
		Scan(&total); err != nil {
		return nil, 0, err
	}

	size := filter.Size
	if size <= 0 || size > 200 {
		size = 20
	}
	page := filter.Page
	if page < 0 {
		page = 0
	}
	listArgs := append(append([]any{}, args...), size, page*size)
	query := db.rebind(`SELECT id, COALESCE(tenant_id, 'default'), client_id, client_name, channel_id, remote_address, connected_at,
		disconnected_at, success, failure_reason, disconnect_reason FROM specus_connection_record` +
		where + ` ORDER BY id DESC LIMIT ? OFFSET ?`)
	rows, err := db.sql.QueryContext(ctx, query, listArgs...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var records []ConnectionRecord
	for rows.Next() {
		var (
			r              ConnectionRecord
			success        databaseBoolean
			connectedAt    string
			disconnectedAt sql.NullString
			channelID      sql.NullString
			remoteAddress  sql.NullString
			failureReason  sql.NullString
			disconnectRsn  sql.NullString
			clientID       sql.NullInt64
		)
		if err := rows.Scan(&r.ID, &r.TenantID, &clientID, &r.ClientName, &channelID, &remoteAddress, &connectedAt,
			&disconnectedAt, &success, &failureReason, &disconnectRsn); err != nil {
			return nil, 0, err
		}
		if clientID.Valid {
			r.ClientID = &clientID.Int64
		}
		if channelID.Valid {
			r.ChannelID = &channelID.String
		}
		if remoteAddress.Valid {
			r.RemoteAddress = &remoteAddress.String
		}
		r.ConnectedAt = parseTime(connectedAt)
		if disconnectedAt.Valid {
			t := parseTime(disconnectedAt.String)
			r.DisconnectedAt = &t
		}
		r.Success = bool(success)
		if failureReason.Valid {
			r.FailureReason = &failureReason.String
		}
		if disconnectRsn.Valid {
			r.DisconnectReason = &disconnectRsn.String
		}
		records = append(records, r)
	}
	return records, total, rows.Err()
}

// ListTraffic returns traffic usage rows, optionally filtered by client id, newest date first.
func (db *DB) ListTraffic(ctx context.Context, clientID *int64, limit int) ([]TrafficUsage, error) {
	return db.ListTrafficScoped(ctx, "", clientID, nil, limit)
}

// ListTrafficScoped returns traffic usage rows constrained to a visible client set when provided.
func (db *DB) ListTrafficScoped(ctx context.Context, tenantID string, clientID *int64, clientIDs []int64, limit int) ([]TrafficUsage, error) {
	query := `SELECT id, COALESCE(tenant_id, 'default'), client_id, client_name, usage_date, upload_bytes, download_bytes, updated_at
		FROM specus_traffic_usage`
	var args []any
	var clauses []string
	if tenantID != "" {
		clauses = append(clauses, `(tenant_id = ? OR tenant_id IS NULL OR tenant_id = '')`)
		args = append(args, defaultTenant(tenantID))
	}
	if clientID != nil {
		clauses = append(clauses, `client_id = ?`)
		args = append(args, *clientID)
	} else if len(clientIDs) > 0 {
		clauses = append(clauses, `client_id IN (`+placeholders(len(clientIDs))+`)`)
		for _, id := range clientIDs {
			args = append(args, id)
		}
	}
	if len(clauses) > 0 {
		query += ` WHERE ` + strings.Join(clauses, ` AND `)
	}
	query += ` ORDER BY usage_date DESC, id DESC`
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	query += ` LIMIT ?`
	args = append(args, limit)
	rows, err := db.sql.QueryContext(ctx, db.rebind(query), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var usages []TrafficUsage
	for rows.Next() {
		var (
			u       TrafficUsage
			updated string
		)
		if err := rows.Scan(&u.ID, &u.TenantID, &u.ClientID, &u.ClientName, &u.UsageDate, &u.UploadBytes,
			&u.DownloadBytes, &updated); err != nil {
			return nil, err
		}
		u.UpdatedAt = parseTime(updated)
		usages = append(usages, u)
	}
	return usages, rows.Err()
}

// ListResourceTrafficScoped returns resource-level usage rows constrained to a visible client set.
func (db *DB) ListResourceTrafficScoped(ctx context.Context, tenantID string, clientID *int64, clientIDs []int64,
	resourceType string, limit int) ([]ResourceTrafficUsage, error) {
	query := `SELECT id, tenant_id, client_id, client_name, resource_type, resource_key, resource_id,
		resource_name, usage_date, upload_bytes, download_bytes, updated_at
		FROM specus_resource_traffic_usage`
	var args []any
	var clauses []string
	if tenantID != "" {
		clauses = append(clauses, `tenant_id = ?`)
		args = append(args, defaultTenant(tenantID))
	}
	if clientID != nil {
		clauses = append(clauses, `client_id = ?`)
		args = append(args, *clientID)
	} else if len(clientIDs) > 0 {
		clauses = append(clauses, `client_id IN (`+placeholders(len(clientIDs))+`)`)
		for _, id := range clientIDs {
			args = append(args, id)
		}
	}
	if resourceType != "" {
		clauses = append(clauses, `resource_type = ?`)
		args = append(args, strings.ToUpper(strings.TrimSpace(resourceType)))
	}
	if len(clauses) > 0 {
		query += ` WHERE ` + strings.Join(clauses, ` AND `)
	}
	query += ` ORDER BY usage_date DESC, id DESC`
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	query += ` LIMIT ?`
	args = append(args, limit)
	rows, err := db.sql.QueryContext(ctx, db.rebind(query), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var usages []ResourceTrafficUsage
	for rows.Next() {
		var (
			u          ResourceTrafficUsage
			resourceID sql.NullInt64
			updated    string
		)
		if err := rows.Scan(&u.ID, &u.TenantID, &u.ClientID, &u.ClientName, &u.ResourceType,
			&u.ResourceKey, &resourceID, &u.ResourceName, &u.UsageDate, &u.UploadBytes,
			&u.DownloadBytes, &updated); err != nil {
			return nil, err
		}
		if resourceID.Valid {
			u.ResourceID = &resourceID.Int64
		}
		u.UpdatedAt = parseTime(updated)
		usages = append(usages, u)
	}
	return usages, rows.Err()
}

// ListConnectionStats returns archived monthly stats, optionally filtered by client name.
func (db *DB) ListConnectionStats(ctx context.Context, clientName string, limit int) ([]ConnectionStat, error) {
	return db.ListConnectionStatsScoped(ctx, "default", clientName, nil, limit)
}

// ListConnectionStatsScoped returns archived monthly stats constrained to one tenant and optionally
// a visible client-id set. A nil clientIDs slice means all tenant rows are visible.
func (db *DB) ListConnectionStatsScoped(ctx context.Context, tenantID, clientName string, clientIDs []int64, limit int) ([]ConnectionStat, error) {
	query := `SELECT id, COALESCE(tenant_id, 'default'), client_id, client_name, stat_month, total_count, success_count, failure_count, updated_at
		FROM specus_connection_stat`
	args := []any{defaultTenant(tenantID)}
	query += ` WHERE (tenant_id = ? OR tenant_id IS NULL OR tenant_id = '')`
	if clientName != "" {
		query += ` AND client_name = ?`
		args = append(args, clientName)
	} else if clientIDs != nil {
		if len(clientIDs) == 0 {
			return nil, nil
		}
		query += ` AND client_id IN (` + placeholders(len(clientIDs)) + `)`
		for _, id := range clientIDs {
			args = append(args, id)
		}
	}
	query += ` ORDER BY stat_month DESC, id DESC`
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	query += ` LIMIT ?`
	args = append(args, limit)
	rows, err := db.sql.QueryContext(ctx, db.rebind(query), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var stats []ConnectionStat
	for rows.Next() {
		var (
			stat     ConnectionStat
			clientID sql.NullInt64
			updated  string
		)
		if err := rows.Scan(&stat.ID, &stat.TenantID, &clientID, &stat.ClientName, &stat.StatMonth, &stat.TotalCount,
			&stat.SuccessCount, &stat.FailureCount, &updated); err != nil {
			return nil, err
		}
		if clientID.Valid {
			stat.ClientID = &clientID.Int64
		}
		stat.UpdatedAt = parseTime(updated)
		stats = append(stats, stat)
	}
	return stats, rows.Err()
}

func placeholders(count int) string {
	if count <= 0 {
		return ""
	}
	return strings.TrimRight(strings.Repeat("?,", count), ",")
}

// Overview aggregates the dashboard counters.
type Overview struct {
	Clients               int64
	SuccessfulConnections int64
	FailedConnections     int64
	UploadBytes           int64
	DownloadBytes         int64
}

// LoadOverview computes the dashboard summary counters.
func (db *DB) LoadOverview(ctx context.Context) (Overview, error) {
	var o Overview
	if err := db.sql.QueryRowContext(ctx, `SELECT COUNT(*) FROM specus_client_account`).Scan(&o.Clients); err != nil {
		return o, err
	}
	if err := db.sql.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM specus_connection_record WHERE success = 1`).Scan(&o.SuccessfulConnections); err != nil {
		return o, err
	}
	if err := db.sql.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM specus_connection_record WHERE success = 0`).Scan(&o.FailedConnections); err != nil {
		return o, err
	}
	if err := db.sql.QueryRowContext(ctx,
		`SELECT COALESCE(SUM(upload_bytes),0), COALESCE(SUM(download_bytes),0) FROM specus_traffic_usage`).
		Scan(&o.UploadBytes, &o.DownloadBytes); err != nil {
		return o, err
	}
	return o, nil
}

// ArchiveOldConnections aggregates connection records older than cutoff into monthly stats and
// deletes them, returning the number of archived rows. Mirrors the Java ConnectionArchiveService.
func (db *DB) ArchiveOldConnections(ctx context.Context, cutoff time.Time) (int64, error) {
	cutoffISO := formatTime(cutoff)
	rows, err := db.sql.QueryContext(ctx, db.rebind(`SELECT COALESCE(tenant_id, 'default'), client_id, client_name, connected_at, success
		FROM specus_connection_record WHERE connected_at < ?`), cutoffISO)
	if err != nil {
		return 0, err
	}
	type key struct {
		tenantID   string
		clientName string
		month      string
	}
	type agg struct {
		clientID             *int64
		total, success, fail int64
	}
	buckets := make(map[key]*agg)
	var archived int64
	for rows.Next() {
		var (
			tenantID    string
			clientID    sql.NullInt64
			clientName  string
			connectedAt string
			success     databaseBoolean
		)
		if err := rows.Scan(&tenantID, &clientID, &clientName, &connectedAt, &success); err != nil {
			rows.Close()
			return 0, err
		}
		month := parseTime(connectedAt).Format("2006-01")
		k := key{tenantID: defaultTenant(tenantID), clientName: clientName, month: month}
		bucket := buckets[k]
		if bucket == nil {
			bucket = &agg{}
			if clientID.Valid {
				id := clientID.Int64
				bucket.clientID = &id
			}
			buckets[k] = bucket
		}
		bucket.total++
		if bool(success) {
			bucket.success++
		} else {
			bucket.fail++
		}
		archived++
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, err
	}
	if archived == 0 {
		return 0, nil
	}

	for k, bucket := range buckets {
		if err := db.upsertStat(ctx, k.tenantID, bucket.clientID, k.clientName, k.month,
			bucket.total, bucket.success, bucket.fail); err != nil {
			return 0, err
		}
	}
	if _, err := db.sql.ExecContext(ctx,
		db.rebind(`DELETE FROM specus_connection_record WHERE connected_at < ?`), cutoffISO); err != nil {
		return 0, err
	}
	return archived, nil
}

func (db *DB) upsertStat(ctx context.Context, tenantID string, clientID *int64, clientName, month string, total, success, fail int64) error {
	now := formatTime(time.Now())
	clientIDValue := nullableInt64(clientID)
	update := db.rebind(`UPDATE specus_connection_stat
		SET client_id = COALESCE(client_id, ?),
			total_count = total_count + ?,
			success_count = success_count + ?,
			failure_count = failure_count + ?,
			updated_at = ?
		WHERE (tenant_id = ? OR tenant_id IS NULL OR tenant_id = '')
			AND client_name = ? AND stat_month = ?`)
	result, err := db.sql.ExecContext(ctx, update, clientIDValue, total, success, fail, now,
		defaultTenant(tenantID), clientName, month)
	if err != nil {
		return err
	}
	if affected, err := result.RowsAffected(); err == nil && affected > 0 {
		return nil
	}
	insert := db.rebind(`INSERT INTO specus_connection_stat
		(tenant_id, client_id, client_name, stat_month, total_count, success_count, failure_count, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`)
	_, err = db.sql.ExecContext(ctx, insert, defaultTenant(tenantID), clientIDValue, clientName, month,
		total, success, fail, now)
	return err
}
