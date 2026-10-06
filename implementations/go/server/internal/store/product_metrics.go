package store

import (
	"context"
	"database/sql"
	"errors"
)

// ---- product metrics --------------------------------------------------------------------
//
// Opt-in product metrics keep four tables (protocol/spec/product-metrics.md section 6): the
// per-tenant switch, onboarding progress per account (only for the 14-day window), and two daily
// counter tables that carry no user column at all. Times are epoch milliseconds, days are UTC
// "YYYY-MM-DD" text, so day ranges and the retention cutoff are plain string comparisons. The
// rules (window, buckets, ordering) live in the productmetrics package; this file only reads and
// writes rows.

// ProductMetricsSwitch is one row of product_metrics_switch.
type ProductMetricsSwitch struct {
	TenantID    string
	Enabled     bool
	UpdatedBy   *string
	UpdatedAtMs *int64
	PurgedAtMs  *int64
}

// ProductMetricsProgress is one row of product_metrics_onboarding_progress.
type ProductMetricsProgress struct {
	TenantID              string
	Username              string
	StartedAtMs           int64
	SignedInAtMs          *int64
	CredentialCreatedAtMs *int64
	ClientOnlineAtMs      *int64
}

// ProductMetricsOnboardingCount is one row of product_metrics_onboarding_daily.
type ProductMetricsOnboardingCount struct {
	TenantID       string
	CohortDay      string
	ReachedStep    string
	DurationBucket string
	Users          int64
}

// ProductMetricsTransferCount is one row of product_metrics_transfer_daily.
type ProductMetricsTransferCount struct {
	TenantID   string
	Day        string
	Mode       string
	Path       string
	SizeBucket string
	Attempt    string
	Outcome    string
	Count      int64
}

// Progress milestone columns; the only column names SetProductMetricsMilestone accepts.
const (
	ProductMetricsSignedInColumn          = "signed_in_at"
	ProductMetricsCredentialCreatedColumn = "credential_created_at"
	ProductMetricsClientOnlineColumn      = "client_online_at"
)

// productMetricsExec is what both *sql.DB and *sql.Tx offer; every query below runs on either.
type productMetricsExec interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

// ProductMetricsStore runs product metrics reads and writes, either directly on the database or
// inside one transaction (see InProductMetricsTx).
type ProductMetricsStore struct {
	db   *DB
	exec productMetricsExec
}

// ProductMetrics returns the store outside of any transaction.
func (db *DB) ProductMetrics() *ProductMetricsStore {
	return &ProductMetricsStore{db: db, exec: db.sql}
}

// InProductMetricsTx runs fn in one transaction and commits it when fn returns nil.
func (db *DB) InProductMetricsTx(ctx context.Context, fn func(*ProductMetricsStore) error) error {
	tx, err := db.sql.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := fn(&ProductMetricsStore{db: db, exec: tx}); err != nil {
		return err
	}
	return tx.Commit()
}

// -- switch -------------------------------------------------------------------------------------

// Switch returns the tenant's switch row, or nil when the tenant never had one.
func (s *ProductMetricsStore) Switch(ctx context.Context, tenantID string) (*ProductMetricsSwitch, error) {
	row := s.exec.QueryRowContext(ctx, s.db.rebind(`SELECT tenant_id, enabled, updated_by, updated_at, purged_at
		FROM product_metrics_switch WHERE tenant_id = ?`), tenantID)
	value, err := scanProductMetricsSwitch(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &value, nil
}

// SaveSwitch writes the whole switch row, inserting it when absent.
func (s *ProductMetricsStore) SaveSwitch(ctx context.Context, row ProductMetricsSwitch) error {
	enabled := s.db.clientMessageCapabilityValue(row.Enabled)
	result, err := s.exec.ExecContext(ctx, s.db.rebind(`UPDATE product_metrics_switch
		SET enabled = ?, updated_by = ?, updated_at = ?, purged_at = ? WHERE tenant_id = ?`),
		enabled, productMetricsText(row.UpdatedBy), nullableInt64(row.UpdatedAtMs), nullableInt64(row.PurgedAtMs), row.TenantID)
	if err != nil {
		return err
	}
	if updated, err := result.RowsAffected(); err != nil || updated > 0 {
		return err
	}
	_, err = s.exec.ExecContext(ctx, s.db.rebind(`INSERT INTO product_metrics_switch
		(tenant_id, enabled, updated_by, updated_at, purged_at) VALUES (?, ?, ?, ?, ?)`),
		row.TenantID, enabled, productMetricsText(row.UpdatedBy), nullableInt64(row.UpdatedAtMs), nullableInt64(row.PurgedAtMs))
	return err
}

// Switches returns every switch row.
func (s *ProductMetricsStore) Switches(ctx context.Context) ([]ProductMetricsSwitch, error) {
	rows, err := s.exec.QueryContext(ctx, `SELECT tenant_id, enabled, updated_by, updated_at, purged_at
		FROM product_metrics_switch`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	switches := make([]ProductMetricsSwitch, 0)
	for rows.Next() {
		value, err := scanProductMetricsSwitch(rows)
		if err != nil {
			return nil, err
		}
		switches = append(switches, value)
	}
	return switches, rows.Err()
}

// -- onboarding progress ------------------------------------------------------------------------

// InsertProgressIfAbsent starts a progress row and reports whether it did; an existing row of the
// account is left as it is.
func (s *ProductMetricsStore) InsertProgressIfAbsent(ctx context.Context, row ProductMetricsProgress) (bool, error) {
	var query string
	switch s.db.dialect {
	case DialectMySQL:
		query = `INSERT INTO product_metrics_onboarding_progress
			(tenant_id, username, started_at, signed_in_at, credential_created_at, client_online_at)
			VALUES (?, ?, ?, ?, ?, ?) ON DUPLICATE KEY UPDATE tenant_id = tenant_id`
	default:
		query = `INSERT INTO product_metrics_onboarding_progress
			(tenant_id, username, started_at, signed_in_at, credential_created_at, client_online_at)
			VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT (tenant_id, username) DO NOTHING`
	}
	result, err := s.exec.ExecContext(ctx, s.db.rebind(query), row.TenantID, row.Username, row.StartedAtMs,
		nullableInt64(row.SignedInAtMs), nullableInt64(row.CredentialCreatedAtMs), nullableInt64(row.ClientOnlineAtMs))
	if err != nil {
		return false, err
	}
	inserted, err := result.RowsAffected()
	return inserted == 1, err
}

// Progress returns the account's progress row, or nil.
func (s *ProductMetricsStore) Progress(ctx context.Context, tenantID, username string) (*ProductMetricsProgress, error) {
	row := s.exec.QueryRowContext(ctx, s.db.rebind(`SELECT tenant_id, username, started_at, signed_in_at,
		credential_created_at, client_online_at FROM product_metrics_onboarding_progress
		WHERE tenant_id = ? AND username = ?`), tenantID, username)
	value, err := scanProductMetricsProgress(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &value, nil
}

// SetMilestone records a milestone time unless one is already recorded, and reports whether it
// did: the first occurrence wins, also between instances.
func (s *ProductMetricsStore) SetMilestone(ctx context.Context, tenantID, username, column string,
	atMs int64) (bool, error) {
	switch column {
	case ProductMetricsSignedInColumn, ProductMetricsCredentialCreatedColumn, ProductMetricsClientOnlineColumn:
	default:
		return false, errors.New("unknown product metrics milestone column")
	}
	result, err := s.exec.ExecContext(ctx, s.db.rebind(`UPDATE product_metrics_onboarding_progress SET `+column+` = ?
		WHERE tenant_id = ? AND username = ? AND `+column+` IS NULL`), atMs, tenantID, username)
	if err != nil {
		return false, err
	}
	updated, err := result.RowsAffected()
	return updated == 1, err
}

// DeleteProgress removes one account's progress row and reports how many rows it removed; folding
// a row into the daily counts only follows a removal of exactly one row.
func (s *ProductMetricsStore) DeleteProgress(ctx context.Context, tenantID, username string) (int64, error) {
	result, err := s.exec.ExecContext(ctx, s.db.rebind(`DELETE FROM product_metrics_onboarding_progress
		WHERE tenant_id = ? AND username = ?`), tenantID, username)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}

// DeleteTenantProgress removes every progress row of a tenant.
func (s *ProductMetricsStore) DeleteTenantProgress(ctx context.Context, tenantID string) error {
	_, err := s.exec.ExecContext(ctx, s.db.rebind(`DELETE FROM product_metrics_onboarding_progress
		WHERE tenant_id = ?`), tenantID)
	return err
}

// ProgressRows returns the progress rows of one tenant, or of every tenant when tenantID is empty.
func (s *ProductMetricsStore) ProgressRows(ctx context.Context, tenantID string) ([]ProductMetricsProgress, error) {
	query := `SELECT tenant_id, username, started_at, signed_in_at, credential_created_at, client_online_at
		FROM product_metrics_onboarding_progress`
	var args []any
	if tenantID != "" {
		query += ` WHERE tenant_id = ?`
		args = append(args, tenantID)
	}
	rows, err := s.exec.QueryContext(ctx, s.db.rebind(query), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	progress := make([]ProductMetricsProgress, 0)
	for rows.Next() {
		value, err := scanProductMetricsProgress(rows)
		if err != nil {
			return nil, err
		}
		progress = append(progress, value)
	}
	return progress, rows.Err()
}

// -- daily counts -------------------------------------------------------------------------------

// AddOnboardingCount adds users to one cohort counter with an atomic upsert.
func (s *ProductMetricsStore) AddOnboardingCount(ctx context.Context, row ProductMetricsOnboardingCount) error {
	var query string
	switch s.db.dialect {
	case DialectMySQL:
		query = `INSERT INTO product_metrics_onboarding_daily
			(tenant_id, cohort_day, reached_step, duration_bucket, users) VALUES (?, ?, ?, ?, ?)
			ON DUPLICATE KEY UPDATE users = users + VALUES(users)`
	case DialectPostgres:
		query = `INSERT INTO product_metrics_onboarding_daily
			(tenant_id, cohort_day, reached_step, duration_bucket, users) VALUES (?, ?, ?, ?, ?)
			ON CONFLICT (tenant_id, cohort_day, reached_step, duration_bucket)
			DO UPDATE SET users = product_metrics_onboarding_daily.users + EXCLUDED.users`
	default:
		query = `INSERT INTO product_metrics_onboarding_daily
			(tenant_id, cohort_day, reached_step, duration_bucket, users) VALUES (?, ?, ?, ?, ?)
			ON CONFLICT (tenant_id, cohort_day, reached_step, duration_bucket)
			DO UPDATE SET users = users + excluded.users`
	}
	_, err := s.exec.ExecContext(ctx, s.db.rebind(query), row.TenantID, row.CohortDay, row.ReachedStep,
		row.DurationBucket, row.Users)
	return err
}

// AddTransferCount adds to one transfer counter with an atomic upsert; never read-then-write.
func (s *ProductMetricsStore) AddTransferCount(ctx context.Context, row ProductMetricsTransferCount) error {
	var query string
	switch s.db.dialect {
	case DialectMySQL:
		query = `INSERT INTO product_metrics_transfer_daily
			(tenant_id, day, mode, path, size_bucket, attempt, outcome, count) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
			ON DUPLICATE KEY UPDATE count = count + VALUES(count)`
	case DialectPostgres:
		query = `INSERT INTO product_metrics_transfer_daily
			(tenant_id, day, mode, path, size_bucket, attempt, outcome, count) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
			ON CONFLICT (tenant_id, day, mode, path, size_bucket, attempt, outcome)
			DO UPDATE SET count = product_metrics_transfer_daily.count + EXCLUDED.count`
	default:
		query = `INSERT INTO product_metrics_transfer_daily
			(tenant_id, day, mode, path, size_bucket, attempt, outcome, count) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
			ON CONFLICT (tenant_id, day, mode, path, size_bucket, attempt, outcome)
			DO UPDATE SET count = count + excluded.count`
	}
	_, err := s.exec.ExecContext(ctx, s.db.rebind(query), row.TenantID, row.Day, row.Mode, row.Path,
		row.SizeBucket, row.Attempt, row.Outcome, row.Count)
	return err
}

// OnboardingCounts returns cohort counters of one tenant with fromDay <= cohort_day <= toDay; an
// empty tenantID selects every tenant and empty days leave that side open.
func (s *ProductMetricsStore) OnboardingCounts(ctx context.Context, tenantID, fromDay, toDay string) (
	[]ProductMetricsOnboardingCount, error) {
	where, args := productMetricsDayFilter("cohort_day", tenantID, fromDay, toDay)
	rows, err := s.exec.QueryContext(ctx, s.db.rebind(`SELECT tenant_id, cohort_day, reached_step, duration_bucket,
		users FROM product_metrics_onboarding_daily`+where), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	counts := make([]ProductMetricsOnboardingCount, 0)
	for rows.Next() {
		var row ProductMetricsOnboardingCount
		if err := rows.Scan(&row.TenantID, &row.CohortDay, &row.ReachedStep, &row.DurationBucket, &row.Users); err != nil {
			return nil, err
		}
		counts = append(counts, row)
	}
	return counts, rows.Err()
}

// TransferCounts returns transfer counters filtered like OnboardingCounts.
func (s *ProductMetricsStore) TransferCounts(ctx context.Context, tenantID, fromDay, toDay string) (
	[]ProductMetricsTransferCount, error) {
	where, args := productMetricsDayFilter("day", tenantID, fromDay, toDay)
	rows, err := s.exec.QueryContext(ctx, s.db.rebind(`SELECT tenant_id, day, mode, path, size_bucket, attempt,
		outcome, count FROM product_metrics_transfer_daily`+where), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	counts := make([]ProductMetricsTransferCount, 0)
	for rows.Next() {
		var row ProductMetricsTransferCount
		if err := rows.Scan(&row.TenantID, &row.Day, &row.Mode, &row.Path, &row.SizeBucket, &row.Attempt,
			&row.Outcome, &row.Count); err != nil {
			return nil, err
		}
		counts = append(counts, row)
	}
	return counts, rows.Err()
}

// DeleteTenantCounts removes both daily tables' rows of a tenant.
func (s *ProductMetricsStore) DeleteTenantCounts(ctx context.Context, tenantID string) error {
	for _, table := range []string{"product_metrics_onboarding_daily", "product_metrics_transfer_daily"} {
		if _, err := s.exec.ExecContext(ctx, s.db.rebind(`DELETE FROM `+table+` WHERE tenant_id = ?`),
			tenantID); err != nil {
			return err
		}
	}
	return nil
}

// DeleteCountsBefore removes the daily rows of every tenant dated before cutoffDay.
func (s *ProductMetricsStore) DeleteCountsBefore(ctx context.Context, cutoffDay string) error {
	if _, err := s.exec.ExecContext(ctx, s.db.rebind(`DELETE FROM product_metrics_onboarding_daily
		WHERE cohort_day < ?`), cutoffDay); err != nil {
		return err
	}
	_, err := s.exec.ExecContext(ctx, s.db.rebind(`DELETE FROM product_metrics_transfer_daily WHERE day < ?`),
		cutoffDay)
	return err
}

func productMetricsDayFilter(column, tenantID, fromDay, toDay string) (string, []any) {
	var clauses []string
	var args []any
	if tenantID != "" {
		clauses = append(clauses, "tenant_id = ?")
		args = append(args, tenantID)
	}
	if fromDay != "" {
		clauses = append(clauses, column+" >= ?")
		args = append(args, fromDay)
	}
	if toDay != "" {
		clauses = append(clauses, column+" <= ?")
		args = append(args, toDay)
	}
	if len(clauses) == 0 {
		return "", nil
	}
	where := " WHERE " + clauses[0]
	for _, clause := range clauses[1:] {
		where += " AND " + clause
	}
	return where, args
}

type productMetricsScanner interface {
	Scan(dest ...any) error
}

func scanProductMetricsSwitch(row productMetricsScanner) (ProductMetricsSwitch, error) {
	var (
		value     ProductMetricsSwitch
		enabled   databaseBoolean
		updatedBy sql.NullString
		updatedAt sql.NullInt64
		purgedAt  sql.NullInt64
	)
	if err := row.Scan(&value.TenantID, &enabled, &updatedBy, &updatedAt, &purgedAt); err != nil {
		return ProductMetricsSwitch{}, err
	}
	value.Enabled = bool(enabled)
	if updatedBy.Valid {
		text := updatedBy.String
		value.UpdatedBy = &text
	}
	value.UpdatedAtMs = productMetricsMillis(updatedAt)
	value.PurgedAtMs = productMetricsMillis(purgedAt)
	return value, nil
}

func scanProductMetricsProgress(row productMetricsScanner) (ProductMetricsProgress, error) {
	var (
		value                        ProductMetricsProgress
		signedIn, credential, client sql.NullInt64
	)
	if err := row.Scan(&value.TenantID, &value.Username, &value.StartedAtMs, &signedIn, &credential,
		&client); err != nil {
		return ProductMetricsProgress{}, err
	}
	value.SignedInAtMs = productMetricsMillis(signedIn)
	value.CredentialCreatedAtMs = productMetricsMillis(credential)
	value.ClientOnlineAtMs = productMetricsMillis(client)
	return value, nil
}

func productMetricsMillis(value sql.NullInt64) *int64 {
	if !value.Valid {
		return nil
	}
	number := value.Int64
	return &number
}

func productMetricsText(value *string) any {
	if value == nil {
		return nil
	}
	return *value
}
