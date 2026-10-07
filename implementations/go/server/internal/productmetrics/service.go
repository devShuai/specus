package productmetrics

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/devShuai/specus/implementations/go/server/internal/store"
)

const (
	sweepFirstDelay = time.Minute
	sweepInterval   = time.Hour
)

// Actor is the authenticated management identity of a request; the tenant and the username come
// from the session, never from a request body.
type Actor struct {
	TenantID string
	Username string
	Admin    bool
}

// Response is the status and JSON body of one endpoint call. A nil body on 401/403 means the
// caller answers with its usual error shape.
type Response struct {
	Status int
	Body   any
}

// Service is the server side of the contract: the switch, the onboarding hooks, ingest, the
// sweep, purge and the summary. It holds no counters of its own; every count lives in the shared
// database, and only the rate limiter is per process.
type Service struct {
	db      *store.DB
	logger  *slog.Logger
	allowed atomic.Bool
	clockMu sync.RWMutex
	now     func() time.Time
	limiter *limiter
}

// New builds the service with the deployment switch on and the contract's default limits.
func New(db *store.DB, logger *slog.Logger) *Service {
	if logger == nil {
		logger = slog.Default()
	}
	service := &Service{db: db, logger: logger, now: time.Now, limiter: newLimiter(DefaultLimits())}
	service.allowed.Store(true)
	return service
}

// SetAllowed applies the deployment-level productMetrics.allowed flag (section 13): when false no
// tenant can switch metrics on and nothing is collected.
func (s *Service) SetAllowed(allowed bool) { s.allowed.Store(allowed) }

// SetClock replaces the clock; tests pin it to each vector op's time.
func (s *Service) SetClock(now func() time.Time) {
	s.clockMu.Lock()
	defer s.clockMu.Unlock()
	s.now = now
}

// SetLimits replaces the rate limits and forgets every window.
func (s *Service) SetLimits(limits Limits) { s.limiter.reset(limits) }

func (s *Service) nowMs() int64 {
	s.clockMu.RLock()
	defer s.clockMu.RUnlock()
	return s.now().UnixMilli()
}

func tenantOf(tenantID string) string {
	if strings.TrimSpace(tenantID) == "" {
		return "default"
	}
	return tenantID
}

func (s *Service) collecting(row *store.ProductMetricsSwitch) bool {
	return s.allowed.Load() && row != nil && row.Enabled
}

// errorClass is what a log line may say about an error (section 14): its Go type, never its text,
// which a database driver may fill with column values.
func errorClass(err error) string { return fmt.Sprintf("%T", err) }

func (s *Service) unavailable(operation, tenantID string, err error) Response {
	s.logger.Warn("product metrics storage failed", "operation", operation, "tenant", tenantID,
		"error", errorClass(err))
	return Response{Status: http.StatusServiceUnavailable, Body: codeBody(CodeUnavailable)}
}

func codeBody(code string) map[string]string { return map[string]string{"code": code} }

// -- settings (7.1, 7.2) -----------------------------------------------------------------------

func (s *Service) settingsView(row *store.ProductMetricsSwitch, admin bool) map[string]any {
	view := map[string]any{"schemaVersion": SchemaVersion, "enabled": s.collecting(row),
		"disclosureVersion": DisclosureVersion, "retentionDays": RetentionDays,
		"onboardingWindowDays": WindowDays, "updatedAt": nil}
	if row != nil && row.UpdatedAtMs != nil {
		view["updatedAt"] = Instant(*row.UpdatedAtMs)
	}
	if admin {
		view["updatedBy"] = nil
		if row != nil && row.UpdatedBy != nil {
			view["updatedBy"] = *row.UpdatedBy
		}
	}
	return view
}

// Settings answers GET /settings for any member of the tenant.
func (s *Service) Settings(ctx context.Context, actor Actor) Response {
	tenant := tenantOf(actor.TenantID)
	row, err := s.db.ProductMetrics().Switch(ctx, tenant)
	if err != nil {
		return s.unavailable("settings", tenant, err)
	}
	return Response{Status: http.StatusOK, Body: s.settingsView(row, actor.Admin)}
}

// PutSettings answers PUT /settings. Switching off drops the tenant's progress rows (they are not
// folded into counts). Any change of state clears the purge mark, so while the switch is off the
// mark only stands for a purge made after switching off; an unchanged state keeps updatedAt/By and
// the mark.
func (s *Service) PutSettings(ctx context.Context, actor Actor, body []byte) Response {
	if !actor.Admin {
		return Response{Status: http.StatusForbidden}
	}
	update, ok := ParseSettingsUpdate(body)
	if !ok {
		return Response{Status: http.StatusBadRequest, Body: codeBody(CodeInvalid)}
	}
	if update.Enabled && (update.Disclosure == nil || *update.Disclosure != "1") {
		return Response{Status: http.StatusBadRequest, Body: codeBody(CodeDisclosureRequired)}
	}
	if update.Enabled && !s.allowed.Load() {
		return Response{Status: http.StatusConflict, Body: codeBody(CodeNotAllowed)}
	}
	tenant := tenantOf(actor.TenantID)
	now := s.nowMs()
	var saved store.ProductMetricsSwitch
	err := s.db.InProductMetricsTx(ctx, func(tx *store.ProductMetricsStore) error {
		row, err := tx.Switch(ctx, tenant)
		if err != nil {
			return err
		}
		if row == nil {
			row = &store.ProductMetricsSwitch{TenantID: tenant}
		}
		if row.Enabled != update.Enabled {
			username := actor.Username
			row.Enabled, row.UpdatedBy, row.UpdatedAtMs, row.PurgedAtMs = update.Enabled, &username, &now, nil
		}
		if err := tx.SaveSwitch(ctx, *row); err != nil {
			return err
		}
		saved = *row
		if !update.Enabled {
			return tx.DeleteTenantProgress(ctx, tenant)
		}
		return nil
	})
	if err != nil {
		return s.unavailable("put-settings", tenant, err)
	}
	return Response{Status: http.StatusOK, Body: s.settingsView(&saved, true)}
}

// -- purge (7.3) -------------------------------------------------------------------------------

// Purge answers DELETE /data: in one transaction it deletes the tenant's progress rows and both
// daily tables' rows and stamps purgedAt.
func (s *Service) Purge(ctx context.Context, actor Actor) Response {
	if !actor.Admin {
		return Response{Status: http.StatusForbidden}
	}
	tenant := tenantOf(actor.TenantID)
	now := s.nowMs()
	var saved store.ProductMetricsSwitch
	err := s.db.InProductMetricsTx(ctx, func(tx *store.ProductMetricsStore) error {
		if err := tx.DeleteTenantProgress(ctx, tenant); err != nil {
			return err
		}
		if err := tx.DeleteTenantCounts(ctx, tenant); err != nil {
			return err
		}
		row, err := tx.Switch(ctx, tenant)
		if err != nil {
			return err
		}
		if row == nil {
			row = &store.ProductMetricsSwitch{TenantID: tenant}
		}
		row.PurgedAtMs = &now
		saved = *row
		return tx.SaveSwitch(ctx, *row)
	})
	if err != nil {
		return s.unavailable("purge", tenant, err)
	}
	return Response{Status: http.StatusOK, Body: map[string]any{"purged": true, "enabled": s.collecting(&saved)}}
}

// -- ingest (7.4) ------------------------------------------------------------------------------

type transferKey struct {
	mode, path, sizeBucket, attempt, outcome string
}

// Ingest answers POST /transfer-outcomes after authentication. body holds at most MaxBodyBytes+1
// raw bytes. The order of section 7.4 holds: size, schema, switch, limiter, count; a refusal at
// any step leaves the limiter untouched. The counting runs in one transaction with atomic upserts.
func (s *Service) Ingest(ctx context.Context, actor Actor, body []byte) Response {
	events, code := ParseIngest(body)
	switch code {
	case CodeTooLarge:
		return Response{Status: http.StatusRequestEntityTooLarge, Body: codeBody(code)}
	case CodeInvalid:
		return Response{Status: http.StatusBadRequest, Body: codeBody(code)}
	}
	tenant := tenantOf(actor.TenantID)
	now := s.nowMs()
	day := DayOfMillis(now)
	counts := map[transferKey]int64{}
	order := make([]transferKey, 0, len(events))
	for _, event := range events {
		key := transferKey{event.Mode, event.Path, event.SizeBucket, event.Attempt, event.Outcome}
		if counts[key] == 0 {
			order = append(order, key)
		}
		counts[key]++
	}
	response := Response{Status: http.StatusOK, Body: map[string]any{"collecting": true, "accepted": len(events)}}
	err := s.db.InProductMetricsTx(ctx, func(tx *store.ProductMetricsStore) error {
		row, err := tx.Switch(ctx, tenant)
		if err != nil {
			return err
		}
		if !s.collecting(row) {
			response = Response{Status: http.StatusOK, Body: map[string]any{"collecting": false, "accepted": 0}}
			return nil
		}
		if !s.limiter.admit(tenant, actor.Username, len(events), now) {
			response = Response{Status: http.StatusTooManyRequests, Body: codeBody(CodeRateLimited)}
			return nil
		}
		for _, key := range order {
			if err := tx.AddTransferCount(ctx, store.ProductMetricsTransferCount{TenantID: tenant, Day: day,
				Mode: key.mode, Path: key.path, SizeBucket: key.sizeBucket, Attempt: key.attempt,
				Outcome: key.outcome, Count: counts[key]}); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return s.unavailable("ingest", tenant, err)
	}
	return response
}

// -- onboarding hooks (4.1) --------------------------------------------------------------------

func milestoneColumn(step string) string {
	switch step {
	case StepSignedIn:
		return store.ProductMetricsSignedInColumn
	case StepCredentialCreated:
		return store.ProductMetricsCredentialCreatedColumn
	case StepClientOnline:
		return store.ProductMetricsClientOnlineColumn
	}
	return ""
}

func reachedStep(row store.ProductMetricsProgress) string {
	switch {
	case row.ClientOnlineAtMs != nil:
		return StepClientOnline
	case row.CredentialCreatedAtMs != nil:
		return StepCredentialCreated
	case row.SignedInAtMs != nil:
		return StepSignedIn
	}
	return StepAccountCreated
}

// Milestone records one onboarding milestone observed on a server write path, after that write
// succeeded, and returns its effect ("ignored", "started", "recorded", "completed" or "expired",
// for tests only). It never fails the caller: storage errors are logged without the username.
func (s *Service) Milestone(ctx context.Context, tenantID, username, step string) string {
	tenant := tenantOf(tenantID)
	effect, err := s.milestone(ctx, tenant, username, step)
	if err != nil {
		s.logger.Warn("product metrics milestone failed", "tenant", tenant, "step", step, "error", errorClass(err))
		return "ignored"
	}
	return effect
}

func (s *Service) milestone(ctx context.Context, tenant, username, step string) (string, error) {
	if !s.allowed.Load() || strings.TrimSpace(username) == "" {
		return "ignored", nil
	}
	metrics := s.db.ProductMetrics()
	row, err := metrics.Switch(ctx, tenant)
	if err != nil || !s.collecting(row) {
		return "ignored", err
	}
	now := s.nowMs()
	if step == StepAccountCreated {
		started, err := metrics.InsertProgressIfAbsent(ctx, store.ProductMetricsProgress{TenantID: tenant,
			Username: username, StartedAtMs: now})
		if err != nil || !started {
			return "ignored", err
		}
		return "started", nil
	}
	column := milestoneColumn(step)
	if column == "" && step != StepServicePublished {
		return "ignored", nil
	}
	progress, err := metrics.Progress(ctx, tenant, username)
	if err != nil || progress == nil {
		return "ignored", err
	}
	if now >= progress.StartedAtMs+windowMs {
		if _, err := s.close(ctx, tenant, username, nil); err != nil {
			return "ignored", err
		}
		return "expired", nil
	}
	if step == StepServicePublished {
		closed, err := s.close(ctx, tenant, username, &now)
		if err != nil || !closed {
			return "ignored", err
		}
		return "completed", nil
	}
	recorded, err := metrics.SetMilestone(ctx, tenant, username, column, now)
	if err != nil || !recorded {
		return "ignored", err
	}
	return "recorded", nil
}

// close folds one progress row into the daily cohort counter: completed when completedAt is set,
// otherwise at the furthest recorded step. Deleting the row must remove exactly one row before the
// counter moves, so a completion racing the sweep (or another instance) is counted once.
func (s *Service) close(ctx context.Context, tenant, username string, completedAt *int64) (bool, error) {
	closed := false
	err := s.db.InProductMetricsTx(ctx, func(tx *store.ProductMetricsStore) error {
		row, err := tx.Progress(ctx, tenant, username)
		if err != nil || row == nil {
			return err
		}
		removed, err := tx.DeleteProgress(ctx, tenant, username)
		if err != nil || removed != 1 {
			return err
		}
		reached, bucket := reachedStep(*row), NoDuration
		if completedAt != nil {
			elapsed := *completedAt - row.StartedAtMs
			if elapsed < 0 {
				elapsed = 0
			}
			name, ok := DurationBucket(elapsed / 1000)
			if !ok {
				return nil // unreachable: callers expire such rows instead
			}
			reached, bucket = StepServicePublished, name
		}
		closed = true
		return tx.AddOnboardingCount(ctx, store.ProductMetricsOnboardingCount{TenantID: tenant,
			CohortDay: DayOfMillis(row.StartedAtMs), ReachedStep: reached, DurationBucket: bucket, Users: 1})
	})
	return closed && err == nil, err
}

// UserDeleted drops the account's progress row without folding it into any count.
func (s *Service) UserDeleted(ctx context.Context, tenantID, username string) string {
	tenant := tenantOf(tenantID)
	removed, err := s.db.ProductMetrics().DeleteProgress(ctx, tenant, username)
	if err != nil {
		s.logger.Warn("product metrics progress removal failed", "tenant", tenant, "error", errorClass(err))
		return "ignored"
	}
	if removed > 0 {
		return "deleted"
	}
	return "ignored"
}

// -- retention (9) -----------------------------------------------------------------------------

// Sweep runs the four retention steps of section 9. It is idempotent, its result does not depend
// on when it runs, and any number of instances may run it. Step 4 only reaches tenants purged since
// they switched off: switching off clears the mark a purge made while collecting.
func (s *Service) Sweep(ctx context.Context) error {
	now := s.nowMs()
	metrics := s.db.ProductMetrics()
	switches, err := metrics.Switches(ctx)
	if err != nil {
		return err
	}
	enabled := map[string]bool{}
	for index := range switches {
		enabled[switches[index].TenantID] = s.collecting(&switches[index])
	}
	progress, err := metrics.ProgressRows(ctx, "")
	if err != nil {
		return err
	}
	sort.Slice(progress, func(i, j int) bool {
		if progress[i].TenantID != progress[j].TenantID {
			return progress[i].TenantID < progress[j].TenantID
		}
		return progress[i].Username < progress[j].Username
	})
	for _, row := range progress {
		switch {
		case !enabled[row.TenantID]:
			if _, err := metrics.DeleteProgress(ctx, row.TenantID, row.Username); err != nil {
				return err
			}
		case now >= row.StartedAtMs+windowMs:
			if _, err := s.close(ctx, row.TenantID, row.Username, nil); err != nil {
				return err
			}
		}
	}
	cutoff := DayOfMillis(now - (RetentionDays-1)*dayMs)
	if err := metrics.DeleteCountsBefore(ctx, cutoff); err != nil {
		return err
	}
	for _, row := range switches {
		if !row.Enabled && row.PurgedAtMs != nil {
			if err := metrics.DeleteTenantCounts(ctx, row.TenantID); err != nil {
				return err
			}
			if err := metrics.DeleteTenantProgress(ctx, row.TenantID); err != nil {
				return err
			}
		}
	}
	return nil
}

// Run sweeps a minute after start and then every hour until ctx ends.
func (s *Service) Run(ctx context.Context) {
	timer := time.NewTimer(sweepFirstDelay)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
		if err := s.Sweep(ctx); err != nil && ctx.Err() == nil {
			s.logger.Warn("product metrics sweep failed", "error", errorClass(err))
		}
		timer.Reset(sweepInterval)
	}
}

// -- summary (7.5) -----------------------------------------------------------------------------

type stepSummary struct {
	Step               string `json:"step"`
	Users              int64  `json:"users"`
	FromPreviousRateBp *int64 `json:"fromPreviousRateBp"`
}

type durationSummary struct {
	Bucket string `json:"bucket"`
	Users  int64  `json:"users"`
}

type onboardingSummary struct {
	WindowDays           int               `json:"windowDays"`
	CohortUsers          int64             `json:"cohortUsers"`
	PendingUsers         int64             `json:"pendingUsers"`
	Final                bool              `json:"final"`
	Steps                []stepSummary     `json:"steps"`
	Completed            int64             `json:"completed"`
	CompletionRateBp     *int64            `json:"completionRateBp"`
	Durations            []durationSummary `json:"durations"`
	MedianDurationBucket *string           `json:"medianDurationBucket"`
}

type tally struct {
	Success       int64  `json:"success"`
	Failure       int64  `json:"failure"`
	Cancelled     int64  `json:"cancelled"`
	SuccessRateBp *int64 `json:"successRateBp"`
}

type cellSummary struct {
	Path       string `json:"path"`
	SizeBucket string `json:"sizeBucket"`
	tally
}

type modeSummary struct {
	Mode string `json:"mode"`
	tally
}

type attemptSummary struct {
	Attempt string `json:"attempt"`
	tally
}

type transferSummary struct {
	Cells     []cellSummary    `json:"cells"`
	ByMode    []modeSummary    `json:"byMode"`
	ByAttempt []attemptSummary `json:"byAttempt"`
	Total     tally            `json:"total"`
}

type summaryBody struct {
	SchemaVersion int               `json:"schemaVersion"`
	Enabled       bool              `json:"enabled"`
	From          string            `json:"from"`
	To            string            `json:"to"`
	GeneratedAt   string            `json:"generatedAt"`
	Onboarding    onboardingSummary `json:"onboarding"`
	Transfers     transferSummary   `json:"transfers"`
}

func parseDay(text string) (time.Time, bool) {
	if len(text) != len("2006-01-02") {
		return time.Time{}, false
	}
	day, err := time.Parse("2006-01-02", text)
	return day, err == nil
}

// Summary answers GET /summary?from&to for the tenant's ADMIN.
func (s *Service) Summary(ctx context.Context, actor Actor, query url.Values) Response {
	if !actor.Admin {
		return Response{Status: http.StatusForbidden}
	}
	now := s.nowMs()
	today, _ := parseDay(DayOfMillis(now))
	toDay, fromDay := today, time.Time{}
	if query.Has("to") {
		parsed, ok := parseDay(query.Get("to"))
		if !ok {
			return Response{Status: http.StatusBadRequest, Body: codeBody(CodeRange)}
		}
		toDay = parsed
	}
	fromDay = toDay.AddDate(0, 0, -29)
	if query.Has("from") {
		parsed, ok := parseDay(query.Get("from"))
		if !ok {
			return Response{Status: http.StatusBadRequest, Body: codeBody(CodeRange)}
		}
		fromDay = parsed
	}
	spanDays := int64(toDay.Sub(fromDay)/(24*time.Hour)) + 1
	if fromDay.After(toDay) || spanDays > MaxRangeDays || toDay.After(today) ||
		fromDay.Before(today.AddDate(0, 0, -(RetentionDays-1))) {
		return Response{Status: http.StatusBadRequest, Body: codeBody(CodeRange)}
	}
	tenant := tenantOf(actor.TenantID)
	low, high := Day(fromDay), Day(toDay)
	metrics := s.db.ProductMetrics()
	row, err := metrics.Switch(ctx, tenant)
	if err != nil {
		return s.unavailable("summary", tenant, err)
	}
	cohorts, err := metrics.OnboardingCounts(ctx, tenant, low, high)
	if err != nil {
		return s.unavailable("summary", tenant, err)
	}
	progress, err := metrics.ProgressRows(ctx, tenant)
	if err != nil {
		return s.unavailable("summary", tenant, err)
	}
	transfers, err := metrics.TransferCounts(ctx, tenant, low, high)
	if err != nil {
		return s.unavailable("summary", tenant, err)
	}
	return Response{Status: http.StatusOK, Body: summaryBody{SchemaVersion: SchemaVersion,
		Enabled: s.collecting(row), From: low, To: high, GeneratedAt: Instant(now),
		Onboarding: onboardingOf(cohorts, progress, low, high, now), Transfers: transfersOf(transfers)}}
}

func onboardingOf(cohorts []store.ProductMetricsOnboardingCount, progress []store.ProductMetricsProgress,
	low, high string, now int64) onboardingSummary {
	reached := map[string]int64{}
	durations := map[string]int64{}
	var pending int64
	for _, row := range cohorts {
		reached[row.ReachedStep] += row.Users
		if row.DurationBucket != NoDuration {
			durations[row.DurationBucket] += row.Users
		}
	}
	for _, row := range progress {
		if day := DayOfMillis(row.StartedAtMs); day < low || day > high {
			continue
		}
		reached[reachedStep(row)]++
		if now < row.StartedAtMs+windowMs {
			pending++
		}
	}
	steps := make([]stepSummary, 0, len(Steps))
	var previous *int64
	for index, step := range Steps {
		var users int64
		for _, later := range Steps[index:] {
			users += reached[later]
		}
		summary := stepSummary{Step: step, Users: users}
		if previous != nil {
			summary.FromPreviousRateBp = RateBp(users, *previous)
		}
		steps = append(steps, summary)
		count := users
		previous = &count
	}
	cohortUsers, completed := steps[0].Users, steps[len(steps)-1].Users
	buckets := make([]durationSummary, 0, len(DurationBuckets))
	var completers int64
	for _, name := range DurationBuckets {
		buckets = append(buckets, durationSummary{Bucket: name, Users: durations[name]})
		completers += durations[name]
	}
	var median *string
	if completers > 0 {
		position := (completers + 1) / 2 // the ceil(n/2)-th completer, counted from 1
		for _, bucket := range buckets {
			if position <= bucket.Users {
				name := bucket.Bucket
				median = &name
				break
			}
			position -= bucket.Users
		}
	}
	return onboardingSummary{WindowDays: WindowDays, CohortUsers: cohortUsers, PendingUsers: pending,
		Final: pending == 0, Steps: steps, Completed: completed, CompletionRateBp: RateBp(completed, cohortUsers),
		Durations: buckets, MedianDurationBucket: median}
}

func tallyOf(rows []store.ProductMetricsTransferCount, match func(store.ProductMetricsTransferCount) bool) tally {
	var result tally
	for _, row := range rows {
		if !match(row) {
			continue
		}
		switch row.Outcome {
		case "success":
			result.Success += row.Count
		case "failure":
			result.Failure += row.Count
		case "cancelled":
			result.Cancelled += row.Count
		}
	}
	result.SuccessRateBp = RateBp(result.Success, result.Success+result.Failure)
	return result
}

func transfersOf(rows []store.ProductMetricsTransferCount) transferSummary {
	summary := transferSummary{Cells: []cellSummary{}}
	for _, path := range Paths {
		for _, size := range SizeBuckets {
			counts := tallyOf(rows, func(row store.ProductMetricsTransferCount) bool {
				return row.Path == path && row.SizeBucket == size
			})
			if counts.Success+counts.Failure+counts.Cancelled > 0 {
				summary.Cells = append(summary.Cells, cellSummary{Path: path, SizeBucket: size, tally: counts})
			}
		}
	}
	for _, mode := range Modes {
		summary.ByMode = append(summary.ByMode, modeSummary{Mode: mode,
			tally: tallyOf(rows, func(row store.ProductMetricsTransferCount) bool { return row.Mode == mode })})
	}
	for _, attempt := range Attempts {
		summary.ByAttempt = append(summary.ByAttempt, attemptSummary{Attempt: attempt,
			tally: tallyOf(rows, func(row store.ProductMetricsTransferCount) bool { return row.Attempt == attempt })})
	}
	summary.Total = tallyOf(rows, func(store.ProductMetricsTransferCount) bool { return true })
	return summary
}
