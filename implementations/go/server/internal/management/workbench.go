package management

import (
	"context"
	"errors"
	"math"
	"net/http"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/devShuai/specus/implementations/go/server/internal/store"
)

// Service workbench: each management identity (tenant + username, exactly as authenticated)
// keeps a list of favourite services and a list of services it recently opened from the admin
// web. Rows hold references and times only; the page resolves them against the lists it already
// reads. No endpoint reads or clears another identity's lists, administrators included.
// See protocol/spec/service-workbench.md.

const (
	workbenchMaxFavorites       = 50
	workbenchMaxRecents         = 20
	workbenchRetentionDays      = 30
	workbenchRetentionMs        = int64(workbenchRetentionDays) * 24 * 3600 * 1000
	workbenchMaxObjectID        = int64(1)<<53 - 1
	workbenchRateIntervalMs     = int64(1000)
	workbenchRateBurst          = 30
	workbenchRateMaxKeys        = 10_000
	workbenchSweepInterval      = time.Hour
	workbenchSweepFirstDelay    = time.Minute
	workbenchCodeInvalid        = "WORKBENCH_REQUEST_INVALID"
	workbenchCodeRateLimited    = "WORKBENCH_RATE_LIMITED"
	workbenchCodeUnavailable    = "WORKBENCH_UNAVAILABLE"
	workbenchCodeTargetNotFound = "WORKBENCH_TARGET_NOT_FOUND"
	workbenchCodeFavoritesFull  = "WORKBENCH_FAVORITES_FULL"
)

// workbenchKinds is closed; its order is also the tie-break order of both lists.
var workbenchKinds = []string{store.WorkbenchKindHTTPRoute, store.WorkbenchKindTCPMapping, store.WorkbenchKindPeerService}

type workbenchOp struct {
	name   string
	list   string
	hasRef bool
	growth bool
}

var (
	workbenchGet            = workbenchOp{name: "get"}
	workbenchAddFavorite    = workbenchOp{name: "add-favorite", list: store.WorkbenchListFavorite, hasRef: true, growth: true}
	workbenchRemoveFavorite = workbenchOp{name: "remove-favorite", list: store.WorkbenchListFavorite, hasRef: true}
	workbenchClearFavorites = workbenchOp{name: "clear-favorites", list: store.WorkbenchListFavorite}
	workbenchRecordVisit    = workbenchOp{name: "record-visit", list: store.WorkbenchListRecent, hasRef: true, growth: true}
	workbenchRemoveRecent   = workbenchOp{name: "remove-recent", list: store.WorkbenchListRecent, hasRef: true}
	workbenchClearRecents   = workbenchOp{name: "clear-recents", list: store.WorkbenchListRecent}
)

var errWorkbenchFavoritesFull = errors.New("workbench favourites are full")

// workbench holds what the endpoints share beyond the database: the clock, the growth limiter and
// the lock that keeps the favourites bound within one instance.
type workbench struct {
	now         func() time.Time
	limiter     *workbenchLimiter
	favoritesMu sync.Mutex
}

func newWorkbench() *workbench {
	return &workbench{now: time.Now, limiter: newWorkbenchLimiter()}
}

func (a *API) registerWorkbench(mux *http.ServeMux) {
	routes := []struct {
		pattern string
		op      workbenchOp
	}{
		{"GET /api/admin/workbench", workbenchGet},
		{"PUT /api/admin/workbench/favorites/{kind}/{id}", workbenchAddFavorite},
		{"DELETE /api/admin/workbench/favorites/{kind}/{id}", workbenchRemoveFavorite},
		{"DELETE /api/admin/workbench/favorites", workbenchClearFavorites},
		{"POST /api/admin/workbench/recents/{kind}/{id}", workbenchRecordVisit},
		{"DELETE /api/admin/workbench/recents/{kind}/{id}", workbenchRemoveRecent},
		{"DELETE /api/admin/workbench/recents", workbenchClearRecents},
	}
	for _, route := range routes {
		handler := a.requireAuth(a.handleWorkbench(route.op))
		mux.HandleFunc(route.pattern, func(w http.ResponseWriter, r *http.Request) {
			// Set before authentication so the refusal of a missing session is not cached either.
			w.Header().Set("Cache-Control", "private, no-store")
			handler(w, r)
		})
	}
}

func (a *API) handleWorkbench(op workbenchOp) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		principal, ok := principalFromContext(r)
		if !ok {
			writeError(w, http.StatusUnauthorized, "未授权")
			return
		}
		tenantID, username := normalizeTenant(principal.TenantID), principal.Username
		var kind string
		var objectID int64
		if op.hasRef {
			kind = r.PathValue("kind")
			id, valid := parseWorkbenchObjectID(r.PathValue("id"))
			if !validWorkbenchKind(kind) || !valid {
				writeWorkbenchError(w, http.StatusBadRequest, workbenchCodeInvalid, "invalid kind or id")
				return
			}
			objectID = id
		}
		now := a.workbench.now().UnixMilli()
		if op.growth {
			if wait, admitted := a.workbench.limiter.take(tenantID+"\n"+username, now); !admitted {
				seconds := int64(math.Ceil(float64(wait) / 1000))
				if seconds < 1 {
					seconds = 1
				}
				w.Header().Set("Retry-After", strconv.FormatInt(seconds, 10))
				writeWorkbenchError(w, http.StatusTooManyRequests, workbenchCodeRateLimited, "too many workbench writes")
				return
			}
		}
		items, status, err := a.runWorkbench(r.Context(), principal, tenantID, username, op, kind, objectID, now)
		if err != nil {
			a.logger.Warn("[workbench] tenant=" + tenantID + " user=" + username + " op=" + op.name +
				" code=" + workbenchCodeUnavailable)
			writeWorkbenchError(w, http.StatusServiceUnavailable, workbenchCodeUnavailable, "workbench storage unavailable")
			return
		}
		switch status {
		case http.StatusNotFound:
			writeWorkbenchError(w, status, workbenchCodeTargetNotFound, "service not found")
		case http.StatusConflict:
			writeWorkbenchError(w, status, workbenchCodeFavoritesFull, "favourites are full")
		default:
			writeJSON(w, http.StatusOK, workbenchDocumentOf(items, now))
		}
	}
}

// runWorkbench performs one operation and returns the identity's rows afterwards, or the status of
// a refusal. Any storage error is returned as err and answered with 503: a failed read must never
// look like empty lists.
func (a *API) runWorkbench(ctx context.Context, principal managementPrincipal, tenantID, username string,
	op workbenchOp, kind string, objectID int64, now int64) ([]store.WorkbenchItem, int, error) {
	// Touch the store before the visibility check, so a broken store answers 503 even for an object
	// that does not exist.
	items, err := a.db.ListWorkbenchItems(ctx, tenantID, username)
	if err != nil {
		return nil, 0, err
	}
	if op == workbenchGet {
		return items, http.StatusOK, nil
	}
	if op.growth {
		visible, err := a.workbenchTargetVisible(ctx, principal, kind, objectID)
		if err != nil {
			return nil, 0, err
		}
		if !visible {
			return nil, http.StatusNotFound, nil
		}
	}
	if op == workbenchAddFavorite {
		// SQLite has one writer; on a shared MySQL/PostgreSQL two instances may still race and leave
		// one favourite too many, which reads show and further adds refuse until it is gone.
		a.workbench.favoritesMu.Lock()
		defer a.workbench.favoritesMu.Unlock()
	}
	err = a.db.InWorkbenchTx(ctx, func(tx *store.WorkbenchTx) error {
		switch op {
		case workbenchAddFavorite:
			current, err := tx.Items(ctx, tenantID, username)
			if err != nil {
				return err
			}
			favorites := 0
			for _, item := range current {
				if item.List != store.WorkbenchListFavorite {
					continue
				}
				if item.Kind == kind && item.ObjectID == objectID {
					favorites = -1 // already a favourite: nothing changes, addedAt included
					break
				}
				favorites++
			}
			if favorites >= workbenchMaxFavorites {
				return errWorkbenchFavoritesFull
			}
			if favorites >= 0 {
				if err := tx.Insert(ctx, store.WorkbenchItem{TenantID: tenantID, Username: username,
					List: op.list, Kind: kind, ObjectID: objectID, AtMs: now}); err != nil {
					return err
				}
			}
		case workbenchRecordVisit:
			if err := tx.Touch(ctx, store.WorkbenchItem{TenantID: tenantID, Username: username,
				List: op.list, Kind: kind, ObjectID: objectID, AtMs: now}); err != nil {
				return err
			}
		case workbenchRemoveFavorite, workbenchRemoveRecent:
			if err := tx.Delete(ctx, tenantID, username, op.list, kind, objectID); err != nil {
				return err
			}
		case workbenchClearFavorites, workbenchClearRecents:
			if err := tx.Clear(ctx, tenantID, username, op.list); err != nil {
				return err
			}
		}
		// Every successful write leaves the identity's recents within retention and bound: expired
		// rows and rows beyond the twentieth are deleted, not hidden.
		current, err := tx.Items(ctx, tenantID, username)
		if err != nil {
			return err
		}
		keep := map[workbenchRef]bool{}
		for _, item := range workbenchRecents(current, now) {
			keep[workbenchRef{item.Kind, item.ObjectID}] = true
		}
		items = make([]store.WorkbenchItem, 0, len(current))
		for _, item := range current {
			if item.List == store.WorkbenchListRecent && !keep[workbenchRef{item.Kind, item.ObjectID}] {
				if err := tx.Delete(ctx, tenantID, username, item.List, item.Kind, item.ObjectID); err != nil {
					return err
				}
				continue
			}
			items = append(items, item)
		}
		return nil
	})
	if errors.Is(err, errWorkbenchFavoritesFull) {
		return nil, http.StatusConflict, nil
	}
	if err != nil {
		return nil, 0, err
	}
	return items, http.StatusOK, nil
}

// workbenchTargetVisible applies the visibility rule of the kind's list endpoint: the object
// exists, its client is in the caller's tenant, and the caller administers the tenant or owns
// the client. Missing, foreign and unserved objects look the same.
func (a *API) workbenchTargetVisible(ctx context.Context, principal managementPrincipal, kind string,
	objectID int64) (bool, error) {
	var clientID int64
	switch kind {
	case store.WorkbenchKindHTTPRoute:
		route, err := a.db.GetHTTPRoute(ctx, objectID)
		if errors.Is(err, store.ErrNotFound) {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		clientID = route.ClientID
	case store.WorkbenchKindTCPMapping:
		mapping, err := a.db.GetSpecus(ctx, objectID)
		if errors.Is(err, store.ErrNotFound) {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		clientID = mapping.ClientID
	case store.WorkbenchKindPeerService:
		if a.peerMesh == nil {
			return false, nil
		}
		service, err := a.db.GetPeerMeshSharedService(ctx, normalizeTenant(principal.TenantID), objectID)
		if err != nil || service == nil {
			return false, err
		}
		if principal.Admin {
			// The Peer service list shows an administrator every service of the tenant.
			return true, nil
		}
		clientID = service.ClientID
	default:
		return false, nil
	}
	account, err := a.db.GetClient(ctx, clientID)
	if errors.Is(err, store.ErrNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return principal.canAccessClient(*account), nil
}

// RunWorkbenchSweep deletes every identity's expired recent entries shortly after start and then
// every hour, so an identity that never writes again does not keep them.
func (a *API) RunWorkbenchSweep(ctx context.Context) {
	timer := time.NewTimer(workbenchSweepFirstDelay)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			if _, err := a.SweepWorkbench(ctx); err != nil && ctx.Err() == nil {
				a.logger.Warn("[workbench] retention sweep failed", "err", err)
			}
			timer.Reset(workbenchSweepInterval)
		}
	}
}

// SweepWorkbench runs one retention sweep at the workbench clock's current time.
func (a *API) SweepWorkbench(ctx context.Context) (int64, error) {
	return a.db.SweepWorkbenchRecents(ctx, a.workbench.now().UnixMilli()-workbenchRetentionMs)
}

// ---- document -------------------------------------------------------------------------

type workbenchRef struct {
	kind string
	id   int64
}

type workbenchLimits struct {
	MaxFavorites        int `json:"maxFavorites"`
	MaxRecents          int `json:"maxRecents"`
	RecentRetentionDays int `json:"recentRetentionDays"`
}

type workbenchFavoriteView struct {
	Kind    string `json:"kind"`
	ID      int64  `json:"id"`
	AddedAt string `json:"addedAt"`
}

type workbenchRecentView struct {
	Kind      string `json:"kind"`
	ID        int64  `json:"id"`
	VisitedAt string `json:"visitedAt"`
}

type workbenchDocument struct {
	SchemaVersion int                     `json:"schemaVersion"`
	Limits        workbenchLimits         `json:"limits"`
	Favorites     []workbenchFavoriteView `json:"favorites"`
	Recents       []workbenchRecentView   `json:"recents"`
}

func workbenchDocumentOf(items []store.WorkbenchItem, now int64) workbenchDocument {
	document := workbenchDocument{
		SchemaVersion: 1,
		Limits: workbenchLimits{MaxFavorites: workbenchMaxFavorites, MaxRecents: workbenchMaxRecents,
			RecentRetentionDays: workbenchRetentionDays},
		Favorites: []workbenchFavoriteView{},
		Recents:   []workbenchRecentView{},
	}
	// Every favourite is returned, even beyond the bound after a race: an explicit choice is never
	// hidden. Oldest first, so a new favourite goes to the end and the others keep their place.
	var favorites []store.WorkbenchItem
	for _, item := range items {
		if item.List == store.WorkbenchListFavorite {
			favorites = append(favorites, item)
		}
	}
	sort.Slice(favorites, func(i, j int) bool {
		if favorites[i].AtMs != favorites[j].AtMs {
			return favorites[i].AtMs < favorites[j].AtMs
		}
		return workbenchRefLess(favorites[i], favorites[j])
	})
	for _, item := range favorites {
		document.Favorites = append(document.Favorites, workbenchFavoriteView{Kind: item.Kind, ID: item.ObjectID,
			AddedAt: workbenchStamp(item.AtMs)})
	}
	for _, item := range workbenchRecents(items, now) {
		document.Recents = append(document.Recents, workbenchRecentView{Kind: item.Kind, ID: item.ObjectID,
			VisitedAt: workbenchStamp(item.AtMs)})
	}
	return document
}

// workbenchRecents returns the recent entries a reader sees: within retention (strictly younger
// than 30 days), newest first, at most twenty.
func workbenchRecents(items []store.WorkbenchItem, now int64) []store.WorkbenchItem {
	var recents []store.WorkbenchItem
	for _, item := range items {
		if item.List == store.WorkbenchListRecent && now-item.AtMs < workbenchRetentionMs {
			recents = append(recents, item)
		}
	}
	sort.Slice(recents, func(i, j int) bool {
		if recents[i].AtMs != recents[j].AtMs {
			return recents[i].AtMs > recents[j].AtMs
		}
		return workbenchRefLess(recents[i], recents[j])
	})
	if len(recents) > workbenchMaxRecents {
		recents = recents[:workbenchMaxRecents]
	}
	return recents
}

func workbenchRefLess(left, right store.WorkbenchItem) bool {
	if l, r := workbenchKindOrder(left.Kind), workbenchKindOrder(right.Kind); l != r {
		return l < r
	}
	return left.ObjectID < right.ObjectID
}

func workbenchKindOrder(kind string) int {
	for i, candidate := range workbenchKinds {
		if candidate == kind {
			return i
		}
	}
	return len(workbenchKinds)
}

func validWorkbenchKind(kind string) bool {
	return workbenchKindOrder(kind) < len(workbenchKinds)
}

// parseWorkbenchObjectID accepts decimal ASCII digits without sign, blank or leading zero, in
// 1..2^53-1 -- an id a browser holds exactly as a JSON number.
func parseWorkbenchObjectID(text string) (int64, bool) {
	if text == "" || len(text) > 16 || text[0] == '0' {
		return 0, false
	}
	for i := 0; i < len(text); i++ {
		if text[i] < '0' || text[i] > '9' {
			return 0, false
		}
	}
	value, err := strconv.ParseInt(text, 10, 64)
	if err != nil || value > workbenchMaxObjectID {
		return 0, false
	}
	return value, true
}

// workbenchStamp renders epoch milliseconds as RFC 3339 UTC with exactly three fractional digits.
func workbenchStamp(ms int64) string {
	return time.UnixMilli(ms).UTC().Format("2006-01-02T15:04:05.000Z")
}

func writeWorkbenchError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, map[string]string{"code": code, "error": message})
}

// ---- rate limit -------------------------------------------------------------------------

// workbenchLimiter is a GCRA limiter over the growth operations (adding a favourite, recording an
// open), one theoretical arrival time per identity: interval 1 s, burst 30. A refused request
// consumes nothing. It lives in process memory, like the other limiters, so each instance counts
// on its own.
type workbenchLimiter struct {
	mu  sync.Mutex
	tat map[string]int64
}

func newWorkbenchLimiter() *workbenchLimiter {
	return &workbenchLimiter{tat: make(map[string]int64)}
}

// take admits the request at now, or returns how many milliseconds the caller has to wait.
func (l *workbenchLimiter) take(key string, now int64) (int64, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	tolerance := int64(workbenchRateBurst-1) * workbenchRateIntervalMs
	tat, known := l.tat[key]
	if !known {
		if len(l.tat) >= workbenchRateMaxKeys {
			// An entry whose TAT is not after now is the same as no entry.
			for candidate, value := range l.tat {
				if value <= now {
					delete(l.tat, candidate)
				}
			}
			if len(l.tat) >= workbenchRateMaxKeys {
				return 1000, false
			}
		}
		tat = now
	}
	if wait := tat - tolerance - now; wait > 0 {
		return wait, false
	}
	if tat < now {
		tat = now
	}
	l.tat[key] = tat + workbenchRateIntervalMs
	return 0, true
}
