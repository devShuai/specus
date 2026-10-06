package management

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strconv"

	"github.com/devShuai/specus/implementations/go/server/internal/connectivity"
	"github.com/devShuai/specus/implementations/go/server/internal/store"
)

// SetConnectivityChecker attaches the process-wide connectivity checker; without one the endpoint
// answers 503 CHECK_UNAVAILABLE.
func (a *API) SetConnectivityChecker(checker *connectivity.Checker) { a.connectivity = checker }

// noStore marks every answer of the wrapped handler private and uncacheable, the 401 included.
func noStore(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "private, no-store")
		next(w, r)
	}
}

// handleHTTPRouteConnectivityCheck is POST /api/admin/http-routes/{routeId}/connectivity-check
// (protocol/spec/service-connectivity-check.md). The route is visible exactly as for PUT; absent,
// foreign and not-owned routes all answer the same 404.
func (a *API) handleHTTPRouteConnectivityCheck(w http.ResponseWriter, r *http.Request) {
	principal, ok := principalFromContext(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "未授权")
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, connectivity.MaxBodyBytes+1))
	if err != nil {
		writeConnectivityRefusal(w, http.StatusBadRequest, "CHECK_REQUEST_INVALID", 0)
		return
	}
	if a.connectivity == nil {
		writeConnectivityRefusal(w, http.StatusServiceUnavailable, "CHECK_UNAVAILABLE", 1)
		return
	}
	request := connectivity.Request{
		Principal: &connectivity.Principal{TenantID: normalizeTenant(principal.TenantID), Username: principal.Username},
		RouteID:   r.PathValue("routeId"),
		Body:      body,
	}
	response := a.connectivity.Handle(r.Context(), request, func(ctx context.Context, routeID int64) (*connectivity.Route, error) {
		return a.connectivityRoute(ctx, principal, routeID)
	})
	if response.Status == http.StatusUnauthorized {
		writeError(w, http.StatusUnauthorized, "未授权")
		return
	}
	if response.RetryAfterSeconds > 0 {
		w.Header().Set("Retry-After", strconv.Itoa(response.RetryAfterSeconds))
	}
	writeJSON(w, response.Status, response.Body)
}

func (a *API) connectivityRoute(ctx context.Context, principal managementPrincipal, routeID int64) (*connectivity.Route, error) {
	mapping, err := a.db.GetHTTPRoute(ctx, routeID)
	if errors.Is(err, store.ErrNotFound) {
		return nil, connectivity.ErrRouteNotFound
	}
	if err != nil {
		return nil, err
	}
	account, err := a.db.GetClient(ctx, mapping.ClientID)
	if errors.Is(err, store.ErrNotFound) {
		return nil, connectivity.ErrRouteNotFound
	}
	if err != nil {
		return nil, err
	}
	if !principal.canAccessClient(*account) {
		return nil, connectivity.ErrRouteNotFound
	}
	return &connectivity.Route{
		ID: mapping.ID, TenantID: normalizeTenant(account.TenantID), ClientName: account.ClientName,
		Name: mapping.Route, TargetBaseURL: mapping.TargetBaseURL, Enabled: mapping.Enabled,
		ClientEnabled: account.Enabled,
	}, nil
}

func writeConnectivityRefusal(w http.ResponseWriter, status int, code string, retryAfterSeconds int) {
	if retryAfterSeconds > 0 {
		w.Header().Set("Retry-After", strconv.Itoa(retryAfterSeconds))
	}
	writeJSON(w, status, connectivity.RefusalBody{Code: code})
}
