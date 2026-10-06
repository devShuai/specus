package management

import (
	"encoding/json"
	"io"
	"net/http"

	"github.com/devShuai/specus/implementations/go/server/internal/httpshare"
	"github.com/devShuai/specus/implementations/go/server/internal/store"
)

// Temporary HTTP shares: management endpoints and the public token exchange. See
// protocol/spec/temporary-http-share.md.

const maxShareRequestBytes = 8 * 1024

// HTTPShares is the share service behind these endpoints and the /http-share/ entry.
func (a *API) HTTPShares() *httpshare.Service { return a.shares }

func (a *API) registerHTTPShares(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/admin/http-routes/{routeId}/shares", a.requireAuth(a.handleCreateHTTPShare))
	mux.HandleFunc("GET /api/admin/http-routes/{routeId}/shares", a.requireAuth(a.handleListHTTPShares))
	mux.HandleFunc("GET /api/admin/http-routes/{routeId}/shares/{shareId}", a.requireAuth(a.handleGetHTTPShare))
	mux.HandleFunc("POST /api/admin/http-routes/{routeId}/shares/{shareId}/revoke", a.requireAuth(a.handleRevokeHTTPShare))
	mux.HandleFunc("GET /api/admin/http-routes/{routeId}/access-audit", a.requireAuth(a.handleRouteAccessAudit))
	mux.HandleFunc("GET /api/admin/http-access-audit", a.requireAuth(a.handleTenantAccessAudit))
	mux.HandleFunc("POST /api/public/http-shares/exchange", a.handleExchangeHTTPShare)
}

func shareCaller(r *http.Request) (httpshare.Caller, bool) {
	principal, ok := principalFromContext(r)
	if !ok {
		return httpshare.Caller{}, false
	}
	return httpshare.Caller{Username: principal.Username, TenantID: principal.TenantID}, true
}

func readShareBody(r *http.Request) ([]byte, bool) {
	body, err := io.ReadAll(io.LimitReader(r.Body, maxShareRequestBytes+1))
	return body, err == nil && len(body) <= maxShareRequestBytes
}

// writeShareResult answers a share endpoint. Management answers are private and never stored.
func writeShareResult(w http.ResponseWriter, result httpshare.Result, cacheControl string) {
	for name, values := range result.Headers {
		if name == "Set-Cookie" {
			for _, value := range values {
				w.Header().Add(name, value)
			}
			continue
		}
		// Replaces the portal default, e.g. Referrer-Policy: no-referrer on the exchange.
		w.Header()[name] = values
	}
	w.Header().Set("Cache-Control", cacheControl)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(result.Status)
	body := result.Body
	if result.Code != "" {
		body = map[string]string{"code": result.Code}
	}
	_ = json.NewEncoder(w).Encode(body)
}

const managementCacheControl = "private, no-store"

func (a *API) handleCreateHTTPShare(w http.ResponseWriter, r *http.Request) {
	caller, ok := shareCaller(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "未授权")
		return
	}
	body, ok := readShareBody(r)
	if !ok {
		writeShareResult(w, httpshare.Result{Status: http.StatusBadRequest, Code: httpshare.CodeRequestInvalid},
			managementCacheControl)
		return
	}
	writeShareResult(w, a.shares.Create(r.Context(), caller, r.PathValue("routeId"), body), managementCacheControl)
}

func (a *API) handleListHTTPShares(w http.ResponseWriter, r *http.Request) {
	caller, ok := shareCaller(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "未授权")
		return
	}
	writeShareResult(w, a.shares.List(r.Context(), caller, r.PathValue("routeId")), managementCacheControl)
}

func (a *API) handleGetHTTPShare(w http.ResponseWriter, r *http.Request) {
	caller, ok := shareCaller(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "未授权")
		return
	}
	writeShareResult(w, a.shares.Get(r.Context(), caller, r.PathValue("routeId"), r.PathValue("shareId")),
		managementCacheControl)
}

func (a *API) handleRevokeHTTPShare(w http.ResponseWriter, r *http.Request) {
	caller, ok := shareCaller(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "未授权")
		return
	}
	body, ok := readShareBody(r)
	if !ok {
		writeShareResult(w, httpshare.Result{Status: http.StatusBadRequest, Code: httpshare.CodeRequestInvalid},
			managementCacheControl)
		return
	}
	writeShareResult(w, a.shares.Revoke(r.Context(), caller, r.PathValue("routeId"), r.PathValue("shareId"), body),
		managementCacheControl)
}

func auditQuery(r *http.Request) httpshare.AuditQuery {
	query := r.URL.Query()
	return httpshare.AuditQuery{RouteID: query.Get("routeId"), Limit: query.Get("limit"), Before: query.Get("before")}
}

func (a *API) handleRouteAccessAudit(w http.ResponseWriter, r *http.Request) {
	caller, ok := shareCaller(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "未授权")
		return
	}
	writeShareResult(w, a.shares.RouteAudit(r.Context(), caller, r.PathValue("routeId"), auditQuery(r)),
		managementCacheControl)
}

func (a *API) handleTenantAccessAudit(w http.ResponseWriter, r *http.Request) {
	caller, ok := shareCaller(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "未授权")
		return
	}
	writeShareResult(w, a.shares.TenantAudit(r.Context(), caller, auditQuery(r)), managementCacheControl)
}

// handleExchangeHTTPShare is anonymous: the token in the body is the only credential.
func (a *API) handleExchangeHTTPShare(w http.ResponseWriter, r *http.Request) {
	body, ok := readShareBody(r)
	if !ok {
		body = make([]byte, maxShareRequestBytes+1)
	}
	source := r.RemoteAddr
	if a.addressResolver != nil {
		source = a.addressResolver.Resolve(r)
	}
	writeShareResult(w, a.shares.Exchange(r.Context(), r.Header.Get("Content-Type"), body, source), "no-store")
}

// ---- hooks: route, client and user changes that end shares ------------------------------------

func routeExposure(route store.HTTPRouteMapping) string {
	return httpshare.Exposure(route.Enabled, route.AuthEnabled)
}

func routeChange(before, after store.HTTPRouteMapping, req httpRouteMutation) store.RouteChange {
	change := store.RouteChange{ExposureBefore: routeExposure(before), ExposureAfter: routeExposure(after)}
	newPassword := req.AuthPassword != nil && len(*req.AuthPassword) > 0 && before.AuthPasswordHash != after.AuthPasswordHash
	change.CredentialsChanged = after.AuthEnabled && (before.AuthUsername != after.AuthUsername || newPassword)
	switch change.ExposureAfter {
	case httpshare.ExposureDisabled:
		change.RevokeReason = httpshare.ReasonRouteDisabled
	case httpshare.ExposurePublic:
		change.RevokeReason = httpshare.ReasonRouteMadePublic
	}
	return change
}

func (a *API) shareNow() int64 { return a.shares.Now().Unix() }
