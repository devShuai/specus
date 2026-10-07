package management

import (
	"context"
	"io"
	"net/http"

	"github.com/devShuai/specus/implementations/go/server/internal/productmetrics"
)

// Opt-in product metrics (protocol/spec/product-metrics.md). The endpoints share the management
// Bearer authentication; the tenant and the username always come from the session. The handlers
// never log a request body.

// ProductMetrics returns the product metrics service, for the server's own write-path hooks, the
// deployment switch and the retention sweep.
func (a *API) ProductMetrics() *productmetrics.Service { return a.productMetrics }

// RunProductMetricsSweep runs the hourly retention sweep until ctx ends.
func (a *API) RunProductMetricsSweep(ctx context.Context) { a.productMetrics.Run(ctx) }

func (a *API) registerProductMetrics(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/admin/product-metrics/settings", noStore(a.requireAuth(a.handleProductMetricsSettings)))
	mux.HandleFunc("PUT /api/admin/product-metrics/settings", noStore(a.requireAuth(a.handleProductMetricsPutSettings)))
	mux.HandleFunc("DELETE /api/admin/product-metrics/data", noStore(a.requireAuth(a.handleProductMetricsPurge)))
	mux.HandleFunc("POST /api/admin/product-metrics/transfer-outcomes",
		noStore(a.requireAuth(a.handleProductMetricsIngest)))
	mux.HandleFunc("GET /api/admin/product-metrics/summary", noStore(a.requireAuth(a.handleProductMetricsSummary)))
}

func productMetricsActor(r *http.Request) (productmetrics.Actor, bool) {
	principal, ok := principalFromContext(r)
	if !ok {
		return productmetrics.Actor{}, false
	}
	return productmetrics.Actor{TenantID: normalizeTenant(principal.TenantID), Username: principal.Username,
		Admin: principal.Admin}, true
}

func writeProductMetrics(w http.ResponseWriter, response productmetrics.Response) {
	switch {
	case response.Status == http.StatusUnauthorized:
		writeError(w, http.StatusUnauthorized, "未授权")
	case response.Status == http.StatusForbidden && response.Body == nil:
		writeError(w, http.StatusForbidden, "需要 admin 权限")
	default:
		writeJSON(w, response.Status, response.Body)
	}
}

func (a *API) withProductMetricsActor(w http.ResponseWriter, r *http.Request,
	handle func(productmetrics.Actor) productmetrics.Response) {
	actor, ok := productMetricsActor(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "未授权")
		return
	}
	writeProductMetrics(w, handle(actor))
}

func (a *API) handleProductMetricsSettings(w http.ResponseWriter, r *http.Request) {
	a.withProductMetricsActor(w, r, func(actor productmetrics.Actor) productmetrics.Response {
		return a.productMetrics.Settings(r.Context(), actor)
	})
}

func (a *API) handleProductMetricsPutSettings(w http.ResponseWriter, r *http.Request) {
	a.withProductMetricsActor(w, r, func(actor productmetrics.Actor) productmetrics.Response {
		if !actor.Admin {
			return productmetrics.Response{Status: http.StatusForbidden}
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, productmetrics.MaxBodyBytes+1))
		if err != nil || len(body) > productmetrics.MaxBodyBytes {
			return productmetrics.Response{Status: http.StatusBadRequest,
				Body: map[string]string{"code": productmetrics.CodeInvalid}}
		}
		return a.productMetrics.PutSettings(r.Context(), actor, body)
	})
}

func (a *API) handleProductMetricsPurge(w http.ResponseWriter, r *http.Request) {
	a.withProductMetricsActor(w, r, func(actor productmetrics.Actor) productmetrics.Response {
		return a.productMetrics.Purge(r.Context(), actor)
	})
}

// handleProductMetricsIngest reads at most one byte more than the limit, so an oversized body is
// refused before anything parses it.
func (a *API) handleProductMetricsIngest(w http.ResponseWriter, r *http.Request) {
	a.withProductMetricsActor(w, r, func(actor productmetrics.Actor) productmetrics.Response {
		body, err := io.ReadAll(io.LimitReader(r.Body, productmetrics.MaxBodyBytes+1))
		if err != nil {
			return productmetrics.Response{Status: http.StatusBadRequest,
				Body: map[string]string{"code": productmetrics.CodeInvalid}}
		}
		return a.productMetrics.Ingest(r.Context(), actor, body)
	})
}

func (a *API) handleProductMetricsSummary(w http.ResponseWriter, r *http.Request) {
	a.withProductMetricsActor(w, r, func(actor productmetrics.Actor) productmetrics.Response {
		return a.productMetrics.Summary(r.Context(), actor, r.URL.Query())
	})
}

// recordMilestone reports an onboarding milestone after the write path it belongs to succeeded.
func (a *API) recordMilestone(ctx context.Context, tenantID, username, step string) {
	if a.productMetrics != nil {
		a.productMetrics.Milestone(ctx, normalizeTenant(tenantID), username, step)
	}
}
