package store

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

func TestHTTPRouteAuthenticationCRUDAndAccessPolicy(t *testing.T) {
	db, err := Open("sqlite", filepath.Join(t.TempDir(), "http-route-auth.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	ctx := context.Background()
	now := time.Date(2026, 8, 4, 12, 0, 0, 0, time.UTC)
	account := ClientAccount{
		ID: 101, TenantID: "tenant-a", OwnerUsername: "alice", ClientName: "route-client",
		PasswordHash: "client-hash", Enabled: true, ConnectionRateLimitPerMinute: 60,
		CreatedAt: now, UpdatedAt: now,
	}
	if err := db.InsertClient(ctx, account); err != nil {
		t.Fatalf("insert client: %v", err)
	}
	route := HTTPRouteMapping{
		ID: 201, TenantID: account.TenantID, ClientID: account.ID, ClientName: account.ClientName,
		Route: "private", TargetBaseURL: "http://127.0.0.1:8080", Enabled: true,
		PathRewriteEnabled: true, MediaCaptureEnabled: true, AuthEnabled: true, AuthUsername: "route-user",
		AuthPasswordHash: "password-hash", CreatedAt: now, UpdatedAt: now,
	}
	if err := db.InsertHTTPRoute(ctx, route); err != nil {
		t.Fatalf("insert route: %v", err)
	}

	loaded, err := db.GetHTTPRoute(ctx, route.ID)
	if err != nil {
		t.Fatalf("get route: %v", err)
	}
	if !loaded.AuthEnabled || !loaded.MediaCaptureEnabled || loaded.AuthUsername != route.AuthUsername ||
		loaded.AuthPasswordHash != route.AuthPasswordHash {
		t.Fatalf("loaded auth fields = %+v", loaded)
	}
	policy, err := db.HTTPRouteAccessPolicy(ctx, account.ClientName, route.Route)
	if err != nil {
		t.Fatalf("load access policy: %v", err)
	}
	if policy == nil || !policy.AuthEnabled || !policy.PathRewriteEnabled || !policy.MediaCaptureEnabled ||
		policy.TenantID != account.TenantID || policy.ClientID != account.ID || policy.ResourceID != route.ID ||
		policy.AuthUsername != route.AuthUsername || policy.AuthPasswordHash != route.AuthPasswordHash {
		t.Fatalf("access policy = %+v", policy)
	}
	unmanaged, err := db.HTTPRouteAccessPolicy(ctx, account.ClientName, "local-only")
	if err != nil || unmanaged != nil {
		t.Fatalf("unmanaged policy = %+v, err=%v; want nil, nil", unmanaged, err)
	}

	loaded.AuthEnabled = false
	loaded.AuthUsername = "retained-user"
	loaded.AuthPasswordHash = "retained-hash"
	loaded.UpdatedAt = now.Add(time.Minute)
	if err := db.UpdateHTTPRoute(ctx, *loaded); err != nil {
		t.Fatalf("update route: %v", err)
	}
	updated, err := db.GetHTTPRoute(ctx, route.ID)
	if err != nil {
		t.Fatalf("get updated route: %v", err)
	}
	if updated.AuthEnabled || updated.AuthUsername != "retained-user" || updated.AuthPasswordHash != "retained-hash" {
		t.Fatalf("updated auth fields = %+v", updated)
	}
}
