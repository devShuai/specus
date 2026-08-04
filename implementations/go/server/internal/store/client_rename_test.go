package store

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

func TestUpdateClientAndRenameReferencesIsJavaCompatible(t *testing.T) {
	db, err := Open("sqlite", filepath.Join(t.TempDir(), "rename.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx := context.Background()
	now := time.Now().UTC()
	account := ClientAccount{ID: 1001, TenantID: "default", OwnerUsername: "owner",
		ClientName: "old-name", PasswordHash: "hash", Enabled: true,
		ConnectionRateLimitPerMinute: 30, CreatedAt: now, UpdatedAt: now}
	if err := db.InsertClient(ctx, account); err != nil {
		t.Fatal(err)
	}
	stamp := formatTime(now)
	statements := []string{
		`INSERT INTO specus_client_identity
			(id, tenant_id, credential_id, client_id, client_name, machine_fingerprint, os_user, first_seen_at, last_seen_at)
			VALUES (1, 'default', 1, 1001, 'old-name', 'machine', 'user', '` + stamp + `', '` + stamp + `')`,
		`INSERT INTO specus_mapping
			(id, tenant_id, client_id, client_name, listen_port, target_address, target_port, enabled, created_at, updated_at)
			VALUES (1, 'default', 1001, 'old-name', 19001, '127.0.0.1', 80, 1, '` + stamp + `', '` + stamp + `')`,
		`INSERT INTO http_route_mapping
			(id, tenant_id, client_id, client_name, route, target_base_url, enabled, created_at, updated_at)
			VALUES (1, 'default', 1001, 'old-name', 'api', 'http://127.0.0.1', 1, '` + stamp + `', '` + stamp + `')`,
		`INSERT INTO peer_mesh_device
			(id, tenant_id, owner_username, client_id, client_name, virtual_ip, cidr, enabled, created_at, updated_at)
			VALUES (1, 'default', 'owner', 1001, 'old-name', '100.96.0.2', '100.96.0.0/11', 1, '` + stamp + `', '` + stamp + `')`,
		`INSERT INTO peer_mesh_acl
			(id, tenant_id, owner_username, source_client_id, source_client_name, target_client_id, target_client_name, allowed, created_at, updated_at)
			VALUES (1, 'default', 'owner', 1001, 'old-name', 1001, 'old-name', 1, '` + stamp + `', '` + stamp + `')`,
		`INSERT INTO specus_traffic_usage
			(tenant_id, client_id, client_name, usage_date, upload_bytes, download_bytes, updated_at)
			VALUES ('default', 1001, 'old-name', '2026-08-04', 1, 2, '` + stamp + `')`,
		`INSERT INTO specus_resource_traffic_usage
			(tenant_id, client_id, client_name, resource_type, resource_key, resource_name, usage_date, upload_bytes, download_bytes, updated_at)
			VALUES ('default', 1001, 'old-name', 'HTTP', 'api', 'api', '2026-08-04', 1, 2, '` + stamp + `')`,
	}
	for _, statement := range statements {
		if _, err := db.sql.ExecContext(ctx, statement); err != nil {
			t.Fatalf("seed rename reference: %v\n%s", err, statement)
		}
	}

	account.ClientName = "new-name"
	account.UpdatedAt = now.Add(time.Minute)
	if err := db.UpdateClientAndRenameReferences(ctx, account, "old-name"); err != nil {
		t.Fatal(err)
	}
	checks := []struct{ table, column, predicate string }{
		{"specus_client_account", "client_name", "id = 1001"},
		{"specus_client_identity", "client_name", "client_id = 1001"},
		{"specus_mapping", "client_name", "client_id = 1001"},
		{"http_route_mapping", "client_name", "client_id = 1001"},
		{"peer_mesh_device", "client_name", "client_id = 1001"},
		{"peer_mesh_acl", "source_client_name", "source_client_id = 1001"},
		{"peer_mesh_acl", "target_client_name", "target_client_id = 1001"},
		{"specus_traffic_usage", "client_name", "client_id = 1001"},
		{"specus_resource_traffic_usage", "client_name", "client_id = 1001"},
	}
	for _, check := range checks {
		var name string
		query := `SELECT ` + check.column + ` FROM ` + check.table + ` WHERE ` + check.predicate
		if err := db.sql.QueryRowContext(ctx, query).Scan(&name); err != nil || name != "new-name" {
			t.Fatalf("%s.%s = %q, err=%v", check.table, check.column, name, err)
		}
	}
}
