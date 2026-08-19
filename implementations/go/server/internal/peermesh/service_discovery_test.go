package peermesh

import (
	"context"
	"testing"

	"github.com/devShuai/specus/implementations/go/server/internal/config"
	"github.com/devShuai/specus/implementations/go/server/internal/session"
)

func TestSharingDefaultsOffAndRejectsPublicTarget(t *testing.T) {
	ctx := context.Background()
	db := openPeerMeshTestDB(t)
	service := New(config.PeerMeshConfig{Enabled: true, CIDR: "100.96.0.0/11", SessionTTLSeconds: 3600}, db, session.NewRegistry(), nil)
	access := AccessContext{Username: "admin", TenantID: "tenant-a", Admin: true}

	status, err := service.SharingStatus(ctx, access)
	if err != nil {
		t.Fatal(err)
	}
	if status.ConfiguredEnabled || status.EffectiveEnabled || status.EnabledServiceCount != 0 {
		t.Fatalf("sharing should default off: %+v", status)
	}

	user := AccessContext{Username: "alice", TenantID: "tenant-a", Admin: false}
	if _, err := service.SetSharing(ctx, user, true); err == nil {
		t.Fatal("expected forbidden")
	}

	disabled := New(config.PeerMeshConfig{Enabled: false, CIDR: "100.96.0.0/11"}, db, session.NewRegistry(), nil)
	if _, err := disabled.SetSharing(ctx, access, true); err == nil {
		t.Fatal("expected deployment disabled error")
	}

	account := insertPeerClient(t, db, 3001, "tenant-a", "alice", "alice-laptop")
	host := "evil.example"
	name := "web"
	app := "http"
	port := 80
	published := 8080
	_, err = service.CreateSharedService(ctx, access, ServiceMutation{
		ClientID: &account.ID, Name: &name, Application: &app, TargetHost: &host, TargetPort: &port, PublishedPort: &published,
	})
	if err == nil {
		t.Fatal("expected public target host rejection")
	}

	local := "127.0.0.1"
	view, err := service.CreateSharedService(ctx, access, ServiceMutation{
		ClientID: &account.ID, Name: &name, Application: &app, TargetHost: &local, TargetPort: &port, PublishedPort: &published,
	})
	if err != nil {
		t.Fatal(err)
	}
	if view.Enabled {
		t.Fatal("new services must default disabled")
	}
	if view.TargetHost == nil || *view.TargetHost != "127.0.0.1" {
		t.Fatalf("admin view should include targetHost: %+v", view)
	}
}

func TestLoginConfigIncludesOwnerLocalServices(t *testing.T) {
	ctx := context.Background()
	db := openPeerMeshTestDB(t)
	service := New(config.PeerMeshConfig{Enabled: true, CIDR: "100.96.0.0/11", SessionTTLSeconds: 3600}, db, session.NewRegistry(), nil)
	access := AccessContext{Username: "admin", TenantID: "tenant-a", Admin: true}
	account := insertPeerClient(t, db, 3002, "tenant-a", "alice", "alice-laptop")
	local := "127.0.0.1"
	name := "ssh"
	app := "ssh"
	port := 22
	published := 2222
	if _, err := service.CreateSharedService(ctx, access, ServiceMutation{
		ClientID: &account.ID, Name: &name, Application: &app, TargetHost: &local, TargetPort: &port, PublishedPort: &published,
	}); err != nil {
		t.Fatal(err)
	}
	cfg, err := service.BuildLoginConfig(ctx, account, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.LocalServices) != 1 {
		t.Fatalf("localServices = %#v", cfg.LocalServices)
	}
	if cfg.LocalServices[0].TargetHost != "127.0.0.1" || cfg.LocalServices[0].TargetPort != 22 {
		t.Fatalf("owner config must include target: %+v", cfg.LocalServices[0])
	}
}

func TestUdpAndAclAndMdnsDefaults(t *testing.T) {
	ctx := context.Background()
	db := openPeerMeshTestDB(t)
	service := New(config.PeerMeshConfig{Enabled: true, CIDR: "100.96.0.0/11", SessionTTLSeconds: 3600}, db, session.NewRegistry(), nil)
	access := AccessContext{Username: "admin", TenantID: "tenant-a", Admin: true}
	account := insertPeerClient(t, db, 3003, "tenant-a", "alice", "alice-laptop")
	name := "dns"
	app := "udp"
	tcp := "tcp"
	host := "127.0.0.1"
	port := 53
	if _, err := service.CreateSharedService(ctx, access, ServiceMutation{
		ClientID: &account.ID, Name: &name, Transport: &tcp, Application: &app, TargetHost: &host, TargetPort: &port, PublishedPort: &port,
	}); err == nil {
		t.Fatal("udp application must reject tcp transport")
	}
	udp := "udp"
	view, err := service.CreateSharedService(ctx, access, ServiceMutation{
		ClientID: &account.ID, Name: &name, Transport: &udp, Application: &app, TargetHost: &host, TargetPort: &port, PublishedPort: &port,
	})
	if err != nil {
		t.Fatal(err)
	}
	if view.Transport != "udp" {
		t.Fatalf("transport=%s", view.Transport)
	}
	status, err := service.SharingStatus(ctx, access)
	if err != nil {
		t.Fatal(err)
	}
	if status.MdnsImportEnabled {
		t.Fatal("mdns import must default off")
	}
	allowed := []int64{9}
	visibility := "ACL"
	if _, err := service.UpdateSharedService(ctx, access, view.ID, ServiceMutation{Visibility: &visibility, AllowedClientIDs: allowed}); err != nil {
		t.Fatal(err)
	}
	items, err := service.ListSharedServices(ctx, access)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 || len(items[0].AllowedClientIDs) != 1 || items[0].AllowedClientIDs[0] != 9 {
		t.Fatalf("allowedClientIds=%v", items)
	}
}

func TestRequireTargetHostAcceptsLoopbackOnly(t *testing.T) {
	if _, err := requireTargetHost("127.0.0.1"); err != nil {
		t.Fatal(err)
	}
	if _, err := requireTargetHost("http://127.0.0.1"); err == nil {
		t.Fatal("url should be rejected")
	}
	if _, err := requirePath("javascript:alert(1)", "http"); err == nil {
		t.Fatal("script path should be rejected")
	}
}
