package server

import (
	"context"
	"database/sql"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/devShuai/specus/implementations/go/server/internal/config"
	"github.com/devShuai/specus/implementations/go/server/internal/peermesh"
	"github.com/devShuai/specus/implementations/go/server/internal/protocol"
	"github.com/go-sql-driver/mysql"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
)

func TestPeerRuntimeHTTPExternalProvider(t *testing.T) {
	provider, dsn := os.Getenv("SPECUS_TEST_STARTUP_PROVIDER"), os.Getenv("SPECUS_TEST_STARTUP_DSN")
	if provider == "" && dsn == "" {
		t.Skip("requires an explicitly owned native HTTP/TCP fixture")
	}
	if os.Getenv("SPECUS_TEST_STARTUP_DATABASE_OWNED") != "1" || dsn == "" {
		t.Fatal("explicitly owned native fixture required")
	}
	driver, query := "mysql", "SELECT DATABASE()"
	if provider == "postgresql" || provider == "postgres" {
		driver, query = "pgx", "SELECT current_database()"
	} else if provider != "mysql" {
		t.Fatal("unsupported native fixture provider")
	}
	parent, err := sql.Open(driver, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer parent.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	var database string
	if err := parent.QueryRowContext(ctx, query).Scan(&database); err != nil || !strings.HasPrefix(database, "specus_startup_237_") {
		t.Fatal("refusing non-owned native fixture")
	}
	child := "specus_startup_237_runtime_http_" + strconv.FormatInt(time.Now().UnixNano(), 10)
	if _, err := parent.ExecContext(ctx, "CREATE DATABASE "+child); err != nil {
		t.Fatal(err)
	}
	if driver == "mysql" {
		cfg, err := mysql.ParseDSN(dsn)
		if err != nil {
			t.Fatal(err)
		}
		cfg.DBName = child
		dsn = cfg.FormatDSN()
	} else {
		cfg, err := pgx.ParseConfig(dsn)
		if err != nil {
			t.Fatal(err)
		}
		cfg.Database = child
		dsn = stdlib.RegisterConnConfig(cfg)
		t.Cleanup(func() { stdlib.UnregisterConnConfig(dsn) })
	}
	cfg := config.Default()
	cfg.Env = "test"
	cfg.Auth.Password = "admin"
	cfg.Database.Provider = provider
	cfg.Database.SeedDemoClient = false
	cfg.ConnectionString = dsn
	cfg.DataDirectory = filepath.Join(t.TempDir(), "data")
	cfg.Netty.Port = 0
	cfg.ManagementAddr = "127.0.0.1:0"
	cfg.PeerMesh.Enabled = true
	cfg.ClientAuth.PerMachineUserMaxInstances = 4
	app, err := New(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("native app startup: %v", err)
	}
	runCtx, stop := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); _ = app.Run(runCtx) }()
	t.Cleanup(func() {
		stop()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("native app did not stop")
		}
		_ = app.Close()
	})
	deadline := time.Now().Add(5 * time.Second)
	for app.ControlPort() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if app.ControlPort() == 0 {
		t.Fatal("native control did not bind")
	}
	_, http := newHTTPTestServer(t, app)
	insertCredentialForTest(t, app, "default", "admin", "ck_runtime_http", "runtime-http-secret", 8)
	environment := map[string]any{"clientPeerServiceCapabilities": map[string]any{"version": 2, "applications": []string{"http"}}}
	first := clientAuthLoginWithEnvironmentForTest(t, http.URL, "ck_runtime_http", "runtime-http-secret", "CanonicalMachine", "CanonicalUser", environment)
	second := clientAuthLoginWithEnvironmentForTest(t, http.URL, "ck_runtime_http", "runtime-http-secret", "canonicalmachine", "canonicaluser", environment)
	firstRow, err := app.db.GetClientSession(ctx, first.ClientSessionID)
	if err != nil {
		t.Fatal(err)
	}
	secondRow, err := app.db.GetClientSession(ctx, second.ClientSessionID)
	if err != nil {
		t.Fatal(err)
	}
	if driver == "mysql" && (firstRow.ClientID != secondRow.ClientID || firstRow.IdentityID != secondRow.IdentityID) {
		t.Fatal("native case-insensitive identity was not reused")
	}
	target := clientAuthLoginWithEnvironmentForTest(t, http.URL, "ck_runtime_http", "runtime-http-secret", "RemoteMachine", "remoteuser", environment)
	access := peermesh.AccessContext{TenantID: "default", Username: "admin", Admin: true, BuiltIn: true}
	on := true
	for _, login := range []clientAuthLoginForTestResponse{second, target} {
		runtime, err := app.db.GetClientSession(ctx, login.ClientSessionID)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := app.peerMesh.UpdateDevice(ctx, access, runtime.ClientID, peermesh.DeviceMutation{Enabled: &on}); err != nil {
			t.Fatal(err)
		}
	}
	f := &generationFixture{t: t, app: app, pub: second, recipient: target, managementURL: http.URL}
	f.consumer = f.login(target, protocol.ConnectionRoleControl)
	source := f.login(second, protocol.ConnectionRoleControl)
	row, err := app.db.GetClientSession(ctx, second.ClientSessionID)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := sql.Open(driver, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	identityQuery := "SELECT machine_fingerprint,os_user FROM specus_client_identity WHERE id=?"
	if driver == "pgx" {
		identityQuery = "SELECT machine_fingerprint,os_user FROM specus_client_identity WHERE id=$1"
	}
	var fingerprint, user string
	if err := raw.QueryRowContext(ctx, identityQuery, row.IdentityID).Scan(&fingerprint, &user); err != nil {
		t.Fatal(err)
	}
	original, ok := source.server.RuntimeReference()
	if !ok || original.IdentityID != row.IdentityID || original.MachineFingerprint != fingerprint || original.OSUser != user || row.MachineFingerprint != fingerprint || row.OSUser != user {
		t.Error("HTTP runtime did not bind the resolved canonical identity key")
	}
	if err := protocol.WritePacket(source.net, protocol.MessageRequest{ToClientName: target.ClientName, MessageType: protocol.MessageTypePeerControl, Message: `{"type":"candidates","sourceKeyEpoch":"native-source-epoch","candidates":[]}`}); err != nil {
		t.Fatal(err)
	}
	grant := peerGenerationMessage(t, source, peermesh.TypeSessionGrant)
	forwarded := peerGenerationMessage(t, f.consumer, peermesh.TypeCandidates)
	if grant.SessionID == nil || grant.Token == "" || forwarded.SessionID == nil || *grant.SessionID != *forwarded.SessionID || grant.Token != forwarded.Token || forwarded.SourceKeyEpoch != "native-source-epoch" {
		t.Fatal("native HTTP/TCP runtime publication failed")
	}
	f.heartbeat(source)
	t.Logf("native HTTP/TCP runtime publication PASS provider=%s canonical-identity/real-signed-HTTP/original-control/grant/forward/epoch", provider)
}
