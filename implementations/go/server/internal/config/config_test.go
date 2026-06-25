package config

import "testing"

func TestLoadFromEnvMapsTLSKeystore(t *testing.T) {
	t.Setenv("TUNNEL_TLS_MODE", "file")
	t.Setenv("TUNNEL_TLS_KEYSTORE", "server.p12")
	t.Setenv("TUNNEL_TLS_KEYSTORE_PASSWORD", "changeit")

	cfg, err := Load("")
	if err != nil {
		t.Fatalf("load config: %v", err)
	}

	if cfg.TLS.Mode != "file" {
		t.Fatalf("TLS mode = %q, want file", cfg.TLS.Mode)
	}
	if cfg.TLS.Keystore != "server.p12" {
		t.Fatalf("TLS keystore = %q, want server.p12", cfg.TLS.Keystore)
	}
	if cfg.TLS.KeystorePassword != "changeit" {
		t.Fatalf("TLS keystore password = %q, want changeit", cfg.TLS.KeystorePassword)
	}
}

func TestLoadFromEnvMapsOidcTenantClaim(t *testing.T) {
	t.Setenv("TUNNEL_OIDC_TENANT_CLAIM", "org_id")

	cfg, err := Load("")
	if err != nil {
		t.Fatalf("load config: %v", err)
	}

	if cfg.Oidc.TenantClaim != "org_id" {
		t.Fatalf("OIDC tenant claim = %q, want org_id", cfg.Oidc.TenantClaim)
	}
}

func TestLoadFromEnvMapsJavaClientAuthOptions(t *testing.T) {
	t.Setenv("TUNNEL_CLIENT_AUTH_DEFAULT_MAX_ONLINE_INSTANCES", "5")
	t.Setenv("TUNNEL_CLIENT_AUTH_PER_MACHINE_USER_MAX_INSTANCES", "3")
	t.Setenv("TUNNEL_CLIENT_AUTH_TOKEN_TTL_SECONDS", "1234")

	cfg, err := Load("")
	if err != nil {
		t.Fatalf("load config: %v", err)
	}

	if cfg.ClientAuth.DefaultMaxOnlineInstances != 5 {
		t.Fatalf("default max online = %d, want 5", cfg.ClientAuth.DefaultMaxOnlineInstances)
	}
	if cfg.ClientAuth.PerMachineUserMaxInstances != 3 {
		t.Fatalf("per-machine max online = %d, want 3", cfg.ClientAuth.PerMachineUserMaxInstances)
	}
	if cfg.ClientAuth.TokenTTLSeconds != 1234 {
		t.Fatalf("client token ttl = %d, want 1234", cfg.ClientAuth.TokenTTLSeconds)
	}
}

func TestLoadFromEnvMapsJavaLoginExecutorAliases(t *testing.T) {
	t.Setenv("TUNNEL_LOGIN_EXECUTOR_MAX", "64")
	t.Setenv("TUNNEL_LOGIN_EXECUTOR_QUEUE", "4096")

	cfg, err := Load("")
	if err != nil {
		t.Fatalf("load config: %v", err)
	}

	if cfg.Login.ExecutorMaxSize != 64 {
		t.Fatalf("login executor max = %d, want 64", cfg.Login.ExecutorMaxSize)
	}
	if cfg.Login.ExecutorQueueCapacity != 4096 {
		t.Fatalf("login executor queue = %d, want 4096", cfg.Login.ExecutorQueueCapacity)
	}
}

func TestLoadFromEnvMapsJavaConnectionRecordArchiveOptions(t *testing.T) {
	t.Setenv("TUNNEL_CONNECTION_DETAIL_RETENTION_DAYS", "7")
	t.Setenv("TUNNEL_CONNECTION_ARCHIVE_INTERVAL_MS", "15000")

	cfg, err := Load("")
	if err != nil {
		t.Fatalf("load config: %v", err)
	}

	if cfg.ConnectionRecord.DetailRetentionDays != 7 {
		t.Fatalf("connection detail retention days = %d, want 7", cfg.ConnectionRecord.DetailRetentionDays)
	}
	if cfg.ConnectionRecord.ArchiveIntervalMs != 15000 {
		t.Fatalf("connection archive interval = %d, want 15000", cfg.ConnectionRecord.ArchiveIntervalMs)
	}
}

func TestLoadFromEnvMapsJavaTrafficCaptureQueueOptions(t *testing.T) {
	t.Setenv("TUNNEL_TRAFFIC_CAPTURE_MAX_PENDING", "300")
	t.Setenv("TUNNEL_TRAFFIC_CAPTURE_FLUSH_BATCH_SIZE", "25")
	t.Setenv("TUNNEL_TRAFFIC_CAPTURE_FLUSH_INTERVAL_MS", "500")

	cfg, err := Load("")
	if err != nil {
		t.Fatalf("load config: %v", err)
	}

	if cfg.Traffic.CaptureMaxPending != 300 {
		t.Fatalf("capture max pending = %d, want 300", cfg.Traffic.CaptureMaxPending)
	}
	if cfg.Traffic.CaptureFlushBatchSize != 25 {
		t.Fatalf("capture flush batch size = %d, want 25", cfg.Traffic.CaptureFlushBatchSize)
	}
	if cfg.Traffic.CaptureFlushIntervalMs != 500 {
		t.Fatalf("capture flush interval = %d, want 500", cfg.Traffic.CaptureFlushIntervalMs)
	}
}
