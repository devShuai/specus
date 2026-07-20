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
	t.Setenv("TUNNEL_TRAFFIC_CAPTURE_DECODE_MAX_BYTES", "2048")
	t.Setenv("TUNNEL_TRAFFIC_CAPTURE_SAMPLE_RATE", "0.25")

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
	if cfg.Traffic.CaptureDecodeMaxBytes != 2048 {
		t.Fatalf("capture decode max bytes = %d, want 2048", cfg.Traffic.CaptureDecodeMaxBytes)
	}
	if cfg.Traffic.CaptureSampleRate != 0.25 {
		t.Fatalf("capture sample rate = %f, want 0.25", cfg.Traffic.CaptureSampleRate)
	}
}

func TestLoadFromEnvMapsJavaPeerMeshStunAndRelayOptions(t *testing.T) {
	t.Setenv("TUNNEL_PEER_MESH_PUBLIC_STUN_SERVERS", "stun:stun1.example.com:3478, stun2.example.com:5349")
	t.Setenv("TUNNEL_PEER_MESH_STANDALONE_STUN_ADDRESS", "stun.example.com")
	t.Setenv("TUNNEL_PEER_MESH_STANDALONE_STUN_PORT", "5349")
	t.Setenv("TUNNEL_PEER_MESH_RELAY_MIN_PORT", "50000")
	t.Setenv("TUNNEL_PEER_MESH_RELAY_MAX_PORT", "50100")
	t.Setenv("TUNNEL_PEER_MESH_RELAY_WORKER_THREADS", "4")
	t.Setenv("TUNNEL_PEER_MESH_RELAY_WORKER_QUEUE_CAPACITY", "1234")
	t.Setenv("TUNNEL_PEER_MESH_RELAY_TRAFFIC_FLUSH_INTERVAL_MS", "2500")

	cfg, err := Load("")
	if err != nil {
		t.Fatalf("load config: %v", err)
	}

	if len(cfg.PeerMesh.PublicStunServers) != 2 {
		t.Fatalf("public stun servers = %#v, want 2 entries", cfg.PeerMesh.PublicStunServers)
	}
	if cfg.PeerMesh.StandaloneStunAddress != "stun.example.com" || cfg.PeerMesh.StandaloneStunPort != 5349 {
		t.Fatalf("standalone STUN = %s:%d, want stun.example.com:5349",
			cfg.PeerMesh.StandaloneStunAddress, cfg.PeerMesh.StandaloneStunPort)
	}
	if cfg.PeerMesh.RelayMinPort != 50000 || cfg.PeerMesh.RelayMaxPort != 50100 {
		t.Fatalf("relay port range = %d-%d, want 50000-50100", cfg.PeerMesh.RelayMinPort, cfg.PeerMesh.RelayMaxPort)
	}
	if cfg.PeerMesh.RelayWorkerThreads != 4 {
		t.Fatalf("relay worker threads = %d, want 4", cfg.PeerMesh.RelayWorkerThreads)
	}
	if cfg.PeerMesh.RelayWorkerQueueCapacity != 1234 {
		t.Fatalf("relay worker queue = %d, want 1234", cfg.PeerMesh.RelayWorkerQueueCapacity)
	}
	if cfg.PeerMesh.RelayTrafficFlushIntervalMs != 2500 {
		t.Fatalf("relay traffic flush = %d, want 2500", cfg.PeerMesh.RelayTrafficFlushIntervalMs)
	}
}

func TestDefaultTrafficCaptureDetailDisabledLikeJava(t *testing.T) {
	cfg, err := Load("")
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if cfg.Traffic.CaptureDetailEnabled {
		t.Fatalf("capture detail should default to disabled")
	}
}

func TestLoadMapsTurnAndPublicTransferOptions(t *testing.T) {
	t.Setenv("TUNNEL_PEER_MESH_TURN_AUTH_REQUIRED", "false")
	t.Setenv("TUNNEL_PEER_MESH_TURN_REALM", "example.org")
	t.Setenv("TUNNEL_PEER_MESH_TURN_SHARED_SECRET", "shared")
	t.Setenv("TUNNEL_PEER_MESH_TURN_CREDENTIAL_TTL_SECONDS", "7200")
	t.Setenv("TUNNEL_OBJECT_STORAGE_PROVIDER", "aliyun-oss")
	t.Setenv("TUNNEL_OBJECT_STORAGE_REGION", "cn-shanghai")
	t.Setenv("TUNNEL_OBJECT_STORAGE_UPLOAD_CALLBACK_URL", "https://tunnel.example/api/public/transfer/oss-callback")
	t.Setenv("TUNNEL_OBJECT_STORAGE_DOWNLOAD_OBJECT_URL_TTL_SECONDS", "45")
	t.Setenv("TUNNEL_OBJECT_STORAGE_MAX_ATTACHMENT_BYTES", "12345")
	t.Setenv("TUNNEL_OBJECT_STORAGE_PER_USER_STORAGE_QUOTA_BYTES", "23456")
	t.Setenv("TUNNEL_OBJECT_STORAGE_PER_USER_MONTHLY_DOWNLOAD_QUOTA_BYTES", "34567")
	t.Setenv("TUNNEL_PUBLIC_TRANSFER_MAX_PENDING_UPLOADS_PER_ROOM", "7")
	t.Setenv("TUNNEL_PUBLIC_TRANSFER_MAX_DISCOVERY_PEERS_PER_ROOM", "9")

	cfg, err := Load("")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.PeerMesh.TurnAuthRequired || cfg.PeerMesh.TurnRealm != "example.org" ||
		cfg.PeerMesh.TurnSharedSecret != "shared" || cfg.PeerMesh.TurnCredentialTTLSeconds != 7200 {
		t.Fatalf("TURN env mapping mismatch: %+v", cfg.PeerMesh)
	}
	if cfg.ObjectStorage.Provider != "aliyun-oss" || cfg.ObjectStorage.Region != "cn-shanghai" ||
		cfg.ObjectStorage.UploadCallbackURL != "https://tunnel.example/api/public/transfer/oss-callback" ||
		cfg.ObjectStorage.DownloadObjectURLTTLSeconds != 45 || cfg.ObjectStorage.MaxAttachmentBytes != 12345 ||
		cfg.ObjectStorage.PerUserStorageQuotaBytes != 23456 ||
		cfg.ObjectStorage.PerUserMonthlyDownloadQuotaBytes != 34567 ||
		cfg.PublicTransfer.MaxPendingUploadsPerRoom != 7 || cfg.PublicTransfer.MaxDiscoveryPeersPerRoom != 9 {
		t.Fatalf("transfer env mapping mismatch: object=%+v public=%+v", cfg.ObjectStorage, cfg.PublicTransfer)
	}
}

func TestDefaultTurnAuthenticationAndTransferLimitsMatchJava(t *testing.T) {
	cfg := Default()
	if !cfg.PeerMesh.TurnAuthRequired || cfg.PeerMesh.TurnRealm != "shuai-tunnel" ||
		cfg.PeerMesh.TurnCredentialTTLSeconds != 3600 {
		t.Fatalf("TURN defaults mismatch: %+v", cfg.PeerMesh)
	}
	if cfg.ObjectStorage.Provider != "disabled" || cfg.ObjectStorage.DownloadObjectURLTTLSeconds != 30 ||
		cfg.ObjectStorage.MaxAttachmentBytes != 512*1024*1024 ||
		cfg.ObjectStorage.PerUserStorageQuotaBytes != 1024*1024*1024 ||
		cfg.ObjectStorage.PerUserMonthlyDownloadQuotaBytes != 1024*1024*1024 ||
		cfg.PublicTransfer.MaxDiscoveryPeersPerRoom != 32 {
		t.Fatalf("transfer defaults mismatch: object=%+v public=%+v", cfg.ObjectStorage, cfg.PublicTransfer)
	}
}

func TestLoadAllowsHeaderOnlyFrameLimitAndRejectsSmaller(t *testing.T) {
	t.Setenv("TUNNEL_NETTY_MAX_FRAME_SIZE", "11")
	if cfg, err := Load(""); err != nil || cfg.Netty.MaxFrameSize != 11 {
		t.Fatalf("11-byte full-frame limit rejected: cfg=%+v err=%v", cfg.Netty, err)
	}
	t.Setenv("TUNNEL_NETTY_MAX_FRAME_SIZE", "10")
	if _, err := Load(""); err == nil {
		t.Fatal("10-byte full-frame limit should be rejected")
	}
}
