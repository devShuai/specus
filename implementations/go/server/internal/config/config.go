// Package config holds the tunnel-server configuration: defaults, optional JSON file
// overrides, and Java-style TUNNEL_* environment variable overrides. It mirrors the
// option groups of the C# server (Tunnel:Netty, Tunnel:Auth, etc.).
package config

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
)

// Config is the full server configuration.
type Config struct {
	Netty            NettyConfig            `json:"netty"`
	Login            LoginConfig            `json:"login"`
	Database         DatabaseConfig         `json:"database"`
	Auth             AuthConfig             `json:"auth"`
	ClientAuth       ClientAuthConfig       `json:"clientAuth"`
	ConnectionRecord ConnectionRecordConfig `json:"connectionRecord"`
	Traffic          TrafficConfig          `json:"traffic"`
	Elasticsearch    ElasticsearchConfig    `json:"elasticsearch"`
	HTTP             DirectHTTPConfig       `json:"http"`
	PeerMesh         PeerMeshConfig         `json:"peerMesh"`
	ObjectStorage    ObjectStorageConfig    `json:"objectStorage"`
	PublicTransfer   PublicTransferConfig   `json:"publicTransfer"`
	Oidc             OidcConfig             `json:"oidc"`
	TLS              TLSConfig              `json:"tls"`
	PublicAddress    string                 `json:"publicAddress"`
	ConnectionString string                 `json:"connectionString"`
	// ManagementAddr is the listen address for the admin/HTTP surface (default :8088).
	ManagementAddr string `json:"managementAddr"`
}

// NettyConfig mirrors Tunnel:Netty.
type NettyConfig struct {
	Port                            int `json:"port"`
	MaxFrameSize                    int `json:"maxFrameSize"`
	WriteBufferLowWaterMark         int `json:"writeBufferLowWaterMark"`
	WriteBufferHighWaterMark        int `json:"writeBufferHighWaterMark"`
	MaxExternalConnections          int `json:"maxExternalConnections"`
	MaxExternalConnectionsPerClient int `json:"maxExternalConnectionsPerClient"`
	MaxExternalConnectionsPerPort   int `json:"maxExternalConnectionsPerPort"`
}

// LoginConfig mirrors Tunnel:Login.
type LoginConfig struct {
	ExecutorMaxSize       int `json:"executorMaxSize"`
	ExecutorQueueCapacity int `json:"executorQueueCapacity"`
}

// DatabaseConfig mirrors Tunnel:Database.
type DatabaseConfig struct {
	Provider       string `json:"provider"`
	SeedDemoClient bool   `json:"seedDemoClient"`
}

// AuthConfig mirrors Tunnel:Auth.
type AuthConfig struct {
	PasswordLoginEnabled bool                    `json:"passwordLoginEnabled"`
	RegistrationEnabled  bool                    `json:"registrationEnabled"`
	Username             string                  `json:"username"`
	Password             string                  `json:"password"`
	TenantID             string                  `json:"tenantId"`
	JwtSecret            string                  `json:"jwtSecret"`
	TokenTTLSeconds      int64                   `json:"tokenTtlSeconds"`
	Turnstile            TurnstileConfig         `json:"turnstile"`
	EmailVerification    EmailVerificationConfig `json:"emailVerification"`
}

type TurnstileConfig struct {
	Enabled          bool     `json:"enabled"`
	SiteKey          string   `json:"siteKey"`
	SecretKey        string   `json:"secretKey"`
	VerifyURL        string   `json:"verifyUrl"`
	AllowedHostnames []string `json:"allowedHostnames"`
}

type EmailVerificationConfig struct {
	Enabled               bool   `json:"enabled"`
	FromAddress           string `json:"fromAddress"`
	FromName              string `json:"fromName"`
	Subject               string `json:"subject"`
	CodeTTLSeconds        int64  `json:"codeTtlSeconds"`
	MaxAttempts           int    `json:"maxAttempts"`
	ResendCooldownSeconds int64  `json:"resendCooldownSeconds"`
	CleanupIntervalMs     int64  `json:"cleanupIntervalMs"`
	SMTPHost              string `json:"smtpHost"`
	SMTPPort              int    `json:"smtpPort"`
	SMTPUsername          string `json:"smtpUsername"`
	SMTPPassword          string `json:"smtpPassword"`
	SMTPStartTLS          bool   `json:"smtpStartTls"`
	SMTPStartTLSRequired  bool   `json:"smtpStartTlsRequired"`
	SMTPSSL               bool   `json:"smtpSsl"`
}

// ClientAuthConfig mirrors Tunnel:ClientAuth.
type ClientAuthConfig struct {
	DefaultMaxOnlineInstances  int   `json:"defaultMaxOnlineInstances"`
	PerMachineUserMaxInstances int   `json:"perMachineUserMaxInstances"`
	TokenTTLSeconds            int64 `json:"tokenTtlSeconds"`
}

// ConnectionRecordConfig mirrors tunnel.connection-record in the Java server.
type ConnectionRecordConfig struct {
	DetailRetentionDays int   `json:"detailRetentionDays"`
	ArchiveIntervalMs   int64 `json:"archiveIntervalMs"`
}

// TrafficConfig mirrors Tunnel:Traffic.
type TrafficConfig struct {
	FlushIntervalMs        int     `json:"flushIntervalMs"`
	CaptureDetailEnabled   bool    `json:"captureDetailEnabled"`
	CapturePreviewBytes    int     `json:"capturePreviewBytes"`
	CaptureHeaderChars     int     `json:"captureHeaderChars"`
	CaptureDecodeMaxBytes  int     `json:"captureDecodeMaxBytes"`
	CaptureMaxPending      int     `json:"captureMaxPending"`
	CaptureFlushBatchSize  int     `json:"captureFlushBatchSize"`
	CaptureFlushIntervalMs int     `json:"captureFlushIntervalMs"`
	CaptureSampleRate      float64 `json:"captureSampleRate"`
}

// ElasticsearchConfig mirrors Tunnel:Elasticsearch for traffic detail storage.
type ElasticsearchConfig struct {
	URIs             string `json:"uris"`
	Username         string `json:"username"`
	Password         string `json:"password"`
	APIKey           string `json:"apiKey"`
	HTTPIndex        string `json:"httpIndex"`
	TCPIndex         string `json:"tcpIndex"`
	HTTPMaxStoreSize string `json:"httpMaxStoreSize"`
	TCPMaxStoreSize  string `json:"tcpMaxStoreSize"`
}

func (c ElasticsearchConfig) Configured() bool {
	return strings.TrimSpace(c.URIs) != ""
}

func (c ElasticsearchConfig) EndpointURIs() []string {
	if !c.Configured() {
		return nil
	}
	parts := strings.Split(c.URIs, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		if value := strings.TrimSpace(part); value != "" {
			out = append(out, value)
		}
	}
	return out
}

// ParseDataSizeBytes parses Java-style data-size values such as 100GB or 512MiB.
func ParseDataSizeBytes(value string, fallback int64) int64 {
	normalized := strings.ToUpper(strings.TrimSpace(value))
	if normalized == "" {
		return fallback
	}
	multiplier := int64(1)
	for _, suffix := range []struct {
		text string
		mul  int64
	}{
		{"KIB", 1024},
		{"MIB", 1024 * 1024},
		{"GIB", 1024 * 1024 * 1024},
		{"TIB", 1024 * 1024 * 1024 * 1024},
		{"KB", 1024},
		{"MB", 1024 * 1024},
		{"GB", 1024 * 1024 * 1024},
		{"TB", 1024 * 1024 * 1024 * 1024},
		{"B", 1},
	} {
		if strings.HasSuffix(normalized, suffix.text) {
			multiplier = suffix.mul
			normalized = strings.TrimSpace(strings.TrimSuffix(normalized, suffix.text))
			break
		}
	}
	if n, err := strconv.ParseInt(normalized, 10, 64); err == nil && n >= 0 {
		return n * multiplier
	}
	return fallback
}

// DirectHTTPConfig mirrors Tunnel:Http.
type DirectHTTPConfig struct {
	TimeoutMs           int `json:"timeoutMs"`
	MaxRequestBodySize  int `json:"maxRequestBodySize"`
	RewriteMaxBodyBytes int `json:"rewriteMaxBodyBytes"`
}

// PeerMeshConfig mirrors tunnel.peer-mesh in the Java server.
type PeerMeshConfig struct {
	Enabled                     bool     `json:"enabled"`
	CIDR                        string   `json:"cidr"`
	PublicAddress               string   `json:"publicAddress"`
	StunTurnPort                int      `json:"stunTurnPort"`
	StandaloneStunAddress       string   `json:"standaloneStunAddress"`
	StandaloneStunPort          int      `json:"standaloneStunPort"`
	NatProbeAlternatePort       int      `json:"natProbeAlternatePort"`
	PublicStunServers           []string `json:"publicStunServers"`
	SessionTTLSeconds           int64    `json:"sessionTtlSeconds"`
	AllocationTTLSeconds        int64    `json:"allocationTtlSeconds"`
	SessionCleanupIntervalMs    int64    `json:"sessionCleanupIntervalMs"`
	RelayMinPort                int      `json:"relayMinPort"`
	RelayMaxPort                int      `json:"relayMaxPort"`
	RelayWorkerThreads          int      `json:"relayWorkerThreads"`
	RelayWorkerQueueCapacity    int      `json:"relayWorkerQueueCapacity"`
	RelayTrafficFlushIntervalMs int      `json:"relayTrafficFlushIntervalMs"`
	TurnAuthRequired            bool     `json:"turnAuthRequired"`
	TurnRealm                   string   `json:"turnRealm"`
	TurnSharedSecret            string   `json:"turnSharedSecret"`
	TurnCredentialTTLSeconds    int64    `json:"turnCredentialTtlSeconds"`

	// General relay quotas. Browser WebRTC relays DTLS/SRTP, which cannot pass the Peer Mesh
	// specific checks, so those allocations are forwarded with standard TURN semantics and
	// need their own resource limits. GeneralRelayMaxAllocations <= 0 disables general relay.
	GeneralRelayMaxAllocations          int   `json:"generalRelayMaxAllocations"`
	GeneralRelayMaxAllocationsPerAddr   int   `json:"generalRelayMaxAllocationsPerAddress"`
	GeneralRelayRateBytesPerSecond      int64 `json:"generalRelayRateBytesPerSecond"`
	GeneralRelayMaxBytes                int64 `json:"generalRelayMaxBytes"`
}

// ObjectStorageConfig mirrors tunnel.object-storage. Attachments are uploaded directly
// to a private Aliyun OSS bucket through short-lived presigned URLs.
type ObjectStorageConfig struct {
	Provider                         string `json:"provider"`
	Endpoint                         string `json:"endpoint"`
	Region                           string `json:"region"`
	Bucket                           string `json:"bucket"`
	AccessKeyID                      string `json:"accessKeyId"`
	AccessKeySecret                  string `json:"accessKeySecret"`
	ObjectPrefix                     string `json:"objectPrefix"`
	UploadCallbackURL                string `json:"uploadCallbackUrl"`
	UploadURLTTLSeconds              int64  `json:"uploadUrlTtlSeconds"`
	DownloadURLTTLSeconds            int64  `json:"downloadUrlTtlSeconds"`
	DownloadObjectURLTTLSeconds      int64  `json:"downloadObjectUrlTtlSeconds"`
	RetentionHours                   int64  `json:"retentionHours"`
	MaxAttachmentBytes               int64  `json:"maxAttachmentBytes"`
	PerUserStorageQuotaBytes         int64  `json:"perUserStorageQuotaBytes"`
	PerUserMonthlyDownloadQuotaBytes int64  `json:"perUserMonthlyDownloadQuotaBytes"`
	ExpirationScanIntervalMs         int64  `json:"expirationScanIntervalMs"`
}

// PublicTransferConfig mirrors tunnel.public-transfer abuse-protection limits.
type PublicTransferConfig struct {
	PresignRateLimitPerIP                  int    `json:"presignRateLimitPerIp"`
	PresignRateLimitWindowSeconds          int64  `json:"presignRateLimitWindowSeconds"`
	MaxPendingUploadsPerRoom               int    `json:"maxPendingUploadsPerRoom"`
	MaxDiscoveryPeersPerRoom               int    `json:"maxDiscoveryPeersPerRoom"`
	DiscoveryMessageRateLimitPerConnection int    `json:"discoveryMessageRateLimitPerConnection"`
	DiscoveryMessageRateLimitWindowSeconds int64  `json:"discoveryMessageRateLimitWindowSeconds"`
	ClusterEnabled                         bool   `json:"clusterEnabled"`
	RedisURI                               string `json:"redisUri"`
	RedisKeyPrefix                         string `json:"redisKeyPrefix"`
	PresenceLeaseSeconds                   int64  `json:"presenceLeaseSeconds"`
	PresenceRefreshIntervalMs              int64  `json:"presenceRefreshIntervalMs"`
	RedisCommandTimeoutMs                  int64  `json:"redisCommandTimeoutMs"`
}

// OidcConfig mirrors Tunnel:Oidc.
type OidcConfig struct {
	Issuer                string `json:"issuer"`
	JwkSetURI             string `json:"jwkSetUri"`
	AuthorizationEndpoint string `json:"authorizationEndpoint"`
	TokenEndpoint         string `json:"tokenEndpoint"`
	EndSessionEndpoint    string `json:"endSessionEndpoint"`
	ClientID              string `json:"clientId"`
	ClientSecret          string `json:"clientSecret"`
	RedirectURI           string `json:"redirectUri"`
	Scope                 string `json:"scope"`
	Audience              string `json:"audience"`
	TenantClaim           string `json:"tenantClaim"`
}

// TLSConfig mirrors Tunnel:Tls. Mode is one of disabled|file|self-signed.
type TLSConfig struct {
	Mode             string `json:"mode"`
	Keystore         string `json:"keystore"`
	KeystorePassword string `json:"keystorePassword"`
	CertFile         string `json:"certFile"`
	KeyFile          string `json:"keyFile"`
	KeyPassword      string `json:"keyPassword"`
}

// Default returns the configuration with the same defaults as the C# appsettings.json.
func Default() Config {
	return Config{
		Netty: NettyConfig{
			Port:                            7010,
			MaxFrameSize:                    32 * 1024 * 1024,
			WriteBufferLowWaterMark:         32 * 1024,
			WriteBufferHighWaterMark:        64 * 1024,
			MaxExternalConnections:          10000,
			MaxExternalConnectionsPerClient: 10000,
			MaxExternalConnectionsPerPort:   10000,
		},
		Login:    LoginConfig{ExecutorMaxSize: 32, ExecutorQueueCapacity: 20000},
		Database: DatabaseConfig{Provider: "sqlite", SeedDemoClient: true},
		Auth: AuthConfig{
			PasswordLoginEnabled: true,
			RegistrationEnabled:  true,
			Username:             "admin",
			Password:             "admin",
			TenantID:             "default",
			TokenTTLSeconds:      28800,
			Turnstile: TurnstileConfig{
				VerifyURL: "https://challenges.cloudflare.com/turnstile/v0/siteverify",
			},
			EmailVerification: EmailVerificationConfig{
				FromName:              "shuai-tunnel",
				Subject:               "shuai-tunnel 注册验证码",
				CodeTTLSeconds:        600,
				MaxAttempts:           5,
				ResendCooldownSeconds: 60,
				CleanupIntervalMs:     3600000,
				SMTPPort:              587,
				SMTPStartTLS:          true,
				SMTPStartTLSRequired:  true,
			},
		},
		ClientAuth: ClientAuthConfig{
			DefaultMaxOnlineInstances:  2,
			PerMachineUserMaxInstances: 1,
			TokenTTLSeconds:            28800,
		},
		ConnectionRecord: ConnectionRecordConfig{
			DetailRetentionDays: 60,
			ArchiveIntervalMs:   3600000,
		},
		Traffic: TrafficConfig{
			FlushIntervalMs:        5000,
			CaptureDetailEnabled:   false,
			CapturePreviewBytes:    256,
			CaptureHeaderChars:     8192,
			CaptureDecodeMaxBytes:  1024 * 1024,
			CaptureMaxPending:      20000,
			CaptureFlushBatchSize:  1000,
			CaptureFlushIntervalMs: 2000,
			CaptureSampleRate:      1.0,
		},
		Elasticsearch: ElasticsearchConfig{
			HTTPIndex:        "shuai-tunnel-http-traffic",
			TCPIndex:         "shuai-tunnel-tcp-traffic",
			HTTPMaxStoreSize: "100GB",
			TCPMaxStoreSize:  "10GB",
		},
		HTTP: DirectHTTPConfig{
			TimeoutMs:           30000,
			MaxRequestBodySize:  16 * 1024 * 1024,
			RewriteMaxBodyBytes: 10 * 1024 * 1024,
		},
		PeerMesh: PeerMeshConfig{
			Enabled:                     false,
			CIDR:                        "100.96.0.0/11",
			StunTurnPort:                3478,
			StandaloneStunPort:          3478,
			NatProbeAlternatePort:       3479,
			SessionTTLSeconds:           3600,
			AllocationTTLSeconds:        300,
			SessionCleanupIntervalMs:    60000,
			RelayMinPort:                49152,
			RelayMaxPort:                65535,
			RelayWorkerQueueCapacity:    10000,
			RelayTrafficFlushIntervalMs: 5000,
			TurnAuthRequired:            true,
			TurnRealm:                   "shuai-tunnel",
			TurnCredentialTTLSeconds:    3600,

			GeneralRelayMaxAllocations:        256,
			GeneralRelayMaxAllocationsPerAddr: 4,
			GeneralRelayRateBytesPerSecond:    2 * 1024 * 1024,
			GeneralRelayMaxBytes:              512 * 1024 * 1024,
		},
		ObjectStorage: ObjectStorageConfig{
			Provider:                         "disabled",
			ObjectPrefix:                     "shuai-tunnel/attachments",
			UploadURLTTLSeconds:              900,
			DownloadURLTTLSeconds:            600,
			DownloadObjectURLTTLSeconds:      30,
			RetentionHours:                   72,
			MaxAttachmentBytes:               512 * 1024 * 1024,
			PerUserStorageQuotaBytes:         1024 * 1024 * 1024,
			PerUserMonthlyDownloadQuotaBytes: 1024 * 1024 * 1024,
			ExpirationScanIntervalMs:         3600000,
		},
		PublicTransfer: PublicTransferConfig{
			PresignRateLimitPerIP:                  30,
			PresignRateLimitWindowSeconds:          300,
			MaxPendingUploadsPerRoom:               50,
			MaxDiscoveryPeersPerRoom:               32,
			DiscoveryMessageRateLimitPerConnection: 360,
			DiscoveryMessageRateLimitWindowSeconds: 60,
			RedisKeyPrefix:                         "shuai-tunnel:v2:public-transfer",
			PresenceLeaseSeconds:                   30,
			PresenceRefreshIntervalMs:              10000,
			RedisCommandTimeoutMs:                  2000,
		},
		Oidc: OidcConfig{
			Issuer:                "https://gateway.toys.theshuai.com/auth",
			JwkSetURI:             "https://gateway.toys.theshuai.com/auth/oauth2/jwks",
			AuthorizationEndpoint: "https://gateway.toys.theshuai.com/auth/oauth2/authorize",
			TokenEndpoint:         "https://gateway.toys.theshuai.com/auth/oauth2/token",
			EndSessionEndpoint:    "https://gateway.toys.theshuai.com/auth/connect/logout",
			RedirectURI:           "http://127.0.0.1:8088/",
			Scope:                 "openid",
			TenantClaim:           "tenant_id",
		},
		TLS:              TLSConfig{Mode: "disabled"},
		ConnectionString: "./shuai-tunnel.db",
		ManagementAddr:   ":8088",
	}
}

// Load builds the configuration: defaults, then the optional JSON file at path (when
// non-empty and present), then TUNNEL_* environment overrides.
func Load(path string) (Config, error) {
	cfg := Default()
	if path != "" {
		data, err := os.ReadFile(path)
		if err == nil {
			if err := json.Unmarshal(data, &cfg); err != nil {
				return Config{}, fmt.Errorf("parse config %s: %w", path, err)
			}
		} else if !os.IsNotExist(err) {
			return Config{}, fmt.Errorf("read config %s: %w", path, err)
		}
	}
	cfg.applyEnv(environMap())
	if cfg.Netty.MaxFrameSize < 11 {
		return Config{}, fmt.Errorf("netty.maxFrameSize must be at least the 11-byte frame header")
	}
	if cfg.PublicTransfer.ClusterEnabled && strings.TrimSpace(cfg.PublicTransfer.RedisURI) == "" {
		return Config{}, fmt.Errorf("publicTransfer.redisUri is required when clusterEnabled=true")
	}
	if cfg.PublicTransfer.ClusterEnabled && (cfg.PublicTransfer.PresenceRefreshIntervalMs <= 0 ||
		cfg.PublicTransfer.PresenceRefreshIntervalMs*2 >= cfg.PublicTransfer.PresenceLeaseSeconds*1000) {
		return Config{}, fmt.Errorf("publicTransfer presence refresh must be positive and less than half the lease TTL")
	}
	return cfg, nil
}

func environMap() map[string]string {
	result := make(map[string]string)
	for _, kv := range os.Environ() {
		if i := strings.IndexByte(kv, '='); i >= 0 {
			result[kv[:i]] = kv[i+1:]
		}
	}
	return result
}

// applyEnv applies the documented Java-style TUNNEL_* overrides.
func (cfg *Config) applyEnv(env map[string]string) {
	setInt := func(key string, target *int) {
		if v, ok := env[key]; ok {
			if n, err := strconv.Atoi(strings.TrimSpace(v)); err == nil {
				*target = n
			}
		}
	}
	setInt64 := func(key string, target *int64) {
		if v, ok := env[key]; ok {
			if n, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64); err == nil {
				*target = n
			}
		}
	}
	setStr := func(key string, target *string) {
		if v, ok := env[key]; ok {
			*target = v
		}
	}
	setBool := func(key string, target *bool) {
		if v, ok := env[key]; ok {
			if b, err := strconv.ParseBool(strings.TrimSpace(v)); err == nil {
				*target = b
			}
		}
	}
	setFloat64 := func(key string, target *float64) {
		if v, ok := env[key]; ok {
			if n, err := strconv.ParseFloat(strings.TrimSpace(v), 64); err == nil {
				*target = n
			}
		}
	}
	setStrSlice := func(key string, target *[]string) {
		if v, ok := env[key]; ok {
			parts := regexp.MustCompile(`[,\s]+`).Split(v, -1)
			out := make([]string, 0, len(parts))
			for _, part := range parts {
				if trimmed := strings.TrimSpace(part); trimmed != "" {
					out = append(out, trimmed)
				}
			}
			*target = out
		}
	}

	setInt("TUNNEL_NETTY_PORT", &cfg.Netty.Port)
	setInt("TUNNEL_NETTY_MAX_FRAME_SIZE", &cfg.Netty.MaxFrameSize)
	setInt("TUNNEL_NETTY_WRITE_BUFFER_LOW_WATER_MARK", &cfg.Netty.WriteBufferLowWaterMark)
	setInt("TUNNEL_NETTY_WRITE_BUFFER_HIGH_WATER_MARK", &cfg.Netty.WriteBufferHighWaterMark)
	setInt("TUNNEL_NETTY_MAX_EXTERNAL_CONNECTIONS", &cfg.Netty.MaxExternalConnections)
	setInt("TUNNEL_NETTY_MAX_EXTERNAL_CONNECTIONS_PER_CLIENT", &cfg.Netty.MaxExternalConnectionsPerClient)
	setInt("TUNNEL_NETTY_MAX_EXTERNAL_CONNECTIONS_PER_PORT", &cfg.Netty.MaxExternalConnectionsPerPort)

	setInt("TUNNEL_LOGIN_EXECUTOR_MAX_SIZE", &cfg.Login.ExecutorMaxSize)
	setInt("TUNNEL_LOGIN_EXECUTOR_QUEUE_CAPACITY", &cfg.Login.ExecutorQueueCapacity)
	setInt("TUNNEL_LOGIN_EXECUTOR_MAX", &cfg.Login.ExecutorMaxSize)
	setInt("TUNNEL_LOGIN_EXECUTOR_QUEUE", &cfg.Login.ExecutorQueueCapacity)

	setStr("TUNNEL_DB_PROVIDER", &cfg.Database.Provider)
	setBool("TUNNEL_DB_SEED_DEMO_CLIENT", &cfg.Database.SeedDemoClient)

	setBool("TUNNEL_AUTH_PASSWORD_LOGIN_ENABLED", &cfg.Auth.PasswordLoginEnabled)
	setBool("TUNNEL_AUTH_REGISTRATION_ENABLED", &cfg.Auth.RegistrationEnabled)
	setStr("TUNNEL_AUTH_USERNAME", &cfg.Auth.Username)
	setStr("TUNNEL_AUTH_PASSWORD", &cfg.Auth.Password)
	setStr("TUNNEL_AUTH_TENANT_ID", &cfg.Auth.TenantID)
	setStr("TUNNEL_AUTH_JWT_SECRET", &cfg.Auth.JwtSecret)
	setInt64("TUNNEL_AUTH_TOKEN_TTL_SECONDS", &cfg.Auth.TokenTTLSeconds)
	setBool("TUNNEL_AUTH_TURNSTILE_ENABLED", &cfg.Auth.Turnstile.Enabled)
	setStr("TUNNEL_AUTH_TURNSTILE_SITE_KEY", &cfg.Auth.Turnstile.SiteKey)
	setStr("TUNNEL_AUTH_TURNSTILE_SECRET_KEY", &cfg.Auth.Turnstile.SecretKey)
	setStr("TUNNEL_AUTH_TURNSTILE_VERIFY_URL", &cfg.Auth.Turnstile.VerifyURL)
	setStrSlice("TUNNEL_AUTH_TURNSTILE_ALLOWED_HOSTNAMES", &cfg.Auth.Turnstile.AllowedHostnames)
	setBool("TUNNEL_AUTH_EMAIL_VERIFICATION_ENABLED", &cfg.Auth.EmailVerification.Enabled)
	setStr("TUNNEL_AUTH_EMAIL_FROM_ADDRESS", &cfg.Auth.EmailVerification.FromAddress)
	setStr("TUNNEL_AUTH_EMAIL_FROM_NAME", &cfg.Auth.EmailVerification.FromName)
	setStr("TUNNEL_AUTH_EMAIL_SUBJECT", &cfg.Auth.EmailVerification.Subject)
	setInt64("TUNNEL_AUTH_EMAIL_CODE_TTL_SECONDS", &cfg.Auth.EmailVerification.CodeTTLSeconds)
	setInt("TUNNEL_AUTH_EMAIL_MAX_ATTEMPTS", &cfg.Auth.EmailVerification.MaxAttempts)
	setInt64("TUNNEL_AUTH_EMAIL_RESEND_COOLDOWN_SECONDS", &cfg.Auth.EmailVerification.ResendCooldownSeconds)
	setInt64("TUNNEL_AUTH_EMAIL_CLEANUP_INTERVAL_MS", &cfg.Auth.EmailVerification.CleanupIntervalMs)
	setStr("TUNNEL_AUTH_SMTP_HOST", &cfg.Auth.EmailVerification.SMTPHost)
	setInt("TUNNEL_AUTH_SMTP_PORT", &cfg.Auth.EmailVerification.SMTPPort)
	setStr("TUNNEL_AUTH_SMTP_USERNAME", &cfg.Auth.EmailVerification.SMTPUsername)
	setStr("TUNNEL_AUTH_SMTP_PASSWORD", &cfg.Auth.EmailVerification.SMTPPassword)
	setBool("TUNNEL_AUTH_SMTP_STARTTLS", &cfg.Auth.EmailVerification.SMTPStartTLS)
	setBool("TUNNEL_AUTH_SMTP_STARTTLS_REQUIRED", &cfg.Auth.EmailVerification.SMTPStartTLSRequired)
	setBool("TUNNEL_AUTH_SMTP_SSL", &cfg.Auth.EmailVerification.SMTPSSL)

	setInt("TUNNEL_CLIENT_AUTH_DEFAULT_MAX_ONLINE_INSTANCES", &cfg.ClientAuth.DefaultMaxOnlineInstances)
	setInt("TUNNEL_CLIENT_AUTH_PER_MACHINE_USER_MAX_INSTANCES", &cfg.ClientAuth.PerMachineUserMaxInstances)
	setInt64("TUNNEL_CLIENT_AUTH_TOKEN_TTL_SECONDS", &cfg.ClientAuth.TokenTTLSeconds)

	setInt("TUNNEL_CONNECTION_DETAIL_RETENTION_DAYS", &cfg.ConnectionRecord.DetailRetentionDays)
	setInt64("TUNNEL_CONNECTION_ARCHIVE_INTERVAL_MS", &cfg.ConnectionRecord.ArchiveIntervalMs)

	setInt("TUNNEL_TRAFFIC_FLUSH_INTERVAL_MS", &cfg.Traffic.FlushIntervalMs)
	setBool("TUNNEL_TRAFFIC_CAPTURE_DETAIL_ENABLED", &cfg.Traffic.CaptureDetailEnabled)
	setInt("TUNNEL_TRAFFIC_CAPTURE_PREVIEW_BYTES", &cfg.Traffic.CapturePreviewBytes)
	setInt("TUNNEL_TRAFFIC_CAPTURE_HEADER_CHARS", &cfg.Traffic.CaptureHeaderChars)
	setInt("TUNNEL_TRAFFIC_CAPTURE_DECODE_MAX_BYTES", &cfg.Traffic.CaptureDecodeMaxBytes)
	setInt("TUNNEL_TRAFFIC_CAPTURE_MAX_PENDING", &cfg.Traffic.CaptureMaxPending)
	setInt("TUNNEL_TRAFFIC_CAPTURE_FLUSH_BATCH_SIZE", &cfg.Traffic.CaptureFlushBatchSize)
	setInt("TUNNEL_TRAFFIC_CAPTURE_FLUSH_INTERVAL_MS", &cfg.Traffic.CaptureFlushIntervalMs)
	setFloat64("TUNNEL_TRAFFIC_CAPTURE_SAMPLE_RATE", &cfg.Traffic.CaptureSampleRate)

	setStr("TUNNEL_ELASTICSEARCH_URIS", &cfg.Elasticsearch.URIs)
	setStr("TUNNEL_ELASTICSEARCH_USERNAME", &cfg.Elasticsearch.Username)
	setStr("TUNNEL_ELASTICSEARCH_PASSWORD", &cfg.Elasticsearch.Password)
	setStr("TUNNEL_ELASTICSEARCH_API_KEY", &cfg.Elasticsearch.APIKey)
	setStr("TUNNEL_ELASTICSEARCH_HTTP_INDEX", &cfg.Elasticsearch.HTTPIndex)
	setStr("TUNNEL_ELASTICSEARCH_TCP_INDEX", &cfg.Elasticsearch.TCPIndex)
	setStr("TUNNEL_ELASTICSEARCH_HTTP_MAX_STORE_SIZE", &cfg.Elasticsearch.HTTPMaxStoreSize)
	setStr("TUNNEL_ELASTICSEARCH_TCP_MAX_STORE_SIZE", &cfg.Elasticsearch.TCPMaxStoreSize)

	setInt("TUNNEL_HTTP_TIMEOUT_MS", &cfg.HTTP.TimeoutMs)
	setInt("TUNNEL_HTTP_MAX_REQUEST_BODY_SIZE", &cfg.HTTP.MaxRequestBodySize)
	setInt("TUNNEL_HTTP_REWRITE_MAX_BODY_BYTES", &cfg.HTTP.RewriteMaxBodyBytes)

	setBool("TUNNEL_PEER_MESH_ENABLED", &cfg.PeerMesh.Enabled)
	setStr("TUNNEL_PEER_MESH_CIDR", &cfg.PeerMesh.CIDR)
	setStr("TUNNEL_PEER_MESH_PUBLIC_ADDRESS", &cfg.PeerMesh.PublicAddress)
	setInt("TUNNEL_PEER_MESH_STUN_TURN_PORT", &cfg.PeerMesh.StunTurnPort)
	setStr("TUNNEL_PEER_MESH_STANDALONE_STUN_ADDRESS", &cfg.PeerMesh.StandaloneStunAddress)
	setInt("TUNNEL_PEER_MESH_STANDALONE_STUN_PORT", &cfg.PeerMesh.StandaloneStunPort)
	setInt("TUNNEL_PEER_MESH_NAT_PROBE_ALTERNATE_PORT", &cfg.PeerMesh.NatProbeAlternatePort)
	setStrSlice("TUNNEL_PEER_MESH_PUBLIC_STUN_SERVERS", &cfg.PeerMesh.PublicStunServers)
	setInt64("TUNNEL_PEER_MESH_SESSION_TTL_SECONDS", &cfg.PeerMesh.SessionTTLSeconds)
	setInt64("TUNNEL_PEER_MESH_ALLOCATION_TTL_SECONDS", &cfg.PeerMesh.AllocationTTLSeconds)
	setInt64("TUNNEL_PEER_MESH_SESSION_CLEANUP_INTERVAL_MS", &cfg.PeerMesh.SessionCleanupIntervalMs)
	setInt("TUNNEL_PEER_MESH_RELAY_MIN_PORT", &cfg.PeerMesh.RelayMinPort)
	setInt("TUNNEL_PEER_MESH_RELAY_MAX_PORT", &cfg.PeerMesh.RelayMaxPort)
	setInt("TUNNEL_PEER_MESH_RELAY_WORKER_THREADS", &cfg.PeerMesh.RelayWorkerThreads)
	setInt("TUNNEL_PEER_MESH_RELAY_WORKER_QUEUE_CAPACITY", &cfg.PeerMesh.RelayWorkerQueueCapacity)
	setInt("TUNNEL_PEER_MESH_RELAY_TRAFFIC_FLUSH_INTERVAL_MS", &cfg.PeerMesh.RelayTrafficFlushIntervalMs)
	setBool("TUNNEL_PEER_MESH_TURN_AUTH_REQUIRED", &cfg.PeerMesh.TurnAuthRequired)
	setStr("TUNNEL_PEER_MESH_TURN_REALM", &cfg.PeerMesh.TurnRealm)
	setStr("TUNNEL_PEER_MESH_TURN_SHARED_SECRET", &cfg.PeerMesh.TurnSharedSecret)
	setInt64("TUNNEL_PEER_MESH_TURN_CREDENTIAL_TTL_SECONDS", &cfg.PeerMesh.TurnCredentialTTLSeconds)
	setInt("TUNNEL_PEER_MESH_GENERAL_RELAY_MAX_ALLOCATIONS", &cfg.PeerMesh.GeneralRelayMaxAllocations)
	setInt("TUNNEL_PEER_MESH_GENERAL_RELAY_MAX_ALLOCATIONS_PER_ADDRESS", &cfg.PeerMesh.GeneralRelayMaxAllocationsPerAddr)
	setInt64("TUNNEL_PEER_MESH_GENERAL_RELAY_RATE_BYTES_PER_SECOND", &cfg.PeerMesh.GeneralRelayRateBytesPerSecond)
	setInt64("TUNNEL_PEER_MESH_GENERAL_RELAY_MAX_BYTES", &cfg.PeerMesh.GeneralRelayMaxBytes)

	setStr("TUNNEL_OBJECT_STORAGE_PROVIDER", &cfg.ObjectStorage.Provider)
	setStr("TUNNEL_OBJECT_STORAGE_ENDPOINT", &cfg.ObjectStorage.Endpoint)
	setStr("TUNNEL_OBJECT_STORAGE_REGION", &cfg.ObjectStorage.Region)
	setStr("TUNNEL_OBJECT_STORAGE_BUCKET", &cfg.ObjectStorage.Bucket)
	setStr("TUNNEL_OBJECT_STORAGE_ACCESS_KEY_ID", &cfg.ObjectStorage.AccessKeyID)
	setStr("TUNNEL_OBJECT_STORAGE_ACCESS_KEY_SECRET", &cfg.ObjectStorage.AccessKeySecret)
	setStr("TUNNEL_OBJECT_STORAGE_PREFIX", &cfg.ObjectStorage.ObjectPrefix)
	setStr("TUNNEL_OBJECT_STORAGE_UPLOAD_CALLBACK_URL", &cfg.ObjectStorage.UploadCallbackURL)
	setInt64("TUNNEL_OBJECT_STORAGE_UPLOAD_URL_TTL_SECONDS", &cfg.ObjectStorage.UploadURLTTLSeconds)
	setInt64("TUNNEL_OBJECT_STORAGE_DOWNLOAD_URL_TTL_SECONDS", &cfg.ObjectStorage.DownloadURLTTLSeconds)
	setInt64("TUNNEL_OBJECT_STORAGE_DOWNLOAD_OBJECT_URL_TTL_SECONDS", &cfg.ObjectStorage.DownloadObjectURLTTLSeconds)
	setInt64("TUNNEL_OBJECT_STORAGE_RETENTION_HOURS", &cfg.ObjectStorage.RetentionHours)
	setInt64("TUNNEL_OBJECT_STORAGE_MAX_ATTACHMENT_BYTES", &cfg.ObjectStorage.MaxAttachmentBytes)
	setInt64("TUNNEL_OBJECT_STORAGE_PER_USER_STORAGE_QUOTA_BYTES", &cfg.ObjectStorage.PerUserStorageQuotaBytes)
	setInt64("TUNNEL_OBJECT_STORAGE_PER_USER_MONTHLY_DOWNLOAD_QUOTA_BYTES", &cfg.ObjectStorage.PerUserMonthlyDownloadQuotaBytes)
	setInt64("TUNNEL_OBJECT_STORAGE_EXPIRATION_SCAN_INTERVAL_MS", &cfg.ObjectStorage.ExpirationScanIntervalMs)

	setInt("TUNNEL_PUBLIC_TRANSFER_PRESIGN_RATE_LIMIT_PER_IP", &cfg.PublicTransfer.PresignRateLimitPerIP)
	setInt64("TUNNEL_PUBLIC_TRANSFER_PRESIGN_RATE_LIMIT_WINDOW_SECONDS", &cfg.PublicTransfer.PresignRateLimitWindowSeconds)
	setInt("TUNNEL_PUBLIC_TRANSFER_MAX_PENDING_UPLOADS_PER_ROOM", &cfg.PublicTransfer.MaxPendingUploadsPerRoom)
	setInt("TUNNEL_PUBLIC_TRANSFER_MAX_DISCOVERY_PEERS_PER_ROOM", &cfg.PublicTransfer.MaxDiscoveryPeersPerRoom)
	setInt("TUNNEL_PUBLIC_TRANSFER_DISCOVERY_MESSAGE_RATE_LIMIT_PER_CONNECTION", &cfg.PublicTransfer.DiscoveryMessageRateLimitPerConnection)
	setInt64("TUNNEL_PUBLIC_TRANSFER_DISCOVERY_MESSAGE_RATE_LIMIT_WINDOW_SECONDS", &cfg.PublicTransfer.DiscoveryMessageRateLimitWindowSeconds)
	setBool("TUNNEL_PUBLIC_TRANSFER_CLUSTER_ENABLED", &cfg.PublicTransfer.ClusterEnabled)
	setStr("TUNNEL_PUBLIC_TRANSFER_REDIS_URI", &cfg.PublicTransfer.RedisURI)
	setStr("TUNNEL_PUBLIC_TRANSFER_REDIS_KEY_PREFIX", &cfg.PublicTransfer.RedisKeyPrefix)
	setInt64("TUNNEL_PUBLIC_TRANSFER_PRESENCE_LEASE_SECONDS", &cfg.PublicTransfer.PresenceLeaseSeconds)
	setInt64("TUNNEL_PUBLIC_TRANSFER_PRESENCE_REFRESH_INTERVAL_MS", &cfg.PublicTransfer.PresenceRefreshIntervalMs)
	setInt64("TUNNEL_PUBLIC_TRANSFER_REDIS_COMMAND_TIMEOUT_MS", &cfg.PublicTransfer.RedisCommandTimeoutMs)

	setStr("TUNNEL_OIDC_ISSUER", &cfg.Oidc.Issuer)
	setStr("TUNNEL_OIDC_JWK_SET_URI", &cfg.Oidc.JwkSetURI)
	setStr("TUNNEL_OIDC_AUTHORIZATION_ENDPOINT", &cfg.Oidc.AuthorizationEndpoint)
	setStr("TUNNEL_OIDC_TOKEN_ENDPOINT", &cfg.Oidc.TokenEndpoint)
	setStr("TUNNEL_OIDC_END_SESSION_ENDPOINT", &cfg.Oidc.EndSessionEndpoint)
	setStr("TUNNEL_OIDC_CLIENT_ID", &cfg.Oidc.ClientID)
	setStr("TUNNEL_OIDC_CLIENT_SECRET", &cfg.Oidc.ClientSecret)
	setStr("TUNNEL_OIDC_REDIRECT_URI", &cfg.Oidc.RedirectURI)
	setStr("TUNNEL_OIDC_SCOPE", &cfg.Oidc.Scope)
	setStr("TUNNEL_OIDC_AUDIENCE", &cfg.Oidc.Audience)
	setStr("TUNNEL_OIDC_TENANT_CLAIM", &cfg.Oidc.TenantClaim)

	setStr("TUNNEL_TLS_MODE", &cfg.TLS.Mode)
	setStr("TUNNEL_TLS_KEYSTORE", &cfg.TLS.Keystore)
	setStr("TUNNEL_TLS_KEYSTORE_PASSWORD", &cfg.TLS.KeystorePassword)
	setStr("TUNNEL_TLS_CERT_FILE", &cfg.TLS.CertFile)
	setStr("TUNNEL_TLS_KEY_FILE", &cfg.TLS.KeyFile)
	setStr("TUNNEL_TLS_KEY_PASSWORD", &cfg.TLS.KeyPassword)

	setStr("TUNNEL_PUBLIC_ADDRESS", &cfg.PublicAddress)
	setStr("TUNNEL_MANAGEMENT_ADDR", &cfg.ManagementAddr)

	// Connection string: both TUNNEL_CONNECTIONSTRINGS_TUNNEL and TUNNEL_DB_CONNECTION_STRING.
	setStr("TUNNEL_CONNECTIONSTRINGS_TUNNEL", &cfg.ConnectionString)
	setStr("TUNNEL_DB_CONNECTION_STRING", &cfg.ConnectionString)
}
