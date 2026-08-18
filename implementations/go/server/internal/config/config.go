// Package config holds the specus-server configuration: defaults, optional JSON file
// overrides, and Java-style SPECUS_* environment variable overrides. It mirrors the
// option groups of the C# server (Specus:Netty, Specus:Auth, etc.).
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
	MediaCapture     MediaCaptureConfig     `json:"mediaCapture"`
	PeerMesh         PeerMeshConfig         `json:"peerMesh"`
	ObjectStorage    ObjectStorageConfig    `json:"objectStorage"`
	PublicTransfer   PublicTransferConfig   `json:"publicTransfer"`
	Oidc             OidcConfig             `json:"oidc"`
	TLS              TLSConfig              `json:"tls"`
	// Env is the deployment environment: prod (default) | dev | test. Unset or unknown values
	// resolve to prod so a typo never disables a production guard.
	Env              string                 `json:"env"`
	PublicAddress    string                 `json:"publicAddress"`
	ConnectionString string                 `json:"connectionString"`
	// ManagementAddr is the listen address for the admin/HTTP surface (default :8088).
	ManagementAddr string `json:"managementAddr"`
}

// NettyConfig mirrors Specus:Netty.
type NettyConfig struct {
	BindAddress                     string `json:"bindAddress"`
	Port                            int    `json:"port"`
	BossThreads                     int    `json:"bossThreads"`
	WorkerThreads                   int    `json:"workerThreads"`
	RemoteBossThreads               int    `json:"remoteBossThreads"`
	RemoteWorkerThreads             int    `json:"remoteWorkerThreads"`
	SOBacklog                       int    `json:"soBacklog"`
	ReuseAddress                    bool   `json:"reuseAddress"`
	KeepAlive                       bool   `json:"keepAlive"`
	TCPNoDelay                      bool   `json:"tcpNoDelay"`
	MaxFrameSize                    int    `json:"maxFrameSize"`
	PreAuthMaxFrameSize             int    `json:"preAuthMaxFrameSize"`
	WriteBufferLowWaterMark         int    `json:"writeBufferLowWaterMark"`
	WriteBufferHighWaterMark        int    `json:"writeBufferHighWaterMark"`
	MaxExternalConnections          int    `json:"maxExternalConnections"`
	MaxExternalConnectionsPerClient int    `json:"maxExternalConnectionsPerClient"`
	MaxExternalConnectionsPerPort   int    `json:"maxExternalConnectionsPerPort"`
}

// LoginConfig mirrors Specus:Login.
type LoginConfig struct {
	ExecutorCoreSize      int `json:"executorCoreSize"`
	ExecutorMaxSize       int `json:"executorMaxSize"`
	ExecutorQueueCapacity int `json:"executorQueueCapacity"`
}

// DatabaseConfig mirrors Specus:Database.
type DatabaseConfig struct {
	Provider       string `json:"provider"`
	SeedDemoClient bool   `json:"seedDemoClient"`
}

// AuthConfig mirrors Specus:Auth.
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
	LoginRateLimit       LoginRateLimitConfig    `json:"loginRateLimit"`
}

// LoginRateLimitConfig bounds login attempts independently of the captcha, so deployments that run
// without Turnstile still limit credential stuffing.
type LoginRateLimitConfig struct {
	Enabled       bool  `json:"enabled"`
	PerIP         int   `json:"perIp"`
	PerAccount    int   `json:"perAccount"`
	WindowSeconds int64 `json:"windowSeconds"`
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

// ClientAuthConfig mirrors Specus:ClientAuth.
type ClientAuthConfig struct {
	DefaultMaxOnlineInstances  int   `json:"defaultMaxOnlineInstances"`
	PerMachineUserMaxInstances int   `json:"perMachineUserMaxInstances"`
	TokenTTLSeconds            int64 `json:"tokenTtlSeconds"`
}

// ConnectionRecordConfig mirrors specus.connection-record in the Java server.
type ConnectionRecordConfig struct {
	DetailRetentionDays int   `json:"detailRetentionDays"`
	ArchiveIntervalMs   int64 `json:"archiveIntervalMs"`
}

// TrafficConfig mirrors Specus:Traffic.
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

// ElasticsearchConfig mirrors Specus:Elasticsearch for traffic detail storage.
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

// DirectHTTPConfig mirrors Specus:Http.
type DirectHTTPConfig struct {
	TimeoutMs           int `json:"timeoutMs"`
	MaxRequestBodySize  int `json:"maxRequestBodySize"`
	RouteCacheTTLms     int `json:"routeCacheTtlMs"`
	RewriteMaxBodyBytes int `json:"rewriteMaxBodyBytes"`
}

// MediaCaptureConfig mirrors specus.media-capture in the Java server. Media capture is
// deliberately independent from attachment object storage because captured responses are
// streamed into a RustFS/S3-compatible private bucket by the server itself.
type MediaCaptureConfig struct {
	Enabled                  bool   `json:"enabled"`
	Endpoint                 string `json:"endpoint"`
	Region                   string `json:"region"`
	Bucket                   string `json:"bucket"`
	AccessKeyID              string `json:"accessKeyId"`
	AccessKeySecret          string `json:"accessKeySecret"`
	ObjectPrefix             string `json:"objectPrefix"`
	PathStyle                bool   `json:"pathStyle"`
	CreateBucketIfMissing    bool   `json:"createBucketIfMissing"`
	PartSizeBytes            int64  `json:"partSizeBytes"`
	MaxInflightParts         int    `json:"maxInflightParts"`
	UploadThreads            int    `json:"uploadThreads"`
	RetentionSeconds         int64  `json:"retentionSeconds"`
	LiveWindowSeconds        int64  `json:"liveWindowSeconds"`
	ManifestMaxBytes         int64  `json:"manifestMaxBytes"`
	PlaybackTicketTTLSeconds int64  `json:"playbackTicketTtlSeconds"`
	CleanupIntervalMs        int64  `json:"cleanupIntervalMs"`
}

// Ready reports whether capture was explicitly enabled and every credential needed for
// server-side S3 access is present. Incomplete configuration is treated as disabled.
func (c MediaCaptureConfig) Ready() bool {
	return c.Enabled && strings.TrimSpace(c.Endpoint) != "" && strings.TrimSpace(c.Bucket) != "" &&
		strings.TrimSpace(c.AccessKeyID) != "" && strings.TrimSpace(c.AccessKeySecret) != ""
}

func (c MediaCaptureConfig) NormalizedPartSizeBytes() int64 {
	if c.PartSizeBytes < 5*1024*1024 {
		return 5 * 1024 * 1024
	}
	return c.PartSizeBytes
}

func (c MediaCaptureConfig) NormalizedMaxInflightParts() int {
	if c.MaxInflightParts < 1 {
		return 1
	}
	return c.MaxInflightParts
}

func (c MediaCaptureConfig) NormalizedUploadThreads() int {
	if c.UploadThreads < 1 {
		return 1
	}
	return c.UploadThreads
}

// PeerMeshConfig mirrors specus.peer-mesh in the Java server.
type PeerMeshConfig struct {
	Enabled                        bool     `json:"enabled"`
	CIDR                           string   `json:"cidr"`
	PublicAddress                  string   `json:"publicAddress"`
	StunTurnPort                   int      `json:"stunTurnPort"`
	StandaloneStunAddress          string   `json:"standaloneStunAddress"`
	StandaloneStunPort             int      `json:"standaloneStunPort"`
	StandaloneStunAlternateAddress string   `json:"standaloneStunAlternateAddress"`
	StandaloneStunAlternatePort    int      `json:"standaloneStunAlternatePort"`
	StunAlternatePublicAddress     string   `json:"stunAlternatePublicAddress"`
	StunPrimaryBindAddress         string   `json:"stunPrimaryBindAddress"`
	StunAlternateBindAddress       string   `json:"stunAlternateBindAddress"`
	StunBehaviorStrict             bool     `json:"stunBehaviorStrict"`
	NatProbeAlternatePort          int      `json:"natProbeAlternatePort"`
	PublicStunServers              []string `json:"publicStunServers"`
	SessionTTLSeconds              int64    `json:"sessionTtlSeconds"`
	AllocationTTLSeconds           int64    `json:"allocationTtlSeconds"`
	SessionCleanupIntervalMs       int64    `json:"sessionCleanupIntervalMs"`
	RelayMinPort                   int      `json:"relayMinPort"`
	RelayMaxPort                   int      `json:"relayMaxPort"`
	RelayWorkerThreads             int      `json:"relayWorkerThreads"`
	RelayWorkerQueueCapacity       int      `json:"relayWorkerQueueCapacity"`
	UDPReceiveBufferBytes          int      `json:"udpReceiveBufferBytes"`
	UDPSendBufferBytes             int      `json:"udpSendBufferBytes"`
	UDPTrafficClass                int      `json:"udpTrafficClass"`
	RelayTrafficFlushIntervalMs    int      `json:"relayTrafficFlushIntervalMs"`
	TurnAuthRequired               bool     `json:"turnAuthRequired"`
	TurnRealm                      string   `json:"turnRealm"`
	TurnSharedSecret               string   `json:"turnSharedSecret"`
	TurnCredentialTTLSeconds       int64    `json:"turnCredentialTtlSeconds"`

	// General relay quotas. Browser WebRTC relays DTLS/SRTP, which cannot pass the Peer Mesh
	// specific checks, so those allocations are forwarded with standard TURN semantics and
	// need their own resource limits. GeneralRelayMaxAllocations <= 0 disables general relay.
	GeneralRelayMaxAllocations        int   `json:"generalRelayMaxAllocations"`
	GeneralRelayMaxAllocationsPerAddr int   `json:"generalRelayMaxAllocationsPerAddress"`
	GeneralRelayRateBytesPerSecond    int64 `json:"generalRelayRateBytesPerSecond"`
	GeneralRelayMaxBytes              int64 `json:"generalRelayMaxBytes"`
}

// ObjectStorageConfig mirrors specus.object-storage. Attachments are uploaded directly
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

// PublicTransferConfig mirrors specus.public-transfer abuse-protection limits.
type PublicTransferConfig struct {
	PresignRateLimitPerIP                   int    `json:"presignRateLimitPerIp"`
	PresignRateLimitWindowSeconds           int64  `json:"presignRateLimitWindowSeconds"`
	MaxPendingUploadsPerRoom                int    `json:"maxPendingUploadsPerRoom"`
	MaxDiscoveryPeersPerRoom                int    `json:"maxDiscoveryPeersPerRoom"`
	DiscoveryMessageRateLimitPerConnection  int    `json:"discoveryMessageRateLimitPerConnection"`
	DiscoveryMessageRateLimitWindowSeconds  int64  `json:"discoveryMessageRateLimitWindowSeconds"`
	ClusterEnabled                          bool   `json:"clusterEnabled"`
	RedisURI                                string `json:"redisUri"`
	// RedisKeyPrefix namespaces the coordination keys. The net-merged visibility
	// indexes (nets/groupnets, global roster revision) are incompatible with
	// pre-merge nodes: deploy all cluster nodes together, or bump this prefix so
	// old and new nodes never share a keyspace.
	RedisKeyPrefix                          string `json:"redisKeyPrefix"`
	PresenceLeaseSeconds                    int64  `json:"presenceLeaseSeconds"`
	PresenceRefreshIntervalMs               int64  `json:"presenceRefreshIntervalMs"`
	RedisCommandTimeoutMs                   int64  `json:"redisCommandTimeoutMs"`
	PairingCodeTtlSeconds                   int64  `json:"pairingCodeTtlSeconds"`
	PairingCodeRedeemRateLimitPerIP         int    `json:"pairingCodeRedeemRateLimitPerIp"`
	PairingCodeRedeemRateLimitWindowSeconds int64  `json:"pairingCodeRedeemRateLimitWindowSeconds"`
}

// OidcConfig mirrors Specus:Oidc.
type OidcConfig struct {
	Issuer                string `json:"issuer"`
	JwkSetURI             string `json:"jwkSetUri"`
	AuthorizationEndpoint string `json:"authorizationEndpoint"`
	RegistrationEndpoint  string `json:"registrationEndpoint"`
	TokenEndpoint         string `json:"tokenEndpoint"`
	EndSessionEndpoint    string `json:"endSessionEndpoint"`
	ClientID              string `json:"clientId"`
	ClientSecret          string `json:"clientSecret"`
	RedirectURI           string `json:"redirectUri"`
	Scope                 string `json:"scope"`
	Audience              string `json:"audience"`
	TenantClaim           string `json:"tenantClaim"`
}

// TLSConfig mirrors Specus:Tls. Mode is one of disabled|file|self-signed.
type TLSConfig struct {
	Mode               string `json:"mode"`
	Keystore           string `json:"keystore"`
	KeystorePassword   string `json:"keystorePassword"`
	CertFile           string `json:"certFile"`
	KeyFile            string `json:"keyFile"`
	KeyPassword        string `json:"keyPassword"`
	RequireEncryption  bool   `json:"requireEncryption"`
	TerminatedUpstream bool   `json:"terminatedUpstream"`
}

// Default returns the configuration with the same defaults as the C# appsettings.json.
func Default() Config {
	return Config{
		Netty: NettyConfig{
			BindAddress:                     "0.0.0.0",
			Port:                            7010,
			BossThreads:                     1,
			WorkerThreads:                   0,
			RemoteBossThreads:               1,
			RemoteWorkerThreads:             0,
			SOBacklog:                       8192,
			ReuseAddress:                    true,
			KeepAlive:                       true,
			TCPNoDelay:                      true,
			MaxFrameSize:                    32 * 1024 * 1024,
			PreAuthMaxFrameSize:             16 * 1024,
			WriteBufferLowWaterMark:         32 * 1024,
			WriteBufferHighWaterMark:        64 * 1024,
			MaxExternalConnections:          10000,
			MaxExternalConnectionsPerClient: 10000,
			MaxExternalConnectionsPerPort:   10000,
		},
		Login:    LoginConfig{ExecutorCoreSize: 8, ExecutorMaxSize: 32, ExecutorQueueCapacity: 20000},
		Database: DatabaseConfig{Provider: "sqlite", SeedDemoClient: true},
		Auth: AuthConfig{
			PasswordLoginEnabled: true,
			RegistrationEnabled:  true,
			Username:             "admin",
			// Blank by default: password login stays disabled until an operator sets one.
			Password:        "",
			TenantID:        "default",
			TokenTTLSeconds: 28800,
			LoginRateLimit: LoginRateLimitConfig{
				Enabled:       true,
				PerIP:         20,
				PerAccount:    10,
				WindowSeconds: 300,
			},
			Turnstile: TurnstileConfig{
				VerifyURL: "https://challenges.cloudflare.com/turnstile/v0/siteverify",
			},
			EmailVerification: EmailVerificationConfig{
				FromName:              "specus",
				Subject:               "specus 注册验证码",
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
			HTTPIndex:        "specus-http-traffic",
			TCPIndex:         "specus-tcp-traffic",
			HTTPMaxStoreSize: "100GB",
			TCPMaxStoreSize:  "10GB",
		},
		HTTP: DirectHTTPConfig{
			TimeoutMs:           30000,
			MaxRequestBodySize:  16 * 1024 * 1024,
			RouteCacheTTLms:     2000,
			RewriteMaxBodyBytes: 10 * 1024 * 1024,
		},
		MediaCapture: MediaCaptureConfig{
			Region:                   "us-east-1",
			ObjectPrefix:             "specus/http-media",
			PathStyle:                true,
			PartSizeBytes:            8 * 1024 * 1024,
			MaxInflightParts:         4,
			UploadThreads:            4,
			RetentionSeconds:         7 * 24 * 60 * 60,
			LiveWindowSeconds:        5 * 60,
			ManifestMaxBytes:         16 * 1024 * 1024,
			PlaybackTicketTTLSeconds: 15 * 60,
			CleanupIntervalMs:        60 * 1000,
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
			UDPReceiveBufferBytes:       4 * 1024 * 1024,
			UDPSendBufferBytes:          4 * 1024 * 1024,
			UDPTrafficClass:             16,
			RelayTrafficFlushIntervalMs: 5000,
			TurnAuthRequired:            true,
			TurnRealm:                   "specus",
			TurnCredentialTTLSeconds:    3600,

			GeneralRelayMaxAllocations:        256,
			GeneralRelayMaxAllocationsPerAddr: 4,
			GeneralRelayMaxBytes:              512 * 1024 * 1024,
		},
		ObjectStorage: ObjectStorageConfig{
			Provider:                         "disabled",
			ObjectPrefix:                     "specus/attachments",
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
			PresignRateLimitPerIP:                   30,
			PresignRateLimitWindowSeconds:           300,
			MaxPendingUploadsPerRoom:                50,
			MaxDiscoveryPeersPerRoom:                32,
			DiscoveryMessageRateLimitPerConnection:  360,
			DiscoveryMessageRateLimitWindowSeconds:  60,
			RedisKeyPrefix:                          "specus:v2:public-transfer",
			PresenceLeaseSeconds:                    30,
			PresenceRefreshIntervalMs:               10000,
			RedisCommandTimeoutMs:                   2000,
			PairingCodeTtlSeconds:                   300,
			PairingCodeRedeemRateLimitPerIP:         10,
			PairingCodeRedeemRateLimitWindowSeconds: 300,
		},
		Oidc: OidcConfig{
			Issuer:                "https://certus.devshuai.com",
			JwkSetURI:             "https://certus.devshuai.com/oauth2/jwks",
			AuthorizationEndpoint: "https://certus.devshuai.com/oauth2/authorize",
			RegistrationEndpoint:  "https://certus.devshuai.com/register",
			TokenEndpoint:         "https://certus.devshuai.com/oauth2/token",
			EndSessionEndpoint:    "https://certus.devshuai.com/oauth2/logout",
			RedirectURI:           "http://127.0.0.1:8088/",
			Scope:                 "openid profile email",
			TenantClaim:           "tenant_id",
		},
		TLS:              TLSConfig{Mode: "disabled"},
		ConnectionString: "./specus.db",
		ManagementAddr:   ":8088",
	}
}

// Load builds the configuration: defaults, then the optional JSON file at path (when
// non-empty and present), then SPECUS_* environment overrides.
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
	if err := cfg.validateSecurityBaseline(); err != nil {
		return Config{}, err
	}
	if cfg.Netty.MaxFrameSize < 11 {
		return Config{}, fmt.Errorf("netty.maxFrameSize must be at least the 11-byte frame header")
	}
	if cfg.Netty.PreAuthMaxFrameSize < 11 || cfg.Netty.PreAuthMaxFrameSize > cfg.Netty.MaxFrameSize {
		return Config{}, fmt.Errorf("netty.preAuthMaxFrameSize must be between 11 and netty.maxFrameSize")
	}
	if cfg.Login.ExecutorCoreSize < 1 || cfg.Login.ExecutorMaxSize < cfg.Login.ExecutorCoreSize {
		return Config{}, fmt.Errorf("login executor sizes must satisfy 1 <= coreSize <= maxSize")
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

// applyEnv applies the documented Java-style SPECUS_* overrides.
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

	setStr("SPECUS_NETTY_BIND_ADDRESS", &cfg.Netty.BindAddress)
	setInt("SPECUS_NETTY_PORT", &cfg.Netty.Port)
	setInt("SPECUS_NETTY_BOSS_THREADS", &cfg.Netty.BossThreads)
	setInt("SPECUS_NETTY_WORKER_THREADS", &cfg.Netty.WorkerThreads)
	setInt("SPECUS_NETTY_REMOTE_BOSS_THREADS", &cfg.Netty.RemoteBossThreads)
	setInt("SPECUS_NETTY_REMOTE_WORKER_THREADS", &cfg.Netty.RemoteWorkerThreads)
	setInt("SPECUS_NETTY_SO_BACKLOG", &cfg.Netty.SOBacklog)
	setBool("SPECUS_NETTY_REUSE_ADDRESS", &cfg.Netty.ReuseAddress)
	setBool("SPECUS_NETTY_KEEP_ALIVE", &cfg.Netty.KeepAlive)
	setBool("SPECUS_NETTY_TCP_NO_DELAY", &cfg.Netty.TCPNoDelay)
	setInt("SPECUS_NETTY_MAX_FRAME_SIZE", &cfg.Netty.MaxFrameSize)
	setInt("SPECUS_NETTY_PRE_AUTH_MAX_FRAME_SIZE", &cfg.Netty.PreAuthMaxFrameSize)
	setInt("SPECUS_NETTY_WRITE_BUFFER_LOW_WATER_MARK", &cfg.Netty.WriteBufferLowWaterMark)
	setInt("SPECUS_NETTY_WRITE_BUFFER_HIGH_WATER_MARK", &cfg.Netty.WriteBufferHighWaterMark)
	setInt("SPECUS_NETTY_MAX_EXTERNAL_CONNECTIONS", &cfg.Netty.MaxExternalConnections)
	setInt("SPECUS_NETTY_MAX_EXTERNAL_CONNECTIONS_PER_CLIENT", &cfg.Netty.MaxExternalConnectionsPerClient)
	setInt("SPECUS_NETTY_MAX_EXTERNAL_CONNECTIONS_PER_PORT", &cfg.Netty.MaxExternalConnectionsPerPort)

	setInt("SPECUS_LOGIN_EXECUTOR_CORE_SIZE", &cfg.Login.ExecutorCoreSize)
	setInt("SPECUS_LOGIN_EXECUTOR_CORE", &cfg.Login.ExecutorCoreSize)
	setInt("SPECUS_LOGIN_EXECUTOR_MAX_SIZE", &cfg.Login.ExecutorMaxSize)
	setInt("SPECUS_LOGIN_EXECUTOR_QUEUE_CAPACITY", &cfg.Login.ExecutorQueueCapacity)
	setInt("SPECUS_LOGIN_EXECUTOR_MAX", &cfg.Login.ExecutorMaxSize)
	setInt("SPECUS_LOGIN_EXECUTOR_QUEUE", &cfg.Login.ExecutorQueueCapacity)

	setStr("SPECUS_ENV", &cfg.Env)

	setStr("SPECUS_DB_PROVIDER", &cfg.Database.Provider)
	setBool("SPECUS_DB_SEED_DEMO_CLIENT", &cfg.Database.SeedDemoClient)

	setBool("SPECUS_AUTH_PASSWORD_LOGIN_ENABLED", &cfg.Auth.PasswordLoginEnabled)
	setBool("SPECUS_AUTH_REGISTRATION_ENABLED", &cfg.Auth.RegistrationEnabled)
	setStr("SPECUS_AUTH_USERNAME", &cfg.Auth.Username)
	setStr("SPECUS_AUTH_PASSWORD", &cfg.Auth.Password)
	setStr("SPECUS_AUTH_TENANT_ID", &cfg.Auth.TenantID)
	setStr("SPECUS_AUTH_JWT_SECRET", &cfg.Auth.JwtSecret)
	setInt64("SPECUS_AUTH_TOKEN_TTL_SECONDS", &cfg.Auth.TokenTTLSeconds)
	setBool("SPECUS_AUTH_LOGIN_RATE_LIMIT_ENABLED", &cfg.Auth.LoginRateLimit.Enabled)
	setInt("SPECUS_AUTH_LOGIN_RATE_LIMIT_PER_IP", &cfg.Auth.LoginRateLimit.PerIP)
	setInt("SPECUS_AUTH_LOGIN_RATE_LIMIT_PER_ACCOUNT", &cfg.Auth.LoginRateLimit.PerAccount)
	setInt64("SPECUS_AUTH_LOGIN_RATE_LIMIT_WINDOW_SECONDS", &cfg.Auth.LoginRateLimit.WindowSeconds)
	setBool("SPECUS_AUTH_TURNSTILE_ENABLED", &cfg.Auth.Turnstile.Enabled)
	setStr("SPECUS_AUTH_TURNSTILE_SITE_KEY", &cfg.Auth.Turnstile.SiteKey)
	setStr("SPECUS_AUTH_TURNSTILE_SECRET_KEY", &cfg.Auth.Turnstile.SecretKey)
	setStr("SPECUS_AUTH_TURNSTILE_VERIFY_URL", &cfg.Auth.Turnstile.VerifyURL)
	setStrSlice("SPECUS_AUTH_TURNSTILE_ALLOWED_HOSTNAMES", &cfg.Auth.Turnstile.AllowedHostnames)
	setBool("SPECUS_AUTH_EMAIL_VERIFICATION_ENABLED", &cfg.Auth.EmailVerification.Enabled)
	setStr("SPECUS_AUTH_EMAIL_FROM_ADDRESS", &cfg.Auth.EmailVerification.FromAddress)
	setStr("SPECUS_AUTH_EMAIL_FROM_NAME", &cfg.Auth.EmailVerification.FromName)
	setStr("SPECUS_AUTH_EMAIL_SUBJECT", &cfg.Auth.EmailVerification.Subject)
	setInt64("SPECUS_AUTH_EMAIL_CODE_TTL_SECONDS", &cfg.Auth.EmailVerification.CodeTTLSeconds)
	setInt("SPECUS_AUTH_EMAIL_MAX_ATTEMPTS", &cfg.Auth.EmailVerification.MaxAttempts)
	setInt64("SPECUS_AUTH_EMAIL_RESEND_COOLDOWN_SECONDS", &cfg.Auth.EmailVerification.ResendCooldownSeconds)
	setInt64("SPECUS_AUTH_EMAIL_CLEANUP_INTERVAL_MS", &cfg.Auth.EmailVerification.CleanupIntervalMs)
	setStr("SPECUS_AUTH_SMTP_HOST", &cfg.Auth.EmailVerification.SMTPHost)
	setInt("SPECUS_AUTH_SMTP_PORT", &cfg.Auth.EmailVerification.SMTPPort)
	setStr("SPECUS_AUTH_SMTP_USERNAME", &cfg.Auth.EmailVerification.SMTPUsername)
	setStr("SPECUS_AUTH_SMTP_PASSWORD", &cfg.Auth.EmailVerification.SMTPPassword)
	setBool("SPECUS_AUTH_SMTP_STARTTLS", &cfg.Auth.EmailVerification.SMTPStartTLS)
	setBool("SPECUS_AUTH_SMTP_STARTTLS_REQUIRED", &cfg.Auth.EmailVerification.SMTPStartTLSRequired)
	setBool("SPECUS_AUTH_SMTP_SSL", &cfg.Auth.EmailVerification.SMTPSSL)

	setInt("SPECUS_CLIENT_AUTH_DEFAULT_MAX_ONLINE_INSTANCES", &cfg.ClientAuth.DefaultMaxOnlineInstances)
	setInt("SPECUS_CLIENT_AUTH_PER_MACHINE_USER_MAX_INSTANCES", &cfg.ClientAuth.PerMachineUserMaxInstances)
	setInt64("SPECUS_CLIENT_AUTH_TOKEN_TTL_SECONDS", &cfg.ClientAuth.TokenTTLSeconds)

	setInt("SPECUS_CONNECTION_DETAIL_RETENTION_DAYS", &cfg.ConnectionRecord.DetailRetentionDays)
	setInt64("SPECUS_CONNECTION_ARCHIVE_INTERVAL_MS", &cfg.ConnectionRecord.ArchiveIntervalMs)

	setInt("SPECUS_TRAFFIC_FLUSH_INTERVAL_MS", &cfg.Traffic.FlushIntervalMs)
	setBool("SPECUS_TRAFFIC_CAPTURE_DETAIL_ENABLED", &cfg.Traffic.CaptureDetailEnabled)
	setInt("SPECUS_TRAFFIC_CAPTURE_PREVIEW_BYTES", &cfg.Traffic.CapturePreviewBytes)
	setInt("SPECUS_TRAFFIC_CAPTURE_HEADER_CHARS", &cfg.Traffic.CaptureHeaderChars)
	setInt("SPECUS_TRAFFIC_CAPTURE_DECODE_MAX_BYTES", &cfg.Traffic.CaptureDecodeMaxBytes)
	setInt("SPECUS_TRAFFIC_CAPTURE_MAX_PENDING", &cfg.Traffic.CaptureMaxPending)
	setInt("SPECUS_TRAFFIC_CAPTURE_FLUSH_BATCH_SIZE", &cfg.Traffic.CaptureFlushBatchSize)
	setInt("SPECUS_TRAFFIC_CAPTURE_FLUSH_INTERVAL_MS", &cfg.Traffic.CaptureFlushIntervalMs)
	setFloat64("SPECUS_TRAFFIC_CAPTURE_SAMPLE_RATE", &cfg.Traffic.CaptureSampleRate)

	setStr("SPECUS_ELASTICSEARCH_URIS", &cfg.Elasticsearch.URIs)
	setStr("SPECUS_ELASTICSEARCH_USERNAME", &cfg.Elasticsearch.Username)
	setStr("SPECUS_ELASTICSEARCH_PASSWORD", &cfg.Elasticsearch.Password)
	setStr("SPECUS_ELASTICSEARCH_API_KEY", &cfg.Elasticsearch.APIKey)
	setStr("SPECUS_ELASTICSEARCH_HTTP_INDEX", &cfg.Elasticsearch.HTTPIndex)
	setStr("SPECUS_ELASTICSEARCH_TCP_INDEX", &cfg.Elasticsearch.TCPIndex)
	setStr("SPECUS_ELASTICSEARCH_HTTP_MAX_STORE_SIZE", &cfg.Elasticsearch.HTTPMaxStoreSize)
	setStr("SPECUS_ELASTICSEARCH_TCP_MAX_STORE_SIZE", &cfg.Elasticsearch.TCPMaxStoreSize)

	setInt("SPECUS_HTTP_TIMEOUT_MS", &cfg.HTTP.TimeoutMs)
	setInt("SPECUS_HTTP_MAX_REQUEST_BODY_SIZE", &cfg.HTTP.MaxRequestBodySize)
	setInt("SPECUS_HTTP_ROUTE_CACHE_TTL_MS", &cfg.HTTP.RouteCacheTTLms)
	setInt("SPECUS_HTTP_REWRITE_MAX_BODY_BYTES", &cfg.HTTP.RewriteMaxBodyBytes)

	setBool("SPECUS_MEDIA_CAPTURE_ENABLED", &cfg.MediaCapture.Enabled)
	setStr("SPECUS_MEDIA_CAPTURE_ENDPOINT", &cfg.MediaCapture.Endpoint)
	setStr("SPECUS_MEDIA_CAPTURE_REGION", &cfg.MediaCapture.Region)
	setStr("SPECUS_MEDIA_CAPTURE_BUCKET", &cfg.MediaCapture.Bucket)
	setStr("SPECUS_MEDIA_CAPTURE_ACCESS_KEY_ID", &cfg.MediaCapture.AccessKeyID)
	// Legacy aliases are applied first; the Java-canonical names win when both exist.
	setStr("SPECUS_MEDIA_CAPTURE_SECRET_ACCESS_KEY", &cfg.MediaCapture.AccessKeySecret)
	setStr("SPECUS_MEDIA_CAPTURE_OBJECT_PREFIX", &cfg.MediaCapture.ObjectPrefix)
	setStr("SPECUS_MEDIA_CAPTURE_ACCESS_KEY_SECRET", &cfg.MediaCapture.AccessKeySecret)
	setStr("SPECUS_MEDIA_CAPTURE_PREFIX", &cfg.MediaCapture.ObjectPrefix)
	setBool("SPECUS_MEDIA_CAPTURE_PATH_STYLE", &cfg.MediaCapture.PathStyle)
	setBool("SPECUS_MEDIA_CAPTURE_CREATE_BUCKET_IF_MISSING", &cfg.MediaCapture.CreateBucketIfMissing)
	setInt64("SPECUS_MEDIA_CAPTURE_PART_SIZE_BYTES", &cfg.MediaCapture.PartSizeBytes)
	setInt("SPECUS_MEDIA_CAPTURE_MAX_INFLIGHT_PARTS", &cfg.MediaCapture.MaxInflightParts)
	setInt("SPECUS_MEDIA_CAPTURE_UPLOAD_THREADS", &cfg.MediaCapture.UploadThreads)
	setInt64("SPECUS_MEDIA_CAPTURE_RETENTION_SECONDS", &cfg.MediaCapture.RetentionSeconds)
	setInt64("SPECUS_MEDIA_CAPTURE_LIVE_WINDOW_SECONDS", &cfg.MediaCapture.LiveWindowSeconds)
	setInt64("SPECUS_MEDIA_CAPTURE_MANIFEST_MAX_BYTES", &cfg.MediaCapture.ManifestMaxBytes)
	setInt64("SPECUS_MEDIA_CAPTURE_PLAYBACK_TICKET_TTL_SECONDS", &cfg.MediaCapture.PlaybackTicketTTLSeconds)
	setInt64("SPECUS_MEDIA_CAPTURE_CLEANUP_INTERVAL_MS", &cfg.MediaCapture.CleanupIntervalMs)

	setBool("SPECUS_PEER_MESH_ENABLED", &cfg.PeerMesh.Enabled)
	setStr("SPECUS_PEER_MESH_CIDR", &cfg.PeerMesh.CIDR)
	setStr("SPECUS_PEER_MESH_PUBLIC_ADDRESS", &cfg.PeerMesh.PublicAddress)
	setInt("SPECUS_PEER_MESH_STUN_TURN_PORT", &cfg.PeerMesh.StunTurnPort)
	setStr("SPECUS_PEER_MESH_STANDALONE_STUN_ADDRESS", &cfg.PeerMesh.StandaloneStunAddress)
	setInt("SPECUS_PEER_MESH_STANDALONE_STUN_PORT", &cfg.PeerMesh.StandaloneStunPort)
	setStr("SPECUS_PEER_MESH_STANDALONE_STUN_ALTERNATE_ADDRESS", &cfg.PeerMesh.StandaloneStunAlternateAddress)
	setInt("SPECUS_PEER_MESH_STANDALONE_STUN_ALTERNATE_PORT", &cfg.PeerMesh.StandaloneStunAlternatePort)
	setStr("SPECUS_PEER_MESH_STUN_ALTERNATE_PUBLIC_ADDRESS", &cfg.PeerMesh.StunAlternatePublicAddress)
	setStr("SPECUS_PEER_MESH_STUN_PRIMARY_BIND_ADDRESS", &cfg.PeerMesh.StunPrimaryBindAddress)
	setStr("SPECUS_PEER_MESH_STUN_ALTERNATE_BIND_ADDRESS", &cfg.PeerMesh.StunAlternateBindAddress)
	setBool("SPECUS_PEER_MESH_STUN_BEHAVIOR_STRICT", &cfg.PeerMesh.StunBehaviorStrict)
	setInt("SPECUS_PEER_MESH_NAT_PROBE_ALTERNATE_PORT", &cfg.PeerMesh.NatProbeAlternatePort)
	setStrSlice("SPECUS_PEER_MESH_PUBLIC_STUN_SERVERS", &cfg.PeerMesh.PublicStunServers)
	setInt64("SPECUS_PEER_MESH_SESSION_TTL_SECONDS", &cfg.PeerMesh.SessionTTLSeconds)
	setInt64("SPECUS_PEER_MESH_ALLOCATION_TTL_SECONDS", &cfg.PeerMesh.AllocationTTLSeconds)
	setInt64("SPECUS_PEER_MESH_SESSION_CLEANUP_INTERVAL_MS", &cfg.PeerMesh.SessionCleanupIntervalMs)
	setInt("SPECUS_PEER_MESH_RELAY_MIN_PORT", &cfg.PeerMesh.RelayMinPort)
	setInt("SPECUS_PEER_MESH_RELAY_MAX_PORT", &cfg.PeerMesh.RelayMaxPort)
	setInt("SPECUS_PEER_MESH_RELAY_WORKER_THREADS", &cfg.PeerMesh.RelayWorkerThreads)
	setInt("SPECUS_PEER_MESH_RELAY_WORKER_QUEUE_CAPACITY", &cfg.PeerMesh.RelayWorkerQueueCapacity)
	setInt("SPECUS_PEER_MESH_UDP_RECEIVE_BUFFER_BYTES", &cfg.PeerMesh.UDPReceiveBufferBytes)
	setInt("SPECUS_PEER_MESH_UDP_SEND_BUFFER_BYTES", &cfg.PeerMesh.UDPSendBufferBytes)
	setInt("SPECUS_PEER_MESH_UDP_TRAFFIC_CLASS", &cfg.PeerMesh.UDPTrafficClass)
	setInt("SPECUS_PEER_MESH_RELAY_TRAFFIC_FLUSH_INTERVAL_MS", &cfg.PeerMesh.RelayTrafficFlushIntervalMs)
	setBool("SPECUS_PEER_MESH_TURN_AUTH_REQUIRED", &cfg.PeerMesh.TurnAuthRequired)
	setStr("SPECUS_PEER_MESH_TURN_REALM", &cfg.PeerMesh.TurnRealm)
	setStr("SPECUS_PEER_MESH_TURN_SHARED_SECRET", &cfg.PeerMesh.TurnSharedSecret)
	setInt64("SPECUS_PEER_MESH_TURN_CREDENTIAL_TTL_SECONDS", &cfg.PeerMesh.TurnCredentialTTLSeconds)
	setInt("SPECUS_PEER_MESH_GENERAL_RELAY_MAX_ALLOCATIONS", &cfg.PeerMesh.GeneralRelayMaxAllocations)
	setInt("SPECUS_PEER_MESH_GENERAL_RELAY_MAX_ALLOCATIONS_PER_ADDRESS", &cfg.PeerMesh.GeneralRelayMaxAllocationsPerAddr)
	setInt64("SPECUS_PEER_MESH_GENERAL_RELAY_MAX_BYTES", &cfg.PeerMesh.GeneralRelayMaxBytes)

	setStr("SPECUS_OBJECT_STORAGE_PROVIDER", &cfg.ObjectStorage.Provider)
	setStr("SPECUS_OBJECT_STORAGE_ENDPOINT", &cfg.ObjectStorage.Endpoint)
	setStr("SPECUS_OBJECT_STORAGE_REGION", &cfg.ObjectStorage.Region)
	setStr("SPECUS_OBJECT_STORAGE_BUCKET", &cfg.ObjectStorage.Bucket)
	setStr("SPECUS_OBJECT_STORAGE_ACCESS_KEY_ID", &cfg.ObjectStorage.AccessKeyID)
	setStr("SPECUS_OBJECT_STORAGE_ACCESS_KEY_SECRET", &cfg.ObjectStorage.AccessKeySecret)
	setStr("SPECUS_OBJECT_STORAGE_PREFIX", &cfg.ObjectStorage.ObjectPrefix)
	setStr("SPECUS_OBJECT_STORAGE_UPLOAD_CALLBACK_URL", &cfg.ObjectStorage.UploadCallbackURL)
	setInt64("SPECUS_OBJECT_STORAGE_UPLOAD_URL_TTL_SECONDS", &cfg.ObjectStorage.UploadURLTTLSeconds)
	setInt64("SPECUS_OBJECT_STORAGE_DOWNLOAD_URL_TTL_SECONDS", &cfg.ObjectStorage.DownloadURLTTLSeconds)
	setInt64("SPECUS_OBJECT_STORAGE_DOWNLOAD_OBJECT_URL_TTL_SECONDS", &cfg.ObjectStorage.DownloadObjectURLTTLSeconds)
	setInt64("SPECUS_OBJECT_STORAGE_RETENTION_HOURS", &cfg.ObjectStorage.RetentionHours)
	setInt64("SPECUS_OBJECT_STORAGE_MAX_ATTACHMENT_BYTES", &cfg.ObjectStorage.MaxAttachmentBytes)
	setInt64("SPECUS_OBJECT_STORAGE_PER_USER_STORAGE_QUOTA_BYTES", &cfg.ObjectStorage.PerUserStorageQuotaBytes)
	setInt64("SPECUS_OBJECT_STORAGE_PER_USER_MONTHLY_DOWNLOAD_QUOTA_BYTES", &cfg.ObjectStorage.PerUserMonthlyDownloadQuotaBytes)
	setInt64("SPECUS_OBJECT_STORAGE_EXPIRATION_SCAN_INTERVAL_MS", &cfg.ObjectStorage.ExpirationScanIntervalMs)

	setInt("SPECUS_PUBLIC_TRANSFER_PRESIGN_RATE_LIMIT_PER_IP", &cfg.PublicTransfer.PresignRateLimitPerIP)
	setInt64("SPECUS_PUBLIC_TRANSFER_PRESIGN_RATE_LIMIT_WINDOW_SECONDS", &cfg.PublicTransfer.PresignRateLimitWindowSeconds)
	setInt("SPECUS_PUBLIC_TRANSFER_MAX_PENDING_UPLOADS_PER_ROOM", &cfg.PublicTransfer.MaxPendingUploadsPerRoom)
	setInt("SPECUS_PUBLIC_TRANSFER_MAX_DISCOVERY_PEERS_PER_ROOM", &cfg.PublicTransfer.MaxDiscoveryPeersPerRoom)
	setInt("SPECUS_PUBLIC_TRANSFER_DISCOVERY_MESSAGE_RATE_LIMIT_PER_CONNECTION", &cfg.PublicTransfer.DiscoveryMessageRateLimitPerConnection)
	setInt64("SPECUS_PUBLIC_TRANSFER_DISCOVERY_MESSAGE_RATE_LIMIT_WINDOW_SECONDS", &cfg.PublicTransfer.DiscoveryMessageRateLimitWindowSeconds)
	setInt64("SPECUS_PUBLIC_TRANSFER_PAIRING_CODE_TTL_SECONDS", &cfg.PublicTransfer.PairingCodeTtlSeconds)
	setInt("SPECUS_PUBLIC_TRANSFER_PAIRING_CODE_REDEEM_RATE_LIMIT_PER_IP", &cfg.PublicTransfer.PairingCodeRedeemRateLimitPerIP)
	setInt64("SPECUS_PUBLIC_TRANSFER_PAIRING_CODE_REDEEM_RATE_LIMIT_WINDOW_SECONDS", &cfg.PublicTransfer.PairingCodeRedeemRateLimitWindowSeconds)
	setBool("SPECUS_PUBLIC_TRANSFER_CLUSTER_ENABLED", &cfg.PublicTransfer.ClusterEnabled)
	setStr("SPECUS_PUBLIC_TRANSFER_REDIS_URI", &cfg.PublicTransfer.RedisURI)
	setStr("SPECUS_PUBLIC_TRANSFER_REDIS_KEY_PREFIX", &cfg.PublicTransfer.RedisKeyPrefix)
	setInt64("SPECUS_PUBLIC_TRANSFER_PRESENCE_LEASE_SECONDS", &cfg.PublicTransfer.PresenceLeaseSeconds)
	setInt64("SPECUS_PUBLIC_TRANSFER_PRESENCE_REFRESH_INTERVAL_MS", &cfg.PublicTransfer.PresenceRefreshIntervalMs)
	setInt64("SPECUS_PUBLIC_TRANSFER_REDIS_COMMAND_TIMEOUT_MS", &cfg.PublicTransfer.RedisCommandTimeoutMs)

	setStr("SPECUS_OIDC_ISSUER", &cfg.Oidc.Issuer)
	setStr("SPECUS_OIDC_JWK_SET_URI", &cfg.Oidc.JwkSetURI)
	setStr("SPECUS_OIDC_AUTHORIZATION_ENDPOINT", &cfg.Oidc.AuthorizationEndpoint)
	setStr("SPECUS_OIDC_REGISTRATION_ENDPOINT", &cfg.Oidc.RegistrationEndpoint)
	setStr("SPECUS_OIDC_TOKEN_ENDPOINT", &cfg.Oidc.TokenEndpoint)
	setStr("SPECUS_OIDC_END_SESSION_ENDPOINT", &cfg.Oidc.EndSessionEndpoint)
	setStr("SPECUS_OIDC_CLIENT_ID", &cfg.Oidc.ClientID)
	setStr("SPECUS_OIDC_CLIENT_SECRET", &cfg.Oidc.ClientSecret)
	setStr("SPECUS_OIDC_REDIRECT_URI", &cfg.Oidc.RedirectURI)
	setStr("SPECUS_OIDC_SCOPE", &cfg.Oidc.Scope)
	setStr("SPECUS_OIDC_AUDIENCE", &cfg.Oidc.Audience)
	setStr("SPECUS_OIDC_TENANT_CLAIM", &cfg.Oidc.TenantClaim)

	setStr("SPECUS_TLS_MODE", &cfg.TLS.Mode)
	setStr("SPECUS_TLS_KEYSTORE", &cfg.TLS.Keystore)
	setStr("SPECUS_TLS_KEYSTORE_PASSWORD", &cfg.TLS.KeystorePassword)
	setStr("SPECUS_TLS_CERT_FILE", &cfg.TLS.CertFile)
	setStr("SPECUS_TLS_KEY_FILE", &cfg.TLS.KeyFile)
	setStr("SPECUS_TLS_KEY_PASSWORD", &cfg.TLS.KeyPassword)
	setBool("SPECUS_TLS_REQUIRE_ENCRYPTION", &cfg.TLS.RequireEncryption)
	setBool("SPECUS_TLS_TERMINATED_UPSTREAM", &cfg.TLS.TerminatedUpstream)

	setStr("SPECUS_PUBLIC_ADDRESS", &cfg.PublicAddress)
	setStr("SPECUS_MANAGEMENT_ADDR", &cfg.ManagementAddr)

	// Connection string: both SPECUS_CONNECTIONSTRINGS_SPECUS and SPECUS_DB_CONNECTION_STRING.
	setStr("SPECUS_CONNECTIONSTRINGS_SPECUS", &cfg.ConnectionString)
	setStr("SPECUS_DB_CONNECTION_STRING", &cfg.ConnectionString)
}
