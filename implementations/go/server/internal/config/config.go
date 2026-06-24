// Package config holds the tunnel-server configuration: defaults, optional JSON file
// overrides, and Java-style TUNNEL_* environment variable overrides. It mirrors the
// option groups of the C# server (Tunnel:Netty, Tunnel:Auth, etc.).
package config

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// Config is the full server configuration.
type Config struct {
	Netty            NettyConfig      `json:"netty"`
	Login            LoginConfig      `json:"login"`
	Database         DatabaseConfig   `json:"database"`
	Auth             AuthConfig       `json:"auth"`
	Traffic          TrafficConfig    `json:"traffic"`
	HTTP             DirectHTTPConfig `json:"http"`
	Oidc             OidcConfig       `json:"oidc"`
	TLS              TLSConfig        `json:"tls"`
	PublicAddress    string           `json:"publicAddress"`
	ConnectionString string           `json:"connectionString"`
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
	PasswordLoginEnabled bool   `json:"passwordLoginEnabled"`
	Username             string `json:"username"`
	Password             string `json:"password"`
	JwtSecret            string `json:"jwtSecret"`
	TokenTTLSeconds      int64  `json:"tokenTtlSeconds"`
}

// TrafficConfig mirrors Tunnel:Traffic.
type TrafficConfig struct {
	FlushIntervalMs int `json:"flushIntervalMs"`
}

// DirectHTTPConfig mirrors Tunnel:Http.
type DirectHTTPConfig struct {
	TimeoutMs          int `json:"timeoutMs"`
	MaxRequestBodySize int `json:"maxRequestBodySize"`
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
}

// TLSConfig mirrors Tunnel:Tls. Mode is one of disabled|file|self-signed.
type TLSConfig struct {
	Mode        string `json:"mode"`
	CertFile    string `json:"certFile"`
	KeyFile     string `json:"keyFile"`
	KeyPassword string `json:"keyPassword"`
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
			Username:             "admin",
			Password:             "admin",
			TokenTTLSeconds:      28800,
		},
		Traffic: TrafficConfig{FlushIntervalMs: 5000},
		HTTP:    DirectHTTPConfig{TimeoutMs: 30000, MaxRequestBodySize: 16 * 1024 * 1024},
		Oidc: OidcConfig{
			Issuer:                "https://gateway.toys.theshuai.com/auth",
			JwkSetURI:             "https://gateway.toys.theshuai.com/auth/oauth2/jwks",
			AuthorizationEndpoint: "https://gateway.toys.theshuai.com/auth/oauth2/authorize",
			TokenEndpoint:         "https://gateway.toys.theshuai.com/auth/oauth2/token",
			EndSessionEndpoint:    "https://gateway.toys.theshuai.com/auth/connect/logout",
			RedirectURI:           "http://127.0.0.1:8088/",
			Scope:                 "openid",
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

	setInt("TUNNEL_NETTY_PORT", &cfg.Netty.Port)
	setInt("TUNNEL_NETTY_MAX_FRAME_SIZE", &cfg.Netty.MaxFrameSize)
	setInt("TUNNEL_NETTY_WRITE_BUFFER_LOW_WATER_MARK", &cfg.Netty.WriteBufferLowWaterMark)
	setInt("TUNNEL_NETTY_WRITE_BUFFER_HIGH_WATER_MARK", &cfg.Netty.WriteBufferHighWaterMark)
	setInt("TUNNEL_NETTY_MAX_EXTERNAL_CONNECTIONS", &cfg.Netty.MaxExternalConnections)
	setInt("TUNNEL_NETTY_MAX_EXTERNAL_CONNECTIONS_PER_CLIENT", &cfg.Netty.MaxExternalConnectionsPerClient)
	setInt("TUNNEL_NETTY_MAX_EXTERNAL_CONNECTIONS_PER_PORT", &cfg.Netty.MaxExternalConnectionsPerPort)

	setInt("TUNNEL_LOGIN_EXECUTOR_MAX_SIZE", &cfg.Login.ExecutorMaxSize)
	setInt("TUNNEL_LOGIN_EXECUTOR_QUEUE_CAPACITY", &cfg.Login.ExecutorQueueCapacity)

	setStr("TUNNEL_DB_PROVIDER", &cfg.Database.Provider)
	setBool("TUNNEL_DB_SEED_DEMO_CLIENT", &cfg.Database.SeedDemoClient)

	setBool("TUNNEL_AUTH_PASSWORD_LOGIN_ENABLED", &cfg.Auth.PasswordLoginEnabled)
	setStr("TUNNEL_AUTH_USERNAME", &cfg.Auth.Username)
	setStr("TUNNEL_AUTH_PASSWORD", &cfg.Auth.Password)
	setStr("TUNNEL_AUTH_JWT_SECRET", &cfg.Auth.JwtSecret)
	setInt64("TUNNEL_AUTH_TOKEN_TTL_SECONDS", &cfg.Auth.TokenTTLSeconds)

	setInt("TUNNEL_TRAFFIC_FLUSH_INTERVAL_MS", &cfg.Traffic.FlushIntervalMs)

	setInt("TUNNEL_HTTP_TIMEOUT_MS", &cfg.HTTP.TimeoutMs)
	setInt("TUNNEL_HTTP_MAX_REQUEST_BODY_SIZE", &cfg.HTTP.MaxRequestBodySize)

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

	setStr("TUNNEL_TLS_MODE", &cfg.TLS.Mode)
	setStr("TUNNEL_TLS_CERT_FILE", &cfg.TLS.CertFile)
	setStr("TUNNEL_TLS_KEY_FILE", &cfg.TLS.KeyFile)
	setStr("TUNNEL_TLS_KEY_PASSWORD", &cfg.TLS.KeyPassword)

	setStr("TUNNEL_PUBLIC_ADDRESS", &cfg.PublicAddress)
	setStr("TUNNEL_MANAGEMENT_ADDR", &cfg.ManagementAddr)

	// Connection string: both TUNNEL_CONNECTIONSTRINGS_TUNNEL and TUNNEL_DB_CONNECTION_STRING.
	setStr("TUNNEL_CONNECTIONSTRINGS_TUNNEL", &cfg.ConnectionString)
	setStr("TUNNEL_DB_CONNECTION_STRING", &cfg.ConnectionString)
}
