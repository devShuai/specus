package client

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"
)

type Config struct {
	ServerBaseURL string `json:"serverBaseUrl"`
	APIKey        string `json:"apiKey"`
	Secret        string `json:"secret"`
	// SecretIsIndirect records that Secret names the credential rather than being it, so the
	// client knows a rotation can be picked up by re-reading the source.
	SecretIsIndirect         bool              `json:"-"`
	ControlTLS               ControlTLSConfig  `json:"controlTls"`
	UpstreamTLS              UpstreamTLSConfig `json:"upstreamTls"`
	PeerMeshDevice           string            `json:"peerMeshDevice"`
	PeerMeshTunName          string            `json:"peerMeshTunName"`
	PeerMeshMTU              int               `json:"peerMeshMtu"`
	UpdateCheckEnabled       *bool             `json:"updateCheckEnabled"`
	AutoUpdate               bool              `json:"autoUpdate"`
	UpdateCheckIntervalHours int               `json:"updateCheckIntervalHours"`
}

// UpdatesEnabled defaults to true so packaged clients participate without requiring a config
// migration. Operators can explicitly disable polling in service-managed environments.
func (config Config) UpdatesEnabled() bool {
	return config.UpdateCheckEnabled == nil || *config.UpdateCheckEnabled
}

func (config Config) UpdateCheckInterval() time.Duration {
	hours := config.UpdateCheckIntervalHours
	if hours <= 0 {
		hours = DefaultUpdateCheckIntervalHours
	}
	if hours < MinUpdateCheckIntervalHours {
		hours = MinUpdateCheckIntervalHours
	}
	if hours > MaxUpdateCheckIntervalHours {
		hours = MaxUpdateCheckIntervalHours
	}
	return time.Duration(hours) * time.Hour
}

type ControlTLSConfig struct {
	Enabled            *bool  `json:"enabled"`
	CACertificatePath  string `json:"caCertificatePath"`
	ServerName         string `json:"serverName"`
	InsecureSkipVerify bool   `json:"insecureSkipVerify"`
}

const (
	DefaultConfigFileName           = "client.jsonc"
	DefaultPeerMeshDevice           = "noop"
	DefaultPeerMeshTunName          = "specus0"
	DefaultPeerMeshMTU              = 1280
	MinPeerMeshMTU                  = 576
	MaxPeerMeshMTU                  = 1280
	DefaultUpdateCheckIntervalHours = 24
	MinUpdateCheckIntervalHours     = 1
	MaxUpdateCheckIntervalHours     = 168
)

type SpecusConfig struct {
	Port          int    `json:"port"`
	SpecusAddress string `json:"specusAddress"`
	SpecusPort    int    `json:"specusPort"`
}

type HTTPSpecusConfig struct {
	Route              string `json:"route"`
	TargetBaseURL      string `json:"targetBaseUrl"`
	InsecureSkipVerify bool   `json:"insecureSkipVerify"`
}

type RuntimeConfig struct {
	TenantID             string             `json:"tenantId"`
	ClientID             int64              `json:"clientId"`
	ClientName           string             `json:"clientName"`
	ClientSessionID      int64              `json:"clientSessionId"`
	AccessToken          string             `json:"accessToken"`
	TokenTTLSeconds      int64              `json:"tokenTtlSeconds"`
	NettyHost            string             `json:"nettyHost"`
	NettyPort            int                `json:"nettyPort"`
	NettyTLS             bool               `json:"nettyTls"`
	MaxOnlineInstances   int                `json:"maxOnlineInstances"`
	Policy               ClientPolicy       `json:"policy"`
	PeerMesh             PeerMeshConfig     `json:"peerMesh"`
	SpecusConfigList     []SpecusConfig     `json:"specusConfigList"`
	HTTPSpecusConfigList []HTTPSpecusConfig `json:"httpSpecusConfigList"`
	TokenExpiresAt       time.Time          `json:"-"`
}

type ClientPolicy struct {
	Enabled           bool   `json:"enabled"`
	BillingStatus     string `json:"billingStatus"`
	RetryAfterSeconds int64  `json:"retryAfterSeconds"`
}

type PeerMeshConfig struct {
	Enabled                     bool                 `json:"enabled"`
	ClientID                    int64                `json:"clientId"`
	ClientName                  string               `json:"clientName"`
	VirtualIP                   string               `json:"virtualIp"`
	CIDR                        string               `json:"cidr"`
	StunHost                    string               `json:"stunHost"`
	StunPort                    int                  `json:"stunPort"`
	TurnHost                    string               `json:"turnHost"`
	TurnPort                    int                  `json:"turnPort"`
	PublicStunServers           []string             `json:"publicStunServers"`
	IceUsername                 string               `json:"iceUsername"`
	IceCredential               string               `json:"iceCredential"`
	IceRealm                    string               `json:"iceRealm"`
	IceNonce                    string               `json:"iceNonce"`
	ServerPublicKey             string               `json:"serverPublicKey"`
	ClientPublicKey             string               `json:"clientPublicKey"`
	SessionTTLSeconds           int64                `json:"sessionTtlSeconds"`
	PeerServiceDiscoveryVersion int                  `json:"peerServiceDiscoveryVersion"`
	ServiceSharing              ServiceSharingStatus `json:"serviceSharing"`
	LocalServices               []LocalPeerService   `json:"localServices"`
}

type ServiceSharingStatus struct {
	DeploymentEnabled bool `json:"deploymentEnabled"`
	ConfiguredEnabled bool `json:"configuredEnabled"`
	EffectiveEnabled  bool `json:"effectiveEnabled"`
	MdnsImportEnabled bool `json:"mdnsImportEnabled"`
}

type LocalPeerService struct {
	ServiceID             string   `json:"serviceId"`
	Name                  string   `json:"name"`
	Description           string   `json:"description,omitempty"`
	Transport             string   `json:"transport"`
	Application           string   `json:"application"`
	TargetHost            string   `json:"targetHost"`
	TargetPort            int      `json:"targetPort"`
	PublishedPort         int      `json:"publishedPort"`
	Path                  string   `json:"path,omitempty"`
	Enabled               bool     `json:"enabled"`
	Visibility            string   `json:"visibility,omitempty"`
	AllowedPeerVirtualIPs []string `json:"allowedPeerVirtualIps"`
}

func LoadConfig(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("read config: %w", err)
	}
	var config Config
	if err := unmarshalJSONC(data, &config); err != nil {
		return Config{}, fmt.Errorf("decode config: %w", err)
	}
	if err := config.Validate(); err != nil {
		return Config{}, err
	}
	// Resolved once here so a bad reference fails at startup rather than at the first login, but
	// the reference itself is kept: a rotated secret has to be picked up without a restart, and
	// that is only possible if the client still knows where the secret came from.
	if _, err := resolveSecret(config.Secret); err != nil {
		return Config{}, fmt.Errorf("resolve secret: %w", err)
	}
	config.SecretIsIndirect = secretIsIndirect(config.Secret)
	return config, nil
}

func (config *Config) Validate() error {
	config.ServerBaseURL = strings.TrimSpace(config.ServerBaseURL)
	config.APIKey = strings.TrimSpace(config.APIKey)
	config.Secret = strings.TrimSpace(config.Secret)
	config.ControlTLS.CACertificatePath = strings.TrimSpace(config.ControlTLS.CACertificatePath)
	config.ControlTLS.ServerName = strings.TrimSpace(config.ControlTLS.ServerName)
	config.PeerMeshDevice = strings.TrimSpace(config.PeerMeshDevice)
	config.PeerMeshTunName = strings.TrimSpace(config.PeerMeshTunName)

	if config.PeerMeshDevice == "" {
		config.PeerMeshDevice = DefaultPeerMeshDevice
	}
	if config.PeerMeshTunName == "" {
		config.PeerMeshTunName = DefaultPeerMeshTunName
	}
	if config.PeerMeshMTU <= 0 {
		config.PeerMeshMTU = DefaultPeerMeshMTU
	} else if config.PeerMeshMTU < MinPeerMeshMTU {
		config.PeerMeshMTU = MinPeerMeshMTU
	} else if config.PeerMeshMTU > MaxPeerMeshMTU {
		config.PeerMeshMTU = MaxPeerMeshMTU
	}
	if config.UpdateCheckIntervalHours <= 0 {
		config.UpdateCheckIntervalHours = DefaultUpdateCheckIntervalHours
	} else if config.UpdateCheckIntervalHours < MinUpdateCheckIntervalHours {
		config.UpdateCheckIntervalHours = MinUpdateCheckIntervalHours
	} else if config.UpdateCheckIntervalHours > MaxUpdateCheckIntervalHours {
		config.UpdateCheckIntervalHours = MaxUpdateCheckIntervalHours
	}

	if config.ServerBaseURL == "" {
		return errors.New("serverBaseUrl is required")
	}
	parsed, err := url.Parse(config.ServerBaseURL)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" ||
		(!strings.EqualFold(parsed.Scheme, "http") && !strings.EqualFold(parsed.Scheme, "https")) {
		return errors.New("serverBaseUrl must be an absolute http/https URL")
	}
	if config.APIKey == "" {
		return errors.New("apiKey is required")
	}
	if config.Secret == "" {
		return errors.New("secret is required")
	}
	if _, err := config.buildControlTLSConfig(false); err != nil {
		return err
	}
	return nil
}

func unmarshalJSONC(data []byte, value any) error {
	withoutComments := stripJSONCComments(data)
	normalized := stripJSONCTrailingCommas(withoutComments)
	return json.Unmarshal(normalized, value)
}

func stripJSONCComments(data []byte) []byte {
	out := make([]byte, 0, len(data))
	inString := false
	escaped := false
	inLineComment := false
	inBlockComment := false

	for i := 0; i < len(data); i++ {
		ch := data[i]
		next := byte(0)
		if i+1 < len(data) {
			next = data[i+1]
		}

		switch {
		case inLineComment:
			if ch == '\r' || ch == '\n' {
				inLineComment = false
				out = append(out, ch)
			} else {
				out = append(out, ' ')
			}
			continue
		case inBlockComment:
			if ch == '*' && next == '/' {
				inBlockComment = false
				out = append(out, ' ', ' ')
				i++
			} else if ch == '\r' || ch == '\n' {
				out = append(out, ch)
			} else {
				out = append(out, ' ')
			}
			continue
		case inString:
			out = append(out, ch)
			if escaped {
				escaped = false
			} else if ch == '\\' {
				escaped = true
			} else if ch == '"' {
				inString = false
			}
			continue
		}

		if ch == '"' {
			inString = true
			out = append(out, ch)
			continue
		}
		if ch == '/' && next == '/' {
			inLineComment = true
			out = append(out, ' ', ' ')
			i++
			continue
		}
		if ch == '/' && next == '*' {
			inBlockComment = true
			out = append(out, ' ', ' ')
			i++
			continue
		}
		out = append(out, ch)
	}
	return out
}

func stripJSONCTrailingCommas(data []byte) []byte {
	out := make([]byte, 0, len(data))
	inString := false
	escaped := false

	for i := 0; i < len(data); i++ {
		ch := data[i]
		if inString {
			out = append(out, ch)
			if escaped {
				escaped = false
			} else if ch == '\\' {
				escaped = true
			} else if ch == '"' {
				inString = false
			}
			continue
		}

		if ch == '"' {
			inString = true
			out = append(out, ch)
			continue
		}
		if ch == ',' {
			j := i + 1
			for j < len(data) && (data[j] == ' ' || data[j] == '\t' || data[j] == '\r' || data[j] == '\n') {
				j++
			}
			if j < len(data) && (data[j] == '}' || data[j] == ']') {
				continue
			}
		}
		out = append(out, ch)
	}
	return out
}
