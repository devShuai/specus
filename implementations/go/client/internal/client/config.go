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
	ServerBaseURL   string `json:"serverBaseUrl"`
	APIKey          string `json:"apiKey"`
	Secret          string `json:"secret"`
	PeerMeshDevice  string `json:"peerMeshDevice"`
	PeerMeshTunName string `json:"peerMeshTunName"`
	PeerMeshMTU     int    `json:"peerMeshMtu"`
}

const (
	DefaultConfigFileName  = "client.jsonc"
	DefaultPeerMeshDevice  = "noop"
	DefaultPeerMeshTunName = "shuai0"
	DefaultPeerMeshMTU     = 1280
	MinPeerMeshMTU         = 576
	MaxPeerMeshMTU         = 1280
)

type TunnelConfig struct {
	Port          int    `json:"port"`
	TunnelAddress string `json:"tunnelAddress"`
	TunnelPort    int    `json:"tunnelPort"`
}

type HTTPTunnelConfig struct {
	Route         string `json:"route"`
	TargetBaseURL string `json:"targetBaseUrl"`
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
	MaxOnlineInstances   int                `json:"maxOnlineInstances"`
	Policy               ClientPolicy       `json:"policy"`
	PeerMesh             PeerMeshConfig     `json:"peerMesh"`
	TunnelConfigList     []TunnelConfig     `json:"tunnelConfigList"`
	HTTPTunnelConfigList []HTTPTunnelConfig `json:"httpTunnelConfigList"`
	TokenExpiresAt       time.Time          `json:"-"`
}

type ClientPolicy struct {
	Enabled           bool   `json:"enabled"`
	BillingStatus     string `json:"billingStatus"`
	RetryAfterSeconds int64  `json:"retryAfterSeconds"`
}

type PeerMeshConfig struct {
	Enabled           bool     `json:"enabled"`
	ClientID          int64    `json:"clientId"`
	ClientName        string   `json:"clientName"`
	VirtualIP         string   `json:"virtualIp"`
	CIDR              string   `json:"cidr"`
	StunHost          string   `json:"stunHost"`
	StunPort          int      `json:"stunPort"`
	TurnHost          string   `json:"turnHost"`
	TurnPort          int      `json:"turnPort"`
	PublicStunServers []string `json:"publicStunServers"`
	IceUsername       string   `json:"iceUsername"`
	IceCredential     string   `json:"iceCredential"`
	ServerPublicKey   string   `json:"serverPublicKey"`
	ClientPublicKey   string   `json:"clientPublicKey"`
	SessionTTLSeconds int64    `json:"sessionTtlSeconds"`
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
	return config, nil
}

func (config *Config) Validate() error {
	config.ServerBaseURL = strings.TrimSpace(config.ServerBaseURL)
	config.APIKey = strings.TrimSpace(config.APIKey)
	config.Secret = strings.TrimSpace(config.Secret)
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
