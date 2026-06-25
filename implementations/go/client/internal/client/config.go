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
	Enabled           bool   `json:"enabled"`
	ClientID          int64  `json:"clientId"`
	ClientName        string `json:"clientName"`
	VirtualIP         string `json:"virtualIp"`
	CIDR              string `json:"cidr"`
	StunHost          string `json:"stunHost"`
	StunPort          int    `json:"stunPort"`
	TurnHost          string `json:"turnHost"`
	TurnPort          int    `json:"turnPort"`
	IceUsername       string `json:"iceUsername"`
	IceCredential     string `json:"iceCredential"`
	ServerPublicKey   string `json:"serverPublicKey"`
	ClientPublicKey   string `json:"clientPublicKey"`
	SessionTTLSeconds int64  `json:"sessionTtlSeconds"`
}

func LoadConfig(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("read config: %w", err)
	}
	var config Config
	if err := json.Unmarshal(data, &config); err != nil {
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
