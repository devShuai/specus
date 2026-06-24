package client

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
)

type Config struct {
	ServerBaseURL string `json:"serverBaseUrl"`
	APIKey        string `json:"apiKey"`
	Secret        string `json:"secret"`
}

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
	TunnelConfigList     []TunnelConfig     `json:"tunnelConfigList"`
	HTTPTunnelConfigList []HTTPTunnelConfig `json:"httpTunnelConfigList"`
}

type ClientPolicy struct {
	Enabled           bool   `json:"enabled"`
	BillingStatus     string `json:"billingStatus"`
	RetryAfterSeconds int64  `json:"retryAfterSeconds"`
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

func (config Config) Validate() error {
	if strings.TrimSpace(config.ServerBaseURL) == "" {
		return errors.New("serverBaseUrl is required")
	}
	if strings.TrimSpace(config.APIKey) == "" {
		return errors.New("apiKey is required")
	}
	if config.Secret == "" {
		return errors.New("secret is required")
	}
	return nil
}
