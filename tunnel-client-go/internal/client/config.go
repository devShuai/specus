package client

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
)

type Config struct {
	ClientName           string             `json:"clientName"`
	Password             string             `json:"password"`
	TunnelConfigList     []TunnelConfig     `json:"tunnelConfigList"`
	HTTPTunnelConfigList []HTTPTunnelConfig `json:"httpTunnelConfigList"`
	RemoteAddress        string             `json:"remoteAddress"`
	RemotePort           int                `json:"remotePort"`
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
	if strings.TrimSpace(config.ClientName) == "" {
		return errors.New("clientName is required")
	}
	if config.Password == "" {
		return errors.New("password is required")
	}
	if strings.TrimSpace(config.RemoteAddress) == "" {
		return errors.New("remoteAddress is required")
	}
	if config.RemotePort < 1 || config.RemotePort > 65535 {
		return errors.New("remotePort must be between 1 and 65535")
	}
	for _, tunnel := range config.TunnelConfigList {
		if tunnel.Port < 1 || tunnel.Port > 65535 || tunnel.TunnelPort < 1 || tunnel.TunnelPort > 65535 {
			return errors.New("tunnel ports must be between 1 and 65535")
		}
		if strings.TrimSpace(tunnel.TunnelAddress) == "" {
			return errors.New("tunnelAddress is required")
		}
	}
	for _, tunnel := range config.HTTPTunnelConfigList {
		if strings.TrimSpace(tunnel.Route) == "" || strings.TrimSpace(tunnel.TargetBaseURL) == "" {
			return errors.New("HTTP tunnel route and targetBaseUrl are required")
		}
	}
	return nil
}
