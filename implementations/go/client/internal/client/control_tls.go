package client

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"time"
)

const serverConnectionTimeout = 5 * time.Second

func (config Config) controlTLSEnabled(runtimeNettyTLS bool) bool {
	if config.ControlTLS.Enabled != nil {
		return *config.ControlTLS.Enabled
	}
	return runtimeNettyTLS || strings.TrimSpace(config.ControlTLS.CACertificatePath) != "" ||
		strings.TrimSpace(config.ControlTLS.ServerName) != "" || config.ControlTLS.InsecureSkipVerify
}

func (config Config) buildControlTLSConfig(runtimeNettyTLS bool) (*tls.Config, error) {
	enabled := config.controlTLSEnabled(runtimeNettyTLS)
	caPath := strings.TrimSpace(config.ControlTLS.CACertificatePath)
	serverName := strings.TrimSpace(config.ControlTLS.ServerName)
	if !enabled {
		switch {
		case caPath != "":
			return nil, errors.New("controlTls.caCertificatePath requires control TLS to be enabled")
		case serverName != "":
			return nil, errors.New("controlTls.serverName requires control TLS to be enabled")
		case config.ControlTLS.InsecureSkipVerify:
			return nil, errors.New("controlTls.insecureSkipVerify requires control TLS to be enabled")
		default:
			return nil, nil
		}
	}

	if err := validateTLSServerName(serverName); err != nil {
		return nil, err
	}
	if caPath != "" && config.ControlTLS.InsecureSkipVerify {
		return nil, errors.New("controlTls.caCertificatePath cannot be combined with controlTls.insecureSkipVerify")
	}

	var rootCAs *x509.CertPool
	if caPath != "" {
		rootCAs = x509.NewCertPool()
		contents, err := os.ReadFile(caPath)
		if err != nil {
			return nil, fmt.Errorf("read controlTls.caCertificatePath %q: %w", caPath, err)
		}
		if !rootCAs.AppendCertsFromPEM(contents) {
			return nil, fmt.Errorf("controlTls.caCertificatePath %q does not contain a valid PEM certificate", caPath)
		}
	}

	return &tls.Config{
		MinVersion:         tls.VersionTLS12,
		RootCAs:            rootCAs,
		ServerName:         serverName,
		InsecureSkipVerify: config.ControlTLS.InsecureSkipVerify,
	}, nil
}

func validateTLSServerName(serverName string) error {
	if serverName == "" {
		return nil
	}
	if strings.Contains(serverName, "://") || strings.ContainsAny(serverName, "/\\") {
		return errors.New("controlTls.serverName must be a hostname or IP address without scheme or path")
	}
	if strings.HasPrefix(serverName, "[") || strings.HasSuffix(serverName, "]") {
		return errors.New("controlTls.serverName must not use brackets around an IP address")
	}
	if strings.Contains(serverName, ":") && net.ParseIP(serverName) == nil {
		return errors.New("controlTls.serverName must not include a port")
	}
	return nil
}

func (client *Client) dialServerConnection(
	ctx context.Context, address string, timeout time.Duration, runtimeNettyTLS bool,
) (net.Conn, error) {
	if timeout <= 0 {
		return nil, errors.New("server connection timeout must be positive")
	}
	tlsConfig, err := client.config.buildControlTLSConfig(runtimeNettyTLS)
	if err != nil {
		return nil, fmt.Errorf("configure control TLS: %w", err)
	}

	dialContext, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	netDialer := &net.Dialer{Timeout: timeout, KeepAlive: 30 * time.Second}
	if tlsConfig == nil {
		return netDialer.DialContext(dialContext, "tcp", address)
	}
	tlsDialer := &tls.Dialer{NetDialer: netDialer, Config: tlsConfig}
	return tlsDialer.DialContext(dialContext, "tcp", address)
}
