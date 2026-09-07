package client

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"time"
)

type authLoginRequest struct {
	APIKey      string                `json:"apiKey,omitempty"`
	Timestamp   string                `json:"timestamp,omitempty"`
	Nonce       string                `json:"nonce,omitempty"`
	Signature   string                `json:"signature,omitempty"`
	Environment clientEnvironmentInfo `json:"environment"`
}

type clientEnvironmentInfo struct {
	MachineFingerprint            string                        `json:"machineFingerprint"`
	Hostname                      string                        `json:"hostname"`
	OSUser                        string                        `json:"osUser"`
	OSName                        string                        `json:"osName"`
	OSVersion                     string                        `json:"osVersion"`
	OSArch                        string                        `json:"osArch"`
	ClientVersion                 string                        `json:"clientVersion"`
	JavaVersion                   string                        `json:"javaVersion"`
	PeerPublicKey                 string                        `json:"peerPublicKey"`
	ClientMessageCapabilities     clientMessageCapabilities     `json:"clientMessageCapabilities"`
	ClientPeerServiceCapabilities clientPeerServiceCapabilities `json:"clientPeerServiceCapabilities"`
	LocalAddresses                []string                      `json:"localAddresses"`
	StartedAt                     string                        `json:"startedAt"`
}

type clientMessageCapabilities struct {
	SendMessages       bool  `json:"sendMessages"`
	ReceiveMessages    bool  `json:"receiveMessages"`
	Attachments        bool  `json:"attachments"`
	MediaPreview       bool  `json:"mediaPreview"`
	MaxAttachmentBytes int64 `json:"maxAttachmentBytes"`
}

type clientPeerServiceCapabilities struct {
	Version      int      `json:"version"`
	Applications []string `json:"applications"`
}

var authHTTPClient = &http.Client{Timeout: 20 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

// clientVersion is reported to the server during the login handshake. The binary sets it from the
// version injected at package time; it stays empty for embedders that never call SetVersion, which
// matches the previous wire behaviour.
var clientVersion atomic.Pointer[string]

// SetVersion records the version this build reports to the server.
func SetVersion(value string) {
	normalized := strings.TrimSpace(value)
	clientVersion.Store(&normalized)
}

func currentClientVersion() string {
	if value := clientVersion.Load(); value != nil {
		return *value
	}
	return ""
}

func (client *Client) loginOnce(ctx context.Context) (RuntimeConfig, error) {
	environment := collectEnvironment()
	request := authLoginRequest{
		Environment: environment,
		APIKey:      strings.TrimSpace(client.config.APIKey),
		Timestamp:   fmt.Sprintf("%d", time.Now().UnixMilli()),
		Nonce:       randomHex(16),
	}
	// Re-resolved per login rather than cached at startup: rotating the credential should take
	// effect on the next reconnect, not on the next restart. An inline secret resolves to itself.
	secret, secretErr := resolveSecret(client.config.Secret)
	if secretErr != nil {
		return RuntimeConfig{}, &LoginFailure{Code: 2, Message: "Cannot resolve secret. Check the env:/file: credential reference."}
	}
	request.Signature = signAPIKey(request.APIKey, request.Timestamp, request.Nonce, environment, strings.TrimSpace(secret))

	body, err := json.Marshal(request)
	if err != nil {
		return RuntimeConfig{}, err
	}
	url := strings.TrimRight(client.config.ServerBaseURL, "/") + "/api/client/auth/login"
	httpRequest, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return RuntimeConfig{}, err
	}
	httpRequest.Header.Set("Content-Type", "application/json")
	response, err := authHTTPClient.Do(httpRequest)
	if err != nil {
		if ctx.Err() != nil {
			return RuntimeConfig{}, ctx.Err()
		}
		var certificate *tls.CertificateVerificationError
		if errors.As(err, &certificate) {
			return RuntimeConfig{}, &LoginFailure{Code: 1, Message: "HTTP login TLS failure. Check the certificate, hostname and system trust store; do not disable verification."}
		}
		return RuntimeConfig{}, &LoginFailure{Code: 1, Retryable: true, Message: "HTTP login network failure. Check DNS, proxy and server availability."}
	}
	defer response.Body.Close()
	var runtime RuntimeConfig
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return RuntimeConfig{}, loginStatusFailure(response.StatusCode, response.Header.Get("Retry-After"))
	}
	if err := json.NewDecoder(response.Body).Decode(&runtime); err != nil {
		if ctx.Err() != nil {
			return RuntimeConfig{}, ctx.Err()
		}
		var networkError net.Error
		if errors.As(err, &networkError) && networkError.Timeout() {
			return RuntimeConfig{}, &LoginFailure{Code: 1, Retryable: true, Message: "HTTP login request timeout. Check network/server availability."}
		}
		return RuntimeConfig{}, &LoginFailure{Code: 1, Message: "Invalid HTTP login response. Check serverBaseUrl and server/client compatibility."}
	}
	if strings.TrimSpace(runtime.ClientName) == "" || runtime.ClientSessionID <= 0 ||
		strings.TrimSpace(runtime.AccessToken) == "" || strings.TrimSpace(runtime.NettyHost) == "" ||
		runtime.NettyPort < 1 || runtime.NettyPort > 65535 {
		return RuntimeConfig{}, &LoginFailure{Code: 1, Message: "Invalid HTTP login response: missing client/session/token/netty endpoint."}
	}
	if runtime.TokenTTLSeconds > 0 {
		runtime.TokenExpiresAt = time.Now().Add(time.Duration(runtime.TokenTTLSeconds) * time.Second)
	}
	return runtime, nil
}

func signAPIKey(apiKey, timestamp, nonce string, environment clientEnvironmentInfo, secret string) string {
	message := strings.Join([]string{
		apiKey,
		timestamp,
		nonce,
		environment.MachineFingerprint,
		environment.OSUser,
	}, "\n")
	key := sha256.Sum256([]byte(secret))
	mac := hmac.New(sha256.New, key[:])
	mac.Write([]byte(message))
	return hex.EncodeToString(mac.Sum(nil))
}

func collectEnvironment() clientEnvironmentInfo {
	hostname, _ := os.Hostname()
	if hostname == "" {
		hostname = "unknown-host"
	}
	username := "unknown"
	if current, err := user.Current(); err == nil && current.Username != "" {
		username = normalizeOSUser(current.Username)
	}
	return clientEnvironmentInfo{
		MachineFingerprint: machineFingerprint(hostname),
		Hostname:           hostname,
		OSUser:             username,
		OSName:             runtime.GOOS,
		OSArch:             runtime.GOARCH,
		ClientVersion:      currentClientVersion(),
		JavaVersion:        "",
		PeerPublicKey:      peerPublicKeyBase64(),
		ClientMessageCapabilities: clientMessageCapabilities{
			SendMessages: true, ReceiveMessages: true,
		},
		ClientPeerServiceCapabilities: clientPeerServiceCapabilities{
			Version:      2,
			Applications: []string{"http", "https", "ssh", "tcp", "udp"},
		},
		LocalAddresses: localAddresses(),
		StartedAt:      time.Now().UTC().Format(time.RFC3339Nano),
	}
}

func normalizeOSUser(value string) string {
	normalized := strings.TrimSpace(value)
	if normalized == "" {
		return "unknown"
	}
	if index := strings.LastIndex(normalized, `\`); index >= 0 && index+1 < len(normalized) {
		normalized = normalized[index+1:]
	}
	if index := strings.LastIndex(normalized, "/"); index >= 0 && index+1 < len(normalized) {
		normalized = normalized[index+1:]
	}
	if normalized == "" {
		return "unknown"
	}
	return normalized
}

func machineFingerprint(hostname string) string {
	home, err := os.UserHomeDir()
	if err == nil && home != "" {
		dir := filepath.Join(home, ".specus")
		path := filepath.Join(dir, "machine-id")
		if data, err := os.ReadFile(path); err == nil {
			if existing := strings.TrimSpace(string(data)); existing != "" {
				return existing
			}
		}
		if err := os.MkdirAll(dir, 0o700); err == nil {
			generated := "m_" + randomHex(16)
			if err := os.WriteFile(path, []byte(generated), 0o600); err == nil {
				return generated
			}
		}
	}
	sum := sha256.Sum256([]byte(hostname + "\n" + runtime.GOOS + "\n" + runtime.GOARCH))
	return "m_" + hex.EncodeToString(sum[:])[:32]
}

func randomHex(size int) string {
	data := make([]byte, size)
	if _, err := rand.Read(data); err != nil {
		sum := sha256.Sum256([]byte(fmt.Sprintf("%d", time.Now().UnixNano())))
		return hex.EncodeToString(sum[:size])
	}
	return hex.EncodeToString(data)
}

func localAddresses() []string {
	var result []string
	interfaces, err := net.Interfaces()
	if err != nil {
		return result
	}
	for _, item := range interfaces {
		if item.Flags&net.FlagUp == 0 || item.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := item.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			var ip net.IP
			switch value := addr.(type) {
			case *net.IPNet:
				ip = value.IP
			case *net.IPAddr:
				ip = value.IP
			}
			if ip == nil || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
				continue
			}
			result = append(result, ip.String())
		}
	}
	return result
}
