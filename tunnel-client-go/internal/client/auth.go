package client

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

type authLoginRequest struct {
	AuthType    string                `json:"authType"`
	APIKey      string                `json:"apiKey,omitempty"`
	Secret      string                `json:"secret,omitempty"`
	Username    string                `json:"username,omitempty"`
	Password    string                `json:"password,omitempty"`
	Timestamp   string                `json:"timestamp,omitempty"`
	Nonce       string                `json:"nonce,omitempty"`
	Signature   string                `json:"signature,omitempty"`
	Environment clientEnvironmentInfo `json:"environment"`
}

type clientEnvironmentInfo struct {
	MachineFingerprint string   `json:"machineFingerprint"`
	Hostname           string   `json:"hostname"`
	OSUser             string   `json:"osUser"`
	OSName             string   `json:"osName"`
	OSVersion          string   `json:"osVersion"`
	OSArch             string   `json:"osArch"`
	ClientVersion      string   `json:"clientVersion"`
	JavaVersion        string   `json:"javaVersion"`
	LocalAddresses     []string `json:"localAddresses"`
	StartedAt          string   `json:"startedAt"`
}

var authHTTPClient = &http.Client{Timeout: 20 * time.Second}

func (client *Client) login(ctx context.Context) (RuntimeConfig, error) {
	environment := collectEnvironment()
	request := authLoginRequest{
		AuthType:    strings.TrimSpace(client.config.AuthType),
		Environment: environment,
	}
	if request.AuthType == "" {
		request.AuthType = "apiKey"
	}
	if strings.EqualFold(request.AuthType, "password") {
		request.Username = client.config.Username
		request.Password = client.config.Password
	} else {
		request.AuthType = "apiKey"
		request.APIKey = client.config.APIKey
		request.Timestamp = fmt.Sprintf("%d", time.Now().UnixMilli())
		request.Nonce = randomHex(16)
		request.Signature = signAPIKey(client.config.APIKey, request.Timestamp, request.Nonce, environment, client.config.Secret)
	}

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
		return RuntimeConfig{}, fmt.Errorf("client HTTP login request failed: %w", err)
	}
	defer response.Body.Close()
	var runtime RuntimeConfig
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		var errorBody bytes.Buffer
		_, _ = errorBody.ReadFrom(response.Body)
		return RuntimeConfig{}, fmt.Errorf("client HTTP login failed HTTP %d: %s", response.StatusCode, strings.TrimSpace(errorBody.String()))
	}
	if err := json.NewDecoder(response.Body).Decode(&runtime); err != nil {
		return RuntimeConfig{}, fmt.Errorf("decode client HTTP login response: %w", err)
	}
	if strings.TrimSpace(runtime.ClientName) == "" || runtime.ClientSessionID <= 0 ||
		strings.TrimSpace(runtime.AccessToken) == "" || strings.TrimSpace(runtime.NettyHost) == "" ||
		runtime.NettyPort < 1 || runtime.NettyPort > 65535 {
		return RuntimeConfig{}, fmt.Errorf("client HTTP login response is missing client/session/token/netty endpoint")
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
		username = current.Username
	}
	return clientEnvironmentInfo{
		MachineFingerprint: machineFingerprint(hostname),
		Hostname:           hostname,
		OSUser:             username,
		OSName:             runtime.GOOS,
		OSArch:             runtime.GOARCH,
		ClientVersion:      "",
		JavaVersion:        "",
		LocalAddresses:     localAddresses(),
		StartedAt:          time.Now().UTC().Format(time.RFC3339Nano),
	}
}

func machineFingerprint(hostname string) string {
	home, err := os.UserHomeDir()
	if err == nil && home != "" {
		dir := filepath.Join(home, ".shuai-tunnel")
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
