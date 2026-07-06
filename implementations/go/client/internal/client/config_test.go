package client

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoadConfigNormalizesPeerMeshOptions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "client.jsonc")
	content := `{
  "$schema": "https://tunnel.devshuai.com/schemas/client-startup-config.schema.json",
  // JSONC comments are allowed in client.jsonc.
  "serverBaseUrl": " http://127.0.0.1:8088/ ",
  "apiKey": " demo-client ",
  "secret": " test1234 ",
  "peerMeshDevice": " auto ",
  "peerMeshTunName": " mesh0 ",
  "peerMeshMtu": 4096,
}`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	config, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if config.ServerBaseURL != "http://127.0.0.1:8088/" {
		t.Fatalf("serverBaseUrl not trimmed: %q", config.ServerBaseURL)
	}
	if config.APIKey != "demo-client" || config.Secret != "test1234" {
		t.Fatalf("credentials not trimmed: apiKey=%q secret=%q", config.APIKey, config.Secret)
	}
	if config.PeerMeshDevice != "auto" || config.PeerMeshTunName != "mesh0" {
		t.Fatalf("peer mesh options not loaded: %#v", config)
	}
	if config.PeerMeshMTU != MaxPeerMeshMTU {
		t.Fatalf("peerMeshMtu should be clamped to %d, got %d", MaxPeerMeshMTU, config.PeerMeshMTU)
	}
}

func TestLoadConfigDefaultsPeerMeshOptions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "client.jsonc")
	content := `{"serverBaseUrl":"http://127.0.0.1:8088","apiKey":"demo","secret":"test1234"}`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	config, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if config.PeerMeshDevice != DefaultPeerMeshDevice {
		t.Fatalf("peerMeshDevice default mismatch: %q", config.PeerMeshDevice)
	}
	if config.PeerMeshTunName != DefaultPeerMeshTunName {
		t.Fatalf("peerMeshTunName default mismatch: %q", config.PeerMeshTunName)
	}
	if config.PeerMeshMTU != DefaultPeerMeshMTU {
		t.Fatalf("peerMeshMtu default mismatch: %d", config.PeerMeshMTU)
	}
}

func TestLoadConfigRejectsNonHTTPServerBaseURL(t *testing.T) {
	path := filepath.Join(t.TempDir(), "client.jsonc")
	content := `{"serverBaseUrl":"ftp://127.0.0.1:8088","apiKey":"demo","secret":"test1234"}`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := LoadConfig(path); err == nil {
		t.Fatal("LoadConfig accepted a non-http serverBaseUrl")
	}
}

func TestTokenRefreshDelayUsesLeadWindow(t *testing.T) {
	now := time.Unix(1000, 0)
	delay := tokenRefreshDelay(now, now.Add(10*time.Minute))
	if delay != 9*time.Minute {
		t.Fatalf("expected 10%% lead for 10m ttl, got %s", delay)
	}

	shortDelay := tokenRefreshDelay(now, now.Add(40*time.Second))
	if shortDelay != 20*time.Second {
		t.Fatalf("expected half remaining delay for short ttl, got %s", shortDelay)
	}

	expiredDelay := tokenRefreshDelay(now, now.Add(-time.Second))
	if expiredDelay != tokenRefreshMinDelay {
		t.Fatalf("expired token should use min delay, got %s", expiredDelay)
	}
}

func TestNormalizeOSUserMatchesJavaStyleUsername(t *testing.T) {
	tests := map[string]string{
		`DESKTOP\shshi`: "shshi",
		`DOMAIN\admin`:  "admin",
		"root":          "root",
		"/users/alice":  "alice",
		"  bob  ":       "bob",
		"":              "unknown",
	}
	for input, want := range tests {
		if got := normalizeOSUser(input); got != want {
			t.Fatalf("normalizeOSUser(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestNatControlConfigDistinguishesMissingAndEmptyHTTPRoutesLikeJava(t *testing.T) {
	var missing natControlConfig
	if err := json.Unmarshal([]byte(`{"tunnelConfigList":[]}`), &missing); err != nil {
		t.Fatal(err)
	}
	if missing.HTTPTunnelConfigList != nil {
		t.Fatalf("missing httpTunnelConfigList should keep current routes, got %#v", missing.HTTPTunnelConfigList)
	}

	var empty natControlConfig
	if err := json.Unmarshal([]byte(`{"tunnelConfigList":[],"httpTunnelConfigList":[]}`), &empty); err != nil {
		t.Fatal(err)
	}
	if empty.HTTPTunnelConfigList == nil {
		t.Fatal("empty httpTunnelConfigList should be a present empty slice")
	}
	if len(*empty.HTTPTunnelConfigList) != 0 {
		t.Fatalf("empty httpTunnelConfigList length = %d", len(*empty.HTTPTunnelConfigList))
	}
}
