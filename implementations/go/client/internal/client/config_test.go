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
  "$schema": "https://specus.devshuai.com/schemas/client-startup-config.schema.json",
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
	if !config.UpdatesEnabled() {
		t.Fatal("update checks should default to enabled")
	}
	if config.UpdateCheckIntervalHours != DefaultUpdateCheckIntervalHours ||
		config.UpdateCheckInterval() != 24*time.Hour {
		t.Fatalf("update interval default mismatch: hours=%d duration=%s",
			config.UpdateCheckIntervalHours, config.UpdateCheckInterval())
	}
}

func TestLoadConfigCanDisableUpdateChecksAndEnableAutomaticUpdates(t *testing.T) {
	path := filepath.Join(t.TempDir(), "client.jsonc")
	content := `{"serverBaseUrl":"https://specus.example.com","apiKey":"demo","secret":"test1234","updateCheckEnabled":false,"autoUpdate":true}`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	config, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if config.UpdatesEnabled() || !config.AutoUpdate {
		t.Fatalf("update options not loaded: enabled=%t auto=%t", config.UpdatesEnabled(), config.AutoUpdate)
	}
}

func TestLoadConfigClampsUpdateCheckInterval(t *testing.T) {
	tests := []struct {
		name, value string
		want        int
	}{
		{"zero defaults", "0", DefaultUpdateCheckIntervalHours},
		{"negative defaults", "-1", DefaultUpdateCheckIntervalHours},
		{"minimum", "1", MinUpdateCheckIntervalHours},
		{"maximum clamp", "999", MaxUpdateCheckIntervalHours},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "client.jsonc")
			content := `{"serverBaseUrl":"https://specus.example.com","apiKey":"demo","secret":"test1234",` +
				`"updateCheckIntervalHours":` + test.value + `}`
			if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
				t.Fatal(err)
			}
			config, err := LoadConfig(path)
			if err != nil {
				t.Fatal(err)
			}
			if config.UpdateCheckIntervalHours != test.want ||
				config.UpdateCheckInterval() != time.Duration(test.want)*time.Hour {
				t.Fatalf("interval hours=%d duration=%s, want %d hours",
					config.UpdateCheckIntervalHours, config.UpdateCheckInterval(), test.want)
			}
		})
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
	if err := json.Unmarshal([]byte(`{"specusConfigList":[]}`), &missing); err != nil {
		t.Fatal(err)
	}
	if missing.HTTPSpecusConfigList != nil {
		t.Fatalf("missing httpSpecusConfigList should keep current routes, got %#v", missing.HTTPSpecusConfigList)
	}

	var empty natControlConfig
	if err := json.Unmarshal([]byte(`{"specusConfigList":[],"httpSpecusConfigList":[]}`), &empty); err != nil {
		t.Fatal(err)
	}
	if empty.HTTPSpecusConfigList == nil {
		t.Fatal("empty httpSpecusConfigList should be a present empty slice")
	}
	if len(*empty.HTTPSpecusConfigList) != 0 {
		t.Fatalf("empty httpSpecusConfigList length = %d", len(*empty.HTTPSpecusConfigList))
	}
}

func TestNatControlConfigReadsPerRouteTLSPolicy(t *testing.T) {
	var snapshot natControlConfig
	if err := json.Unmarshal([]byte(`{"specusConfigList":[],"httpSpecusConfigList":[{"route":"secure","targetBaseUrl":"https://localhost:8443","insecureSkipVerify":true}]}`), &snapshot); err != nil {
		t.Fatal(err)
	}
	if snapshot.HTTPSpecusConfigList == nil || len(*snapshot.HTTPSpecusConfigList) != 1 {
		t.Fatalf("unexpected HTTP route snapshot: %#v", snapshot.HTTPSpecusConfigList)
	}
	if !(*snapshot.HTTPSpecusConfigList)[0].InsecureSkipVerify {
		t.Fatal("route-level insecureSkipVerify was not preserved")
	}
}
