package client

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestConfigDiagnosticsWarnWithoutDisclosingValues(t *testing.T) {
	path := filepath.Join(t.TempDir(), "client.jsonc")
	data := `{"serverBaseUrl":"http://127.0.0.1:1","apiKey":"DO_NOT_PRINT_KEY","secret":"DO_NOT_PRINT_SECRET",
	"peerMeshMtu":9999,"updateCheckIntervalHours":9999,"typo":"DO_NOT_PRINT_UNKNOWN",
	"controlTls":{"serverNmae":"DO_NOT_PRINT_HOST"},"upstreamTls":{"bad":"DO_NOT_PRINT_PIN"},"openUpdatePage":true}`
	if err := os.WriteFile(path, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	var warnings []string
	config, err := LoadConfigWithDiagnostics(path, func(w string) { warnings = append(warnings, w) })
	if err != nil {
		t.Fatal(err)
	}
	if config.PeerMeshMTU != 1280 || config.UpdateCheckIntervalHours != 168 {
		t.Fatal("not normalized")
	}
	joined := strings.Join(warnings, "\n")
	for _, expected := range []string{"typo", "controlTls.serverNmae", "upstreamTls.bad", "peerMeshMtu normalized to 1280", "updateCheckIntervalHours normalized to 168", "not used by Go"} {
		if !strings.Contains(joined, expected) {
			t.Fatalf("missing %s in %s", expected, joined)
		}
	}
	if strings.Contains(joined, "DO_NOT_PRINT") {
		t.Fatal("configuration values leaked")
	}
}

func TestConfigDiagnosticsAcceptsCaseInsensitiveKeysAndEscapesNames(t *testing.T) {
	var warnings []string
	configWarnings([]byte(`{"APIKEY":"private","controlTLS":{"ENABLED":false},"bad\nname":"private"}`), Config{}, func(w string) { warnings = append(warnings, w) })
	if len(warnings) != 1 || strings.Contains(warnings[0], "\n") {
		t.Fatalf("unexpected warnings: %q", warnings)
	}
}

// A configuration that uses peerEgressRules is not told the field is unknown, and each rule that will
// not be in force is named by index and code without its match.
//
// The unknown-field half is the one that was wrong: the field is omitempty, so it was missing from
// the list of known fields and every such configuration was told its rules were ignored.
func TestConfigWarningsKnowEgressRulesAndNameTheOnesNotInForce(t *testing.T) {
	data := []byte(`{"peerEgressRules":[
		{"match":"203.0.113.0/24","action":"egress","egressClientId":42},
		{"match":"0.0.0.0/0","action":"egress","egressClientId":42},
		{"match":"example.com","action":"egress","egressClientId":42}]}`)
	var config Config
	if err := unmarshalJSONC(data, &config); err != nil {
		t.Fatalf("decode: %v", err)
	}
	var warnings []string
	configWarnings(data, config, func(w string) { warnings = append(warnings, w) })

	joined := strings.Join(warnings, " | ")
	if strings.Contains(joined, "Unknown configuration field") {
		t.Errorf("peerEgressRules was reported as unknown: %q", joined)
	}
	for _, want := range []string{
		"peerEgressRules[1] is not in force: " + egressCodeRuleDefaultRoute,
		"peerEgressRules[2] is not in force: " + egressCodeRuleDomainUnsupported,
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing warning %q in %q", want, joined)
		}
	}
	if strings.Contains(joined, "peerEgressRules[0]") || strings.Contains(joined, "example.com") {
		t.Errorf("a usable rule was named or a match was printed: %q", joined)
	}
}
