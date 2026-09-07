package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCLIRejectsInvalidArguments(t *testing.T) {
	for _, args := range [][]string{
		{"unknown-command"}, {"--unknown"}, {"--config"}, {"--config="},
		{"--config", "--version"}, {"--help", "extra"}, {"--version", "--typo"},
		{"config"}, {"config", "unknown"}, {"--update-parent-pid=42"},
		{"--apply-update-helper"}, {"run", "extra"},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			if _, err := parseCLI(args); err == nil {
				t.Fatal("accepted invalid arguments")
			}
		})
	}
}

func TestCLIAliasesAndUpdateRollback(t *testing.T) {
	o, err := parseCLI([]string{"run", "-c", "path with spaces/client.jsonc", "--auto-update", "--no-update-check"})
	if err != nil || o.configPath != "path with spaces/client.jsonc" || !o.noUpdate {
		t.Fatalf("%+v %v", o, err)
	}
	o, err = parseCLI([]string{"config", "validate", "--config=custom.jsonc"})
	if err != nil || o.command != "validate" {
		t.Fatalf("%+v %v", o, err)
	}
	o, err = parseCLI([]string{"--apply-update-helper", "--update-parent-pid=42", "--update-candidate-sha256=abc", "--", "--config", "path with spaces.jsonc", "--auto-update"})
	if err != nil || len(o.helperArgs) != 3 {
		t.Fatalf("helper forwarding: %+v %v", o, err)
	}
	if strings.Contains(cliHelp, "apply-update-helper") {
		t.Fatal("internal helper leaked into help")
	}
}

// Exercise the real CLI dispatcher in isolated processes: a test failure cannot
// log in using a developer's working-directory config or hang the test runner.
func TestCLIProcess(t *testing.T) {
	if encoded := os.Getenv("SPECUS_TEST_CLI_ARGS"); encoded != "" {
		var args []string
		if err := json.Unmarshal([]byte(encoded), &args); err != nil {
			os.Exit(99)
		}
		os.Exit(runCLI(args))
	}
	path := filepath.Join(t.TempDir(), "config with spaces.jsonc")
	if err := os.WriteFile(path, []byte(`{"serverBaseUrl":"http://127.0.0.1:1","apiKey":"test","secret":"DO_NOT_PRINT_SECRET"}`), 0600); err != nil {
		t.Fatal(err)
	}
	diagnosticPath := filepath.Join(t.TempDir(), "diagnostics.jsonc")
	if err := os.WriteFile(diagnosticPath, []byte(`{"serverBaseUrl":"http://127.0.0.1:1","apiKey":"test","secret":"DO_NOT_PRINT_SECRET","peerMeshMtu":9999,"typo":"DO_NOT_PRINT_SECRET"}`), 0600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		args []string
		code int
		text string
	}{
		{[]string{"--help"}, 0, "Usage:"},
		{[]string{"--version"}, 0, version},
		{[]string{"--help", "--config=missing.jsonc"}, 0, "Usage:"},
		{[]string{"unknown-command"}, 2, "unexpected"},
		{[]string{"--config"}, 2, "config"},
		{[]string{"--config=missing.jsonc"}, 2, "invalid config"},
		{[]string{"config", "validate", "--config", path}, 0, "offline"},
		{[]string{"config", "validate", "--config", diagnosticPath}, 0, "Warning:"},
	} {
		t.Run(strings.Join(tc.args, " "), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			encoded, _ := json.Marshal(tc.args)
			cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestCLIProcess$")
			cmd.Dir = t.TempDir()
			cmd.Env = append(os.Environ(), "SPECUS_TEST_CLI_ARGS="+string(encoded))
			var stdout, stderr bytes.Buffer
			cmd.Stdout, cmd.Stderr = &stdout, &stderr
			_ = cmd.Run()
			if ctx.Err() != nil {
				t.Fatal("CLI hung or attempted to connect")
			}
			if cmd.ProcessState.ExitCode() != tc.code {
				t.Fatalf("code=%d stdout=%s stderr=%s", cmd.ProcessState.ExitCode(), &stdout, &stderr)
			}
			if !strings.Contains(stdout.String()+stderr.String(), tc.text) {
				t.Fatalf("missing %q: %s %s", tc.text, &stdout, &stderr)
			}
			if strings.Contains(stdout.String()+stderr.String(), "DO_NOT_PRINT_SECRET") {
				t.Fatal("secret leaked")
			}
			if tc.text == "Warning:" && (strings.Contains(stdout.String(), "Warning:") || !strings.Contains(stderr.String(), "peerMeshMtu normalized to 1280")) {
				t.Fatalf("warning channel/normalization: stdout=%s stderr=%s", &stdout, &stderr)
			}
			if tc.code == 0 && tc.text != "Warning:" && stderr.Len() > 0 {
				t.Fatalf("unexpected stderr: %s", &stderr)
			}
			if tc.code != 0 && stdout.Len() > 0 {
				t.Fatalf("unexpected stdout: %s", &stdout)
			}
		})
	}
}
