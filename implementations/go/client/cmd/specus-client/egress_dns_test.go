package main

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/devShuai/specus/implementations/go/client/internal/client"
)

// `egress dns status` and `egress dns restore`, run in this process against a fake machine and a
// journal under a temporary home. Nothing here changes the DNS of the machine the tests run on.

type fakeRestoreHost struct {
	files map[string]string
	fail  map[string]string
	ran   []string
}

func (h *fakeRestoreHost) Run(argv []string) (string, error) {
	line := strings.Join(argv, " ")
	h.ran = append(h.ran, line)
	if output, failing := h.fail[line]; failing {
		return "", errors.New(output)
	}
	return "", nil
}
func (h *fakeRestoreHost) ReadFile(path string) (string, error) {
	content, ok := h.files[path]
	if !ok {
		return "", os.ErrNotExist
	}
	return content, nil
}
func (h *fakeRestoreHost) WriteFile(path, content string) error { h.files[path] = content; return nil }
func (h *fakeRestoreHost) IsSymlink(string) (bool, error)       { return false, nil }
func (h *fakeRestoreHost) LinkExists(string) bool               { return true }

const writtenResolvConf = "# Written by specus for peer egress DNS takeover. The original is kept in the journal\n" +
	"# and is put back when the client stops or when `egress dns restore` runs.\n" +
	"nameserver 198.18.0.1\n"

// dnsCLI points the journal's home at a temporary directory and restore at a fake machine.
func dnsCLI(t *testing.T) (*fakeRestoreHost, string) {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("SPECUS_CLI_STATE_DIR", filepath.Join(home, "no-state"))
	host := &fakeRestoreHost{files: map[string]string{"/etc/resolv.conf": writtenResolvConf}, fail: map[string]string{}}
	previous := newEgressDNSHost
	newEgressDNSHost = func() client.EgressDNSHost { return host }
	t.Cleanup(func() { newEgressDNSHost = previous })
	path := client.EgressDNSJournalPath()
	if !strings.HasPrefix(path, home) {
		t.Fatalf("the journal is at %s, outside the test's home", path)
	}
	return host, path
}

func writeTestJournal(t *testing.T, path string, journal client.EgressDNSJournal) {
	t.Helper()
	raw, _ := json.Marshal(journal)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
}

// runCaptured runs the CLI in this process and returns its exit code and JSON document.
func runCaptured(t *testing.T, args ...string) (int, map[string]any) {
	t.Helper()
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, stderr := os.Stdout, os.Stderr
	os.Stdout, os.Stderr = writer, writer
	code := runCLI(append(args, "--json"))
	os.Stdout, os.Stderr = stdout, stderr
	writer.Close()
	raw, _ := io.ReadAll(reader)
	var document map[string]any
	for _, line := range strings.Split(string(raw), "\n") {
		if strings.HasPrefix(line, "{") {
			_ = json.Unmarshal([]byte(line), &document)
		}
	}
	if document == nil {
		t.Fatalf("no JSON document in %q", raw)
	}
	return code, document
}

// deadPID is the process ID of a process that has exited.
func deadPID(t *testing.T) int {
	t.Helper()
	command := exec.Command(os.Args[0], "-test.run=^$")
	if err := command.Run(); err != nil {
		t.Fatal(err)
	}
	return command.ProcessState.Pid()
}

func resolvConfJournal(pid int) client.EgressDNSJournal {
	return client.EgressDNSJournal{Version: 1, State: "committed", Platform: "linux-resolvconf", PID: pid,
		Listen: "198.18.0.1", Tunnel: "specus0", Upstreams: []string{"192.168.1.1"}, ResolvConf: "nameserver 192.168.1.1\n"}
}

func TestEgressDNSRestoreWithoutAJournal(t *testing.T) {
	host, _ := dnsCLI(t)
	code, document := runCaptured(t, "egress", "dns", "restore")
	if code != 0 || document["ok"] != true {
		t.Fatalf("code %d: %v", code, document)
	}
	if len(host.ran) != 0 || host.files["/etc/resolv.conf"] != writtenResolvConf {
		t.Error("restore with no journal touched the machine")
	}
}

// The client that took over still runs: restore refuses and changes nothing, unless forced.
func TestEgressDNSRestoreRefusesWhileTheClientRuns(t *testing.T) {
	host, path := dnsCLI(t)
	writeTestJournal(t, path, resolvConfJournal(os.Getppid()))
	code, document := runCaptured(t, "egress", "dns", "restore")
	message, _ := document["error"].(string)
	if code != 1 || !strings.Contains(message, "still running") {
		t.Fatalf("code %d: %v", code, document)
	}
	if host.files["/etc/resolv.conf"] != writtenResolvConf {
		t.Error("a refused restore changed resolv.conf")
	}
	if _, err := os.Stat(path); err != nil {
		t.Error("a refused restore removed the journal")
	}

	code, document = runCaptured(t, "egress", "dns", "restore", "--force")
	if code != 0 || host.files["/etc/resolv.conf"] != "nameserver 192.168.1.1\n" {
		t.Fatalf("forced restore: code %d, resolv.conf %q: %v", code, host.files["/etc/resolv.conf"], document)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Error("the journal outlived a restore")
	}
}

// A journal whose client is gone is given back; a step that fails keeps the journal and is named.
func TestEgressDNSRestoreGivesBackAKilledClientsTakeover(t *testing.T) {
	host, path := dnsCLI(t)
	writeTestJournal(t, path, resolvConfJournal(deadPID(t)))
	if code, document := runCaptured(t, "egress", "dns", "restore"); code != 0 || host.files["/etc/resolv.conf"] != "nameserver 192.168.1.1\n" {
		t.Fatalf("code %d, resolv.conf %q: %v", code, host.files["/etc/resolv.conf"], document)
	}

	host.fail["resolvectl revert specus0"] = "Failed to revert interface configuration: Access denied"
	writeTestJournal(t, path, client.EgressDNSJournal{Version: 1, State: "committed", Platform: "linux-resolved",
		PID: deadPID(t), Listen: "198.18.0.1", Tunnel: "specus0", Upstreams: []string{"1.1.1.1"}})
	code, document := runCaptured(t, "egress", "dns", "restore")
	message, _ := document["error"].(string)
	if code != 1 || !strings.Contains(message, "resolvectl revert specus0") {
		t.Fatalf("code %d: %v", code, document)
	}
	if _, err := os.Stat(path); err != nil {
		t.Error("a failed restore removed the journal")
	}
}

// status works with no client running and tells what the journal says and what to do.
func TestEgressDNSStatusReadsTheJournalWithoutAClient(t *testing.T) {
	_, path := dnsCLI(t)
	config := filepath.Join(t.TempDir(), "client.jsonc")
	code, document := runCaptured(t, "egress", "dns", "status", "--config", config)
	data, _ := document["data"].(map[string]any)
	journal, _ := data["journal"].(map[string]any)
	if code != 0 || journal["state"] != "none" {
		t.Fatalf("code %d: %v", code, document)
	}

	pid := deadPID(t)
	writeTestJournal(t, path, resolvConfJournal(pid))
	code, document = runCaptured(t, "egress", "dns", "status", "--config", config)
	data, _ = document["data"].(map[string]any)
	journal, _ = data["journal"].(map[string]any)
	if code != 0 || journal["state"] != "committed" || journal["processRunning"] != false || journal["platform"] != "linux-resolvconf" {
		t.Fatalf("code %d: %v", code, document)
	}
	lines := strings.Join(append(egressDNSLines(nil), egressDNSLinesForTest(t)...), "\n")
	if !strings.Contains(lines, "not asked for") {
		t.Errorf("lines %q", lines)
	}
}

// egressDNSLinesForTest renders a running instance's consumer.dns as the status command does.
func egressDNSLinesForTest(t *testing.T) []string {
	t.Helper()
	var dns map[string]any
	if err := json.Unmarshal([]byte(`{"active":true,"takeover":false,"code":"EGRESS_DNS_TAKEOVER_REFUSED",
		"reason":"system-dns-loopback","listen":"198.18.0.1","pool":"198.18.0.0/15","mappings":131,"quarantined":2,
		"upstreams":[],"journal":"none","queries":{"answered":5,"forwarded":3,"failed":1}}`), &dns); err != nil {
		t.Fatal(err)
	}
	lines := egressDNSLines(dns)
	joined := strings.Join(lines, "\n")
	for _, want := range []string{"phase two: running", "system DNS takeover: off (EGRESS_DNS_TAKEOVER_REFUSED: system-dns-loopback)",
		"responder 198.18.0.1 | no upstream", "pool 198.18.0.0/15: 131 mappings (0.10% in use), 2 quarantined",
		"queries: answered 5, forwarded 3, failed 1"} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing %q in %q", want, joined)
		}
	}
	return lines
}

func TestEgressDNSCommandsParse(t *testing.T) {
	for _, args := range [][]string{
		{"egress", "dns"}, {"egress", "dns", "flush"}, {"egress", "dns", "status", "--force"},
	} {
		if _, err := parseCLI(args); err == nil {
			t.Errorf("%q accepted", args)
		}
	}
	if o, err := parseCLI([]string{"egress", "dns", "restore", "--force"}); err != nil || o.command != "egress dns restore" || !o.egressForce {
		t.Errorf("restore --force: %+v %v", o, err)
	}
	if !strings.Contains(cliHelp, "egress dns restore") || !strings.Contains(cliHelp, "hard-coded IP") {
		t.Error("the help leaves out the DNS commands or the recognisable boundary")
	}
}
