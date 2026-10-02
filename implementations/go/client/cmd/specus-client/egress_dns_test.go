package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

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

// publishTestState writes a state file the way a running client does -- private, in the state
// directory -- under name, for the process and time given. The rest of fields replaces the defaults,
// which are another runtime's and another configuration's, so only the process id can match.
func publishTestState(t *testing.T, name string, pid int, updatedAt time.Time, fields map[string]any) {
	t.Helper()
	root, err := checkedStateRoot(true)
	if err != nil {
		t.Fatal(err)
	}
	state := map[string]any{"schemaVersion": 1, "pid": pid, "updatedAtUnixMs": updatedAt.UnixMilli(),
		"configPath": filepath.Join(root, "another.jsonc"), "processRunning": true, "phase": "ready"}
	for key, value := range fields {
		state[key] = value
	}
	raw, _ := json.Marshal(state)
	path := filepath.Join(root, name)
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := checkPrivate(path, true); err != nil {
		t.Fatal(err)
	}
}

// A client runs as a process id when fresh state from that process is in the state directory: the
// status command's rule, for any configuration and runtime, matched on the id inside the file.
func TestStateClientRunning(t *testing.T) {
	dnsCLI(t)
	parent := os.Getppid()
	if stateClientRunning(parent) {
		t.Fatal("a client was found with no state directory")
	}
	// Named for another process: the id inside is what counts.
	publishTestState(t, "java-0123-1.json", parent, time.Now(), nil)
	if !stateClientRunning(parent) {
		t.Error("fresh state of another runtime and configuration was not recognised")
	}
	if stateClientRunning(os.Getpid()) || stateClientRunning(0) {
		t.Error("a process that published nothing was recognised")
	}
	for _, state := range []struct {
		why    string
		at     time.Time
		fields map[string]any
	}{
		{"stale", time.Now().Add(-6 * time.Second), nil},
		{"from later", time.Now().Add(time.Minute), nil},
		{"of version 2", time.Now(), map[string]any{"schemaVersion": 2}},
		{"without a pid", time.Now(), map[string]any{"pid": nil}},
	} {
		publishTestState(t, "java-0123-1.json", parent, state.at, state.fields)
		if stateClientRunning(parent) {
			t.Errorf("state %s counted", state.why)
		}
	}
	dead := deadPID(t)
	publishTestState(t, "dotnet-4567-1.json", dead, time.Now(), nil)
	if stateClientRunning(dead) {
		t.Error("fresh state of a process that has exited counted")
	}
	if runtime.GOOS != "windows" {
		publishTestState(t, "go-89ab-1.json", parent, time.Now(), nil)
		root, _ := stateRoot()
		if err := os.Chmod(filepath.Join(root, "go-89ab-1.json"), 0o644); err != nil {
			t.Fatal(err)
		}
		if stateClientRunning(parent) {
			t.Error("a state file others can read counted")
		}
	}
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

// The client that took over still runs -- it publishes fresh state -- so restore refuses and changes
// nothing, unless forced.
func TestEgressDNSRestoreRefusesWhileTheClientRuns(t *testing.T) {
	host, path := dnsCLI(t)
	writeTestJournal(t, path, resolvConfJournal(os.Getppid()))
	publishTestState(t, "dotnet-0123-1.json", os.Getppid(), time.Now(), nil)
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

// A journal whose process id runs but publishes no fresh state -- reused by another program since a
// reboot -- is given back without --force.
func TestEgressDNSRestoreGivesBackAReusedProcessID(t *testing.T) {
	host, path := dnsCLI(t)
	for _, state := range []string{"none", "stale", "another process's"} {
		switch state {
		case "stale":
			publishTestState(t, "java-0123-1.json", os.Getppid(), time.Now().Add(-10*time.Second), nil)
		case "another process's":
			publishTestState(t, "java-0123-1.json", os.Getpid(), time.Now(), nil)
		}
		host.files["/etc/resolv.conf"] = writtenResolvConf
		writeTestJournal(t, path, resolvConfJournal(os.Getppid()))
		code, document := runCaptured(t, "egress", "dns", "restore")
		if data, _ := document["data"].(map[string]any); code != 0 || data["restored"] != true ||
			host.files["/etc/resolv.conf"] != "nameserver 192.168.1.1\n" {
			t.Errorf("with %s state: code %d, resolv.conf %q: %v", state, code, host.files["/etc/resolv.conf"], document)
		}
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Errorf("with %s state the journal outlived the restore", state)
		}
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
	if code != 0 || journal["state"] != "committed" || journal["clientRunning"] != false || journal["platform"] != "linux-resolvconf" {
		t.Fatalf("code %d: %v", code, document)
	}
	// A running process id is not a running client; fresh state from it is.
	writeTestJournal(t, path, resolvConfJournal(os.Getppid()))
	_, stdout, _ := runCapturedText(t, "egress", "dns", "status", "--config", config)
	if !strings.Contains(stdout, fmt.Sprintf("no client is running as PID %d", os.Getppid())) {
		t.Errorf("a reused process id read as the client: %q", stdout)
	}
	publishTestState(t, "java-0123-1.json", os.Getppid(), time.Now(), nil)
	_, document = runCaptured(t, "egress", "dns", "status", "--config", config)
	data, _ = document["data"].(map[string]any)
	if journal, _ = data["journal"].(map[string]any); journal["clientRunning"] != true {
		t.Errorf("the publishing client was not seen: %v", document)
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
		{"egress", "dns", "disable", "--yes"}, {"egress", "dns", "enable", "--force"},
	} {
		if _, err := parseCLI(args); err == nil {
			t.Errorf("%q accepted", args)
		}
	}
	if o, err := parseCLI([]string{"egress", "dns", "restore", "--force"}); err != nil || o.command != "egress dns restore" || !o.egressForce {
		t.Errorf("restore --force: %+v %v", o, err)
	}
	if o, err := parseCLI([]string{"egress", "dns", "enable", "--yes", "--config", "c.jsonc"}); err != nil ||
		o.command != "egress dns enable" || !o.egressYes {
		t.Errorf("enable --yes: %+v %v", o, err)
	}
	for _, want := range []string{"egress dns enable", "egress dns disable", "egress dns status", "egress dns restore"} {
		if !strings.Contains(cliHelp, want) {
			t.Errorf("the help leaves out %s", want)
		}
	}
	// The pinned sentence, checked the way the CLI matrix checks it: whitespace normalised.
	boundary := "Domain rules do not match applications that bring their own DoH/DoT, use the system cache, or " +
		"connect to hard-coded IP addresses; that traffic is covered only by IP/CIDR rules."
	if !strings.Contains(strings.Join(strings.Fields(cliHelp), " "), boundary) {
		t.Error("the help leaves out the recognisable-boundary sentence")
	}
}

// The lines restore and status print are the spec's, word for word: the CLI matrix holds all three
// clients to them.
func TestEgressDNSMessagesMatchThePinnedText(t *testing.T) {
	host, path := dnsCLI(t)
	config := filepath.Join(t.TempDir(), "client.jsonc")
	code, stdout, _ := runCapturedText(t, "egress", "dns", "restore")
	if code != 0 || stdout != "No DNS takeover journal at "+path+"; there is nothing to restore.\n" {
		t.Errorf("no journal: %d %q", code, stdout)
	}
	code, stdout, _ = runCapturedText(t, "egress", "dns", "status", "--config", config)
	if code != 0 || stdout != "No running client for this config.\njournal: none (the system DNS is not taken over)\n" {
		t.Errorf("status: %d %q", code, stdout)
	}

	writeTestJournal(t, path, resolvConfJournal(os.Getppid()))
	publishTestState(t, "java-0123-1.json", os.Getppid(), time.Now(), nil)
	code, _, stderr := runCapturedText(t, "egress", "dns", "restore")
	want := fmt.Sprintf("The client that took over the system DNS (PID %d) is still running, and gives it back itself when it "+
		"stops. Stop it, or set peerEgressDnsTakeover to false and restart it. --force skips this check, for when that PID "+
		"now belongs to another client.\n", os.Getppid())
	if code != 1 || stderr != want {
		t.Errorf("still running: %d %q", code, stderr)
	}
	code, stdout, _ = runCapturedText(t, "egress", "dns", "restore", "--force")
	if code != 0 || stdout != fmt.Sprintf("System DNS given back (linux-resolvconf, taken over by PID %d); journal removed.\n", os.Getppid()) {
		t.Errorf("restored: %d %q", code, stdout)
	}

	host.fail["resolvectl revert specus0"] = "Failed to revert interface configuration: Access denied"
	writeTestJournal(t, path, client.EgressDNSJournal{Version: 1, State: "committed", Platform: "linux-resolved",
		PID: deadPID(t), Listen: "198.18.0.1", Tunnel: "specus0", Upstreams: []string{"1.1.1.1"}})
	code, _, stderr = runCapturedText(t, "egress", "dns", "restore")
	if code != 1 || !strings.HasPrefix(stderr, "Giving the system DNS back failed at resolvectl revert specus0: ") ||
		!strings.HasSuffix(stderr, ". The journal is kept; fix what the step reports and run egress dns restore again.\n") {
		t.Errorf("failed step: %d %q", code, stderr)
	}
}

// runCapturedText runs the CLI in this process and returns its exit code, standard output and
// standard error.
func runCapturedText(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	outReader, outWriter, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	errReader, errWriter, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, stderr := os.Stdout, os.Stderr
	os.Stdout, os.Stderr = outWriter, errWriter
	code := runCLI(args)
	os.Stdout, os.Stderr = stdout, stderr
	outWriter.Close()
	errWriter.Close()
	out, _ := io.ReadAll(outReader)
	errText, _ := io.ReadAll(errReader)
	return code, string(out), string(errText)
}

const dnsSwitchConfig = "{\r\n  // the server this client logs in to\r\n  \"serverBaseUrl\": \"http://127.0.0.1:1\",\r\n" +
	"  \"apiKey\": \"k\",\r\n  \"secret\": \"s\"\r\n}\r\n"

// egress dns enable says what it changes every time, changes nothing without --yes, and writes the
// one value in place, comments and line breaks kept; disable writes it back off.
func TestEgressDNSEnableAndDisable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "client.jsonc")
	if err := os.WriteFile(path, []byte(dnsSwitchConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	notice := strings.Join(egressDNSEnableNotice, "\n")

	code, stdout, stderr := runCapturedText(t, "egress", "dns", "enable", "--config", path)
	if code != 2 || stdout != "" || stderr != notice+"\nNot changed. Re-run with --yes to confirm.\n" {
		t.Fatalf("without --yes: code %d stdout %q stderr %q", code, stdout, stderr)
	}
	if raw, _ := os.ReadFile(path); string(raw) != dnsSwitchConfig {
		t.Fatal("enable without --yes changed the file")
	}

	code, stdout, stderr = runCapturedText(t, "egress", "dns", "enable", "--yes", "--config", path)
	want := notice + "\nWarning: peerEgressEnabled is false, so domain rules take effect only after egress enable.\n" +
		"Saved " + path + ". A running client applies the change after a restart.\ndns takeover: on (pool 198.18.0.0/15)\n"
	if code != 0 || stdout != want || stderr != "" {
		t.Fatalf("enable --yes: code %d\nstdout %q\nwant   %q\nstderr %q", code, stdout, want, stderr)
	}
	raw, _ := os.ReadFile(path)
	text := string(raw)
	if !strings.Contains(text, "\"peerEgressDnsTakeover\": true") || !strings.Contains(text, "// the server this client logs in to") ||
		strings.Count(text, "\n") != strings.Count(text, "\r\n") {
		t.Fatalf("the file after enable: %q", text)
	}

	code, document := runCaptured(t, "egress", "dns", "disable", "--config", path)
	data, _ := document["data"].(map[string]any)
	if code != 0 || data["dnsTakeover"] != false || data["pool"] != "198.18.0.0/15" || data["configPath"] != path {
		t.Fatalf("disable: code %d %v", code, document)
	}
	if raw, _ := os.ReadFile(path); !strings.Contains(string(raw), "\"peerEgressDnsTakeover\": false") {
		t.Fatalf("the file after disable: %q", raw)
	}
	code, stdout, _ = runCapturedText(t, "egress", "dns", "disable", "--config", path)
	if code != 0 || !strings.HasSuffix(stdout, "A running client applies the change after a restart.\ndns takeover: off\n") {
		t.Fatalf("disable: code %d stdout %q", code, stdout)
	}

	// With takeover on and a pool of its own: no warning, and the pool named is the one in use.
	custom := strings.Replace(dnsSwitchConfig, "\"secret\": \"s\"", "\"secret\": \"s\",\r\n  \"peerEgressEnabled\": true,\r\n"+
		"  \"peerEgressFakeIpCidr\": \"10.200.0.0/16\"", 1)
	if err := os.WriteFile(path, []byte(custom), 0o600); err != nil {
		t.Fatal(err)
	}
	code, stdout, _ = runCapturedText(t, "egress", "dns", "enable", "--yes", "--config", path)
	if code != 0 || strings.Contains(stdout, "Warning:") || !strings.HasSuffix(stdout, "dns takeover: on (pool 10.200.0.0/16)\n") {
		t.Fatalf("enable with its own pool: code %d stdout %q", code, stdout)
	}
}
