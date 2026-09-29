package client

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"
)

// Pointing the system's DNS at the responder, and putting it back (protocol/spec/peer-egress-dns.md,
// section 六; step five).
//
// This is the one place the feature changes the user's system configuration, so it is built around
// being able to undo itself from any point. The journal is written before anything is touched, with
// everything needed to give back; the takeover is marked committed only once every step succeeded;
// any failure runs the whole give-back, which is safe whatever part of the takeover happened; and a
// journal found at start is given back before anything else, which is how a killed process's
// takeover is undone. Giving back leaves alone whatever somebody else wrote after us.
//
// The decisions -- what to read, what counts as a refusal, the exact commands -- are the pure
// functions of peer_egress_dns_takeover_parse.go, pinned by the shared vector. What is here is the
// order they run in and what is kept on disk, behind EgressDNSHost so that the tests run it against
// fakes and never touch the machine they run on.

// EgressDNSHost is what the takeover needs from the machine. Run executes a command line without a
// shell and returns its standard output; a failure carries what the command printed.
type EgressDNSHost interface {
	Run(argv []string) (string, error)
	ReadFile(path string) (string, error)
	WriteFile(path, content string) error
	IsSymlink(path string) (bool, error)
	// LinkExists reports whether a network interface of that name is there.
	LinkExists(name string) bool
}

// The takeover's codes, as the status and the CLI report them.
const (
	egressCodeDNSTakeoverRefused = "EGRESS_DNS_TAKEOVER_REFUSED"
	egressCodeDNSTakeoverFailed  = "EGRESS_DNS_TAKEOVER_FAILED"
)

// The journal's states, and what the status says when there is none.
const (
	egressDNSJournalNone      = "none"
	egressDNSJournalPending   = "pending"
	egressDNSJournalCommitted = "committed"
	egressDNSJournalVersion   = 1
)

const (
	// egressDNSNetworkCheck is how often the network is compared with the one the takeover was
	// made on.
	egressDNSNetworkCheck = 10 * time.Second
	// egressDNSRetryInterval is how long a refused or failed takeover waits before the system is
	// read again, unless the network or the request changed first. Reading runs commands, and the
	// answer rarely changes by itself between ticks.
	egressDNSRetryInterval = 60 * time.Second
)

// EgressDNSService is one macOS network service the takeover changed, with the DNS it had.
type EgressDNSService struct {
	Name    string   `json:"name"`
	Servers []string `json:"servers"`
}

// EgressDNSJournal is the record, on disk, of a takeover: enough to give it back after a crash.
type EgressDNSJournal struct {
	Version         int      `json:"version"`
	State           string   `json:"state"`
	Platform        string   `json:"platform"`
	PID             int      `json:"pid"`
	Listen          string   `json:"listen"`
	Tunnel          string   `json:"tunnel"`
	Upstreams       []string `json:"upstreams"`
	StartedAtUnixMs int64    `json:"startedAtUnixMs"`
	// ResolvConf is the original /etc/resolv.conf, for linux-resolvconf.
	ResolvConf string `json:"resolvConf,omitempty"`
	// Services are the macOS services changed and what each had, for macos.
	Services []EgressDNSService `json:"services,omitempty"`
}

// egressDNSJournalHome is where the journal's directory is found. The package's tests point it at a
// temporary directory, so no test reads or writes a user's own journal.
var egressDNSJournalHome = os.UserHomeDir

// EgressDNSJournalPath is where the journal lives: beside the route install record, in the same
// private directory.
func EgressDNSJournalPath() string {
	home, err := egressDNSJournalHome()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".specus", "egress-dns-journal.json")
}

// ReadEgressDNSJournal reads the journal, or returns nil when there is none.
func ReadEgressDNSJournal(path string) (*EgressDNSJournal, error) {
	if path == "" {
		return nil, nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	var journal EgressDNSJournal
	if err := json.Unmarshal(raw, &journal); err != nil {
		return nil, fmt.Errorf("DNS takeover journal %s is not readable: %w", path, err)
	}
	if journal.Version != egressDNSJournalVersion {
		// Acting on a journal written differently would mean giving back by guess.
		return nil, fmt.Errorf("DNS takeover journal version %d is not %d", journal.Version, egressDNSJournalVersion)
	}
	return &journal, nil
}

// writeEgressDNSJournal writes the journal the way the route install record is written: through a
// temporary file, so a crash mid-write cannot leave half a journal that describes less than was done.
func writeEgressDNSJournal(path string, journal EgressDNSJournal) error {
	if path == "" {
		return errors.New("no home directory for the DNS takeover journal")
	}
	raw, err := json.MarshalIndent(journal, "", "  ")
	if err != nil {
		return err
	}
	if directory := filepath.Dir(path); directory != "" && directory != "." {
		if err := os.MkdirAll(directory, 0o755); err != nil {
			return err
		}
	}
	temporary := path + ".tmp"
	if err := os.WriteFile(temporary, raw, 0o600); err != nil {
		return err
	}
	return os.Rename(temporary, path)
}

func removeEgressDNSJournal(path string) error {
	if path == "" {
		return nil
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// egressDNSCommandError is a command that failed, with what it printed.
type egressDNSCommandError struct {
	argv   []string
	output string
	err    error
}

func (e *egressDNSCommandError) Error() string {
	return strings.Join(e.argv, " ") + ": " + e.firstLine()
}

func (e *egressDNSCommandError) Unwrap() error { return e.err }

// firstLine is the first line the command printed, or the error when it printed nothing. It is what
// the status shows for a failed takeover: usually the line that says why.
func (e *egressDNSCommandError) firstLine() string {
	for _, line := range dnsTextLines(e.output) {
		if line = strings.TrimSpace(line); line != "" {
			return line
		}
	}
	if e.err != nil {
		return e.err.Error()
	}
	return "failed"
}

// egressDNSFirstLine is the line a failure is reported by.
func egressDNSFirstLine(err error) string {
	var command *egressDNSCommandError
	if errors.As(err, &command) {
		return command.firstLine()
	}
	if err == nil {
		return ""
	}
	line, _, _ := strings.Cut(err.Error(), "\n")
	return strings.TrimSpace(line)
}

// egressDNSTakeoverRequest is what the mesh asks for while phase two runs.
type egressDNSTakeoverRequest struct {
	Listen, Tunnel, Pool, Mesh string
	// PoolRouteInstalled says the pool's route is in the table. Without it nothing sent to a fake
	// address reaches this feature, the responder's own address included.
	PoolRouteInstalled bool
}

func (r egressDNSTakeoverRequest) key() string {
	return r.Listen + "|" + r.Tunnel + "|" + r.Pool + "|" + r.Mesh
}

// egressDNSTakeoverStatus is what the status reports about the takeover.
type egressDNSTakeoverStatus struct {
	// Takeover is whether the system's DNS points at the responder now: the journal is committed.
	Takeover bool
	// Code is EGRESS_DNS_TAKEOVER_REFUSED with Reason, or EGRESS_DNS_TAKEOVER_FAILED with Error.
	Code, Reason, Error string
	Journal             string
}

// egressDNSTakeover runs the takeover. Not safe for concurrent use except for status: the mesh drives
// it under egressPlanMu.
type egressDNSTakeover struct {
	host     EgressDNSHost
	platform string
	path     string
	pid      int
	logger   *log.Logger
	// tunnelAddresses lists the addresses of this device's tunnel-type interfaces other than
	// tunnel, this client's own.
	tunnelAddresses func(tunnel string) []string
	// fingerprint describes the network: the default route's interface and every local IPv4
	// address. Nil means no check.
	fingerprint func() (string, error)

	// held is the journal of the takeover in place, nil when there is none.
	held *EgressDNSJournal
	// The last attempt, so a refusal is not retried every tick.
	attemptKey string
	attemptAt  time.Time
	// The network as last compared.
	network        string
	networkAt      time.Time
	networkChecked bool

	mu     sync.Mutex
	status egressDNSTakeoverStatus
}

func newEgressDNSTakeover(host EgressDNSHost, platform, path string, logger *log.Logger) *egressDNSTakeover {
	if logger == nil {
		logger = log.Default()
	}
	return &egressDNSTakeover{
		host: host, platform: platform, path: path, pid: os.Getpid(), logger: logger,
		tunnelAddresses: func(string) []string { return nil },
		status:          egressDNSTakeoverStatus{Journal: egressDNSJournalNone},
	}
}

func (t *egressDNSTakeover) setStatus(status egressDNSTakeoverStatus) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.status = status
}

// statusSnapshot is safe to call from any goroutine.
func (t *egressDNSTakeover) statusSnapshot() egressDNSTakeoverStatus {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.status
}

func (t *egressDNSTakeover) journalState() string {
	if t.held != nil {
		return t.held.State
	}
	return egressDNSJournalNone
}

// recoverLeftover gives back a takeover a previous run left, pending or committed, before this run
// decides anything. A process that was killed never gave back; this is where it happens.
func (t *egressDNSTakeover) recoverLeftover() {
	journal, err := ReadEgressDNSJournal(t.path)
	if err != nil {
		t.logger.Printf("[peer-egress-consumer] DNS takeover journal left in place: %v", err)
		return
	}
	if journal == nil {
		return
	}
	if err := revertEgressDNSJournal(t.host, t.path, journal, t.logger); err != nil {
		t.logger.Printf("[peer-egress-consumer] DNS takeover left by process %d not given back, the journal stays for "+
			"the next start or `egress dns restore`: %v", journal.PID, err)
		return
	}
	t.logger.Printf("[peer-egress-consumer] DNS takeover left by process %d given back", journal.PID)
}

// release gives back the takeover in place, if there is one. The status keeps no code: nothing is
// refused or failed, it is simply not held.
func (t *egressDNSTakeover) release(why string) {
	if t.held == nil {
		return
	}
	journal := t.held
	if err := revertEgressDNSJournal(t.host, t.path, journal, t.logger); err != nil {
		// Kept, and so is the knowledge that it is kept: the next start, or the command, tries
		// again. Pretending it was given back would lose the only record of what to restore.
		t.logger.Printf("[peer-egress-consumer] system DNS not fully given back (%s), the journal stays: %v", why, err)
		t.held = nil
		t.setStatus(egressDNSTakeoverStatus{Code: egressCodeDNSTakeoverFailed, Error: egressDNSFirstLine(err),
			Journal: journal.State})
		return
	}
	t.held = nil
	t.logger.Printf("[peer-egress-consumer] system DNS given back (%s)", why)
	t.setStatus(egressDNSTakeoverStatus{Journal: egressDNSJournalNone})
}

// idle is the takeover while phase two is not running: nothing held and, unless a give-back failed
// and its journal is still waiting, nothing to report.
func (t *egressDNSTakeover) idle(why string) {
	t.release(why)
	if status := t.statusSnapshot(); status.Code != egressCodeDNSTakeoverFailed || status.Journal == egressDNSJournalNone {
		t.setStatus(egressDNSTakeoverStatus{Journal: egressDNSJournalNone})
	}
	t.forgetAttempt()
}

// networkChanged compares the network with the last reading, at most every egressDNSNetworkCheck.
// The first reading is the baseline.
func (t *egressDNSTakeover) networkChanged(now time.Time) bool {
	if t.fingerprint == nil || (t.networkChecked && now.Sub(t.networkAt) < egressDNSNetworkCheck && !now.Before(t.networkAt)) {
		return false
	}
	current, err := t.fingerprint()
	if err != nil {
		return false
	}
	t.networkAt = now
	previous, known := t.network, t.networkChecked
	t.network, t.networkChecked = current, true
	return known && current != previous
}

// forgetAttempt makes the next engage try at once: the network or the setup changed, and the answer
// the last attempt got may no longer hold.
func (t *egressDNSTakeover) forgetAttempt() { t.attemptKey, t.attemptAt = "", time.Time{} }

// engage takes the system's DNS over for a request, or keeps it. It returns the upstreams when a
// takeover was just committed, for the responder to forward to.
func (t *egressDNSTakeover) engage(request egressDNSTakeoverRequest, now time.Time) ([]string, bool) {
	if t.held != nil {
		if request.PoolRouteInstalled && t.held.Listen == request.Listen && t.held.Tunnel == request.Tunnel {
			return nil, false
		}
		// The pool's route went, or the responder moved: the system would be sending its queries
		// somewhere nothing answers.
		t.release("the pool's route or the listen address changed")
	}
	if !request.PoolRouteInstalled {
		// Checked every tick without reading anything, so the takeover follows the route in.
		t.forgetAttempt()
		t.refuse(egressDNSRefusedPoolRoute)
		return nil, false
	}
	key := request.key()
	if key == t.attemptKey && now.Sub(t.attemptAt) < egressDNSRetryInterval && !now.Before(t.attemptAt) {
		return nil, false
	}
	t.attemptKey, t.attemptAt = key, now
	return t.attempt(request, now)
}

func (t *egressDNSTakeover) refuse(reason string) {
	t.setStatus(egressDNSTakeoverStatus{Code: egressCodeDNSTakeoverRefused, Reason: reason, Journal: t.journalState()})
}

func (t *egressDNSTakeover) fail(err error) {
	t.setStatus(egressDNSTakeoverStatus{Code: egressCodeDNSTakeoverFailed, Error: egressDNSFirstLine(err),
		Journal: t.journalState()})
}

// attempt reads the system, decides, and takes over.
func (t *egressDNSTakeover) attempt(request egressDNSTakeoverRequest, now time.Time) ([]string, bool) {
	// A journal still on disk is a give-back that failed. It is the only record of what the system
	// had, so it is given back first and never written over.
	if leftover, err := ReadEgressDNSJournal(t.path); err != nil || leftover != nil {
		if err == nil {
			err = revertEgressDNSJournal(t.host, t.path, leftover, t.logger)
		}
		if err != nil {
			t.logger.Printf("[peer-egress-consumer] system DNS not taken over, an earlier takeover is still to be "+
				"given back: %v", err)
			t.setStatus(egressDNSTakeoverStatus{Code: egressCodeDNSTakeoverFailed, Error: egressDNSFirstLine(err),
				Journal: egressDNSJournalPending})
			return nil, false
		}
	}
	journal := EgressDNSJournal{
		Version: egressDNSJournalVersion, State: egressDNSJournalPending, PID: t.pid,
		Listen: request.Listen, Tunnel: request.Tunnel, StartedAtUnixMs: now.UnixMilli(),
	}
	servers, reason, err := t.readSystem(&journal)
	if err != nil {
		t.logger.Printf("[peer-egress-consumer] system DNS not taken over, reading it failed: %s", egressDNSFirstLine(err))
		t.fail(err)
		return nil, false
	}
	if reason == "" {
		journal.Upstreams, reason = classifyEgressDNSUpstreams(servers, t.tunnelAddresses(request.Tunnel), request.Pool, request.Mesh)
	}
	if reason != "" {
		if status := t.statusSnapshot(); status.Reason != reason {
			t.logger.Printf("[peer-egress-consumer] system DNS not taken over: %s", reason)
		}
		t.refuse(reason)
		return nil, false
	}

	// Written before anything is changed: whatever happens from here, the record of what to put
	// back is on disk first.
	if err := writeEgressDNSJournal(t.path, journal); err != nil {
		t.logger.Printf("[peer-egress-consumer] system DNS not taken over, the journal could not be written: %v", err)
		t.fail(err)
		return nil, false
	}
	t.setStatus(egressDNSTakeoverStatus{Journal: egressDNSJournalPending})
	plan, _ := egressDNSTakeoverPlan(journal.Platform, journal.Listen, journal.Tunnel, egressDNSServiceNames(journal.Services))
	var failure error
	for _, step := range plan.Apply {
		if failure = runEgressDNSStep(t.host, step); failure != nil {
			break
		}
	}
	if failure == nil {
		journal.State = egressDNSJournalCommitted
		if err := writeEgressDNSJournal(t.path, journal); err != nil {
			failure = fmt.Errorf("record the takeover as done: %w", err)
		}
	}
	if failure != nil {
		// The whole give-back, whatever part of the takeover happened: it is safe from any point.
		t.logger.Printf("[peer-egress-consumer] system DNS takeover failed, giving back: %v", failure)
		journalState := egressDNSJournalNone
		if err := revertEgressDNSJournal(t.host, t.path, &journal, t.logger); err != nil {
			t.logger.Printf("[peer-egress-consumer] giving back the failed takeover failed too, the journal stays: %v", err)
			journalState = egressDNSJournalPending
		}
		t.setStatus(egressDNSTakeoverStatus{Code: egressCodeDNSTakeoverFailed, Error: egressDNSFirstLine(failure),
			Journal: journalState})
		return nil, false
	}
	t.held = &journal
	t.setStatus(egressDNSTakeoverStatus{Takeover: true, Journal: egressDNSJournalCommitted})
	// Said every time, as egress enable says it: this is the one change to the system's own
	// configuration, and the person running the client should never have to discover it.
	t.logger.Printf("[peer-egress-consumer] system DNS now points at %s (%s); forwarding to %s. It is given back when "+
		"the client stops, or by `egress dns restore`", journal.Listen, journal.Platform, strings.Join(journal.Upstreams, ", "))
	return append([]string(nil), journal.Upstreams...), true
}

// readSystem reads the platform's DNS: the servers the upstreams come from, what giving back will
// need (into journal), or the reason the takeover is refused. err is a read that failed.
func (t *egressDNSTakeover) readSystem(journal *EgressDNSJournal) (servers []string, reason string, err error) {
	switch t.platform {
	case "linux":
		resolvectl, resolvectlErr := t.host.Run([]string{"resolvectl", "dns"})
		conf, readErr := t.host.ReadFile(egressDNSResolvConf)
		if readErr != nil && !errors.Is(readErr, os.ErrNotExist) {
			return nil, "", readErr
		}
		symlink, _ := t.host.IsSymlink(egressDNSResolvConf)
		mode, refusal := egressDNSLinuxMode(resolvectlErr == nil, parseResolvConfServers(conf), symlink)
		if refusal != "" {
			return nil, refusal, nil
		}
		journal.Platform = mode
		if mode == egressDNSPlatformResolved {
			return parseResolvectlDNS(resolvectl, journal.Tunnel), "", nil
		}
		journal.ResolvConf = conf
		return parseResolvConfServers(conf), "", nil
	case "darwin":
		journal.Platform = egressDNSPlatformMacOS
		listing, err := t.host.Run([]string{"networksetup", "-listallnetworkservices"})
		if err != nil {
			return nil, "", err
		}
		for _, service := range parseMacNetworkServices(listing) {
			output, err := t.host.Run([]string{"networksetup", "-getdnsservers", service})
			if err != nil {
				return nil, "", err
			}
			journal.Services = append(journal.Services, EgressDNSService{Name: service, Servers: parseMacDNSServers(output)})
		}
		resolvers, err := t.host.Run([]string{"scutil", "--dns"})
		if err != nil {
			return nil, "", err
		}
		return parseScutilDNS(resolvers), "", nil
	case "windows":
		journal.Platform = egressDNSPlatformWindows
		rules, err := t.host.Run(windowsPowerShell(egressDNSWindowsReadNRPT))
		if err != nil {
			return nil, "", err
		}
		foreign, err := parseWindowsNRPT(rules)
		if err != nil {
			return nil, "", err
		}
		if foreign {
			return nil, egressDNSRefusedNRPT, nil
		}
		// The TUN's own index, so its server -- the responder -- is not read back as an upstream.
		tunnelIndex := 0
		if output, err := t.host.Run(windowsPowerShell(windowsInterfaceIndexScript(journal.Tunnel))); err == nil {
			tunnelIndex, _ = parseWindowsInterfaceIndex(output)
		}
		output, err := t.host.Run(windowsPowerShell(egressDNSWindowsReadServers))
		if err != nil {
			return nil, "", err
		}
		servers, err := parseWindowsDNSServers(output, tunnelIndex)
		return servers, "", err
	}
	return nil, egressDNSRefusedUnsupported, nil
}

func egressDNSServiceNames(services []EgressDNSService) []string {
	names := make([]string, 0, len(services))
	for _, service := range services {
		names = append(names, service.Name)
	}
	return names
}

// runEgressDNSStep performs one step of taking over.
func runEgressDNSStep(host EgressDNSHost, step egressDNSStep) error {
	if step.Write != "" {
		return host.WriteFile(step.Write, step.Content)
	}
	_, err := host.Run(step.Argv)
	return err
}

// revertEgressDNSJournal gives a takeover back as its journal describes, and deletes the journal
// when every step succeeded. Every step is tried even after one fails, so as much is given back as
// can be; the error names the first that failed, and the journal is kept for another try.
//
// Somebody else's change is kept: a resolv.conf that no longer holds what we wrote, or a macOS
// service that no longer points at the responder alone, is left as it is, with a warning.
func revertEgressDNSJournal(host EgressDNSHost, path string, journal *EgressDNSJournal, logger *log.Logger) error {
	if logger == nil {
		logger = log.Default()
	}
	plan, known := egressDNSTakeoverPlan(journal.Platform, journal.Listen, journal.Tunnel, egressDNSServiceNames(journal.Services))
	if !known {
		return fmt.Errorf("the journal names platform %q, which this client does not know how to give back", journal.Platform)
	}
	var failed error
	note := func(step string, err error) {
		if err != nil && failed == nil {
			failed = fmt.Errorf("%s: %w", step, err)
		}
	}
	for _, step := range plan.Revert {
		switch {
		case step.Restore != "":
			current, err := host.ReadFile(step.Restore)
			if err != nil && !errors.Is(err, os.ErrNotExist) {
				note("read "+step.Restore, err)
				continue
			}
			if restore, warning := revertResolvConf(current, journal.ResolvConf); restore {
				note("restore "+step.Restore, host.WriteFile(step.Restore, journal.ResolvConf))
			} else {
				logger.Printf("[peer-egress-consumer] %s was changed by someone else during the takeover and is "+
					"kept as it is (%s)", step.Restore, warning)
			}
		case step.RestoreService != "":
			output, err := host.Run([]string{"networksetup", "-getdnsservers", step.RestoreService})
			if err != nil {
				note("read the DNS of "+step.RestoreService, err)
				continue
			}
			original := []string{"Empty"}
			for _, service := range journal.Services {
				if service.Name == step.RestoreService {
					original = service.Servers
				}
			}
			command, warning := revertMacService(step.RestoreService, parseMacDNSServers(output), original, journal.Listen)
			if command == nil {
				logger.Printf("[peer-egress-consumer] the DNS of %s was changed by someone else during the takeover and "+
					"is kept as it is (%s)", step.RestoreService, warning)
				continue
			}
			_, err = host.Run(command)
			note(strings.Join(command, " "), err)
		default:
			if journal.Platform == egressDNSPlatformResolved && len(step.Argv) > 2 && step.Argv[1] == "revert" &&
				!host.LinkExists(journal.Tunnel) {
				// Link settings live and die with the link: with the tunnel gone there is nothing
				// left to revert, and asking resolvectl about a link it cannot find would keep the
				// journal forever.
				continue
			}
			_, err := host.Run(step.Argv)
			note(strings.Join(step.Argv, " "), err)
		}
	}
	if failed != nil {
		return failed
	}
	return removeEgressDNSJournal(path)
}

// RevertEgressDNSJournal is `egress dns restore`: give back what the journal at path records.
func RevertEgressDNSJournal(host EgressDNSHost, path string, journal *EgressDNSJournal, logger *log.Logger) error {
	return revertEgressDNSJournal(host, path, journal, logger)
}

// egressDNSPlatform is this build's platform as the takeover knows it.
func egressDNSPlatform() string { return runtime.GOOS }

// egressDNSNetworkFingerprint describes the network for the change check: the interface the default
// route leaves by, and every local IPv4 address in order. routes and tunnel are the routing table as
// the route installer reads it.
func egressDNSNetworkFingerprint(routes []egressBindRoute, tunnel string, addresses []uint32) string {
	defaultInterface := ""
	var best int64
	for _, route := range routes {
		if route.Prefix != "0.0.0.0/0" || !route.Usable || route.Interface == "" || route.Interface == tunnel {
			continue
		}
		if defaultInterface == "" || route.Metric < best {
			defaultInterface, best = route.Interface, route.Metric
		}
	}
	sorted := append([]uint32(nil), addresses...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	texts := make([]string, 0, len(sorted))
	for _, address := range sorted {
		texts = append(texts, formatEgressAddress(address))
	}
	return defaultInterface + "|" + strings.Join(texts, ",")
}
