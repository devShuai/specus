package main

import (
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/devShuai/specus/implementations/go/client/internal/client"
)

// The system DNS takeover's commands (protocol/spec/peer-egress-dns.md, 六, 命令).
//
// Neither needs the client to be running. status reads what a running client published and the
// journal on disk; restore gives the system DNS back from the journal, which is how a takeover left
// by a killed client is undone without starting it again.

// newEgressDNSHost is the machine restore runs its commands on. Tests replace it, so nothing they
// run changes the DNS of the machine they run on.
var newEgressDNSHost = client.NewEgressDNSSystemHost

// egressDNSEnableNotice is what turning the DNS takeover on means, said every time it is turned on:
// it is the one change this feature makes to the system's own settings. The same lines in every
// runtime (protocol/spec/peer-egress-dns.md, 命令).
var egressDNSEnableNotice = []string{
	"Turning on DNS takeover for domain rules:",
	"  - points the system DNS at this client while it runs and gives it back when it stops (resolvectl or /etc/resolv.conf on Linux, networksetup on macOS, an NRPT rule on Windows)",
	"  - keeps a journal in ~/.specus, so a change left by a killed client is undone at its next start or by egress dns restore",
	"  - domain rules do not match applications that bring their own DoH/DoT, use the system cache, or connect to hard-coded IP addresses; that traffic is covered only by IP/CIDR rules",
}

// egressDNSSwitch is `egress dns enable|disable`: set peerEgressDnsTakeover the way egress
// enable|disable sets peerEgressEnabled, the one value replaced in place and everything else in the
// file -- comments, line breaks -- kept. Turning it on needs --yes after the notice, every time.
func egressDNSSwitch(options cliOptions, path string) int {
	data, revision, config, failed := loadEgressConfig(options, path)
	if failed >= 0 {
		return failed
	}
	enable := options.command == "egress dns enable"
	var lines []string
	value := "false"
	if enable {
		if !options.egressYes {
			return resultOutput(options.json, options.command, 2, nil,
				strings.Join(egressDNSEnableNotice, "\n")+"\nNot changed. Re-run with --yes to confirm.")
		}
		lines = append(lines, egressDNSEnableNotice...)
		if !config.PeerEgressEnabled {
			lines = append(lines, "Warning: peerEgressEnabled is false, so domain rules take effect only after egress enable.")
		}
		value = "true"
	}
	patched, err := uiPatchRawConfig(data, map[string][]byte{"peerEgressDnsTakeover": []byte(value)})
	if err != nil {
		return resultOutput(options.json, options.command, 2, nil, err.Error())
	}
	edited, err := client.ParseConfigWithDiagnostics(patched, func(string) {})
	if err != nil {
		return resultOutput(options.json, options.command, 2, nil,
			fmt.Sprintf("the edited configuration would not load (%v); nothing was written", err))
	}
	if err := uiWriteConfig(path, revision, patched); err != nil {
		return resultOutput(options.json, options.command, 2, nil, err.Error())
	}
	lines = append(lines, "Saved "+path+". "+egressRestartNote)
	if enable {
		lines = append(lines, "dns takeover: on (pool "+edited.PeerEgressFakeIPCIDR+")")
	} else {
		lines = append(lines, "dns takeover: off")
	}
	return resultOutput(options.json, options.command, 0,
		map[string]any{"configPath": path, "dnsTakeover": enable, "pool": edited.PeerEgressFakeIPCIDR},
		strings.Join(lines, "\n"))
}

// egressDNSJournalView is what the commands say about the journal.
func egressDNSJournalView() (map[string]any, string, error) {
	path := client.EgressDNSJournalPath()
	journal, err := client.ReadEgressDNSJournal(path)
	if err != nil {
		return map[string]any{"path": path, "state": "unreadable"}, "journal: unreadable (" + err.Error() + ")", err
	}
	if journal == nil {
		return map[string]any{"path": path, "state": "none"}, "journal: none (the system DNS is not taken over)", nil
	}
	running := processAlive(journal.PID)
	view := map[string]any{
		"path": path, "state": journal.State, "platform": journal.Platform, "pid": journal.PID,
		"processRunning": running, "listen": journal.Listen, "upstreams": journal.Upstreams,
	}
	line := fmt.Sprintf("journal: %s by PID %d (%s), upstreams %s", journal.State, journal.PID, journal.Platform,
		strings.Join(journal.Upstreams, ", "))
	if !running {
		line += fmt.Sprintf("\n  PID %d is not running, so nothing will give the system DNS back by itself\n"+
			"  fix: run egress dns restore", journal.PID)
	}
	return view, line, nil
}

// egressDNSStatus is `egress dns status`: each running instance's consumer.dns, and the journal.
func egressDNSStatus(options cliOptions, config string) int {
	journal, journalLine, _ := egressDNSJournalView()
	states, code, problem := freshStates(config)
	if code == 2 {
		return resultOutput(options.json, options.command, 2, nil, problem)
	}
	instances := []any{}
	var lines []string
	for _, state := range states {
		pid, _ := state["pid"].(float64)
		egress, _ := state["egress"].(map[string]any)
		consumer, _ := egress["consumer"].(map[string]any)
		dns, _ := consumer["dns"].(map[string]any)
		instances = append(instances, map[string]any{"pid": pid, "dns": dns})
		lines = append(lines, fmt.Sprintf("PID %.0f", pid))
		lines = append(lines, egressDNSLines(dns)...)
	}
	if len(states) == 0 {
		lines = append(lines, "No running client for this config.")
	}
	lines = append(lines, journalLine)
	data := map[string]any{"configPath": config, "instances": instances, "journal": journal}
	return resultOutput(options.json, options.command, 0, data, strings.Join(lines, "\n"))
}

// egressDNSLines renders one instance's consumer.dns for a person: whether phase two runs, whether
// the system DNS is taken over and why not, where queries go, and how full the pool is.
func egressDNSLines(dns map[string]any) []string {
	if dns == nil {
		return []string{"  phase two: not asked for (peerEgressDnsTakeover is off)"}
	}
	code, reason, failure := stringAt(dns, "code"), stringAt(dns, "reason"), stringAt(dns, "error")
	phase := "  phase two: running"
	if !boolAt(dns, "active") {
		phase = "  phase two: not running"
		if code == "EGRESS_FAKE_IP_POOL_INVALID" {
			phase += " (" + code + ": check peerEgressFakeIpCidr against the Peer Mesh network and this device's networks)"
		}
	}
	takeover := "on"
	if !boolAt(dns, "takeover") {
		takeover = "off"
		switch {
		case reason != "":
			takeover += " (" + code + ": " + reason + ")"
		case failure != "":
			takeover += " (" + code + ": " + failure + ")"
		}
	}
	lines := []string{phase + " | system DNS takeover: " + takeover + " | journal: " + stringAt(dns, "journal")}
	upstreams := listOfStrings(dns["upstreams"])
	if listen := stringAt(dns, "listen"); listen != "" {
		forwards := "no upstream; forwarded queries are answered SERVFAIL"
		if len(upstreams) > 0 {
			forwards = "forwarding to " + strings.Join(upstreams, ", ")
		}
		lines = append(lines, "  responder "+listen+" | "+forwards)
	}
	pool := stringAt(dns, "pool")
	mappings := intAt(dns, "mappings")
	lines = append(lines, fmt.Sprintf("  pool %s: %d mappings (%s in use), %d quarantined", pool, mappings,
		poolUsage(pool, mappings), intAt(dns, "quarantined")))
	if queries := mapAt(dns, "queries"); queries != nil {
		lines = append(lines, fmt.Sprintf("  queries: answered %d, forwarded %d, failed %d",
			intAt(queries, "answered"), intAt(queries, "forwarded"), intAt(queries, "failed")))
	}
	return lines
}

// poolUsage is the share of the pool's addresses handed out: all of it but the network, the
// broadcast and the responder's own.
func poolUsage(pool string, mappings int64) string {
	_, prefix, found := strings.Cut(pool, "/")
	bits := 0
	if _, err := fmt.Sscanf(prefix, "%d", &bits); !found || err != nil || bits < 8 || bits > 30 {
		return "?"
	}
	size := int64(1)<<(32-bits) - 3
	return fmt.Sprintf("%.2f%%", float64(mappings)*100/float64(size))
}

func listOfStrings(value any) []string {
	items, _ := value.([]any)
	out := make([]string, 0, len(items))
	for _, item := range items {
		if text, ok := item.(string); ok {
			out = append(out, text)
		}
	}
	return out
}

// egressDNSRestore is `egress dns restore`: give the system DNS back as the journal says. Exit 0
// when there is nothing to give back or it was given back; 1 when the client that took it over still
// runs (without --force) or a step failed, which is named.
func egressDNSRestore(options cliOptions) int {
	path := client.EgressDNSJournalPath()
	journal, err := client.ReadEgressDNSJournal(path)
	if err != nil {
		return resultOutput(options.json, options.command, 1, map[string]any{"journal": path}, err.Error())
	}
	if journal == nil {
		return resultOutput(options.json, options.command, 0, map[string]any{"journal": path, "restored": false},
			"No DNS takeover journal at "+path+"; there is nothing to restore.")
	}
	data := map[string]any{"journal": path, "platform": journal.Platform, "pid": journal.PID, "restored": false}
	if !options.egressForce && journal.PID != os.Getpid() && processAlive(journal.PID) {
		return resultOutput(options.json, options.command, 1, data, fmt.Sprintf(
			"The client that took over the system DNS (PID %d) is still running, and gives it back itself when it stops. "+
				"Stop it, or set peerEgressDnsTakeover to false and restart it. --force skips this check, for when that PID "+
				"now belongs to another process.", journal.PID))
	}
	logger := log.New(os.Stderr, "", 0)
	if err := client.RevertEgressDNSJournal(newEgressDNSHost(), path, journal, logger); err != nil {
		data["failedStep"] = err.Error()
		return resultOutput(options.json, options.command, 1, data,
			"Giving the system DNS back failed at "+err.Error()+". The journal is kept; fix what the step reports and run egress dns restore again.")
	}
	data["restored"] = true
	return resultOutput(options.json, options.command, 0, data,
		fmt.Sprintf("System DNS given back (%s, taken over by PID %d); journal removed.", journal.Platform, journal.PID))
}
