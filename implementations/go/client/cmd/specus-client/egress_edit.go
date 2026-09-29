package main

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/devShuai/specus/implementations/go/client/internal/client"
)

// The egress editing commands: list the rules, add, remove, move and switch them, turn takeover on
// and off, and preview what the rules do for one address.
//
// They edit the configuration file the way the local page does: the one top-level value they own is
// replaced in place and everything else in the file is kept, the write is atomic and refused if the
// file changed underneath. They never touch a running client, which reads its configuration once
// at start; every write says so. Comments inside peerEgressRules do not survive an edit, because
// the list is written back whole.
//
// The Java and .NET clients print the same lines and the same JSON for the same file; the CLI
// process matrix holds them to it.

const egressRestartNote = "A running client applies the change after a restart."

// egressEnableNotice is what turning takeover on means, printed every time it is turned on.
var egressEnableNotice = []string{
	"Turning on egress takeover:",
	"  - needs permission to create a virtual interface and install routes (administrator or root; peerMeshDevice must not be noop)",
	"  - takes over only the destinations a rule covers; everything else stays local",
	"  - blocks a destination covered by an egress rule while its egress is unavailable, instead of sending it locally",
}

func runEgressCommand(options cliOptions, path string) int {
	switch options.command {
	case "egress rules":
		return egressList(options, path)
	case "egress test":
		return egressTest(options, path)
	case "egress enable", "egress disable":
		return egressSwitch(options, path)
	case "egress dns enable", "egress dns disable":
		return egressDNSSwitch(options, path)
	case "egress dns status":
		return egressDNSStatus(options, path)
	case "egress dns restore":
		return egressDNSRestore(options)
	default:
		return egressRuleEdit(options, path)
	}
}

func loadEgressConfig(options cliOptions, path string) ([]byte, string, client.Config, int) {
	data, revision, err := uiReadConfig(path)
	if err != nil {
		return nil, "", client.Config{}, resultOutput(options.json, options.command, 2, nil, err.Error())
	}
	if revision == "missing" {
		return nil, "", client.Config{}, resultOutput(options.json, options.command, 2, nil,
			"Configuration file not found: "+path)
	}
	config, err := client.ParseConfigWithDiagnostics(data, func(string) {})
	if err != nil {
		return nil, "", client.Config{}, resultOutput(options.json, options.command, 2, nil,
			fmt.Sprintf("invalid config %s: %v; fix it first (config validate)", path, err))
	}
	return data, revision, config, -1
}

// egressListing is what every egress command that reads or writes the rules reports.
func egressListing(path string, config client.Config) (map[string]any, []string) {
	rules := config.PeerEgressRules
	var lines []string
	switch {
	case config.PeerEgressEnabled:
		lines = append(lines, "takeover: on")
	case len(rules) > 0:
		lines = append(lines, "takeover: off (peerEgressEnabled is false); rules are saved, none is in force")
	default:
		lines = append(lines, "takeover: off (peerEgressEnabled is false)")
	}
	if len(rules) == 0 {
		lines = append(lines, "  No egress rules configured.")
	}
	views := make([]map[string]any, 0, len(rules))
	for index, rule := range rules {
		status := client.EgressRuleStatusCode(config, rule)
		switchedOff := client.EgressRuleSwitchedOff(rule)
		// The rule's own problem, told apart from being off: worth fixing before takeover is on.
		content := client.EgressRuleCode(config, client.EgressRule{
			Match: rule.Match, Action: rule.Action, EgressClientID: rule.EgressClientID, Port: rule.Port,
		})
		view := map[string]any{
			"index":   index,
			"match":   strings.TrimSpace(rule.Match),
			"action":  strings.TrimSpace(rule.Action),
			"enabled": !switchedOff,
			"inForce": status == "",
		}
		if rule.EgressClientID != 0 {
			view["egressClientId"] = rule.EgressClientID
		}
		if rule.Port != 0 {
			view["port"] = rule.Port
		}
		if status != "" {
			view["code"] = status
		}
		if content != "" {
			view["refusal"] = content
		}
		views = append(views, view)

		state := "on"
		if switchedOff {
			state = "off"
		}
		line := fmt.Sprintf("  [%d] %s %s %s", index, state, strings.TrimSpace(rule.Match), strings.TrimSpace(rule.Action))
		if rule.EgressClientID != 0 {
			line += " " + strconv.FormatInt(rule.EgressClientID, 10)
		}
		if content != "" {
			line += fmt.Sprintf(" -- not in force: %s (%s)", content, client.EgressCodeExplanation(content))
		}
		lines = append(lines, line)
	}
	return map[string]any{"configPath": path, "enabled": config.PeerEgressEnabled, "rules": views}, lines
}

func egressList(options cliOptions, path string) int {
	_, _, config, failed := loadEgressConfig(options, path)
	if failed >= 0 {
		return failed
	}
	data, lines := egressListing(path, config)
	return resultOutput(options.json, options.command, 0, data, strings.Join(lines, "\n"))
}

// egressChange is one edit to the rules or the switch, as the commands and the local page ask for it.
type egressChange struct {
	Op             string // add, remove, move, enable, disable, takeover
	Match          string
	Action         string
	EgressClientID int64
	At             int // -1: at the end
	Index          int
	To             int
	Disabled       bool
	Enabled        bool // takeover: the state asked for
	Confirmed      bool // takeover on: the notice was shown and accepted
}

// egressPlanned is what a change writes: one top-level value, already encoded, and what to say before
// the save. Unchanged means the file already says what was asked; NeedsConfirmation means takeover
// was asked for without the notice being accepted.
type egressPlanned struct {
	Key               string
	Value             []byte
	Preface           []string
	Unchanged         bool
	NeedsConfirmation bool
}

// egressPlan works out a change against the configuration as loaded. A failure is a message a person
// can act on, the same in every runtime and on both surfaces.
func egressPlan(config client.Config, change egressChange) (egressPlanned, string) {
	rules := append([]client.EgressRule(nil), config.PeerEgressRules...)
	noRule := func(index int) string {
		return fmt.Sprintf("No rule at index %d; there are %d rule(s). List them with egress rules.", index, len(rules))
	}
	indexOK := func(index int) bool { return index >= 0 && index < len(rules) }
	switch change.Op {
	case "takeover":
		if change.Enabled == config.PeerEgressEnabled {
			return egressPlanned{Unchanged: true}, ""
		}
		if !change.Enabled {
			return egressPlanned{Key: "peerEgressEnabled", Value: []byte("false")}, ""
		}
		preface := append([]string(nil), egressEnableNotice...)
		if !change.Confirmed {
			return egressPlanned{Preface: preface, NeedsConfirmation: true}, ""
		}
		if strings.TrimSpace(config.PeerMeshDevice) == "" || strings.EqualFold(strings.TrimSpace(config.PeerMeshDevice), "noop") {
			preface = append(preface, "Warning: peerMeshDevice is noop, so there is no interface to route into; set it to auto.")
		}
		return egressPlanned{Key: "peerEgressEnabled", Value: []byte("true"), Preface: preface}, ""
	case "add":
		rule := client.EgressRule{Match: strings.TrimSpace(change.Match),
			Action: strings.TrimSpace(change.Action), EgressClientID: change.EgressClientID}
		// Refused rules are allowed in the file, where they are warned about, but an edit that adds
		// one on request would only be writing a rule that steers nothing.
		if code := client.EgressRuleCode(config, rule); code != "" {
			return egressPlanned{}, fmt.Sprintf("Rule not added: %s (%s)", code, client.EgressCodeExplanation(code))
		}
		if change.Disabled {
			off := false
			rule.Enabled = &off
		}
		at := len(rules)
		if change.At >= 0 {
			if change.At > len(rules) {
				return egressPlanned{}, fmt.Sprintf("--at %d is past the end; there are %d rule(s).", change.At, len(rules))
			}
			at = change.At
		}
		rules = append(rules[:at], append([]client.EgressRule{rule}, rules[at:]...)...)
	case "remove":
		if !indexOK(change.Index) {
			return egressPlanned{}, noRule(change.Index)
		}
		rules = append(rules[:change.Index], rules[change.Index+1:]...)
	case "move":
		if !indexOK(change.Index) {
			return egressPlanned{}, noRule(change.Index)
		}
		if !indexOK(change.To) {
			return egressPlanned{}, noRule(change.To)
		}
		moved := rules[change.Index]
		rules = append(rules[:change.Index], rules[change.Index+1:]...)
		rules = append(rules[:change.To], append([]client.EgressRule{moved}, rules[change.To:]...)...)
	case "enable", "disable":
		if !indexOK(change.Index) {
			return egressPlanned{}, noRule(change.Index)
		}
		if change.Op == "enable" {
			rules[change.Index].Enabled = nil
		} else {
			off := false
			rules[change.Index].Enabled = &off
		}
	default:
		return egressPlanned{}, "unknown egress change: " + change.Op
	}
	return egressPlanned{Key: "peerEgressRules", Value: encodeEgressRules(rules)}, ""
}

// egressChangeFromOptions is the change an editing command asks for.
func egressChangeFromOptions(options cliOptions) egressChange {
	change := egressChange{Match: options.egressMatch, Action: options.egressAction,
		EgressClientID: options.egressClientID, At: options.egressAt, Index: options.egressIndex,
		To: options.egressTo, Disabled: options.egressDisabled, Confirmed: options.egressYes}
	switch options.command {
	case "egress enable", "egress disable":
		change.Op = "takeover"
		change.Enabled = options.command == "egress enable"
	default:
		change.Op = strings.TrimPrefix(options.command, "egress rule ")
	}
	return change
}

func egressRuleEdit(options cliOptions, path string) int {
	data, revision, config, failed := loadEgressConfig(options, path)
	if failed >= 0 {
		return failed
	}
	planned, failure := egressPlan(config, egressChangeFromOptions(options))
	if failure != "" {
		return resultOutput(options.json, options.command, 2, nil, failure)
	}
	return writeEgress(options, path, data, revision, map[string][]byte{planned.Key: planned.Value}, planned.Preface)
}

func egressSwitch(options cliOptions, path string) int {
	data, revision, config, failed := loadEgressConfig(options, path)
	if failed >= 0 {
		return failed
	}
	planned, _ := egressPlan(config, egressChangeFromOptions(options))
	switch {
	case planned.Unchanged:
		state := "off"
		if config.PeerEgressEnabled {
			state = "on"
		}
		listing, lines := egressListing(path, config)
		return resultOutput(options.json, options.command, 0, listing,
			"Takeover is already "+state+"; nothing was changed.\n"+strings.Join(lines, "\n"))
	case planned.NeedsConfirmation:
		// Confirmed by a flag rather than a prompt: whether a prompt could be answered depends on a
		// terminal the three runtimes cannot all detect the same way, and a command that waits in
		// one of them and fails in another is not the same command.
		return resultOutput(options.json, options.command, 2, nil, strings.Join(planned.Preface, "\n")+
			"\nNot changed. Re-run with --yes to confirm.")
	}
	return writeEgress(options, path, data, revision, map[string][]byte{planned.Key: planned.Value}, planned.Preface)
}

func writeEgress(options cliOptions, path string, data []byte, revision string, values map[string][]byte, preface []string) int {
	patched, err := uiPatchRawConfig(data, values)
	if err != nil {
		return resultOutput(options.json, options.command, 2, nil, err.Error())
	}
	config, err := client.ParseConfigWithDiagnostics(patched, func(string) {})
	if err != nil {
		return resultOutput(options.json, options.command, 2, nil,
			fmt.Sprintf("the edited configuration would not load (%v); nothing was written", err))
	}
	if err := uiWriteConfig(path, revision, patched); err != nil {
		return resultOutput(options.json, options.command, 2, nil, err.Error())
	}
	listing, lines := egressListing(path, config)
	listing["saved"] = true
	message := append(append([]string{}, preface...), "Saved "+path+". "+egressRestartNote)
	return resultOutput(options.json, options.command, 0, listing, strings.Join(append(message, lines...), "\n"))
}

// egressAddressProblem says why an address cannot be previewed, or "" when it can.
func egressAddressProblem(address string) string {
	valid, domain := client.ValidEgressAddress(address)
	switch {
	case valid:
		return ""
	case domain:
		return "ADDRESS is a domain name; rules match IPv4 addresses only for now. Give the address it resolves to."
	default:
		return "ADDRESS must be an IPv4 address."
	}
}

func egressTest(options cliOptions, path string) int {
	address := strings.TrimSpace(options.egressAddress)
	if problem := egressAddressProblem(address); problem != "" {
		return resultOutput(options.json, options.command, 2, nil, problem)
	}
	_, _, config, failed := loadEgressConfig(options, path)
	if failed >= 0 {
		return failed
	}
	data, lines := egressPreview(path, config, address)
	code := 0
	if options.egressConnect > 0 {
		probe, line := egressConnectProbe(address, options.egressConnect)
		lines = append(lines, line)
		if probe["ok"] != true {
			code = 4
		}
		data["connect"] = probe
	}
	if code != 0 && options.json {
		return resultOutput(true, options.command, code, data, lines[len(lines)-1])
	}
	if code != 0 {
		fmt.Println(strings.Join(lines[:len(lines)-1], "\n"))
		return resultOutput(false, options.command, code, nil, lines[len(lines)-1])
	}
	return resultOutput(options.json, options.command, 0, data, strings.Join(lines, "\n"))
}

// egressConnectProbe connects to address:port once, within five seconds. It shows the address is
// reachable from this device, not which path carried the connection; the preview says that. The
// command and the local page run the same probe and report it the same way.
func egressConnectProbe(address string, port int) (map[string]any, string) {
	target := net.JoinHostPort(address, strconv.Itoa(port))
	started := time.Now()
	connection, err := net.DialTimeout("tcp", target, 5*time.Second)
	elapsed := time.Since(started).Milliseconds()
	probe := map[string]any{"port": port, "ok": err == nil, "millis": elapsed}
	if err != nil {
		probe["error"] = err.Error()
		return probe, fmt.Sprintf("Connection test to %s: failed (%v)", target, err)
	}
	connection.Close()
	return probe, fmt.Sprintf("Connection test to %s: connected in %d ms. This shows the address is reachable, not which path carried it.", target, elapsed)
}

// egressPreview is what the configured rules decide for one IPv4 address, and what takeover being
// on would change. No connection is made.
func egressPreview(path string, config client.Config, address string) (map[string]any, []string) {
	preview := client.PreviewEgressDestination(config.PeerEgressRules, address)
	data := map[string]any{
		"configPath": path, "address": address, "takeover": config.PeerEgressEnabled,
		"matchedRuleIndex": preview.MatchedRuleIndex,
	}
	lines := []string{"Preview for " + address + " from the configuration (no connection is made; --connect PORT tests one)"}
	if config.PeerEgressEnabled {
		lines = append(lines, "  takeover: on")
	} else {
		lines = append(lines, "  takeover: off")
	}
	would := "stays local (direct)"
	result := "direct"
	if preview.MatchedRuleIndex < 0 {
		lines = append(lines, "  rule: none")
		would = "not covered by any rule; stays local (direct)"
	} else {
		rule := config.PeerEgressRules[preview.MatchedRuleIndex]
		line := fmt.Sprintf("  rule: [%d] %s %s", preview.MatchedRuleIndex, strings.TrimSpace(rule.Match), preview.Action)
		if preview.EgressClientID != 0 {
			line += " " + strconv.FormatInt(preview.EgressClientID, 10)
		}
		lines = append(lines, line)
		data["ruleAction"] = preview.Action
		switch preview.Action {
		case "egress":
			would = "through egress " + strconv.FormatInt(preview.EgressClientID, 10)
			result = "egress"
			data["egressClientId"] = preview.EgressClientID
		case "block":
			would = "blocked"
			result = "block"
		}
	}
	if config.PeerEgressEnabled || preview.MatchedRuleIndex < 0 {
		lines = append(lines, "  result: "+would)
		data["result"] = result
	} else {
		lines = append(lines, "  result: takeover is off, so it stays local (direct); with takeover on: "+would)
		data["result"] = "direct"
		data["resultWithTakeover"] = result
	}
	return data, lines
}

// encodeEgressRules writes the rule list the same way in every runtime: one rule per line, fields in
// a fixed order, only what the rule carries. Strings escape only what JSON requires, so a file one
// runtime wrote reads the same when another rewrites it.
func encodeEgressRules(rules []client.EgressRule) []byte {
	if len(rules) == 0 {
		return []byte("[]")
	}
	var b strings.Builder
	b.WriteString("[\n")
	for index, rule := range rules {
		b.WriteString(`    {"match": `)
		b.WriteString(jsonString(strings.TrimSpace(rule.Match)))
		b.WriteString(`, "action": `)
		b.WriteString(jsonString(strings.TrimSpace(rule.Action)))
		if rule.EgressClientID != 0 {
			b.WriteString(`, "egressClientId": ` + strconv.FormatInt(rule.EgressClientID, 10))
		}
		if rule.Port != 0 {
			b.WriteString(`, "port": ` + strconv.Itoa(rule.Port))
		}
		if client.EgressRuleSwitchedOff(rule) {
			b.WriteString(`, "enabled": false`)
		}
		b.WriteString("}")
		if index < len(rules)-1 {
			b.WriteString(",")
		}
		b.WriteString("\n")
	}
	b.WriteString("  ]")
	return []byte(b.String())
}

func jsonString(value string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range value {
		switch {
		case r == '"':
			b.WriteString(`\"`)
		case r == '\\':
			b.WriteString(`\\`)
		case r < 0x20:
			fmt.Fprintf(&b, `\u%04x`, r)
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
	return b.String()
}

var errEgressEditUnsupported = errors.New("请求包含不支持编辑的字段")

// uiPatchRawConfig replaces or adds top-level values the egress commands own, with the encoded JSON
// given. Only the egress switches and rules; everything else goes through uiPatchConfig's checks.
func uiPatchRawConfig(data []byte, values map[string][]byte) ([]byte, error) {
	spans, err := uiConfigSpans(data)
	if err != nil {
		return nil, err
	}
	for key := range values {
		if key != "peerEgressRules" && key != "peerEgressEnabled" && key != "peerEgressDnsTakeover" {
			return nil, errEgressEditUnsupported
		}
		// A differently cased duplicate would leave two readings of the same switch.
		for existing := range spans {
			if strings.EqualFold(existing, key) && existing != key {
				return nil, errors.New("无法安全编辑此 JSONC：请检查语法、重复字段或使用外部编辑器修正")
			}
		}
	}
	// What is written follows the file's line breaks, so a CRLF file stays CRLF. The values carry no
	// raw line break inside a string, since control characters are escaped.
	newline := "\n"
	if strings.Contains(string(data), "\r\n") {
		newline = "\r\n"
	}
	out := append([]byte(nil), data...)
	type edit struct {
		span  uiSpan
		value []byte
	}
	var edits []edit
	var additions []string
	for _, key := range []string{"peerEgressEnabled", "peerEgressDnsTakeover", "peerEgressRules"} {
		value, wanted := values[key]
		if !wanted {
			continue
		}
		value = []byte(strings.ReplaceAll(string(value), "\n", newline))
		if span, ok := spans[key]; ok {
			edits = append(edits, edit{span, value})
		} else {
			additions = append(additions, `"`+key+`": `+string(value))
		}
	}
	for i := 0; i < len(edits); i++ {
		for j := i + 1; j < len(edits); j++ {
			if edits[j].span.start > edits[i].span.start {
				edits[i], edits[j] = edits[j], edits[i]
			}
		}
	}
	for _, e := range edits {
		out = append(append(append([]byte(nil), out[:e.span.start]...), e.value...), out[e.span.end:]...)
	}
	if len(additions) > 0 {
		at := uiObjectStart(out) + 1
		insert := newline + "  " + strings.Join(additions, ","+newline+"  ")
		if len(spans) > 0 {
			insert += ","
		}
		// The brace is usually followed by its own line break already; a second would leave a blank line.
		if at >= len(out) || (out[at] != '\n' && out[at] != '\r') {
			insert += newline
		}
		out = append(append(append([]byte(nil), out[:at]...), []byte(insert)...), out[at:]...)
	}
	return out, nil
}
