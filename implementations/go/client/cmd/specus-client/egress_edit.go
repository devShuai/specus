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
		status := client.EgressRuleStatusCode(config.PeerEgressEnabled, rule)
		switchedOff := client.EgressRuleSwitchedOff(rule)
		// The rule's own problem, told apart from being off: worth fixing before takeover is on.
		content := client.EgressRuleCode(client.EgressRule{
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

func egressRuleEdit(options cliOptions, path string) int {
	data, revision, config, failed := loadEgressConfig(options, path)
	if failed >= 0 {
		return failed
	}
	rules := append([]client.EgressRule(nil), config.PeerEgressRules...)
	indexOK := func(index int) bool { return index >= 0 && index < len(rules) }
	noRule := func(index int) int {
		return resultOutput(options.json, options.command, 2, nil,
			fmt.Sprintf("No rule at index %d; there are %d rule(s). List them with egress rules.", index, len(rules)))
	}
	switch options.command {
	case "egress rule add":
		rule := client.EgressRule{Match: strings.TrimSpace(options.egressMatch),
			Action: strings.TrimSpace(options.egressAction), EgressClientID: options.egressClientID}
		// Refused rules are allowed in the file, where they are warned about, but a command that
		// adds one on request would only be writing a rule that steers nothing.
		if code := client.EgressRuleCode(rule); code != "" {
			return resultOutput(options.json, options.command, 2, nil,
				fmt.Sprintf("Rule not added: %s (%s)", code, client.EgressCodeExplanation(code)))
		}
		if options.egressDisabled {
			off := false
			rule.Enabled = &off
		}
		at := len(rules)
		if options.egressAt >= 0 {
			if options.egressAt > len(rules) {
				return resultOutput(options.json, options.command, 2, nil,
					fmt.Sprintf("--at %d is past the end; there are %d rule(s).", options.egressAt, len(rules)))
			}
			at = options.egressAt
		}
		rules = append(rules[:at], append([]client.EgressRule{rule}, rules[at:]...)...)
	case "egress rule remove":
		if !indexOK(options.egressIndex) {
			return noRule(options.egressIndex)
		}
		rules = append(rules[:options.egressIndex], rules[options.egressIndex+1:]...)
	case "egress rule move":
		if !indexOK(options.egressIndex) {
			return noRule(options.egressIndex)
		}
		if !indexOK(options.egressTo) {
			return noRule(options.egressTo)
		}
		moved := rules[options.egressIndex]
		rules = append(rules[:options.egressIndex], rules[options.egressIndex+1:]...)
		rules = append(rules[:options.egressTo], append([]client.EgressRule{moved}, rules[options.egressTo:]...)...)
	case "egress rule enable", "egress rule disable":
		if !indexOK(options.egressIndex) {
			return noRule(options.egressIndex)
		}
		if options.command == "egress rule enable" {
			rules[options.egressIndex].Enabled = nil
		} else {
			off := false
			rules[options.egressIndex].Enabled = &off
		}
	}
	return writeEgress(options, path, data, revision, map[string][]byte{"peerEgressRules": encodeEgressRules(rules)}, nil)
}

func egressSwitch(options cliOptions, path string) int {
	data, revision, config, failed := loadEgressConfig(options, path)
	if failed >= 0 {
		return failed
	}
	turningOn := options.command == "egress enable"
	if turningOn == config.PeerEgressEnabled {
		state := "off"
		if turningOn {
			state = "on"
		}
		listing, lines := egressListing(path, config)
		return resultOutput(options.json, options.command, 0, listing,
			"Takeover is already "+state+"; nothing was changed.\n"+strings.Join(lines, "\n"))
	}
	var preface []string
	if turningOn {
		preface = append(preface, egressEnableNotice...)
		// Confirmed by a flag rather than a prompt: whether a prompt could be answered depends on a
		// terminal the three runtimes cannot all detect the same way, and a command that waits in
		// one of them and fails in another is not the same command.
		if !options.egressYes {
			return resultOutput(options.json, options.command, 2, nil, strings.Join(egressEnableNotice, "\n")+
				"\nNot changed. Re-run with --yes to confirm.")
		}
		if strings.TrimSpace(config.PeerMeshDevice) == "" || strings.EqualFold(strings.TrimSpace(config.PeerMeshDevice), "noop") {
			preface = append(preface, "Warning: peerMeshDevice is noop, so there is no interface to route into; set it to auto.")
		}
	}
	value := []byte("false")
	if turningOn {
		value = []byte("true")
	}
	return writeEgress(options, path, data, revision, map[string][]byte{"peerEgressEnabled": value}, preface)
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

func egressTest(options cliOptions, path string) int {
	address := strings.TrimSpace(options.egressAddress)
	if valid, domain := client.ValidEgressAddress(address); !valid {
		message := "ADDRESS must be an IPv4 address."
		if domain {
			message = "ADDRESS is a domain name; rules match IPv4 addresses only for now. Give the address it resolves to."
		}
		return resultOutput(options.json, options.command, 2, nil, message)
	}
	_, _, config, failed := loadEgressConfig(options, path)
	if failed >= 0 {
		return failed
	}
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
	code := 0
	if options.egressConnect > 0 {
		target := net.JoinHostPort(address, strconv.Itoa(options.egressConnect))
		started := time.Now()
		connection, err := net.DialTimeout("tcp", target, 5*time.Second)
		elapsed := time.Since(started).Milliseconds()
		probe := map[string]any{"port": options.egressConnect, "ok": err == nil, "millis": elapsed}
		if err != nil {
			probe["error"] = err.Error()
			lines = append(lines, fmt.Sprintf("Connection test to %s: failed (%v)", target, err))
			code = 4
		} else {
			connection.Close()
			lines = append(lines, fmt.Sprintf("Connection test to %s: connected in %d ms. This shows the address is reachable, not which path carried it.", target, elapsed))
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
// given. Only these two fields; everything else goes through uiPatchConfig's checks.
func uiPatchRawConfig(data []byte, values map[string][]byte) ([]byte, error) {
	spans, err := uiConfigSpans(data)
	if err != nil {
		return nil, err
	}
	for key := range values {
		if key != "peerEgressRules" && key != "peerEgressEnabled" {
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
	for _, key := range []string{"peerEgressEnabled", "peerEgressRules"} {
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
