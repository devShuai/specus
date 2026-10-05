package main

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/devShuai/specus/implementations/go/client/internal/client"
)

func TestEgressPatchInsertsReplacesAndKeepsTheRest(t *testing.T) {
	cases := []struct {
		name, input, want string
		values            map[string][]byte
	}{
		{
			name:   "inserted at the top of a file",
			input:  "{\n  // kept\n  \"apiKey\": \"k\"\n}\n",
			values: map[string][]byte{"peerEgressEnabled": []byte("true")},
			want:   "{\n  \"peerEgressEnabled\": true,\n  // kept\n  \"apiKey\": \"k\"\n}\n",
		},
		{
			name:   "an empty object gains its first field",
			input:  "{}",
			values: map[string][]byte{"peerEgressEnabled": []byte("false")},
			want:   "{\n  \"peerEgressEnabled\": false\n}",
		},
		{
			name:   "replaced in place, comment after it kept",
			input:  "{\n  \"peerEgressEnabled\": false, // why\n  \"apiKey\": \"k\"\n}\n",
			values: map[string][]byte{"peerEgressEnabled": []byte("true")},
			want:   "{\n  \"peerEgressEnabled\": true, // why\n  \"apiKey\": \"k\"\n}\n",
		},
		{
			name:   "a CRLF file stays CRLF",
			input:  "{\r\n  \"apiKey\": \"k\"\r\n}\r\n",
			values: map[string][]byte{"peerEgressRules": []byte("[\n    {\"match\": \"10.0.0.0/8\", \"action\": \"direct\"}\n  ]")},
			want:   "{\r\n  \"peerEgressRules\": [\r\n    {\"match\": \"10.0.0.0/8\", \"action\": \"direct\"}\r\n  ],\r\n  \"apiKey\": \"k\"\r\n}\r\n",
		},
	}
	for _, c := range cases {
		got, err := uiPatchRawConfig([]byte(c.input), c.values)
		if err != nil || string(got) != c.want {
			t.Errorf("%s: got %q (%v), want %q", c.name, got, err, c.want)
		}
	}
}

func TestEgressPatchRefusesWhatItDoesNotOwn(t *testing.T) {
	if _, err := uiPatchRawConfig([]byte(`{"apiKey": "k"}`), map[string][]byte{"apiKey": []byte(`"x"`)}); err == nil {
		t.Error("a field outside the egress pair was edited")
	}
	// Two spellings of the switch would leave two readings of it.
	if _, err := uiPatchRawConfig([]byte(`{"PeerEgressEnabled": true}`), map[string][]byte{"peerEgressEnabled": []byte("false")}); err == nil {
		t.Error("a differently cased duplicate was accepted")
	}
}

func TestEgressRulesAreEncodedOnePerLine(t *testing.T) {
	off := false
	got := string(encodeEgressRules([]client.EgressRule{
		{Match: " 203.0.113.0/24 ", Action: "egress", EgressClientID: 42},
		{Match: `a"b\c`, Action: "block", Enabled: &off},
	}))
	want := "[\n    {\"match\": \"203.0.113.0/24\", \"action\": \"egress\", \"egressClientId\": 42},\n" +
		"    {\"match\": \"a\\\"b\\\\c\", \"action\": \"block\", \"enabled\": false}\n  ]"
	if got != want {
		t.Errorf("got %q\nwant %q", got, want)
	}
	if string(encodeEgressRules(nil)) != "[]" {
		t.Error("an empty list should be []")
	}
}

// With phase two asked for, a domain rule is judged as a name: listed in force and accepted by add.
// Without it the listing and add refuse it exactly as before.
func TestEgressDomainRulesFollowTheDNSTakeoverSwitch(t *testing.T) {
	rule := client.EgressRule{Match: "*.example.com", Action: "egress", EgressClientID: 2}
	for _, takeover := range []bool{false, true} {
		config := client.Config{PeerEgressEnabled: true, PeerEgressDNSTakeover: takeover,
			PeerEgressRules: []client.EgressRule{rule}}
		listing, _ := egressListing("client.jsonc", config)
		views, _ := listing["rules"].([]map[string]any)
		if len(views) != 1 || views[0]["inForce"] != takeover {
			t.Errorf("takeover=%v: listed %v", takeover, views)
		}
		_, failure := egressPlan(config, egressChange{Op: "add", Match: "www.example.org", Action: "block", At: -1})
		if (failure == "") != takeover {
			t.Errorf("takeover=%v: adding a domain rule answered %q", takeover, failure)
		}
	}
}

func TestEgressFlagsBelongToTheirCommands(t *testing.T) {
	cases := map[string]string{
		"egress rules --index 1 --config c.jsonc":               "--index is not valid for egress rules",
		"egress rule add --match 10.0.0.0/8 --config c.jsonc":   "requires --match and --action",
		"egress rule remove --config c.jsonc":                   "requires --index INDEX",
		"egress rule move --index 1 --config c.jsonc":           "requires --index INDEX and --to INDEX",
		"egress test 10.0.0.1 --connect 70000 --config c.jsonc": "--connect requires a port",
		"egress test --config c.jsonc":                          "expected: egress test ADDRESS",
		"egress rule rename --config c.jsonc":                   "expected: egress rule add|remove|move|enable|disable",
		"egress bogus --config c.jsonc":                         "unknown egress command",
		"status --yes --config c.jsonc":                         "--yes is not valid for status",
	}
	for args, want := range cases {
		if _, err := parseCLI(strings.Fields(args)); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: error %v, want it to mention %q", args, err, want)
		}
	}
	options, err := parseCLI(strings.Fields("egress test 10.0.0.1 --connect 443 --config c.jsonc"))
	if err != nil || options.command != "egress test" || options.egressAddress != "10.0.0.1" || options.egressConnect != 443 {
		t.Errorf("egress test parsed as %+v (%v)", options, err)
	}
	if options, err := parseCLI(strings.Fields("egress --config c.jsonc")); err != nil || options.command != "egress" {
		t.Errorf("the plain egress command parsed as %q (%v)", options.command, err)
	}
}

const (
	egressNameUnusableText = "ADDRESS is not a name a domain rule can match: use labels of a-z, 0-9 and -, " +
		"with punycode (xn--) for international names."
	egressNotAnAddressText = "ADDRESS must be an IPv4 address."
)

// egress test reads ADDRESS as an IPv4 address or as a name a domain rule could match, written and
// compared the way rules are; anything else is refused in the words the other runtimes use.
func TestEgressTargetReadsAnAddressOrAName(t *testing.T) {
	cases := []struct{ input, kind, target, problem string }{
		{"203.0.113.9", "address", "203.0.113.9", ""},
		{"Example.COM.", "domain", "example.com", ""},
		{"xn--bcher-kva.example", "domain", "xn--bcher-kva.example", ""},
		{"a-b.c1.example", "domain", "a-b.c1.example", ""},
		{"bad_name.example", "", "", egressNameUnusableText},
		{"bücher.example", "", "", egressNameUnusableText},
		// The Kelvin sign lower-cases to an ASCII k, which must not make it a name.
		{"Kelvin.example", "", "", egressNameUnusableText},
		// A wildcard is a rule's, not a name's.
		{"*.example.com", "", "", egressNameUnusableText},
		{"localhost", "", "", egressNameUnusableText},
		{"-bad.example", "", "", egressNameUnusableText},
		{"10.0.0.0/8", "", "", egressNotAnAddressText},
		{"256.1.1.1", "", "", egressNotAnAddressText},
		{"2001:db8::1", "", "", egressNotAnAddressText},
		{"example.com:443", "", "", egressNotAnAddressText},
	}
	for _, c := range cases {
		kind, target, problem := egressTarget(c.input)
		if kind != c.kind || target != c.target || problem != c.problem {
			t.Errorf("%q: read as (%q, %q, %q), want (%q, %q, %q)", c.input, kind, target, problem, c.kind, c.target, c.problem)
		}
	}
}

// The five lines and the JSON of a name's preview (protocol/spec/peer-egress-dns.md, 预演一个域名),
// for each action a rule can have and each reason domain rules can be out of force.
func TestEgressNamePreviewFollowsTheSpec(t *testing.T) {
	egress := client.EgressRule{Match: "example.com", Action: "egress", EgressClientID: 42}
	block := client.EgressRule{Match: "example.com", Action: "block"}
	direct := client.EgressRule{Match: "example.com", Action: "direct"}
	off := false
	switchedOff := client.EgressRule{Match: "example.com", Action: "egress", EgressClientID: 42, Enabled: &off}
	const (
		badPool      = "198.18.0.0/28"
		viaEgress    = "through egress 42, which resolves the name itself"
		local        = "  result: resolved by the system's DNS; egress test <that address> previews where it goes"
		notTakenOver = "  dns: not taken over (peerEgressDnsTakeover is off), so the name is resolved by the system's DNS"
		poolUnusable = "  dns: not taken over (peerEgressFakeIpCidr is not usable), so the name is resolved by the system's DNS"
		forwarded    = "  dns: forwarded to the system's DNS; the address it returns is then decided by the IPv4 rules"
		fakeEgress   = "  dns: answered with a fake IP from 198.18.0.0/15; the egress resolves the name"
		fakeBlock    = "  dns: answered with a fake IP from 198.18.0.0/15"
		notInForce   = "  result: domain rules are not in force ("
	)
	cases := []struct {
		name                 string
		enabled, dnsTakeover bool
		pool                 string
		rules                []client.EgressRule
		lines                []string // from the rule line on
		dns, result, with    string
		index                int
	}{
		{"no rule, DNS takeover off", true, false, "", nil,
			[]string{"  rule: none", notTakenOver, local}, "local", "direct", "", -1},
		{"egress rule in force", true, true, "", []client.EgressRule{egress},
			[]string{"  rule: [0] example.com egress 42", fakeEgress, "  result: " + viaEgress}, "fake", "egress", "", 0},
		{"block rule in force", true, true, "", []client.EgressRule{block},
			[]string{"  rule: [0] example.com block", fakeBlock, "  result: blocked"}, "fake", "block", "", 0},
		{"direct rule", true, true, "", []client.EgressRule{direct},
			[]string{"  rule: [0] example.com direct", forwarded, local}, "forward", "direct", "", 0},
		{"no rule, phase two running", true, true, "", nil,
			[]string{"  rule: none", forwarded, local}, "forward", "direct", "", -1},
		{"takeover off", false, true, "", []client.EgressRule{egress},
			[]string{"  rule: [0] example.com egress 42", fakeEgress, notInForce + "takeover is off); with them on: " + viaEgress},
			"fake", "direct", "egress", 0},
		{"DNS takeover off", true, false, "", []client.EgressRule{egress},
			[]string{"  rule: [0] example.com egress 42", notTakenOver, notInForce + "dns takeover is off); with them on: " + viaEgress},
			"local", "direct", "egress", 0},
		{"pool unusable", true, true, badPool, []client.EgressRule{block},
			[]string{"  rule: [0] example.com block", poolUnusable, notInForce + "peerEgressFakeIpCidr is not usable); with them on: blocked"},
			"local", "direct", "block", 0},
		{"takeover off is named before DNS takeover", false, false, badPool, []client.EgressRule{block},
			[]string{"  rule: [0] example.com block", notTakenOver, notInForce + "takeover is off); with them on: blocked"},
			"local", "direct", "block", 0},
		{"takeover off is named before the pool", false, true, badPool, []client.EgressRule{egress},
			[]string{"  rule: [0] example.com egress 42", poolUnusable, notInForce + "takeover is off); with them on: " + viaEgress},
			"local", "direct", "egress", 0},
		{"DNS takeover off is named before the pool", true, false, badPool, []client.EgressRule{egress},
			[]string{"  rule: [0] example.com egress 42", notTakenOver, notInForce + "dns takeover is off); with them on: " + viaEgress},
			"local", "direct", "egress", 0},
		{"a direct rule is never out of force", false, false, "", []client.EgressRule{direct},
			[]string{"  rule: [0] example.com direct", notTakenOver, local}, "local", "direct", "", 0},
		{"the pool named is the one configured", true, true, "10.200.0.0/16", []client.EgressRule{egress},
			[]string{"  rule: [0] example.com egress 42", "  dns: answered with a fake IP from 10.200.0.0/16; the egress resolves the name",
				"  result: " + viaEgress}, "fake", "egress", "", 0},
		{"a switched-off rule claims nothing", true, true, "", []client.EgressRule{switchedOff},
			[]string{"  rule: none", forwarded, local}, "forward", "direct", "", -1},
	}
	for _, c := range cases {
		config := client.Config{PeerEgressEnabled: c.enabled, PeerEgressDNSTakeover: c.dnsTakeover,
			PeerEgressFakeIPCIDR: c.pool, PeerEgressRules: c.rules}
		data, lines := egressPreview("c.jsonc", config, egressTargetDomain, "example.com")
		want := append([]string{"Preview for example.com from the configuration (no connection is made)",
			"  takeover: " + egressOnOff(c.enabled) + " | dns takeover: " + egressOnOff(c.dnsTakeover)}, c.lines...)
		if !reflect.DeepEqual(lines, want) {
			t.Errorf("%s: lines\n%q\nwant\n%q", c.name, lines, want)
		}
		wantData := map[string]any{"configPath": "c.jsonc", "address": "example.com", "kind": "domain",
			"takeover": c.enabled, "dnsTakeover": c.dnsTakeover, "matchedRuleIndex": c.index, "dns": c.dns, "result": c.result}
		if c.index >= 0 {
			wantData["ruleAction"] = c.rules[c.index].Action
			if c.rules[c.index].Action == "egress" {
				wantData["egressClientId"] = int64(42)
			}
		}
		if c.with != "" {
			wantData["resultWithTakeover"] = c.with
		}
		if !reflect.DeepEqual(data, wantData) {
			t.Errorf("%s: data\n%v\nwant\n%v", c.name, data, wantData)
		}
	}
}

// A name is claimed by the rule the DNS responder would pick: exact before suffix, the longer suffix,
// then the earlier rule, and only rules in force. Address rules take no part.
func TestEgressNamePreviewPicksTheRuleTheResponderWould(t *testing.T) {
	rule := func(match, action string) client.EgressRule {
		return client.EgressRule{Match: match, Action: action, EgressClientID: 42}
	}
	cases := []struct {
		name  string
		rules []client.EgressRule
		index int
	}{
		{"www.example.com", []client.EgressRule{rule("*.example.com", "egress"), rule("www.example.com", "block")}, 1},
		{"a.www.example.com", []client.EgressRule{rule("*.example.com", "egress"), rule("www.example.com", "block")}, 0},
		{"example.com", []client.EgressRule{rule("*.example.com", "egress")}, -1},
		{"a.b.example.com", []client.EgressRule{rule("*.example.com", "egress"), rule("*.b.example.com", "block")}, 1},
		{"example.com", []client.EgressRule{rule("example.com", "block"), rule("example.com", "egress")}, 0},
		{"example.com", []client.EgressRule{rule("203.0.113.0/24", "egress"), rule("Example.COM.", "direct")}, 1},
		{"example.com", []client.EgressRule{{Match: "example.com", Action: "egress"}}, -1},
	}
	for _, c := range cases {
		// Picked with phase two off as well: the preview says what turning it on would change.
		for _, dnsTakeover := range []bool{false, true} {
			config := client.Config{PeerEgressEnabled: true, PeerEgressDNSTakeover: dnsTakeover, PeerEgressRules: c.rules}
			data, _ := egressPreview("c.jsonc", config, egressTargetDomain, c.name)
			if data["matchedRuleIndex"] != c.index {
				t.Errorf("%s in %v (dns takeover %v): rule %v, want %d", c.name, c.rules, dnsTakeover, data["matchedRuleIndex"], c.index)
			}
		}
	}
}

// An IPv4 address previews as before, now saying which kind of destination it was.
func TestEgressAddressPreviewSaysItIsAnAddress(t *testing.T) {
	config := client.Config{PeerEgressEnabled: true, PeerEgressDNSTakeover: true,
		PeerEgressRules: []client.EgressRule{{Match: "203.0.113.0/24", Action: "egress", EgressClientID: 42}}}
	data, lines := egressPreview("c.jsonc", config, egressTargetAddress, "203.0.113.9")
	want := []string{"Preview for 203.0.113.9 from the configuration (no connection is made; --connect PORT tests one)",
		"  takeover: on", "  rule: [0] 203.0.113.0/24 egress 42", "  result: through egress 42"}
	if !reflect.DeepEqual(lines, want) || data["kind"] != "address" || data["result"] != "egress" {
		t.Errorf("lines %q data %v", lines, data)
	}
	if _, present := data["dnsTakeover"]; present {
		t.Errorf("an address preview gained dnsTakeover: %v", data)
	}
}

const egressNameTestConfig = "{\r\n  \"serverBaseUrl\": \"http://127.0.0.1:1\",\r\n  \"apiKey\": \"k\",\r\n  \"secret\": \"s\",\r\n" +
	"  \"peerEgressDnsTakeover\": true,\r\n" +
	"  \"peerEgressRules\": [{\"match\": \"example.com\", \"action\": \"egress\", \"egressClientId\": 42}]\r\n}\r\n"

// The command prints the five lines and returns the JSON for a name, and refuses an unusable name and
// --connect with a name before it reads the configuration.
func TestEgressTestPreviewsANameAndRefusesWhatItCannot(t *testing.T) {
	path := filepath.Join(t.TempDir(), "client.jsonc")
	if err := os.WriteFile(path, []byte(egressNameTestConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	code, stdout, stderr := runCapturedText(t, "egress", "test", "Example.COM.", "--config", path)
	want := "Preview for example.com from the configuration (no connection is made)\n" +
		"  takeover: off | dns takeover: on\n" +
		"  rule: [0] example.com egress 42\n" +
		"  dns: answered with a fake IP from 198.18.0.0/15; the egress resolves the name\n" +
		"  result: domain rules are not in force (takeover is off); with them on: through egress 42, which resolves the name itself\n"
	if code != 0 || stdout != want || stderr != "" {
		t.Fatalf("text: code %d\nstdout %q\nwant   %q\nstderr %q", code, stdout, want, stderr)
	}

	code, document := runCaptured(t, "egress", "test", "example.com", "--config", path)
	data, _ := document["data"].(map[string]any)
	wantData := map[string]any{"configPath": path, "address": "example.com", "kind": "domain", "takeover": false,
		"dnsTakeover": true, "matchedRuleIndex": float64(0), "ruleAction": "egress", "egressClientId": float64(42),
		"dns": "fake", "result": "direct", "resultWithTakeover": "egress"}
	if code != 0 || !reflect.DeepEqual(data, wantData) {
		t.Fatalf("json: code %d data %v\nwant %v", code, data, wantData)
	}
	code, document = runCaptured(t, "egress", "test", "203.0.113.9", "--config", path)
	if data, _ := document["data"].(map[string]any); code != 0 || data["kind"] != "address" {
		t.Fatalf("an address: code %d %v", code, document)
	}

	missing := filepath.Join(t.TempDir(), "missing.jsonc")
	refusals := []struct {
		args []string
		want string
	}{
		{[]string{"bad_name.example"}, egressNameUnusableText},
		{[]string{"bücher.example"}, egressNameUnusableText},
		{[]string{"*.example.com"}, egressNameUnusableText},
		{[]string{"10.0.0.0/8"}, egressNotAnAddressText},
		{[]string{"example.com", "--connect", "443"}, "--connect needs an IPv4 address: a name would be resolved here, not by the egress."},
	}
	for _, r := range refusals {
		args := append(append([]string{"egress", "test"}, r.args...), "--config", missing)
		code, stdout, stderr := runCapturedText(t, args...)
		if code != 2 || stdout != "" || stderr != r.want+"\n" {
			t.Errorf("%v: code %d stdout %q stderr %q", r.args, code, stdout, stderr)
		}
		code, document := runCaptured(t, args...)
		if code != 2 || document["error"] != r.want || document["data"] != nil {
			t.Errorf("%v --json: code %d %v", r.args, code, document)
		}
	}
}
