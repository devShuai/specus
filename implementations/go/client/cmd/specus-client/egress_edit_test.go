package main

import (
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
