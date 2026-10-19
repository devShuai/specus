package server

import (
	"strconv"
	"testing"
)

// ipv6PacketCapable is whether the egress takes IPv6 packets in SPEG1. It is stored on its own:
// an ipv6TargetCapable declaration must not be read as one, nor the other way round.
func TestClientAuthLoginPersistsEgressIPv6PacketAnnouncement(t *testing.T) {
	app, server := newAPIServer(t)
	const key, secret = "ck_egress_ipv6_packets", "isolated-egress-test-secret"
	insertCredentialForTest(t, app, "tenant-a", "alice", key, secret, 16)
	cases := []struct {
		name        string
		caps        map[string]any
		wantPackets bool
		wantTargets bool
	}{
		{"announced", map[string]any{"version": 1, "egressCapable": true, "ipv6PacketCapable": true}, true, false},
		{"absent flag", map[string]any{"version": 1, "egressCapable": true}, false, false},
		{"false flag", map[string]any{"version": 1, "egressCapable": true, "ipv6PacketCapable": false}, false, false},
		{"zero version", map[string]any{"version": 0, "ipv6PacketCapable": true}, false, false},
		{"negative version", map[string]any{"version": -1, "ipv6PacketCapable": true}, false, false},
		{"future normalized version", map[string]any{"version": 2, "egressCapable": true, "ipv6PacketCapable": true}, true, false},
		{"absent capabilities", nil, false, false},
		{"target flag only", map[string]any{"version": 1, "egressCapable": true, "ipv6TargetCapable": true}, false, true},
		{"both flags", map[string]any{"version": 1, "egressCapable": true, "ipv6TargetCapable": true, "ipv6PacketCapable": true}, true, true},
	}
	for index, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			login := clientAuthLoginWithEnvironmentForTest(t, server.URL, key, secret,
				"ipv6-packet-announcement-"+strconv.Itoa(index), "alice",
				map[string]any{"clientEgressCapabilities": test.caps})
			stored := getClientSessionForTest(t, app, login.ClientSessionID)
			if stored.ClientEgressIPv6Packets != test.wantPackets {
				t.Fatalf("HTTP login lost ipv6PacketCapable: got %v, want %v", stored.ClientEgressIPv6Packets, test.wantPackets)
			}
			if stored.ClientEgressIPv6Targets != test.wantTargets {
				t.Fatalf("ipv6TargetCapable leaked across flags: got %v, want %v", stored.ClientEgressIPv6Targets, test.wantTargets)
			}
		})
	}
}
