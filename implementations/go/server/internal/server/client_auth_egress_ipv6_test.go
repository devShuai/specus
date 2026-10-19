package server

import (
	"encoding/json"
	"strconv"
	"testing"
)

// An IPv6 target is the egress's own AAAA socket, not an IPv6 packet from the
// consumer. Keeping this announcement does not enable the consumer data plane.
func TestClientAuthLoginPersistsEgressIPv6TargetAnnouncement(t *testing.T) {
	app, server := newAPIServer(t)
	const key, secret = "ck_egress_ipv6_targets", "isolated-egress-test-secret"
	insertCredentialForTest(t, app, "tenant-a", "alice", key, secret, 16)
	cases := []struct {
		name string
		caps map[string]any
		want bool
	}{
		{"announced", map[string]any{"version": 1, "egressCapable": true, "ipv6TargetCapable": true}, true},
		{"absent flag", map[string]any{"version": 1, "egressCapable": true}, false},
		{"false flag", map[string]any{"version": 1, "egressCapable": true, "ipv6TargetCapable": false}, false},
		{"zero version", map[string]any{"version": 0, "ipv6TargetCapable": true}, false},
		{"negative version", map[string]any{"version": -1, "ipv6TargetCapable": true}, false},
		{"future normalized version", map[string]any{"version": 2, "egressCapable": true, "ipv6TargetCapable": true}, true},
		{"absent capabilities", nil, false},
	}
	for index, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			login := clientAuthLoginWithEnvironmentForTest(t, server.URL, key, secret,
				"ipv6-announcement-"+strconv.Itoa(index), "alice",
				map[string]any{"clientEgressCapabilities": test.caps})
			stored := getClientSessionForTest(t, app, login.ClientSessionID)
			// A legacy model has no field and therefore observes false. This makes
			// the same behavior regression executable before adding the model field.
			encoded, err := json.Marshal(stored)
			if err != nil {
				t.Fatal(err)
			}
			var fields map[string]any
			if err := json.Unmarshal(encoded, &fields); err != nil {
				t.Fatal(err)
			}
			got, _ := fields["ClientEgressIPv6Targets"].(bool)
			if got != test.want {
				t.Fatalf("HTTP login lost ipv6TargetCapable: got %v, want %v", got, test.want)
			}
		})
	}
}
