package client

import "testing"

// These parsers read output formats nobody controls, which makes them the part most likely to be
// wrong. Deliberately not behind a Linux build tag, so they are covered on the machines where
// development and most of CI actually happen.

func TestParseIPRouteGetReadsBothShapes(t *testing.T) {
	cases := []struct {
		name        string
		output      string
		wantGateway string
		wantDevice  string
	}{
		{"through a router",
			"1.2.3.4 via 10.0.0.1 dev eth0 src 10.0.0.5 uid 1000 \n    cache \n",
			"10.0.0.1", "eth0"},
		{"directly attached carries no via",
			"10.0.0.5 dev eth0 src 10.0.0.5 uid 1000 \n    cache \n",
			"", "eth0"},
		{"a named interface with a dash",
			"198.51.100.7 via 192.168.1.1 dev wlp3s0-1 src 192.168.1.44 \n",
			"192.168.1.1", "wlp3s0-1"},
	}
	for _, testCase := range cases {
		hop, ok := parseIPRouteGet(testCase.output)
		if !ok {
			t.Errorf("%s: did not parse", testCase.name)
			continue
		}
		if hop.Gateway != testCase.wantGateway || hop.Device != testCase.wantDevice {
			t.Errorf("%s: gateway=%q device=%q, want %q/%q", testCase.name,
				hop.Gateway, hop.Device, testCase.wantGateway, testCase.wantDevice)
		}
	}
}

// An unreachable destination is reported as a route rather than as an error, so it has to be
// recognised here or a bypass would be installed pointing nowhere.
func TestParseIPRouteGetRefusesNonRoutes(t *testing.T) {
	for _, output := range []string{
		"unreachable 203.0.113.9 dev lo src 127.0.0.1 uid 1000 \n",
		"prohibit 203.0.113.9 dev lo \n",
		"blackhole 203.0.113.9 \n",
		"",
		"   \n\n",
		"RTNETLINK answers: Network is unreachable\n",
	} {
		if _, ok := parseIPRouteGet(output); ok {
			t.Errorf("accepted %q as a usable hop", output)
		}
	}
}

func TestParseIPRouteShowExactDetectsAnExistingRoute(t *testing.T) {
	present, description := parseIPRouteShowExact("192.0.2.0/24 via 10.0.0.1 dev eth0 metric 100 \n")
	if !present {
		t.Fatal("an existing route was not detected")
	}
	// Reported verbatim: a summary of somebody else's routing is less useful to them than the
	// line they can go and look at.
	if description != "192.0.2.0/24 via 10.0.0.1 dev eth0 metric 100" {
		t.Errorf("description = %q", description)
	}

	if present, _ := parseIPRouteShowExact("\n  \n"); present {
		t.Error("empty output was read as an existing route")
	}
}

// On a reapply the address is already covered by a rule's route, so asking the system where to send
// it answers "through the tunnel". Installing that would route the tunnel's transport into itself.
func TestEgressRouteHopIsDeviceMatchesTheTunnel(t *testing.T) {
	if !egressRouteHopIsDevice(egressRouteHop{Device: "specus0"}, "specus0") {
		t.Error("a hop through the tunnel was not recognised")
	}
	if !egressRouteHopIsDevice(egressRouteHop{Device: " specus0 "}, "specus0") {
		t.Error("surrounding whitespace defeated the check")
	}
	if egressRouteHopIsDevice(egressRouteHop{Device: "eth0"}, "specus0") {
		t.Error("an ordinary interface was mistaken for the tunnel")
	}
	if egressRouteHopIsDevice(egressRouteHop{Device: "eth0"}, "") {
		t.Error("an empty tunnel name matched an interface")
	}
}
