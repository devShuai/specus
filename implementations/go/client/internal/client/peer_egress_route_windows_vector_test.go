package client

import "testing"

// Binds the Windows route parsers to protocol/test-vectors/peer-egress-windows-routes-v1.json.
//
// The cases marked sampled in that file are literal output captured from a Windows 11 machine, not
// transcribed from documentation, which is the part worth having: these parsers read a format
// nobody controls, and the failure mode of reading it wrong is installing a route into nothing or
// deciding a prefix is free when it is not.
//
// The expectations come from an independent reference parser in
// tools/protocol/generate_peer_egress_windows_route_vectors.py, so agreement is independent
// agreement rather than three copies of one mistake.

type egressWindowsRoutesVector struct {
	OnLinkNextHop string `json:"onLinkNextHop"`
	RouteFind     []struct {
		Name    string `json:"name"`
		Output  string `json:"output"`
		Sampled bool   `json:"sampled"`
		Expect  struct {
			Parsed         bool   `json:"parsed"`
			Gateway        string `json:"gateway"`
			InterfaceIndex int    `json:"interfaceIndex"`
		} `json:"expect"`
	} `json:"routeFind"`
	RouteShow []struct {
		Name    string `json:"name"`
		Output  string `json:"output"`
		Sampled bool   `json:"sampled"`
		Expect  struct {
			Present     bool   `json:"present"`
			Description string `json:"description"`
		} `json:"expect"`
	} `json:"routeShow"`
	CommandErrors []struct {
		Name    string `json:"name"`
		Output  string `json:"output"`
		Sampled bool   `json:"sampled"`
		Expect  struct {
			Failure string `json:"failure"`
		} `json:"expect"`
	} `json:"commandErrors"`
}

func TestWindowsRouteParsingMatchesSharedVector(t *testing.T) {
	var vector egressWindowsRoutesVector
	readEgressVector(t, "peer-egress-windows-routes-v1.json", &vector)
	if len(vector.RouteFind) == 0 || len(vector.RouteShow) == 0 || len(vector.CommandErrors) == 0 {
		t.Fatal("windows routes vector carried no cases")
	}
	if vector.OnLinkNextHop != windowsOnLinkNextHop {
		t.Errorf("on-link next hop = %q, want %q", windowsOnLinkNextHop, vector.OnLinkNextHop)
	}

	for _, testCase := range vector.RouteFind {
		hop, ok := parseWindowsRouteFind(testCase.Output)
		if ok != testCase.Expect.Parsed {
			t.Errorf("%s: parsed = %v, want %v", testCase.Name, ok, testCase.Expect.Parsed)
			continue
		}
		if !ok {
			continue
		}
		if hop.Gateway != testCase.Expect.Gateway || hop.InterfaceIndex != testCase.Expect.InterfaceIndex {
			t.Errorf("%s: gateway=%q ifIndex=%d, want %q/%d", testCase.Name,
				hop.Gateway, hop.InterfaceIndex,
				testCase.Expect.Gateway, testCase.Expect.InterfaceIndex)
		}
	}

	for _, testCase := range vector.RouteShow {
		present, description := parseWindowsRouteShow(testCase.Output)
		if present != testCase.Expect.Present || description != testCase.Expect.Description {
			t.Errorf("%s: present=%v description=%q, want %v/%q", testCase.Name,
				present, description, testCase.Expect.Present, testCase.Expect.Description)
		}
	}

	for _, testCase := range vector.CommandErrors {
		if got := parseWindowsCommandFailure(testCase.Output); got != testCase.Expect.Failure {
			t.Errorf("%s: failure = %q, want %q", testCase.Name, got, testCase.Expect.Failure)
		}
	}
}

// The sampled cases are the reason this vector is worth more than a set of invented strings, so
// losing them should fail rather than quietly leave a file of guesses behind.
func TestWindowsRouteVectorKeepsItsSampledCases(t *testing.T) {
	var vector egressWindowsRoutesVector
	readEgressVector(t, "peer-egress-windows-routes-v1.json", &vector)

	sampled := 0
	for _, testCase := range vector.RouteFind {
		if testCase.Sampled {
			sampled++
		}
	}
	for _, testCase := range vector.RouteShow {
		if testCase.Sampled {
			sampled++
		}
	}
	for _, testCase := range vector.CommandErrors {
		if testCase.Sampled {
			sampled++
		}
	}
	if sampled < 9 {
		t.Errorf("vector carries %d sampled cases, want at least 9", sampled)
	}
}
