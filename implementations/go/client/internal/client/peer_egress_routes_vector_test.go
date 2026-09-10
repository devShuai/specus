package client

import (
	"os"
	"testing"
)

// Binds the route planner to protocol/test-vectors/peer-egress-routes-v1.json.
//
// Three consumer runtimes have to arrive at the same route set: a Java consumer that installed a
// different prefix than the Go one for the same configuration would send different traffic through
// the tunnel while reporting the same rules.
//
// The vector's expectations come from an independent reference planner in
// tools/protocol/generate_peer_egress_route_vectors.py, not from this package, so agreement means
// independent agreement rather than a shared mistake. The behaviours argued case by case live in
// peer_egress_routes_test.go and stay there.

type egressRoutesVector struct {
	MeshCIDR  string `json:"meshCidr"`
	PlanCases []struct {
		Name        string       `json:"name"`
		Description string       `json:"description"`
		Rules       []egressRule `json:"rules"`
		Bypass      []string     `json:"bypass"`
		Expect      struct {
			Routes  []egressRouteVectorEntry `json:"routes"`
			Refused []struct {
				Index int    `json:"index"`
				Match string `json:"match"`
				Code  string `json:"code"`
			} `json:"refused"`
		} `json:"expect"`
	} `json:"planCases"`
	DiffCases []struct {
		Name    string                   `json:"name"`
		Current []egressRouteVectorEntry `json:"current"`
		Desired []egressRouteVectorEntry `json:"desired"`
		Expect  struct {
			Remove []egressRouteVectorEntry `json:"remove"`
			Add    []egressRouteVectorEntry `json:"add"`
		} `json:"expect"`
	} `json:"diffCases"`
	Journal struct {
		Text    string                   `json:"text"`
		Routes  []egressRouteVectorEntry `json:"routes"`
		Rejects []struct {
			Name   string `json:"name"`
			Text   string `json:"text"`
			Reason string `json:"reason"`
		} `json:"rejects"`
	} `json:"journal"`
	RouteCommands struct {
		RouteGet []struct {
			Name   string `json:"name"`
			Output string `json:"output"`
			Expect struct {
				Parsed  bool   `json:"parsed"`
				Gateway string `json:"gateway"`
				Device  string `json:"device"`
			} `json:"expect"`
		} `json:"routeGet"`
		ShowExact []struct {
			Name   string `json:"name"`
			Output string `json:"output"`
			Expect struct {
				Present     bool   `json:"present"`
				Description string `json:"description"`
			} `json:"expect"`
		} `json:"showExact"`
		TunnelDevice struct {
			Cases []struct {
				Device string `json:"device"`
				Tun    string `json:"tun"`
				Expect bool   `json:"expect"`
			} `json:"cases"`
		} `json:"tunnelDevice"`
	} `json:"routeCommands"`
}

// egressRouteVectorEntry is the vector's spelling of a route. Kept separate from egressRoute
// because the kind travels as a name rather than as this package's integer.
type egressRouteVectorEntry struct {
	CIDR   string `json:"cidr"`
	Kind   string `json:"kind"`
	Origin string `json:"origin"`
}

func (entry egressRouteVectorEntry) route(t *testing.T) egressRoute {
	t.Helper()
	switch entry.Kind {
	case "bypass":
		return egressRoute{CIDR: entry.CIDR, Kind: egressRouteBypass, Origin: entry.Origin}
	case "tun":
		return egressRoute{CIDR: entry.CIDR, Kind: egressRouteToTun, Origin: entry.Origin}
	}
	t.Fatalf("vector names an unknown route kind %q", entry.Kind)
	return egressRoute{}
}

// compareEgressRoutes reports the routes as text so a mismatch names the prefix that differs
// rather than only the count.
func compareEgressRoutes(t *testing.T, label string, got []egressRoute, want []egressRouteVectorEntry) {
	t.Helper()
	if len(got) != len(want) {
		t.Errorf("%s: planned %d routes, want %d: got %+v want %+v", label, len(got), len(want), got, want)
		return
	}
	for index, entry := range want {
		expected := entry.route(t)
		if got[index] != expected {
			t.Errorf("%s: route %d = %+v, want %+v", label, index, got[index], expected)
		}
	}
}

func TestEgressRoutePlanMatchesSharedVector(t *testing.T) {
	var vector egressRoutesVector
	readEgressVector(t, "peer-egress-routes-v1.json", &vector)
	if len(vector.PlanCases) == 0 {
		t.Fatal("routes vector carried no plan cases")
	}

	for _, testCase := range vector.PlanCases {
		routes, refused := planEgressRoutes(testCase.Rules, testCase.Bypass, vector.MeshCIDR)
		compareEgressRoutes(t, testCase.Name, routes, testCase.Expect.Routes)

		// The refusals are asserted alongside the routes because a planner that silently
		// dropped a bad rule would produce exactly the same route list.
		if len(refused) != len(testCase.Expect.Refused) {
			t.Errorf("%s: refused %d rules, want %d: %+v", testCase.Name,
				len(refused), len(testCase.Expect.Refused), refused)
			continue
		}
		for index, want := range testCase.Expect.Refused {
			got := refused[index]
			if got.Index != want.Index || got.Match != want.Match || got.Code != want.Code {
				t.Errorf("%s: refusal %d = %+v, want %+v", testCase.Name, index, got, want)
			}
		}
	}
}

func TestEgressRouteDiffMatchesSharedVector(t *testing.T) {
	var vector egressRoutesVector
	readEgressVector(t, "peer-egress-routes-v1.json", &vector)
	if len(vector.DiffCases) == 0 {
		t.Fatal("routes vector carried no diff cases")
	}

	for _, testCase := range vector.DiffCases {
		current := make([]egressRoute, 0, len(testCase.Current))
		for _, entry := range testCase.Current {
			current = append(current, entry.route(t))
		}
		desired := make([]egressRoute, 0, len(testCase.Desired))
		for _, entry := range testCase.Desired {
			desired = append(desired, entry.route(t))
		}

		remove, add := diffEgressRoutes(current, desired)
		compareEgressRoutes(t, testCase.Name+"/remove", remove, testCase.Expect.Remove)
		compareEgressRoutes(t, testCase.Name+"/add", add, testCase.Expect.Add)
	}
}

// The journal's on-disk shape is a contract with the other two consumers.
//
// A user who switches from this client to the Java or .NET one on the same machine has to have
// these routes adopted and withdrawn, not left behind by a reader that did not recognise the file.
// Asserted against the shared text rather than by round-tripping through this package, because a
// round trip agrees with whatever this package happens to write.
func TestEgressRouteJournalMatchesSharedVector(t *testing.T) {
	var vector egressRoutesVector
	readEgressVector(t, "peer-egress-routes-v1.json", &vector)
	if vector.Journal.Text == "" || len(vector.Journal.Routes) == 0 {
		t.Fatal("routes vector carried no journal")
	}

	written := journalPath(t)
	installer := newEgressRouteInstaller(newFakeRouteCommander(), written)
	desired := make([]egressRoute, 0, len(vector.Journal.Routes))
	for _, entry := range vector.Journal.Routes {
		desired = append(desired, entry.route(t))
	}
	if result := installer.apply(desired); result.Err != nil {
		t.Fatalf("apply failed: %v", result.Err)
	}
	raw, err := os.ReadFile(written)
	if err != nil {
		t.Fatalf("read journal: %v", err)
	}
	if string(raw) != vector.Journal.Text {
		t.Errorf("journal written as:\n%s\nwant:\n%s", raw, vector.Journal.Text)
	}

	// And the other direction: the shared text has to be readable, or a journal another runtime
	// wrote would be adopted as nothing and its routes left in the table forever.
	adopted := journalPath(t)
	if err := os.WriteFile(adopted, []byte(vector.Journal.Text), 0o600); err != nil {
		t.Fatal(err)
	}
	reader := newEgressRouteInstaller(newFakeRouteCommander(), adopted)
	if err := reader.load(); err != nil {
		t.Fatalf("load the shared journal: %v", err)
	}
	compareEgressRoutes(t, "journal", reader.installed, vector.Journal.Routes)
}

// Every refusal leaves the installed set empty. Adopting a journal that could not be read would
// mean withdrawing prefixes by guess, and treating it as empty would mean the routes it describes
// are never taken back at all -- so the only safe answer is to fail and say so.
func TestEgressRouteJournalRejectsMatchSharedVector(t *testing.T) {
	var vector egressRoutesVector
	readEgressVector(t, "peer-egress-routes-v1.json", &vector)
	if len(vector.Journal.Rejects) == 0 {
		t.Fatal("routes vector carried no journal rejects")
	}

	for _, reject := range vector.Journal.Rejects {
		path := journalPath(t)
		if err := os.WriteFile(path, []byte(reject.Text), 0o600); err != nil {
			t.Fatal(err)
		}
		installer := newEgressRouteInstaller(newFakeRouteCommander(), path)
		if err := installer.load(); err == nil {
			t.Errorf("%s: the journal was accepted", reject.Name)
		}
		if len(installer.installed) != 0 {
			t.Errorf("%s: routes were adopted from a journal that could not be read", reject.Name)
		}
	}
}

// Reading what the platform's routing tools say.
//
// These parsers depend on output formats nobody controls, which makes them the part most likely to
// be wrong, and each runtime writing its own fixtures from its own reading of the man page is how
// three readings of one format come about. Deliberately not behind a build tag, so they are covered
// on the machines where development and most of CI actually happen.
func TestEgressRouteCommandParsingMatchesSharedVector(t *testing.T) {
	var vector egressRoutesVector
	readEgressVector(t, "peer-egress-routes-v1.json", &vector)
	if len(vector.RouteCommands.RouteGet) == 0 || len(vector.RouteCommands.ShowExact) == 0 {
		t.Fatal("routes vector carried no route command cases")
	}

	for _, testCase := range vector.RouteCommands.RouteGet {
		hop, ok := parseIPRouteGet(testCase.Output)
		if ok != testCase.Expect.Parsed {
			t.Errorf("%s: parsed = %v, want %v", testCase.Name, ok, testCase.Expect.Parsed)
			continue
		}
		if !ok {
			continue
		}
		if hop.Gateway != testCase.Expect.Gateway || hop.Device != testCase.Expect.Device {
			t.Errorf("%s: gateway=%q device=%q, want %q/%q", testCase.Name,
				hop.Gateway, hop.Device, testCase.Expect.Gateway, testCase.Expect.Device)
		}
	}

	for _, testCase := range vector.RouteCommands.ShowExact {
		present, description := parseIPRouteShowExact(testCase.Output)
		if present != testCase.Expect.Present || description != testCase.Expect.Description {
			t.Errorf("%s: present=%v description=%q, want %v/%q", testCase.Name,
				present, description, testCase.Expect.Present, testCase.Expect.Description)
		}
	}

	for _, testCase := range vector.RouteCommands.TunnelDevice.Cases {
		got := egressRouteHopIsDevice(egressRouteHop{Device: testCase.Device}, testCase.Tun)
		if got != testCase.Expect {
			t.Errorf("device %q against tun %q = %v, want %v",
				testCase.Device, testCase.Tun, got, testCase.Expect)
		}
	}
}
