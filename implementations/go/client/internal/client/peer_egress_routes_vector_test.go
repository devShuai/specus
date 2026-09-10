package client

import "testing"

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
