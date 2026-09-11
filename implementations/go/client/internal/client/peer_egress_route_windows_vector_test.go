package client

import (
	"strings"
	"testing"
)

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
	Scripts struct {
		ShowRoutes []struct {
			Name     string   `json:"name"`
			Prefixes []string `json:"prefixes"`
			Expect   string   `json:"expect"`
		} `json:"showRoutes"`
		FindRoutes []struct {
			Name      string   `json:"name"`
			Addresses []string `json:"addresses"`
			Expect    string   `json:"expect"`
		} `json:"findRoutes"`
		InstallRoute []struct {
			Name           string `json:"name"`
			CIDR           string `json:"cidr"`
			InterfaceIndex int    `json:"interfaceIndex"`
			Gateway        string `json:"gateway"`
			Expect         string `json:"expect"`
		} `json:"installRoute"`
		RemoveRoute []struct {
			Name   string `json:"name"`
			CIDR   string `json:"cidr"`
			Expect string `json:"expect"`
		} `json:"removeRoute"`
		RejectedArguments []struct {
			Name  string `json:"name"`
			Value string `json:"value"`
			Kind  string `json:"kind"`
		} `json:"rejectedArguments"`
		InterfaceIndex []struct {
			Name    string `json:"name"`
			Adapter string `json:"adapter"`
			Expect  string `json:"expect"`
		} `json:"interfaceIndex"`
		ShowAllRoutes string `json:"showAllRoutes"`
	} `json:"scripts"`
	InterfaceIndexParse []struct {
		Name    string `json:"name"`
		Output  string `json:"output"`
		Sampled bool   `json:"sampled"`
		Expect  struct {
			Found          bool `json:"found"`
			InterfaceIndex int  `json:"interfaceIndex"`
		} `json:"expect"`
	} `json:"interfaceIndexParse"`
	OutputEncoding struct {
		ConsoleCodePage int `json:"consoleCodePage"`
	} `json:"outputEncoding"`
	ConflictFromTable struct {
		Table string `json:"table"`
		Cases []struct {
			Name   string `json:"name"`
			Prefix string `json:"prefix"`
			Expect struct {
				Present     bool   `json:"present"`
				Description string `json:"description"`
			} `json:"expect"`
		} `json:"cases"`
	} `json:"conflictFromTable"`
}

// The conflict check answers out of one read of the whole table rather than a process per prefix.
// The reading that matters is that the prefix is compared exactly: under a default route, asking
// whether an address can be routed is always yes, and taking that for a conflict would refuse every
// rule on any machine that has one.
func TestWindowsConflictFromTableMatchesSharedVector(t *testing.T) {
	var vector egressWindowsRoutesVector
	readEgressVector(t, "peer-egress-windows-routes-v1.json", &vector)
	table := vector.ConflictFromTable.Table
	if table == "" || len(vector.ConflictFromTable.Cases) == 0 {
		t.Fatal("windows routes vector carried no table cases")
	}

	for _, testCase := range vector.ConflictFromTable.Cases {
		present, description := windowsConflictFromTable(table, testCase.Prefix)
		if present != testCase.Expect.Present || description != testCase.Expect.Description {
			t.Errorf("%s: present=%v description=%q, want %v/%q", testCase.Name,
				present, description, testCase.Expect.Present, testCase.Expect.Description)
		}
	}

	// The sampled table is the point of this section, and it has to stay readable whatever the
	// console code page is, which is only true while the query selects no name.
	for index := 0; index < len(table); index++ {
		if table[index] > 0x7F {
			t.Fatalf("sampled table carries a non-ASCII byte at %d", index)
		}
	}
}

// The adapter name is the one argument that cannot be whitelisted -- it comes from configuration
// and may legitimately hold spaces and non-ASCII characters -- so it is the one place the escape is
// load-bearing rather than unreachable.
func TestWindowsInterfaceLookupMatchesSharedVector(t *testing.T) {
	var vector egressWindowsRoutesVector
	readEgressVector(t, "peer-egress-windows-routes-v1.json", &vector)
	if len(vector.Scripts.InterfaceIndex) == 0 || len(vector.InterfaceIndexParse) == 0 {
		t.Fatal("windows routes vector carried no interface cases")
	}

	for _, testCase := range vector.Scripts.InterfaceIndex {
		if got := windowsInterfaceIndexScript(testCase.Adapter); got != testCase.Expect {
			t.Errorf("%s: script mismatch\n got %q\nwant %q", testCase.Name, got, testCase.Expect)
		}
	}
	if got := windowsShowAllRoutesScript(); got != vector.Scripts.ShowAllRoutes {
		t.Errorf("show-all script mismatch\n got %q\nwant %q", got, vector.Scripts.ShowAllRoutes)
	}

	for _, testCase := range vector.InterfaceIndexParse {
		index, ok := parseWindowsInterfaceIndex(testCase.Output)
		if ok != testCase.Expect.Found {
			t.Errorf("%s: found = %v, want %v", testCase.Name, ok, testCase.Expect.Found)
			continue
		}
		if ok && index != testCase.Expect.InterfaceIndex {
			t.Errorf("%s: index = %d, want %d", testCase.Name, index, testCase.Expect.InterfaceIndex)
		}
	}

	// Nothing a script selects may be anything but ASCII. The child process writes stdout in the
	// console code page, and in GBK the low byte of a character can be a backslash: a name echoed
	// back into the JSON can break the document.
	for _, testCase := range vector.Scripts.InterfaceIndex {
		if !strings.HasSuffix(testCase.Expect, "Select-Object InterfaceIndex)") {
			t.Errorf("%s: script selects more than the index", testCase.Name)
		}
	}
	if vector.OutputEncoding.ConsoleCodePage == 0 {
		t.Error("vector lost the sampled console code page")
	}
}

// The scripts are asserted as text, not only by what comes back from running them. Three runtimes
// each embedding their own PowerShell string is how two of them end up writing to a different
// policy store than the third, with nothing in the parsed output to show it.
func TestWindowsRouteScriptsMatchSharedVector(t *testing.T) {
	var vector egressWindowsRoutesVector
	readEgressVector(t, "peer-egress-windows-routes-v1.json", &vector)
	scripts := vector.Scripts
	if len(scripts.ShowRoutes) == 0 || len(scripts.InstallRoute) == 0 {
		t.Fatal("windows routes vector carried no script cases")
	}

	for _, testCase := range scripts.ShowRoutes {
		got, err := windowsShowRoutesScript(testCase.Prefixes)
		compareWindowsScript(t, testCase.Name, got, err, testCase.Expect)
	}
	for _, testCase := range scripts.FindRoutes {
		got, err := windowsFindRoutesScript(testCase.Addresses)
		compareWindowsScript(t, testCase.Name, got, err, testCase.Expect)
	}
	for _, testCase := range scripts.InstallRoute {
		got, err := windowsInstallRouteScript(testCase.CIDR, testCase.InterfaceIndex, testCase.Gateway)
		compareWindowsScript(t, testCase.Name, got, err, testCase.Expect)
	}
	for _, testCase := range scripts.RemoveRoute {
		got, err := windowsRemoveRouteScript(testCase.CIDR)
		compareWindowsScript(t, testCase.Name, got, err, testCase.Expect)
	}

	// The arguments that must never reach a script. They arrive inside one command string rather
	// than as argv entries, so a quote in a prefix is a second command.
	for _, testCase := range scripts.RejectedArguments {
		var err error
		switch testCase.Kind {
		case "prefix":
			_, err = windowsShowRoutesScript([]string{testCase.Value})
		case "address":
			_, err = windowsFindRoutesScript([]string{testCase.Value})
		default:
			t.Errorf("%s: unknown argument kind %q", testCase.Name, testCase.Kind)
			continue
		}
		if err == nil {
			t.Errorf("%s: %q was accepted into a script", testCase.Name, testCase.Value)
		}
	}
}

func compareWindowsScript(t *testing.T, name, got string, err error, want string) {
	t.Helper()
	if err != nil {
		t.Errorf("%s: %v", name, err)
		return
	}
	if got != want {
		t.Errorf("%s: script mismatch\n got %q\nwant %q", name, got, want)
	}
}

// A batched query writes one line per input, including an empty result, which is what lets the
// lines be matched back to the prefixes that were asked about.
func TestWindowsScriptLinesSurviveBothLineEndings(t *testing.T) {
	lines := splitWindowsScriptLines("[]\r\n[{\"InterfaceIndex\":3}]\r\n")
	if len(lines) != 2 || lines[0] != "[]" {
		t.Errorf("CRLF output split into %d lines: %q", len(lines), lines)
	}
	if got := splitWindowsScriptLines("\n\n"); len(got) != 0 {
		t.Errorf("blank output split into %d lines: %q", len(got), got)
	}
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
	if sampled < 10 {
		t.Errorf("vector carries %d sampled cases, want at least 10", sampled)
	}
}
