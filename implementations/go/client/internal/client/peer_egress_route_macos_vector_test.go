package client

import (
	"errors"
	"reflect"
	"strings"
	"testing"
)

// Binds the macOS route readings and command builders to
// protocol/test-vectors/peer-egress-macos-routes-v1.json.
//
// Everything marked sampled in that file is literal output captured from a real macOS machine, and
// three of those captures changed the design rather than confirming it: `route` exits 0 when it
// fails, it accepts a /33 and installs half the IPv4 address space, and the readings are cheap
// enough that caching them would buy nothing.
//
// The expectations come from an independent reference implementation in
// tools/protocol/generate_peer_egress_macos_route_vectors.py, so agreement here is independent
// agreement rather than three copies of one mistake.

type egressMacosRoutesVector struct {
	KernelGeneratedFlag string `json:"kernelGeneratedFlag"`
	FailureKinds        struct {
		Denied string `json:"denied"`
		Other  string `json:"other"`
	} `json:"failureKinds"`
	RouteGet []struct {
		Name   string `json:"name"`
		Stdout string `json:"stdout"`
		Stderr string `json:"stderr"`
		Expect struct {
			Parsed    bool   `json:"parsed"`
			Gateway   string `json:"gateway"`
			Interface string `json:"interface"`
		} `json:"expect"`
	} `json:"routeGet"`
	NormalisePrefix struct {
		Cases []struct {
			Input  string `json:"input"`
			Expect string `json:"expect"`
		} `json:"cases"`
	} `json:"normalisePrefix"`
	Table         egressMacosTableCase `json:"table"`
	BothFamilies  egressMacosTableCase `json:"bothFamilies"`
	Duplicates    egressMacosTableCase `json:"duplicates"`
	TunRoute      egressMacosTableCase `json:"tunRoute"`
	ConflictFromTable struct {
		Tables map[string]string `json:"tables"`
		Cases  []struct {
			Prefix string `json:"prefix"`
			Table  string `json:"table"`
			Expect struct {
				Present  bool   `json:"present"`
				Existing string `json:"existing"`
			} `json:"expect"`
		} `json:"cases"`
	} `json:"conflictFromTable"`
	CommandResults []struct {
		Name   string `json:"name"`
		Stdout string `json:"stdout"`
		Stderr string `json:"stderr"`
		Exit   int    `json:"exit"`
		Expect struct {
			Failure string `json:"failure"`
		} `json:"expect"`
	} `json:"commandResults"`
	Commands struct {
		ShowTable []string `json:"showTable"`
		FindRoute []struct {
			Address string   `json:"address"`
			Argv    []string `json:"argv"`
		} `json:"findRoute"`
		InstallInterface []struct {
			Prefix    string   `json:"prefix"`
			Interface string   `json:"interface"`
			Argv      []string `json:"argv"`
		} `json:"installInterface"`
		InstallGateway []struct {
			Prefix  string   `json:"prefix"`
			Gateway string   `json:"gateway"`
			Argv    []string `json:"argv"`
		} `json:"installGateway"`
		Remove []struct {
			Prefix string   `json:"prefix"`
			Argv   []string `json:"argv"`
		} `json:"remove"`
		RejectedArguments []struct {
			Kind  string `json:"kind"`
			Value string `json:"value"`
		} `json:"rejectedArguments"`
	} `json:"commands"`
	MalformedPrefix struct {
		InstalledPrefix string `json:"installedPrefix"`
		Exit            int    `json:"exit"`
		Stdout          string `json:"stdout"`
		TableAfter      string `json:"tableAfter"`
	} `json:"malformedPrefix"`
	Timings struct {
		Cache bool `json:"cache"`
	} `json:"timings"`
}

type egressMacosTableCase struct {
	Name   string `json:"name"`
	Stdout string `json:"stdout"`
	Expect struct {
		Rows     int      `json:"rows"`
		Prefixes []string `json:"prefixes"`
	} `json:"expect"`
}

func loadMacosRoutesVector(t *testing.T) egressMacosRoutesVector {
	t.Helper()
	var vector egressMacosRoutesVector
	readEgressVector(t, "peer-egress-macos-routes-v1.json", &vector)
	if len(vector.RouteGet) == 0 || len(vector.CommandResults) == 0 {
		t.Fatal("macos routes vector carried no cases")
	}
	return vector
}

// `route -n get` is how a bypass next hop is found, and the reading that matters is that an
// on-link destination has no gateway line at all -- not even the gateway's own address, which has a
// cloned entry carrying a MAC address.
func TestMacosRouteGetMatchesSharedVector(t *testing.T) {
	vector := loadMacosRoutesVector(t)
	for _, testCase := range vector.RouteGet {
		hop, ok := parseMacosRouteGet(testCase.Stdout, testCase.Stderr)
		if ok != testCase.Expect.Parsed {
			t.Errorf("%s: parsed=%v, want %v", testCase.Name, ok, testCase.Expect.Parsed)
			continue
		}
		if !ok {
			continue
		}
		if hop.Gateway != testCase.Expect.Gateway || hop.Device != testCase.Expect.Interface {
			t.Errorf("%s: gateway=%q device=%q, want %q/%q", testCase.Name, hop.Gateway,
				hop.Device, testCase.Expect.Gateway, testCase.Expect.Interface)
		}
	}
}

// netstat abbreviates the destination column and the abbreviations are not guessable: "127" is a
// /8, "203.0.113" is a /24, "100.64/10" fills in the missing octet. Reading one wrong means the
// conflict check compares against a prefix nobody asked about.
func TestMacosNormalisePrefixMatchesSharedVector(t *testing.T) {
	vector := loadMacosRoutesVector(t)
	if len(vector.NormalisePrefix.Cases) == 0 {
		t.Fatal("macos routes vector carried no normalisation cases")
	}
	for _, testCase := range vector.NormalisePrefix.Cases {
		if got := normaliseMacosPrefix(testCase.Input); got != testCase.Expect {
			t.Errorf("normalise %q = %q, want %q", testCase.Input, got, testCase.Expect)
		}
	}
}

// Which rows of `netstat -rn` are routes, and which section they have to come from.
func TestMacosRouteTableMatchesSharedVector(t *testing.T) {
	vector := loadMacosRoutesVector(t)
	for _, testCase := range []egressMacosTableCase{vector.Table, vector.BothFamilies,
		vector.Duplicates, vector.TunRoute} {
		if testCase.Stdout == "" {
			t.Fatalf("%s: vector carried no table", testCase.Name)
		}
		routes := parseMacosRouteTable(testCase.Stdout)
		if len(routes) != testCase.Expect.Rows {
			t.Errorf("%s: %d rows, want %d", testCase.Name, len(routes), testCase.Expect.Rows)
		}
		var prefixes []string
		for _, route := range routes {
			prefixes = append(prefixes, route.Prefix)
		}
		if !reflect.DeepEqual(prefixes, testCase.Expect.Prefixes) {
			t.Errorf("%s: prefixes %v, want %v", testCase.Name, prefixes,
				testCase.Expect.Prefixes)
		}
	}

	// The two-family table has to yield the same routes as the IPv4-only one: "default" is the
	// one destination whose IPv6 spelling is indistinguishable from its IPv4 spelling, and the
	// sampling machine had four of them, one per utun.
	if !reflect.DeepEqual(vector.BothFamilies.Expect.Prefixes, vector.Table.Expect.Prefixes) {
		t.Error("the two-family table is expected to carry different routes than the IPv4 one")
	}
}

// The conflict check, which decides whether a rule is applied or refused.
func TestMacosConflictFromTableMatchesSharedVector(t *testing.T) {
	vector := loadMacosRoutesVector(t)
	if len(vector.ConflictFromTable.Cases) == 0 {
		t.Fatal("macos routes vector carried no conflict cases")
	}
	for _, testCase := range vector.ConflictFromTable.Cases {
		table, ok := vector.ConflictFromTable.Tables[testCase.Table]
		if !ok {
			t.Fatalf("%s: vector names a table %q it does not carry", testCase.Prefix,
				testCase.Table)
		}
		present, existing := macosConflictFromTable(table, testCase.Prefix)
		if present != testCase.Expect.Present || existing != testCase.Expect.Existing {
			t.Errorf("%s in %s: present=%v existing=%q, want %v/%q", testCase.Prefix,
				testCase.Table, present, existing, testCase.Expect.Present,
				testCase.Expect.Existing)
		}
	}
}

// Whether a mutation worked, which cannot be read from the exit status.
func TestMacosCommandResultsMatchSharedVector(t *testing.T) {
	vector := loadMacosRoutesVector(t)
	if vector.FailureKinds.Denied != macosRouteFailureDenied ||
		vector.FailureKinds.Other != macosRouteFailureOther {
		t.Fatalf("failure kinds %q/%q do not match the vector", macosRouteFailureDenied,
			macosRouteFailureOther)
	}
	if vector.KernelGeneratedFlag != macosKernelGeneratedFlag {
		t.Fatalf("kernel-generated flag %q does not match the vector %q",
			macosKernelGeneratedFlag, vector.KernelGeneratedFlag)
	}
	zeroExitFailures := 0
	for _, testCase := range vector.CommandResults {
		got := parseMacosCommandFailure(testCase.Stdout, testCase.Stderr)
		if got != testCase.Expect.Failure {
			t.Errorf("%s: failure=%q, want %q", testCase.Name, got,
				testCase.Expect.Failure)
		}
		if testCase.Exit == 0 && testCase.Expect.Failure != "" {
			zeroExitFailures++
		}
	}
	// The reason none of this reads the exit status. Without a case like this an implementation
	// could check it and pass the whole file.
	if zeroExitFailures == 0 {
		t.Error("the vector no longer carries a failure that exited 0")
	}
}

// The argv arrays are pinned as well as their output. Three runtimes each assembling their own
// arguments is exactly how two of them end up using -net while the third uses -host, with nothing
// in the parsed output to show it.
func TestMacosCommandsMatchSharedVector(t *testing.T) {
	vector := loadMacosRoutesVector(t)
	if !reflect.DeepEqual(macosShowTableArgs(), vector.Commands.ShowTable) {
		t.Errorf("show table args %v, want %v", macosShowTableArgs(),
			vector.Commands.ShowTable)
	}
	for _, testCase := range vector.Commands.FindRoute {
		argv, err := macosFindRouteArgs(testCase.Address)
		if err != nil || !reflect.DeepEqual(argv, testCase.Argv) {
			t.Errorf("find %s = %v (%v), want %v", testCase.Address, argv, err,
				testCase.Argv)
		}
	}
	for _, testCase := range vector.Commands.InstallInterface {
		argv, err := macosInstallInterfaceArgs(testCase.Prefix, testCase.Interface)
		if err != nil || !reflect.DeepEqual(argv, testCase.Argv) {
			t.Errorf("install %s via %s = %v (%v), want %v", testCase.Prefix,
				testCase.Interface, argv, err, testCase.Argv)
		}
	}
	for _, testCase := range vector.Commands.InstallGateway {
		argv, err := macosInstallGatewayArgs(testCase.Prefix, testCase.Gateway)
		if err != nil || !reflect.DeepEqual(argv, testCase.Argv) {
			t.Errorf("install %s through %s = %v (%v), want %v", testCase.Prefix,
				testCase.Gateway, argv, err, testCase.Argv)
		}
	}
	for _, testCase := range vector.Commands.Remove {
		argv, err := macosRemoveArgs(testCase.Prefix)
		if err != nil || !reflect.DeepEqual(argv, testCase.Argv) {
			t.Errorf("remove %s = %v (%v), want %v", testCase.Prefix, argv, err,
				testCase.Argv)
		}
	}
}

// What has to be refused. The one that matters is 203.0.113.0/33: `route` accepts it, prints a
// success line naming 203.0.113.0, exits 0, and installs 128.0/1.
func TestMacosRejectedArgumentsMatchSharedVector(t *testing.T) {
	vector := loadMacosRoutesVector(t)
	if len(vector.Commands.RejectedArguments) == 0 {
		t.Fatal("macos routes vector carried no refused arguments")
	}
	for _, testCase := range vector.Commands.RejectedArguments {
		var err error
		switch testCase.Kind {
		case "prefix":
			_, err = macosInstallInterfaceArgs(testCase.Value, "utun3")
		case "address":
			_, err = macosFindRouteArgs(testCase.Value)
		case "interface":
			_, err = macosInstallInterfaceArgs("203.0.113.0/24", testCase.Value)
		default:
			t.Fatalf("vector asks about an argument kind %q nothing here builds",
				testCase.Kind)
		}
		if !errors.Is(err, errEgressRouteArgument) {
			t.Errorf("%s %q was accepted (err=%v)", testCase.Kind, testCase.Value, err)
		}
	}

	// Withdrawal validates too. A removal built from a prefix nobody checked is a removal of
	// whatever `route` decides that text means.
	if _, err := macosRemoveArgs("203.0.113.0/33"); !errors.Is(err, errEgressRouteArgument) {
		t.Errorf("remove accepted a malformed prefix (err=%v)", err)
	}
}

// The capture that says why the prefix is validated before a process starts, kept as a test so the
// evidence travels with the rule rather than living only in a commit message.
func TestMacosMalformedPrefixWouldInstallHalfTheInternet(t *testing.T) {
	vector := loadMacosRoutesVector(t)
	installed := vector.MalformedPrefix.InstalledPrefix
	if installed == "" || vector.MalformedPrefix.TableAfter == "" {
		t.Fatal("macos routes vector carried no malformed-prefix evidence")
	}
	// `route` reported success, and what it says it did names a different prefix than what it
	// did.
	if vector.MalformedPrefix.Exit != 0 {
		t.Errorf("the malformed add exited %d, so the argument check is not the only defence",
			vector.MalformedPrefix.Exit)
	}
	if strings.Contains(vector.MalformedPrefix.Stdout, installed) {
		t.Errorf("the output names %s after all, so this evidence is stale", installed)
	}
	if present, _ := macosConflictFromTable(vector.MalformedPrefix.TableAfter,
		installed); !present {
		t.Errorf("%s is not in the table the malformed add left behind", installed)
	}
	if validMacosPrefix("203.0.113.0/33") {
		t.Error("the argument that installs half the internet is accepted")
	}
}

// The measurement that says not to cache, asserted so a cache cannot be added without the number
// that justifies it.
func TestMacosConflictCheckDoesNotCache(t *testing.T) {
	vector := loadMacosRoutesVector(t)
	if vector.Timings.Cache {
		t.Error("the vector now expects a cached table; the commander does not keep one")
	}
}
