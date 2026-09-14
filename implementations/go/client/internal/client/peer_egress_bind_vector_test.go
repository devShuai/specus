package client

import (
	"encoding/hex"
	"errors"
	"reflect"
	"strings"
	"testing"
)

// Binds the choice of interface for an egress socket, and the two platforms' table readings, to
// protocol/test-vectors/peer-egress-socket-binding-v1.json.
//
// The expectations come from an independent reference in
// tools/protocol/generate_peer_egress_socket_binding_vectors.py, whose Windows tables are built from
// the SDK's structure layouts with ctypes and whose macOS tables are sampled captures.

type egressBindVectorRoute struct {
	Prefix    string `json:"prefix"`
	Interface string `json:"interface"`
	Gateway   string `json:"gateway"`
	Metric    int64  `json:"metric"`
	Usable    bool   `json:"usable"`
}

type egressBindVectorCase struct {
	Name        string                  `json:"name"`
	Routes      []egressBindVectorRoute `json:"routes"`
	Table       string                  `json:"table"`
	Tunnel      string                  `json:"tunnel"`
	Destination string                  `json:"destination"`
	Expect      struct {
		Interface *string `json:"interface"`
	} `json:"expect"`
}

type egressBindVector struct {
	Select struct {
		Cases []egressBindVectorCase `json:"cases"`
	} `json:"select"`
	Windows struct {
		ForwardTables []struct {
			Name   string `json:"name"`
			Hex    string `json:"hex"`
			Expect struct {
				Parsed bool `json:"parsed"`
				Rows   []struct {
					InterfaceIndex uint32 `json:"interfaceIndex"`
					Prefix         string `json:"prefix"`
					NextHop        string `json:"nextHop"`
					Metric         uint32 `json:"metric"`
				} `json:"rows"`
			} `json:"expect"`
		} `json:"forwardTables"`
		InterfaceTables []struct {
			Name   string `json:"name"`
			Hex    string `json:"hex"`
			Expect struct {
				Parsed bool `json:"parsed"`
				Rows   []struct {
					InterfaceIndex       uint32 `json:"interfaceIndex"`
					Metric               uint32 `json:"metric"`
					Connected            bool   `json:"connected"`
					DisableDefaultRoutes bool   `json:"disableDefaultRoutes"`
				} `json:"rows"`
			} `json:"expect"`
		} `json:"interfaceTables"`
		Routes struct {
			Forward    string                  `json:"forward"`
			Interfaces string                  `json:"interfaces"`
			Expect     []egressBindVectorRoute `json:"expect"`
		} `json:"routes"`
		Cases []egressBindVectorCase `json:"cases"`
	} `json:"windows"`
	Macos struct {
		Tables map[string]string `json:"tables"`
		Routes []struct {
			Table  string                  `json:"table"`
			Expect []egressBindVectorRoute `json:"expect"`
		} `json:"routes"`
		Cases []egressBindVectorCase `json:"cases"`
	} `json:"macos"`
	Linux struct {
		Tables   map[string]string `json:"tables"`
		Captures map[string]struct {
			Exit   int    `json:"exit"`
			Stdout string `json:"stdout"`
		} `json:"captures"`
		Routes []struct {
			Table  string                  `json:"table"`
			Expect []egressBindVectorRoute `json:"expect"`
		} `json:"routes"`
	} `json:"linux"`
	Hops struct {
		Cases []struct {
			Name        string                  `json:"name"`
			Platform    string                  `json:"platform"`
			Table       string                  `json:"table"`
			Tunnel      string                  `json:"tunnel"`
			Owned       []string                `json:"owned"`
			Destination string                  `json:"destination"`
			Routes      []egressBindVectorRoute `json:"routes"`
			Expect      struct {
				Hop *struct {
					Interface string `json:"interface"`
					Gateway   string `json:"gateway"`
				} `json:"hop"`
			} `json:"expect"`
		} `json:"cases"`
	} `json:"hops"`
	SocketOptions struct {
		Windows egressBindVectorOption `json:"windows"`
		Macos   egressBindVectorOption `json:"macos"`
	} `json:"socketOptions"`
}

type egressBindVectorOption struct {
	Level int `json:"level"`
	Name  int `json:"name"`
	Cases []struct {
		Index uint32 `json:"index"`
		Hex   string `json:"hex"`
	} `json:"cases"`
}

func loadEgressBindVector(t *testing.T) egressBindVector {
	t.Helper()
	var vector egressBindVector
	readEgressVector(t, "peer-egress-socket-binding-v1.json", &vector)
	return vector
}

func egressBindRoutesFromVector(routes []egressBindVectorRoute) []egressBindRoute {
	converted := make([]egressBindRoute, 0, len(routes))
	for _, route := range routes {
		converted = append(converted, egressBindRoute(route))
	}
	return converted
}

func checkEgressBindChoice(t *testing.T, name string, routes []egressBindRoute, tunnel string,
	destination string, want *string) {
	t.Helper()
	got, ok := selectEgressBindInterface(routes, tunnel, destination)
	switch {
	case want == nil && ok:
		t.Errorf("%s: chose %q, want the dial refused", name, got)
	case want != nil && !ok:
		t.Errorf("%s: refused, want %q", name, *want)
	case want != nil && got != *want:
		t.Errorf("%s: chose %q, want %q", name, got, *want)
	}
}

func TestEgressBindSelectionVectors(t *testing.T) {
	vector := loadEgressBindVector(t)
	if len(vector.Select.Cases) == 0 {
		t.Fatal("no selection cases")
	}
	for _, c := range vector.Select.Cases {
		checkEgressBindChoice(t, c.Name, egressBindRoutesFromVector(c.Routes), c.Tunnel, c.Destination,
			c.Expect.Interface)
	}
}

func TestEgressBindWindowsTableVectors(t *testing.T) {
	vector := loadEgressBindVector(t)
	forwardByName := map[string][]windowsForwardRow{}
	for _, table := range vector.Windows.ForwardTables {
		raw, err := hex.DecodeString(table.Hex)
		if err != nil {
			t.Fatalf("%s: %v", table.Name, err)
		}
		rows, ok := parseWindowsForwardTable(raw)
		if ok != table.Expect.Parsed {
			t.Errorf("forward %s: parsed = %v, want %v", table.Name, ok, table.Expect.Parsed)
			continue
		}
		want := []windowsForwardRow{}
		for _, row := range table.Expect.Rows {
			want = append(want, windowsForwardRow(row))
		}
		if ok && !reflect.DeepEqual(append([]windowsForwardRow{}, rows...), want) {
			t.Errorf("forward %s:\n got %+v\nwant %+v", table.Name, rows, want)
		}
		forwardByName[table.Name] = rows
	}
	interfacesByName := map[string][]windowsInterfaceRow{}
	for _, table := range vector.Windows.InterfaceTables {
		raw, err := hex.DecodeString(table.Hex)
		if err != nil {
			t.Fatalf("%s: %v", table.Name, err)
		}
		rows, ok := parseWindowsInterfaceTable(raw)
		if ok != table.Expect.Parsed {
			t.Errorf("interfaces %s: parsed = %v, want %v", table.Name, ok, table.Expect.Parsed)
			continue
		}
		want := []windowsInterfaceRow{}
		for _, row := range table.Expect.Rows {
			want = append(want, windowsInterfaceRow(row))
		}
		if ok && !reflect.DeepEqual(append([]windowsInterfaceRow{}, rows...), want) {
			t.Errorf("interfaces %s:\n got %+v\nwant %+v", table.Name, rows, want)
		}
		interfacesByName[table.Name] = rows
	}

	routes := windowsBindRoutes(forwardByName[vector.Windows.Routes.Forward],
		interfacesByName[vector.Windows.Routes.Interfaces])
	if want := egressBindRoutesFromVector(vector.Windows.Routes.Expect); !reflect.DeepEqual(routes, want) {
		t.Errorf("joined routes:\n got %+v\nwant %+v", routes, want)
	}
	for _, c := range vector.Windows.Cases {
		checkEgressBindChoice(t, "windows "+c.Name, routes, c.Tunnel, c.Destination, c.Expect.Interface)
	}
}

func TestEgressLinuxRouteTableVectors(t *testing.T) {
	vector := loadEgressBindVector(t)
	if len(vector.Linux.Routes) == 0 {
		t.Fatal("no Linux tables")
	}
	for _, entry := range vector.Linux.Routes {
		routes := parseIPRouteTable(vector.Linux.Tables[entry.Table])
		if want := egressBindRoutesFromVector(entry.Expect); !reflect.DeepEqual(routes, want) {
			t.Errorf("linux routes %s:\n got %+v\nwant %+v", entry.Table, routes, want)
		}
	}
	// The captures that justify reading the table at all: `ip route get` answering with the tunnel.
	for name, capture := range vector.Linux.Captures {
		if !strings.HasPrefix(name, "get-covered") {
			continue
		}
		hop, ok := parseIPRouteGet(capture.Stdout)
		if !ok || !egressRouteHopIsDevice(hop, "specus0") {
			t.Errorf("%s: parsed %+v (ok=%v), want the tunnel", name, hop, ok)
		}
	}
}

func TestEgressBypassHopVectors(t *testing.T) {
	vector := loadEgressBindVector(t)
	tables := map[string]map[string][]egressBindRoute{"linux": {}, "macos": {}, "windows": {}}
	for name, text := range vector.Linux.Tables {
		tables["linux"][name] = parseIPRouteTable(text)
	}
	for name, text := range vector.Macos.Tables {
		tables["macos"][name] = macosBindRoutes(text)
	}
	var forward []windowsForwardRow
	var interfaces []windowsInterfaceRow
	for _, table := range vector.Windows.ForwardTables {
		if table.Name == vector.Windows.Routes.Forward {
			raw, _ := hex.DecodeString(table.Hex)
			forward, _ = parseWindowsForwardTable(raw)
		}
	}
	for _, table := range vector.Windows.InterfaceTables {
		if table.Name == vector.Windows.Routes.Interfaces {
			raw, _ := hex.DecodeString(table.Hex)
			interfaces, _ = parseWindowsInterfaceTable(raw)
		}
	}
	tables["windows"]["typical"] = windowsBindRoutes(forward, interfaces)

	if len(vector.Hops.Cases) == 0 {
		t.Fatal("no hop cases")
	}
	for _, c := range vector.Hops.Cases {
		routes := tables[c.Platform][c.Table]
		if c.Platform == "inline" {
			routes = egressBindRoutesFromVector(c.Routes)
		}
		hop, ok := selectEgressBypassHop(routes, c.Tunnel, c.Owned, c.Destination)
		switch {
		case c.Expect.Hop == nil && ok:
			t.Errorf("%s: chose %+v, want no hop", c.Name, hop)
		case c.Expect.Hop != nil && !ok:
			t.Errorf("%s: no hop, want %+v", c.Name, *c.Expect.Hop)
		case c.Expect.Hop != nil && (hop.Interface != c.Expect.Hop.Interface || hop.Gateway != c.Expect.Hop.Gateway):
			t.Errorf("%s: chose %s via %q, want %s via %q", c.Name, hop.Interface, hop.Gateway,
				c.Expect.Hop.Interface, c.Expect.Hop.Gateway)
		}
	}
}

// The fallback a commander takes when its query answers with the tunnel: the table with the tunnel
// left out, and a refusal that names why when nothing else leads there.
func TestEgressBypassHopFromTableLeavesTheTunnelOut(t *testing.T) {
	vector := loadEgressBindVector(t)
	routes := parseIPRouteTable(vector.Linux.Tables["show-rich"])
	read := func() ([]egressBindRoute, error) { return routes, nil }

	hop, err := egressBypassHopFromTable("203.0.113.9", "specus0", read)
	if err != nil || hop.Interface != "eth0" || hop.Gateway != "192.168.64.1" {
		t.Fatalf("hop = %+v, %v; want eth0 via 192.168.64.1", hop, err)
	}
	if _, err := egressBypassHopFromTable("192.0.2.9", "specus0", read); !errors.Is(err, errEgressNoPhysicalRoute) {
		t.Errorf("blackholed address: err = %v, want the no-physical-route refusal", err)
	}
	failing := func() ([]egressBindRoute, error) { return nil, errors.New("ip: not found") }
	if _, err := egressBypassHopFromTable("203.0.113.9", "specus0", failing); err == nil ||
		!strings.Contains(err.Error(), "ip: not found") {
		t.Errorf("unreadable table: err = %v, want the read error carried", err)
	}
}

func TestEgressBindMacosTableVectors(t *testing.T) {
	vector := loadEgressBindVector(t)
	byTable := map[string][]egressBindRoute{}
	for _, entry := range vector.Macos.Routes {
		routes := macosBindRoutes(vector.Macos.Tables[entry.Table])
		if want := egressBindRoutesFromVector(entry.Expect); !reflect.DeepEqual(routes, want) {
			t.Errorf("macos routes %s:\n got %+v\nwant %+v", entry.Table, routes, want)
		}
		byTable[entry.Table] = routes
	}
	for _, c := range vector.Macos.Cases {
		checkEgressBindChoice(t, "macos "+c.Name, byTable[c.Table], c.Tunnel, c.Destination, c.Expect.Interface)
	}
}

func TestEgressBindSocketOptionVectors(t *testing.T) {
	vector := loadEgressBindVector(t)
	if vector.SocketOptions.Windows.Level != 0 || vector.SocketOptions.Windows.Name != windowsIPUnicastIf {
		t.Errorf("IP_UNICAST_IF is %d/%d here and %d/%d in the vector", 0, windowsIPUnicastIf,
			vector.SocketOptions.Windows.Level, vector.SocketOptions.Windows.Name)
	}
	if vector.SocketOptions.Macos.Level != 0 || vector.SocketOptions.Macos.Name != macosIPBoundIf {
		t.Errorf("IP_BOUND_IF is %d/%d here and %d/%d in the vector", 0, macosIPBoundIf,
			vector.SocketOptions.Macos.Level, vector.SocketOptions.Macos.Name)
	}
	for _, c := range vector.SocketOptions.Windows.Cases {
		if got := hex.EncodeToString(windowsUnicastInterfaceOption(c.Index)); got != c.Hex {
			t.Errorf("IP_UNICAST_IF %d = %s, want %s", c.Index, got, c.Hex)
		}
	}
	for _, c := range vector.SocketOptions.Macos.Cases {
		if got := hex.EncodeToString(macosBoundInterfaceOption(c.Index)); got != c.Hex {
			t.Errorf("IP_BOUND_IF %d = %s, want %s", c.Index, got, c.Hex)
		}
	}
}

// The mesh names its TUN as the tunnel to leave out, and names nothing for a noop device.
//
// A noop device still carries the configured name but creates no interface. Naming it would do no
// harm on its own -- an interface that is not there resolves to no key -- but it would make a
// misconfigured name on a real device indistinguishable from the ordinary egress-only node.
func TestEgressTunnelNameComesFromARealDeviceOnly(t *testing.T) {
	mesh := &peerMeshClient{}
	if got := mesh.egressTunnelName(); got != "" {
		t.Errorf("no device: tunnel = %q, want none", got)
	}
	mesh.device = &noopPeerVirtualDevice{name: "specus0", status: "NOOP"}
	if got := mesh.egressTunnelName(); got != "" {
		t.Errorf("noop device: tunnel = %q, want none", got)
	}
	mesh.device = newRecordingVirtualDevice()
	if got := mesh.egressTunnelName(); got != "recording" {
		t.Errorf("real device: tunnel = %q, want recording", got)
	}
}
