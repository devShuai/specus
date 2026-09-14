package client

import (
	"encoding/hex"
	"reflect"
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
