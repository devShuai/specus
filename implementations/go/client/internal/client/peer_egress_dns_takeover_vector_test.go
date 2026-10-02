package client

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// Every section of peer-egress-dns-takeover-v1.json through the functions the takeover runs: the
// readers of each platform's tools, the Linux mode, the upstream classification, the plans, and the
// give-back decisions.

type dnsTakeoverVector struct {
	MeshCIDR           string   `json:"meshCidr"`
	FakeIPCIDR         string   `json:"fakeIpCidr"`
	Listen             string   `json:"listen"`
	NRPTComment        string   `json:"nrptComment"`
	ResolvConfWritten  string   `json:"resolvConfWritten"`
	ResolvedStubs      []string `json:"resolvedStubs"`
	WindowsReadServers string   `json:"windowsReadServers"`
	WindowsReadNRPT    string   `json:"windowsReadNrpt"`
	ParseResolvectl    []struct {
		Name, Output, Tunnel string
		Servers              []string
	} `json:"parseResolvectl"`
	ParseResolvConf []struct {
		Name, Text string
		Servers    []string
	} `json:"parseResolvConf"`
	ParseMacServices struct {
		Output   string
		Services []string
	} `json:"parseMacServices"`
	ParseMacDNSServers []struct {
		Name, Output string
		Servers      []string
	} `json:"parseMacDnsServers"`
	ParseScutil []struct {
		Name, Output string
		Servers      []string
	} `json:"parseScutil"`
	ParseWindowsServers []struct {
		Name        string
		JSON        string `json:"json"`
		TunnelIndex int    `json:"tunnelIndex"`
		Servers     []string
	} `json:"parseWindowsServers"`
	ParseWindowsNRPT []struct {
		Name        string
		JSON        string `json:"json"`
		ForeignRoot bool   `json:"foreignRoot"`
	} `json:"parseWindowsNrpt"`
	LinuxMode []struct {
		Name                string
		ResolvectlOK        bool     `json:"resolvectlOk"`
		ResolvConfServers   []string `json:"resolvConfServers"`
		ResolvConfIsSymlink bool     `json:"resolvConfIsSymlink"`
		Mode                *string  `json:"mode"`
		Reason              *string  `json:"reason"`
	} `json:"linuxMode"`
	Upstreams []struct {
		Name             string
		Servers          []string `json:"servers"`
		VirtualAddresses []string `json:"virtualAddresses"`
		Code             *string  `json:"code"`
		Upstreams        []string `json:"upstreams"`
		Reason           string   `json:"reason"`
	} `json:"upstreams"`
	Plan []struct {
		Platform string   `json:"platform"`
		Listen   string   `json:"listen"`
		Tunnel   string   `json:"tunnel"`
		Services []string `json:"services"`
		Apply    []any    `json:"apply"`
		Revert   []any    `json:"revert"`
	} `json:"plan"`
	RevertResolvConf []struct {
		Name, Current, Original, Action, Content, Warning string
	} `json:"revertResolvConf"`
	RevertMacService []struct {
		Name     string   `json:"name"`
		Service  string   `json:"service"`
		Current  []string `json:"current"`
		Original []string `json:"original"`
		Action   string   `json:"action"`
		Command  []string `json:"command"`
		Warning  string   `json:"warning"`
	} `json:"revertMacService"`
}

func loadDNSTakeoverVector(t *testing.T) dnsTakeoverVector {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "..", "protocol", "test-vectors", "peer-egress-dns-takeover-v1.json"))
	if err != nil {
		t.Fatalf("read vector: %v", err)
	}
	var vector dnsTakeoverVector
	if err := json.Unmarshal(data, &vector); err != nil {
		t.Fatalf("parse vector: %v", err)
	}
	// A section read as empty would pass every loop below without checking anything.
	for name, count := range map[string]int{
		"parseResolvectl": len(vector.ParseResolvectl), "parseResolvConf": len(vector.ParseResolvConf),
		"parseMacServices": len(vector.ParseMacServices.Services), "parseMacDnsServers": len(vector.ParseMacDNSServers),
		"parseScutil": len(vector.ParseScutil), "parseWindowsServers": len(vector.ParseWindowsServers),
		"parseWindowsNrpt": len(vector.ParseWindowsNRPT), "linuxMode": len(vector.LinuxMode),
		"upstreams": len(vector.Upstreams), "plan": len(vector.Plan), "revertResolvConf": len(vector.RevertResolvConf),
		"revertMacService": len(vector.RevertMacService),
	} {
		if count == 0 {
			t.Fatalf("the vector's %s section read as empty", name)
		}
	}
	return vector
}

func TestEgressDNSTakeoverConstantsMatchTheSharedVector(t *testing.T) {
	vector := loadDNSTakeoverVector(t)
	if vector.NRPTComment != egressDNSNRPTComment || vector.ResolvConfWritten != egressDNSResolvConfWritten ||
		vector.WindowsReadServers != egressDNSWindowsReadServers || vector.WindowsReadNRPT != egressDNSWindowsReadNRPT ||
		!reflect.DeepEqual(vector.ResolvedStubs, egressDNSResolvedStubs) ||
		vector.FakeIPCIDR != egressDefaultFakeIPCIDR || vector.MeshCIDR != egressDefaultMeshCIDR {
		t.Error("a constant differs from the shared vector")
	}
}

func TestEgressDNSReadersMatchTheSharedVector(t *testing.T) {
	vector := loadDNSTakeoverVector(t)
	for _, c := range vector.ParseResolvectl {
		if got := parseResolvectlDNS(c.Output, c.Tunnel); !reflect.DeepEqual(got, c.Servers) {
			t.Errorf("resolvectl %s: %q, want %q", c.Name, got, c.Servers)
		}
	}
	for _, c := range vector.ParseResolvConf {
		if got := parseResolvConfServers(c.Text); !reflect.DeepEqual(got, c.Servers) {
			t.Errorf("resolv.conf %s: %q, want %q", c.Name, got, c.Servers)
		}
	}
	if got := parseMacNetworkServices(vector.ParseMacServices.Output); !reflect.DeepEqual(got, vector.ParseMacServices.Services) {
		t.Errorf("macOS services: %q, want %q", got, vector.ParseMacServices.Services)
	}
	for _, c := range vector.ParseMacDNSServers {
		if got := parseMacDNSServers(c.Output); !reflect.DeepEqual(got, c.Servers) {
			t.Errorf("macOS DNS %s: %q, want %q", c.Name, got, c.Servers)
		}
	}
	for _, c := range vector.ParseScutil {
		if got := parseScutilDNS(c.Output); !reflect.DeepEqual(got, c.Servers) {
			t.Errorf("scutil %s: %q, want %q", c.Name, got, c.Servers)
		}
	}
	for _, c := range vector.ParseWindowsServers {
		got, err := parseWindowsDNSServers(c.JSON, c.TunnelIndex)
		if err != nil || !reflect.DeepEqual(got, c.Servers) {
			t.Errorf("Windows servers %s: %q (%v), want %q", c.Name, got, err, c.Servers)
		}
	}
	for _, c := range vector.ParseWindowsNRPT {
		got, err := parseWindowsNRPT(c.JSON)
		if err != nil || got != c.ForeignRoot {
			t.Errorf("NRPT %s: %v (%v), want %v", c.Name, got, err, c.ForeignRoot)
		}
	}
}

func TestEgressDNSDecisionsMatchTheSharedVector(t *testing.T) {
	vector := loadDNSTakeoverVector(t)
	modes := map[string]string{"resolved": egressDNSPlatformResolved, "resolvconf": egressDNSPlatformResolvConf}
	for _, c := range vector.LinuxMode {
		mode, reason := egressDNSLinuxMode(c.ResolvectlOK, c.ResolvConfServers, c.ResolvConfIsSymlink)
		wantMode, wantReason := "", ""
		if c.Mode != nil {
			wantMode = modes[*c.Mode]
		}
		if c.Reason != nil {
			wantReason = *c.Reason
		}
		if mode != wantMode || reason != wantReason {
			t.Errorf("Linux mode %s: %q %q, want %q %q", c.Name, mode, reason, wantMode, wantReason)
		}
	}
	for _, c := range vector.Upstreams {
		upstreams, reason := classifyEgressDNSUpstreams(c.Servers, c.VirtualAddresses, vector.FakeIPCIDR, vector.MeshCIDR)
		if c.Code != nil {
			if *c.Code != egressCodeDNSTakeoverRefused || reason != c.Reason || upstreams != nil {
				t.Errorf("upstreams %s: %q %q, want refused for %q", c.Name, upstreams, reason, c.Reason)
			}
			continue
		}
		if reason != "" || !reflect.DeepEqual(upstreams, c.Upstreams) {
			t.Errorf("upstreams %s: %q %q, want %q", c.Name, upstreams, reason, c.Upstreams)
		}
	}
	for _, c := range vector.RevertResolvConf {
		restore, warning := revertResolvConf(c.Current, c.Original)
		action := "keep"
		if restore {
			action = "restore"
		}
		if action != c.Action || warning != c.Warning || restore && c.Content != c.Original {
			t.Errorf("resolv.conf give-back %s: %s %q, want %s %q", c.Name, action, warning, c.Action, c.Warning)
		}
	}
	for _, c := range vector.RevertMacService {
		command, warning := revertMacService(c.Service, c.Current, c.Original, vector.Listen)
		action := "keep"
		if command != nil {
			action = "restore"
		}
		if action != c.Action || warning != c.Warning || !reflect.DeepEqual(command, c.Command) {
			t.Errorf("macOS give-back %s: %s %q %q, want %s %q %q", c.Name, action, command, warning, c.Action, c.Command, c.Warning)
		}
	}
}

// planSteps renders steps the way the vector writes them: a command line as an array, the file and
// service actions as objects.
func planSteps(steps []egressDNSStep) []any {
	out := make([]any, 0, len(steps))
	for _, step := range steps {
		switch {
		case step.Write != "":
			out = append(out, map[string]any{"write": step.Write, "content": step.Content})
		case step.Restore != "":
			out = append(out, map[string]any{"restore": step.Restore})
		case step.RestoreService != "":
			out = append(out, map[string]any{"restore-service": step.RestoreService})
		default:
			argv := make([]any, 0, len(step.Argv))
			for _, arg := range step.Argv {
				argv = append(argv, arg)
			}
			out = append(out, argv)
		}
	}
	return out
}

func TestEgressDNSPlansMatchTheSharedVector(t *testing.T) {
	vector := loadDNSTakeoverVector(t)
	if len(vector.Plan) != 4 {
		t.Fatalf("%d plans in the vector, want one per platform", len(vector.Plan))
	}
	for _, c := range vector.Plan {
		tunnel := c.Tunnel
		if tunnel == "" {
			tunnel = "specus0"
		}
		plan, known := egressDNSTakeoverPlan(c.Platform, c.Listen, tunnel, c.Services)
		if !known {
			t.Fatalf("%s: no plan", c.Platform)
		}
		if got := planSteps(plan.Apply); !reflect.DeepEqual(got, c.Apply) {
			t.Errorf("%s apply: %v\nwant %v", c.Platform, got, c.Apply)
		}
		if got := planSteps(plan.Revert); !reflect.DeepEqual(got, c.Revert) {
			t.Errorf("%s revert: %v\nwant %v", c.Platform, got, c.Revert)
		}
	}
	if _, known := egressDNSTakeoverPlan("freebsd", "198.18.0.1", "specus0", nil); known {
		t.Error("a plan for a platform with none")
	}
}
