//go:build windows

package client

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"os/exec"
	"sort"
	"syscall"
	"testing"
	"time"
)

// egressBoundInterface reads IP_UNICAST_IF back from a connected socket.
//
// It comes back in host order, although it has to go in in network order: bound to loopback, whose
// index is 1, getsockopt returns 01 00 00 00. Measured, not documented anywhere found.
func egressBoundInterface(conn net.Conn) (int, error) {
	source, ok := conn.(syscall.Conn)
	if !ok {
		return 0, fmt.Errorf("%T exposes no socket", conn)
	}
	raw, err := source.SyscallConn()
	if err != nil {
		return 0, err
	}
	var value [4]byte
	length := int32(len(value))
	var getErr error
	if err := raw.Control(func(handle uintptr) {
		getErr = syscall.Getsockopt(syscall.Handle(handle), syscall.IPPROTO_IP, windowsIPUnicastIf,
			&value[0], &length)
	}); err != nil {
		return 0, err
	}
	if getErr != nil {
		return 0, getErr
	}
	return int(binary.LittleEndian.Uint32(value[:])), nil
}

// The native table readings agree with Get-NetRoute and Get-NetIPInterface.
//
// This is what keeps the offsets honest on the machine running the tests, rather than only against
// the layouts the vectors were built from. It compares every IPv4 route in the active store and every
// IPv4 interface, so a reader that is one field off disagrees on hundreds of values, not one.
func TestWindowsBindTablesMatchGetNetRoute(t *testing.T) {
	forwardRaw, err := readWindowsMibTable(procGetIpForwardTable2, windowsForwardRowSize)
	if err != nil {
		t.Fatalf("GetIpForwardTable2: %v", err)
	}
	interfaceRaw, err := readWindowsMibTable(procGetIpInterfaceTable, windowsInterfaceRowSize)
	if err != nil {
		t.Fatalf("GetIpInterfaceTable: %v", err)
	}
	forward, ok := parseWindowsForwardTable(forwardRaw)
	if !ok || len(forward) == 0 {
		t.Fatalf("forward table did not parse (ok=%v rows=%d)", ok, len(forward))
	}
	interfaces, ok := parseWindowsInterfaceTable(interfaceRaw)
	if !ok || len(interfaces) == 0 {
		t.Fatalf("interface table did not parse (ok=%v rows=%d)", ok, len(interfaces))
	}

	var cmdletRoutes []struct {
		InterfaceIndex    int
		DestinationPrefix string
		RouteMetric       int
	}
	runWindowsTestScript(t, "ConvertTo-Json -Compress -InputObject @(Get-NetRoute -AddressFamily IPv4 "+
		"-PolicyStore ActiveStore -ErrorAction SilentlyContinue|Select-Object "+
		"InterfaceIndex,DestinationPrefix,RouteMetric)", &cmdletRoutes)
	var cmdletInterfaces []struct {
		InterfaceIndex  int
		InterfaceMetric int
		Connected       bool
	}
	runWindowsTestScript(t, "ConvertTo-Json -Compress -InputObject @(Get-NetIPInterface -AddressFamily IPv4 "+
		"-ErrorAction SilentlyContinue|Select-Object InterfaceIndex,InterfaceMetric,"+
		"@{n='Connected';e={[string]$_.ConnectionState -eq 'Connected'}})", &cmdletInterfaces)

	var native, cmdlet []string
	for _, row := range forward {
		native = append(native, fmt.Sprintf("%d %s %d", row.InterfaceIndex, row.Prefix, row.Metric))
	}
	for _, row := range cmdletRoutes {
		cmdlet = append(cmdlet, fmt.Sprintf("%d %s %d", row.InterfaceIndex, row.DestinationPrefix, row.RouteMetric))
	}
	compareWindowsTestRows(t, "routes", native, cmdlet)

	native, cmdlet = nil, nil
	for _, row := range interfaces {
		native = append(native, fmt.Sprintf("%d metric=%d connected=%v", row.InterfaceIndex, row.Metric, row.Connected))
	}
	for _, row := range cmdletInterfaces {
		cmdlet = append(cmdlet, fmt.Sprintf("%d metric=%d connected=%v", row.InterfaceIndex, row.InterfaceMetric, row.Connected))
	}
	compareWindowsTestRows(t, "interfaces", native, cmdlet)
}

func runWindowsTestScript(t *testing.T, script string, into any) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	output, err := exec.CommandContext(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
		script).Output()
	if err != nil {
		t.Fatalf("powershell: %v", err)
	}
	if err := json.Unmarshal(output, into); err != nil {
		t.Fatalf("decode %q: %v", output, err)
	}
}

func compareWindowsTestRows(t *testing.T, what string, native []string, cmdlet []string) {
	t.Helper()
	sort.Strings(native)
	sort.Strings(cmdlet)
	if fmt.Sprint(native) != fmt.Sprint(cmdlet) {
		t.Errorf("%s disagree\nnative: %q\ncmdlet: %q", what, native, cmdlet)
	}
	t.Logf("%s: %d rows agree", what, len(native))
}
