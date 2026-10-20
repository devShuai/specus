//go:build darwin

package client

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os/exec"
	"sync"
	"syscall"
	"time"
)

// Binding an egress socket to an interface on macOS, with IP_BOUND_IF, or IPV6_BOUND_IF for a socket
// to an IPv6 target.

func newEgressSocketBinder(tunnel func() string) *egressSocketBinder {
	table := &macosBindTable{args: macosShowTableArgs, parse: macosBindRoutes}
	table6 := &macosBindTable{args: macosShowTableArgs6, parse: macosBindRoutes6}
	return &egressSocketBinder{tunnel: tunnel, routes: table.read, routes6: table6.read, tunnelKey: macosInterfaceKey}
}

// macosInterfaceKey is the name itself, which is what netstat's Netif column carries.
func macosInterfaceKey(name string) string { return name }

func (binder *egressSocketBinder) control(_ string, address string, connection syscall.RawConn) error {
	chosen, err := binder.choose(address)
	if err != nil {
		return err
	}
	iface, err := net.InterfaceByName(chosen)
	if err != nil {
		return fmt.Errorf("bind egress socket to %s: %w", chosen, err)
	}
	option := macosBoundInterfaceOption(uint32(iface.Index))
	level, name := syscall.IPPROTO_IP, macosIPBoundIf
	if egressTargetIs6(address) {
		level, name = syscall.IPPROTO_IPV6, macosIPv6BoundIf
	}
	var setErr error
	if err := connection.Control(func(handle uintptr) {
		setErr = syscall.SetsockoptString(int(handle), level, name, string(option))
	}); err != nil {
		return err
	}
	if setErr != nil {
		return fmt.Errorf("bind egress socket to %s: %w", chosen, setErr)
	}
	return nil
}

// macosBindTable holds one read of a table for macosBindTableLifetime: the IPv4 one or the IPv6
// one, each read with its own netstat and kept on its own.
type macosBindTable struct {
	args  func() []string
	parse func(table string) []egressBindRoute

	mu     sync.Mutex
	routes []egressBindRoute
	readAt time.Time
	valid  bool
}

func (table *macosBindTable) read() ([]egressBindRoute, error) {
	table.mu.Lock()
	defer table.mu.Unlock()
	if table.valid && time.Since(table.readAt) < macosBindTableLifetime {
		return table.routes, nil
	}
	args := table.args()
	ctx, cancel := context.WithTimeout(context.Background(), macosCommandTimeout)
	defer cancel()
	command := exec.CommandContext(ctx, args[0], args[1:]...)
	var stdout bytes.Buffer
	command.Stdout = &stdout
	if err := command.Run(); err != nil {
		table.valid = false
		return nil, fmt.Errorf("%s: %w", args[0], err)
	}
	table.routes = table.parse(stdout.String())
	table.readAt = time.Now()
	table.valid = true
	return table.routes, nil
}
