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

// Binding an egress socket to an interface on macOS, with IP_BOUND_IF.

func newEgressSocketBinder(tunnel func() string) *egressSocketBinder {
	table := &macosBindTable{}
	return &egressSocketBinder{tunnel: tunnel, routes: table.read, tunnelKey: macosInterfaceKey}
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
	var setErr error
	if err := connection.Control(func(handle uintptr) {
		setErr = syscall.SetsockoptString(int(handle), syscall.IPPROTO_IP, macosIPBoundIf, string(option))
	}); err != nil {
		return err
	}
	if setErr != nil {
		return fmt.Errorf("bind egress socket to %s: %w", chosen, setErr)
	}
	return nil
}

// macosBindTable holds one read of the table for macosBindTableLifetime.
type macosBindTable struct {
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
	args := macosShowTableArgs()
	ctx, cancel := context.WithTimeout(context.Background(), macosCommandTimeout)
	defer cancel()
	command := exec.CommandContext(ctx, args[0], args[1:]...)
	var stdout bytes.Buffer
	command.Stdout = &stdout
	if err := command.Run(); err != nil {
		table.valid = false
		return nil, fmt.Errorf("%s: %w", args[0], err)
	}
	table.routes = macosBindRoutes(stdout.String())
	table.readAt = time.Now()
	table.valid = true
	return table.routes, nil
}
