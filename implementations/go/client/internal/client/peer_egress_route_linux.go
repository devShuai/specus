//go:build linux

package client

import (
	"errors"
	"fmt"
	"os/exec"
	"strings"
)

// The Linux routing table.
//
// Routes are added, never replaced. The installer checks for a conflict first, but `ip route add`
// failing on an existing prefix is the backstop: replacing would mean quietly winning an argument
// with the user's own routing, which phase one does not do.

type linuxEgressRouteCommander struct {
	tun string
	// hops caches where each bypass address goes, resolved before any tunnel route exists.
	//
	// Resolving again later would ask the system a question this feature has already changed the
	// answer to: once a rule's route covers the address, `ip route get` says "through the
	// tunnel", and installing that would route the tunnel's own transport into the tunnel.
	hops map[string]egressRouteHop
}

func newEgressRouteCommanderForPlatform(tun string) egressRouteCommander {
	return newLinuxEgressRouteCommander(tun)
}

func newLinuxEgressRouteCommander(tun string) *linuxEgressRouteCommander {
	return &linuxEgressRouteCommander{tun: tun, hops: map[string]egressRouteHop{}}
}

func (c *linuxEgressRouteCommander) Conflict(route egressRoute) (bool, string) {
	output, err := runCommandOutput("ip", "route", "show", "exact", route.CIDR)
	if err != nil {
		// Unable to ask. Reporting no conflict would let the add proceed, and `ip route add`
		// refuses an existing prefix anyway, so the install path still fails safe.
		return false, ""
	}
	return parseIPRouteShowExact(output)
}

func (c *linuxEgressRouteCommander) Install(route egressRoute) error {
	if route.Kind == egressRouteBypass {
		return c.installBypass(route)
	}
	if strings.TrimSpace(c.tun) == "" {
		return errors.New("no TUN interface to route into")
	}
	return runCommand("ip", "route", "add", route.CIDR, "dev", c.tun)
}

func (c *linuxEgressRouteCommander) installBypass(route egressRoute) error {
	address := strings.TrimSuffix(route.CIDR, "/32")
	hop, cached := c.hops[address]
	if !cached {
		output, err := runCommandOutput("ip", "route", "get", address)
		if err != nil {
			return fmt.Errorf("resolve bypass hop for %s: %w", address, err)
		}
		resolved, ok := parseIPRouteGet(output)
		if !ok {
			return fmt.Errorf("no route to %s to bypass through", address)
		}
		if egressRouteHopIsDevice(resolved, c.tun) {
			// Pinning it to the tunnel would send the transport through the thing it carries.
			return fmt.Errorf("bypass for %s already resolves to the tunnel", address)
		}
		c.hops[address] = resolved
		hop = resolved
	}
	if hop.Gateway == "" {
		return runCommand("ip", "route", "add", route.CIDR, "dev", hop.Device)
	}
	return runCommand("ip", "route", "add", route.CIDR, "via", hop.Gateway, "dev", hop.Device)
}

func (c *linuxEgressRouteCommander) Remove(route egressRoute) error {
	return runCommand("ip", "route", "del", route.CIDR)
}

func runCommandOutput(args ...string) (string, error) {
	if len(args) == 0 {
		return "", nil
	}
	output, err := exec.Command(args[0], args[1:]...).CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("%s failed: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(string(output)))
	}
	return string(output), nil
}
