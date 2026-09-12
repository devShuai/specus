//go:build darwin

package client

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// The macOS routing table.
//
// Routes are added, never replaced, same as Linux and Windows: the installer checks for a conflict
// first, and `route add` refusing an existing prefix is the backstop.
//
// The suffix on this file name is deliberate, and it is the one file here that should have it.
// _darwin.go is itself a build constraint, so the parsers and the command builders are called
// peer_egress_route_macos_parse.go and _macos_command.go instead -- a darwin suffix on those would
// have compiled them out everywhere but a Mac while the test that exercises them kept compiling,
// which is a mistake the Windows side made and only Linux CI caught. This file runs `route` and has
// nothing to say on any other platform, so here the constraint is the point.

// macosCommandTimeout is how long to wait for one `route` or `netstat` invocation.
//
// The same ten seconds Linux allows `ip`, and for the same reason: it is there to catch a hang, not
// to police a budget. The readings themselves have a median of 25 ms.
const macosCommandTimeout = 10 * time.Second

type macosEgressRouteCommander struct {
	tun string
	// hops caches where each bypass address goes, resolved before any tunnel route exists.
	//
	// Resolving again later would ask the system a question this feature has already changed
	// the answer to: once a rule's route covers the address, `route -n get` answers "through
	// the tunnel", and installing that would route the tunnel's own transport into the tunnel.
	hops map[string]egressRouteHop
}

func newEgressRouteCommanderForPlatform(tun string) egressRouteCommander {
	return &macosEgressRouteCommander{tun: tun, hops: map[string]egressRouteHop{}}
}

// Conflict reads the whole table, every time it is asked.
//
// No cache, which is where this parts company with the Windows commander. That one holds one read
// for five seconds because a PowerShell query costs 419 ms and a plan of twenty prefixes would
// otherwise spend eight seconds asking. Here `netstat -rn -f inet` has a median of 25 ms against
// 3 ms for a process that does nothing, so twenty reads cost half a second: a cache would buy a
// saving that is not there, in exchange for a window in which the answer is stale.
//
// The whole table rather than a query per prefix because there is no query per prefix to make.
// `route -n get` does a longest-prefix lookup, so on any machine with a default route it answers
// "yes, reachable" for every prefix that nobody owns.
func (c *macosEgressRouteCommander) Conflict(route egressRoute) (bool, string) {
	stdout, _, err := c.run(macosShowTableArgs())
	if err != nil {
		// Unable to ask. Reporting no conflict lets the add proceed, and `route add` refuses an
		// existing prefix anyway, so the install path still fails safe.
		return false, ""
	}
	return macosConflictFromTable(stdout, route.CIDR)
}

func (c *macosEgressRouteCommander) Install(route egressRoute) error {
	// Checked before anything is run. On this platform that check is not defence in depth: a
	// prefix of 203.0.113.0/33 is accepted by `route`, which prints a success line naming
	// 203.0.113.0, exits 0, and installs 128.0/1 -- half the IPv4 address space pointed at the
	// gateway. Nothing in the output says so, so nothing downstream could catch it.
	if !validMacosPrefix(route.CIDR) {
		return fmt.Errorf("install %s: %w", route.CIDR, errEgressRouteArgument)
	}
	if route.Kind == egressRouteBypass {
		return c.installBypass(route)
	}
	if strings.TrimSpace(c.tun) == "" {
		return errors.New("no TUN interface to route into")
	}
	args, err := macosInstallInterfaceArgs(route.CIDR, c.tun)
	if err != nil {
		return fmt.Errorf("install %s into %s: %w", route.CIDR, c.tun, err)
	}
	return c.apply(args, "install "+route.CIDR)
}

// installBypass pins one address to the physical path.
//
// The TUN has to carry an IPv4 address before any route can point at it, which is a macOS
// requirement rather than a general one: the same `route add -net ... -interface utun3` reports
// "Network is unreachable" while that interface has only a link-local IPv6 address, and succeeds
// once it has an IPv4 one. Nothing here enforces it -- the caller brings the interface up before
// applying a plan -- but it is why an install can fail in a way that is neither a conflict nor a
// permissions problem.
func (c *macosEgressRouteCommander) installBypass(route egressRoute) error {
	address := strings.TrimSuffix(route.CIDR, "/32")
	hop, cached := c.hops[address]
	if !cached {
		args, err := macosFindRouteArgs(address)
		if err != nil {
			return fmt.Errorf("resolve bypass hop for %s: %w", address, err)
		}
		stdout, stderr, err := c.run(args)
		if err != nil && strings.TrimSpace(stdout) == "" {
			return fmt.Errorf("resolve bypass hop for %s: %w", address, err)
		}
		resolved, ok := parseMacosRouteGet(stdout, stderr)
		if !ok {
			return fmt.Errorf("no route to %s to bypass through", address)
		}
		if egressRouteHopIsDevice(resolved, c.tun) {
			// Pinning it to the tunnel would send the transport through the thing it
			// carries.
			return fmt.Errorf("bypass for %s already resolves to the tunnel", address)
		}
		c.hops[address] = resolved
		hop = resolved
	}
	args, err := c.bypassArgs(route.CIDR, hop)
	if err != nil {
		return fmt.Errorf("install bypass %s: %w", route.CIDR, err)
	}
	return c.apply(args, "install bypass "+route.CIDR)
}

// bypassArgs picks the form of the add, which depends on whether the address is on-link.
func (c *macosEgressRouteCommander) bypassArgs(cidr string, hop egressRouteHop) ([]string, error) {
	if hop.Gateway == "" {
		return macosInstallInterfaceArgs(cidr, hop.Device)
	}
	return macosInstallGatewayArgs(cidr, hop.Gateway)
}

func (c *macosEgressRouteCommander) Remove(route egressRoute) error {
	args, err := macosRemoveArgs(route.CIDR)
	if err != nil {
		return fmt.Errorf("remove %s: %w", route.CIDR, err)
	}
	return c.apply(args, "remove "+route.CIDR)
}

// apply runs a mutation and decides whether it worked.
//
// The exit status is not consulted, because `route` returns 0 when it fails: for a prefix that
// already exists, for a prefix that is not in the table, for an interface with no address and for a
// missing argument. Only a malformed address gets a non-zero status. What it does do is leave
// stderr empty on success, which is what parseMacosCommandFailure keys on.
func (c *macosEgressRouteCommander) apply(args []string, what string) error {
	stdout, stderr, runErr := c.run(args)
	switch parseMacosCommandFailure(stdout, stderr) {
	case macosRouteFailureDenied:
		// Named rather than folded into the generic failure: the fix is to run elevated, and
		// an operator retrying a permissions error learns nothing from the attempt.
		return fmt.Errorf("%s needs root: changing the routing table is not permitted for "+
			"this process", what)
	case macosRouteFailureOther:
		detail := strings.TrimSpace(stdout)
		if detail == "" {
			detail = strings.TrimSpace(stderr)
		}
		return fmt.Errorf("%s failed: %s", what, detail)
	}
	// Nothing classified as a failure. A removal that found no such prefix lands here on
	// purpose: the route is not in the table, which is what the caller asked for.
	if runErr != nil && strings.TrimSpace(stdout) == "" && strings.TrimSpace(stderr) == "" {
		return fmt.Errorf("%s: %w", what, runErr)
	}
	return nil
}

// run executes one command and returns its stdout and stderr, separately.
//
// Kept apart because the classification depends on which stream said what: `route` annotates the
// operation on stdout and names the error on stderr, and every successful mutation leaves stderr
// empty. Merging them the way the Linux commander does would throw away the only signal that
// separates a failed add from a successful one on a platform where both exit 0.
func (c *macosEgressRouteCommander) run(args []string) (string, string, error) {
	if len(args) == 0 {
		return "", "", errors.New("no command to run")
	}
	ctx, cancel := context.WithTimeout(context.Background(), macosCommandTimeout)
	defer cancel()
	command := exec.CommandContext(ctx, args[0], args[1:]...)
	var stdout, stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	err := command.Run()
	if ctx.Err() != nil {
		return stdout.String(), stderr.String(),
			fmt.Errorf("%s did not finish: %w", args[0], ctx.Err())
	}
	return stdout.String(), stderr.String(), err
}
