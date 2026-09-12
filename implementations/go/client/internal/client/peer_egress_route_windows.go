//go:build windows

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

// The Windows routing table.
//
// Routes are added, never replaced, same as Linux: the installer checks for a conflict first, and
// `New-NetRoute` failing on an existing prefix is the backstop.
//
// The suffix on this file name is deliberate here. Unlike the parsers and the script builders --
// which are named peer_egress_route_windows_parse.go and _script.go precisely so the toolchain does
// not exclude them -- this file runs powershell.exe and has nothing to say on any other platform.

// windowsCommandTimeout is how long to wait for one PowerShell invocation.
//
// The same ten seconds Linux allows `ip`, even though a PowerShell process is three orders of
// magnitude more expensive to start: the point of the limit is to catch a hang, not to police a
// budget.
const windowsCommandTimeout = 10 * time.Second

// windowsTableCacheLifetime is how long one read of the whole routing table answers for.
//
// The conflict check is asked once per prefix being added, and reading the table per prefix would
// cost 419 ms each. Caching it turns one apply into one read. The lifetime is what keeps that from
// becoming a stale answer across applies: within a single apply the cache holds, between applies it
// is certainly gone. An apply that runs longer than this pays for one extra read, which is a
// slowdown rather than a wrong answer -- while an unbounded cache would eventually miss a route
// somebody else installed hours ago and turn a refusable conflict into a failed install that rolls
// the whole plan back.
const windowsTableCacheLifetime = 5 * time.Second

type windowsEgressRouteCommander struct {
	tun string

	// tunIndex is the interface index for tun, resolved once. Routing needs the index and the
	// client only has the name, and the name cannot be sent back out of PowerShell safely --
	// see the note in peer_egress_route_windows_script.go.
	tunIndex int

	// table is one read of the whole routing table, and tableAt is when it was taken.
	table   string
	tableAt time.Time

	// hops caches where each bypass address goes, resolved before any tunnel route exists.
	//
	// Resolved one address at a time rather than in one batch, unlike the conflict check. The
	// bypass list is the control endpoint, STUN, TURN and the peer addresses -- single digits in
	// practice -- and each one is resolved once and then cached. Batching them would mean the
	// installer telling the commander what is coming, which is a change to an interface three
	// runtimes and their tests share. Worth revisiting if the list ever grows with the mesh.
	hops map[string]windowsEgressRouteHop
}

func newEgressRouteCommanderForPlatform(tun string) egressRouteCommander {
	return &windowsEgressRouteCommander{tun: tun, hops: map[string]windowsEgressRouteHop{}}
}

func (c *windowsEgressRouteCommander) Conflict(route egressRoute) (bool, string) {
	if c.table == "" || time.Since(c.tableAt) > windowsTableCacheLifetime {
		output, err := c.run(windowsShowAllRoutesScript())
		if err != nil {
			// Unable to ask. Reporting no conflict lets the add proceed, and New-NetRoute
			// refuses an existing prefix anyway, so the install path still fails safe.
			return false, ""
		}
		c.table = output
		c.tableAt = time.Now()
	}
	return windowsConflictFromTable(c.table, route.CIDR)
}

func (c *windowsEgressRouteCommander) Install(route egressRoute) error {
	// Checked before anything is run: an argument the script builder would refuse must not
	// cost a process first, and on this platform that refusal is what keeps a prefix from
	// becoming a second command.
	if !validWindowsPrefix(route.CIDR) {
		return fmt.Errorf("install %s: %w", route.CIDR, errEgressRouteArgument)
	}
	if route.Kind == egressRouteBypass {
		return c.installBypass(route)
	}
	if strings.TrimSpace(c.tun) == "" {
		return errors.New("no TUN interface to route into")
	}
	index, err := c.tunnelIndex()
	if err != nil {
		return err
	}
	script, err := windowsInstallRouteScript(route.CIDR, index, "")
	if err != nil {
		return err
	}
	return c.apply(script, "install "+route.CIDR)
}

func (c *windowsEgressRouteCommander) installBypass(route egressRoute) error {
	address := strings.TrimSuffix(route.CIDR, "/32")
	hop, cached := c.hops[address]
	if !cached {
		script, err := windowsFindRoutesScript([]string{address})
		if err != nil {
			return err
		}
		output, err := c.run(script)
		if err != nil {
			return fmt.Errorf("resolve bypass hop for %s: %w", address, err)
		}
		resolved, ok := parseWindowsRouteFind(output)
		if !ok {
			return fmt.Errorf("no route to %s to bypass through", address)
		}
		if index, known := c.tunnelIndexIfKnown(); known && resolved.InterfaceIndex == index {
			// Pinning it to the tunnel would send the transport through the thing it
			// carries. Compared by index rather than by name, because the name is the one
			// thing that cannot come back out of PowerShell intact.
			return fmt.Errorf("bypass for %s already resolves to the tunnel", address)
		}
		c.hops[address] = resolved
		hop = resolved
	}
	script, err := windowsInstallRouteScript(route.CIDR, hop.InterfaceIndex, hop.Gateway)
	if err != nil {
		return err
	}
	return c.apply(script, "install bypass "+route.CIDR)
}

func (c *windowsEgressRouteCommander) Remove(route egressRoute) error {
	script, err := windowsRemoveRouteScript(route.CIDR)
	if err != nil {
		return err
	}
	return c.apply(script, "remove "+route.CIDR)
}

// tunnelIndex resolves the TUN adapter's interface index, once.
func (c *windowsEgressRouteCommander) tunnelIndex() (int, error) {
	if c.tunIndex > 0 {
		return c.tunIndex, nil
	}
	output, err := c.run(windowsInterfaceIndexScript(c.tun))
	if err != nil {
		return 0, fmt.Errorf("resolve interface index for %s: %w", c.tun, err)
	}
	index, ok := parseWindowsInterfaceIndex(output)
	if !ok {
		return 0, fmt.Errorf("no adapter named %s to route into", c.tun)
	}
	c.tunIndex = index
	return index, nil
}

// tunnelIndexIfKnown reports the cached index without going and asking for it.
//
// Used by the bypass path, which must not fail because the tunnel could not be looked up: a bypass
// route is what keeps the tunnel's own transport off the tunnel, and refusing to install it because
// the adapter is not up yet would be the wrong way round.
func (c *windowsEgressRouteCommander) tunnelIndexIfKnown() (int, bool) {
	return c.tunIndex, c.tunIndex > 0
}

// apply runs a script whose failures come back as JSON on stdout.
func (c *windowsEgressRouteCommander) apply(script string, what string) error {
	output, runErr := c.run(script)
	switch parseWindowsCommandFailure(output) {
	case windowsRouteFailureDenied:
		// Named rather than folded into the generic failure: the fix is to run elevated, and
		// an operator retrying a permissions error learns nothing from the attempt.
		return fmt.Errorf("%s needs administrator rights: changing the routing table is not "+
			"permitted for this process", what)
	case windowsRouteFailureOther:
		return fmt.Errorf("%s failed: %s", what, strings.TrimSpace(output))
	}
	// Nothing classified as a failure. A removal that found no such prefix lands here on
	// purpose: the route is not in the table, which is what the caller asked for.
	if runErr != nil && strings.TrimSpace(output) == "" {
		return fmt.Errorf("%s: %w", what, runErr)
	}
	return nil
}

// run executes one PowerShell script and returns its stdout.
//
// stdout and stderr are kept apart, unlike the Linux commander which merges them. The scripts catch
// their own failures and write them as JSON on stdout; PowerShell's own uncaught errors go to
// stderr. Merging would splice non-JSON text into the document and every parser here would see only
// "could not read it", which is the answer that means "no conflict, go ahead".
//
// Exit codes are not consulted. A script that failed exits 1 after describing itself on stdout, and
// that description is what the caller needs.
func (c *windowsEgressRouteCommander) run(script string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), windowsCommandTimeout)
	defer cancel()
	command := exec.CommandContext(ctx, "powershell.exe",
		"-NoProfile", "-NonInteractive", "-Command", script)
	var stdout, stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	err := command.Run()
	output := stdout.String()
	if ctx.Err() != nil {
		return output, fmt.Errorf("powershell did not finish: %w", ctx.Err())
	}
	if err != nil && strings.TrimSpace(output) == "" {
		detail := strings.TrimSpace(stderr.String())
		if detail == "" {
			return output, err
		}
		return output, fmt.Errorf("%w: %s", err, detail)
	}
	return output, err
}
