package com.theshuai.specusclient.peer;

import com.theshuai.specusclient.peer.PeerEgressRoutePlanner.Kind;
import com.theshuai.specusclient.peer.PeerEgressRoutePlanner.Route;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

/**
 * The macOS routing table.
 *
 * <p>Routes are added, never replaced, same as Linux and Windows: the installer checks for a
 * conflict first, and {@code route add} refusing an existing prefix is the backstop.
 *
 * <p>Choosing between this and the other two lives in {@link PeerEgressRouteCommanders}.
 */
public final class MacosPeerEgressRouteCommander implements PeerEgressRouteInstaller.Commander {

    /**
     * How long to wait for one {@code route} or {@code netstat} invocation.
     *
     * <p>The same ten seconds Linux allows {@code ip}, and for the same reason: it is there to
     * catch a hang, not to police a budget. The readings themselves have a median of 25 ms.
     */
    private static final long COMMAND_TIMEOUT_SECONDS = 10;

    private final String tun;

    /**
     * Where each bypass address goes, resolved before any tunnel route exists.
     *
     * <p>Resolving again later would ask the system a question this feature has already changed the
     * answer to: once a rule's route covers the address, {@code route -n get} answers "through the
     * tunnel", and installing that would route the tunnel's own transport into the tunnel.
     */
    private final Map<String, PeerEgressRouteCommands.Hop> hops = new HashMap<>();

    public MacosPeerEgressRouteCommander(String tun) {
        this.tun = tun;
    }

    /**
     * Reads the whole table, every time it is asked.
     *
     * <p>No cache, which is where this parts company with the Windows commander. That one holds one
     * read for five seconds because a PowerShell query costs 419 ms and a plan of twenty prefixes
     * would otherwise spend eight seconds asking. Here {@code netstat -rn -f inet} has a median of
     * 25 ms against 3 ms for a process that does nothing, so twenty reads cost half a second: a
     * cache would buy a saving that is not there, in exchange for a window in which the answer is
     * stale.
     *
     * <p>The whole table rather than a query per prefix because there is no query per prefix to
     * make. {@code route -n get} does a longest-prefix lookup, so on any machine with a default
     * route it answers "yes, reachable" for every prefix nobody owns.
     */
    @Override
    public PeerEgressRouteInstaller.Conflict conflict(Route route) {
        Result result;
        try {
            result = run(PeerEgressMacosRouteCommands.showTableArgs());
        } catch (IOException unableToAsk) {
            // Reporting no conflict lets the add proceed, and `route add` refuses an existing
            // prefix anyway, so the install path still fails safe.
            return PeerEgressRouteInstaller.Conflict.none();
        }
        PeerEgressRouteCommands.ExistingRoute existing =
                PeerEgressMacosRouteCommands.conflictFromTable(result.stdout(), route.cidr());
        return existing.present()
                ? new PeerEgressRouteInstaller.Conflict(true, existing.description())
                : PeerEgressRouteInstaller.Conflict.none();
    }

    @Override
    public void install(Route route) throws IOException {
        // Checked before anything is run. On this platform that check is not defence in depth: a
        // prefix of 203.0.113.0/33 is accepted by `route`, which prints a success line naming
        // 203.0.113.0, exits 0, and installs 128.0/1 -- half the IPv4 address space pointed at the
        // gateway. Nothing in the output says so, so nothing downstream could catch it.
        if (!PeerEgressMacosRouteCommands.validPrefix(route.cidr())) {
            throw new IllegalArgumentException(
                    PeerEgressMacosRouteCommands.REFUSAL + ": " + route.cidr());
        }
        if (route.kind() == Kind.BYPASS) {
            installBypass(route);
            return;
        }
        if (tun == null || tun.trim().isEmpty()) {
            throw new IOException("no TUN interface to route into");
        }
        apply(PeerEgressMacosRouteCommands.installInterfaceArgs(route.cidr(), tun),
                "install " + route.cidr());
    }

    /**
     * Pins one address to the physical path.
     *
     * <p>The TUN has to carry an IPv4 address before any route can point at it, which is a macOS
     * requirement rather than a general one: the same {@code route add -net ... -interface utun3}
     * reports "Network is unreachable" while that interface has only a link-local IPv6 address, and
     * succeeds once it has an IPv4 one. Nothing here enforces it -- the caller brings the interface
     * up before applying a plan -- but it is why an install can fail in a way that is neither a
     * conflict nor a permissions problem.
     */
    private void installBypass(Route route) throws IOException {
        String address = route.cidr().endsWith("/32")
                ? route.cidr().substring(0, route.cidr().length() - 3)
                : route.cidr();
        PeerEgressRouteCommands.Hop hop = hops.get(address);
        if (hop == null) {
            Result result = run(PeerEgressMacosRouteCommands.findRouteArgs(address));
            hop = PeerEgressMacosRouteCommands.parseRouteGet(result.stdout(), result.stderr());
            if (hop == null) {
                throw new IOException("no route to " + address + " to bypass through");
            }
            if (PeerEgressRouteCommands.hopIsDevice(hop, tun)) {
                // Pinning it to the tunnel would send the transport through the thing it carries.
                throw new IOException("bypass for " + address + " already resolves to the tunnel");
            }
            hops.put(address, hop);
        }
        List<String> command = hop.gateway().isEmpty()
                ? PeerEgressMacosRouteCommands.installInterfaceArgs(route.cidr(), hop.device())
                : PeerEgressMacosRouteCommands.installGatewayArgs(route.cidr(), hop.gateway());
        apply(command, "install bypass " + route.cidr());
    }

    @Override
    public void remove(Route route) throws IOException {
        apply(PeerEgressMacosRouteCommands.removeArgs(route.cidr()), "remove " + route.cidr());
    }

    /**
     * Runs a mutation and decides whether it worked.
     *
     * <p>The exit status is not consulted, because {@code route} returns 0 when it fails: for a
     * prefix that already exists, for a prefix that is not in the table, for an interface with no
     * address and for a missing argument. Only a malformed address gets a non-zero status. What it
     * does do is leave stderr empty on success.
     */
    private void apply(List<String> command, String what) throws IOException {
        Result result = run(command);
        String failure = PeerEgressMacosRouteCommands.classifyFailure(result.stdout(),
                result.stderr());
        if (PeerEgressMacosRouteCommands.FAILURE_PERMISSION_DENIED.equals(failure)) {
            // Named rather than folded into the generic failure: the fix is to run elevated, and
            // an operator retrying a permissions error learns nothing from the attempt.
            throw new IOException(what + " needs root: changing the routing table is not "
                    + "permitted for this process");
        }
        if (PeerEgressMacosRouteCommands.FAILURE_OTHER.equals(failure)) {
            String detail = result.stdout().trim();
            if (detail.isEmpty()) {
                detail = result.stderr().trim();
            }
            throw new IOException(what + " failed: " + detail);
        }
        // Nothing classified as a failure. A removal that found no such prefix lands here on
        // purpose: the route is not in the table, which is what the caller asked for.
    }

    /** What one command said, with the two streams kept apart. */
    private record Result(String stdout, String stderr) {
    }

    /**
     * Runs one command and returns both streams.
     *
     * <p>Not merged, unlike the Linux commander. The classification depends on which stream said
     * what: {@code route} annotates the operation on stdout and names the error on stderr, and
     * every successful mutation leaves stderr empty. Merging them would throw away the only signal
     * that separates a failed add from a successful one on a platform where both exit 0.
     *
     * <p>The streams are read one after the other rather than by a reader each, which is safe
     * because of what these two commands write: {@code route} puts at most a line on stderr and
     * {@code netstat} puts nothing there, orders of magnitude below the pipe buffer. A command that
     * could fill that buffer while this was still draining stdout would need a thread per stream.
     *
     * <p>Decoded as ASCII. Everything read here -- prefixes, addresses, flags, interface names --
     * is ASCII, and an interface name that is not would be refused by the argument check long
     * before it could reach this.
     */
    private Result run(List<String> command) throws IOException {
        Process process = new ProcessBuilder(command).start();
        String stdout;
        String stderr;
        try (var out = process.getInputStream(); var err = process.getErrorStream()) {
            stdout = new String(out.readAllBytes(), StandardCharsets.US_ASCII);
            stderr = new String(err.readAllBytes(), StandardCharsets.US_ASCII);
        }
        boolean finished;
        try {
            finished = process.waitFor(COMMAND_TIMEOUT_SECONDS, TimeUnit.SECONDS);
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
            process.destroyForcibly();
            throw new IOException(String.join(" ", command) + " was interrupted", interrupted);
        }
        if (!finished) {
            process.destroyForcibly();
            throw new IOException(String.join(" ", command) + " did not finish");
        }
        return new Result(stdout, stderr);
    }
}
