package com.theshuai.specusclient.peer;

import com.theshuai.specusclient.peer.PeerEgressRoutePlanner.Kind;
import com.theshuai.specusclient.peer.PeerEgressRoutePlanner.Route;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

/**
 * The Windows routing table.
 *
 * <p>Routes are added, never replaced, same as Linux: the installer checks for a conflict
 * first, and {@code New-NetRoute} failing on an existing prefix is the backstop.
 *
 * <p>Everything this class sends and reads is built and parsed by
 * {@link PeerEgressWindowsRouteCommands}, which three runtimes share and
 * {@code peer-egress-windows-routes-v1.json} pins. What is left here is running the process and
 * caching what does not need asking twice.
 */
public final class WindowsPeerEgressRouteCommander implements PeerEgressRouteInstaller.Commander {

    /**
     * How long to wait for one PowerShell invocation.
     *
     * <p>The same ten seconds Linux allows {@code ip}, even though a PowerShell process is three
     * orders of magnitude more expensive to start: the point of the limit is to catch a hang, not
     * to police a budget.
     */
    private static final long COMMAND_TIMEOUT_SECONDS = 10;

    /**
     * How long one read of the whole routing table answers for.
     *
     * <p>The conflict check is asked once per prefix being added, and reading the table per prefix
     * would cost 419 ms each. Caching it turns one apply into one read. The lifetime is what keeps
     * that from becoming a stale answer across applies: within a single apply the cache holds,
     * between applies it is certainly gone. An apply that runs longer than this pays for one extra
     * read, which is a slowdown rather than a wrong answer -- while an unbounded cache would
     * eventually miss a route somebody else installed hours ago and turn a refusable conflict into
     * a failed install that rolls the whole plan back.
     */
    private static final Duration TABLE_CACHE_LIFETIME = Duration.ofSeconds(5);

    private final String tun;

    /**
     * The interface index for {@link #tun}, resolved once.
     *
     * <p>Routing needs the index and the client only has the name, and the name cannot be sent back
     * out of PowerShell safely -- see the note in {@link PeerEgressWindowsRouteCommands}.
     */
    private int tunIndex;

    /** One read of the whole routing table, and when it was taken. */
    private String table = "";
    private long tableAtNanos;

    /**
     * Where each bypass address goes, resolved before any tunnel route exists.
     *
     * <p>Resolved one address at a time rather than in one batch, unlike the conflict check. The
     * bypass list is the control endpoint, STUN, TURN and the peer addresses -- single digits in
     * practice -- and each one is resolved once and then cached. Batching them would mean the
     * installer telling the commander what is coming, which is a change to an interface three
     * runtimes and their tests share. Worth revisiting if the list ever grows with the mesh.
     */
    private final Map<String, PeerEgressWindowsRouteCommands.Hop> hops = new HashMap<>();

    public WindowsPeerEgressRouteCommander(String tun) {
        this.tun = tun;
    }

    @Override
    public PeerEgressRouteInstaller.Conflict conflict(Route route) {
        if (table.isEmpty()
                || System.nanoTime() - tableAtNanos > TABLE_CACHE_LIFETIME.toNanos()) {
            String output;
            try {
                output = run(PeerEgressWindowsRouteCommands.showAllRoutesScript());
            } catch (IOException unableToAsk) {
                // Reporting no conflict lets the add proceed, and New-NetRoute refuses an
                // existing prefix anyway, so the install path still fails safe.
                return PeerEgressRouteInstaller.Conflict.none();
            }
            table = output;
            tableAtNanos = System.nanoTime();
        }
        PeerEgressRouteCommands.ExistingRoute existing =
                PeerEgressWindowsRouteCommands.conflictFromTable(table, route.cidr());
        return existing.present()
                ? new PeerEgressRouteInstaller.Conflict(true, existing.description())
                : PeerEgressRouteInstaller.Conflict.none();
    }

    @Override
    public void install(Route route) throws IOException {
        // Checked before anything is run: an argument the script builder would refuse must
        // not cost a process first, and on this platform that refusal is what keeps a prefix
        // from becoming a second command.
        if (!PeerEgressWindowsRouteCommands.validPrefix(route.cidr())) {
            throw new IOException(
                    "refusing to build a route command from this argument: " + route.cidr());
        }
        if (route.kind() == Kind.BYPASS) {
            installBypass(route);
            return;
        }
        if (tun == null || tun.trim().isEmpty()) {
            throw new IOException("no TUN interface to route into");
        }
        apply(PeerEgressWindowsRouteCommands.installRouteScript(route.cidr(), tunnelIndex(), ""),
                "install " + route.cidr());
    }

    private void installBypass(Route route) throws IOException {
        String address = route.cidr().endsWith("/32")
                ? route.cidr().substring(0, route.cidr().length() - 3)
                : route.cidr();
        PeerEgressWindowsRouteCommands.Hop hop = hops.get(address);
        if (hop == null) {
            String output = run(PeerEgressWindowsRouteCommands.findRoutesScript(List.of(address)));
            hop = PeerEgressWindowsRouteCommands.parseRouteFind(output);
            if (hop == null) {
                throw new IOException("no route to " + address + " to bypass through");
            }
            if (tunIndex > 0 && hop.interfaceIndex() == tunIndex) {
                // Pinning it to the tunnel would send the transport through the thing it
                // carries. Compared by index rather than by name, because the name is the one
                // thing that cannot come back out of PowerShell intact.
                throw new IOException("bypass for " + address + " already resolves to the tunnel");
            }
            hops.put(address, hop);
        }
        apply(PeerEgressWindowsRouteCommands.installRouteScript(
                        route.cidr(), hop.interfaceIndex(), hop.gateway()),
                "install bypass " + route.cidr());
    }

    @Override
    public void remove(Route route) throws IOException {
        if (!PeerEgressWindowsRouteCommands.validPrefix(route.cidr())) {
            throw new IOException(
                    "refusing to build a route command from this argument: " + route.cidr());
        }
        apply(PeerEgressWindowsRouteCommands.removeRouteScript(route.cidr()),
                "remove " + route.cidr());
    }

    /** Resolves the TUN adapter's interface index, once. */
    private int tunnelIndex() throws IOException {
        if (tunIndex > 0) {
            return tunIndex;
        }
        String output = run(PeerEgressWindowsRouteCommands.interfaceIndexScript(tun));
        int index = PeerEgressWindowsRouteCommands.parseInterfaceIndex(output);
        if (index <= 0) {
            throw new IOException("no adapter named " + tun + " to route into");
        }
        tunIndex = index;
        return index;
    }

    /** Runs a script whose failures come back as JSON on stdout. */
    private void apply(String script, String what) throws IOException {
        String output;
        IOException runFailure = null;
        try {
            output = run(script);
        } catch (IOException failed) {
            // Held rather than thrown: the script describes its own failures on stdout, and
            // that description is more use than the exit status that came with it.
            output = failed.getMessage() == null ? "" : failed.getMessage();
            runFailure = failed;
        }
        String failure = PeerEgressWindowsRouteCommands.parseCommandFailure(output);
        if (PeerEgressWindowsRouteCommands.FAILURE_PERMISSION_DENIED.equals(failure)) {
            // Named rather than folded into the generic failure: the fix is to run elevated, and
            // an operator retrying a permissions error learns nothing from the attempt.
            throw new IOException(what + " needs administrator rights: changing the routing table "
                    + "is not permitted for this process");
        }
        if (PeerEgressWindowsRouteCommands.FAILURE_OTHER.equals(failure)) {
            throw new IOException(what + " failed: " + output.trim());
        }
        // Nothing classified as a failure. A removal that found no such prefix lands here on
        // purpose: the route is not in the table, which is what the caller asked for.
        if (runFailure != null && output.isBlank()) {
            throw runFailure;
        }
    }

    /**
     * Executes one PowerShell script and returns its stdout.
     *
     * <p>stdout and stderr are kept apart, unlike the Linux commander which merges them. The
     * scripts catch their own failures and write them as JSON on stdout; PowerShell's own uncaught
     * errors go to stderr. Merging would splice non-JSON text into the document and every parser
     * here would see only "could not read it", which is the answer that means "no conflict, go
     * ahead".
     *
     * <p>Decoded as UTF-8 even though the child writes in the console code page. That is safe only
     * because every script selects fields that are ASCII in any code page, which is a requirement
     * the shared vector asserts rather than a coincidence.
     */
    private String run(String script) throws IOException {
        ProcessBuilder builder = new ProcessBuilder(
                "powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script);
        Process process = builder.start();
        String output;
        try (var stream = process.getInputStream()) {
            output = new String(stream.readAllBytes(), StandardCharsets.US_ASCII);
        }
        boolean finished;
        try {
            finished = process.waitFor(COMMAND_TIMEOUT_SECONDS, TimeUnit.SECONDS);
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
            process.destroyForcibly();
            throw new IOException("powershell was interrupted", interrupted);
        }
        if (!finished) {
            process.destroyForcibly();
            throw new IOException("powershell did not finish");
        }
        if (process.exitValue() != 0 && output.isBlank()) {
            // Exit codes are not consulted otherwise. A script that failed exits 1 after
            // describing itself on stdout, and that description is what the caller needs.
            throw new IOException(
                    "powershell exited " + process.exitValue() + ": " + stderr(process));
        }
        return output;
    }

    private static String stderr(Process process) {
        try (var stream = process.getErrorStream()) {
            return new String(stream.readAllBytes(), StandardCharsets.UTF_8).trim();
        } catch (IOException unreadable) {
            return "";
        }
    }
}
