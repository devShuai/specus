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
 * The Linux routing table.
 *
 * <p>Routes are added, never replaced. The installer checks for a conflict first, but
 * {@code ip route add} failing on an existing prefix is the backstop: replacing would mean quietly
 * winning an argument with the user's own routing, which phase one does not do.
 *
 * <p>Choosing between this and the Windows table lives in {@link PeerEgressRouteCommanders}.
 */
public final class LinuxPeerEgressRouteCommander implements PeerEgressRouteInstaller.Commander {

    /** How long to wait for one {@code ip} invocation before giving up on it. */
    private static final long COMMAND_TIMEOUT_SECONDS = 10;

    private final String tun;

    /**
     * Where each bypass address goes, resolved before any tunnel route exists.
     *
     * <p>Resolving again later would ask the system a question this feature has already changed the
     * answer to: once a rule's route covers the address, {@code ip route get} says "through the
     * tunnel", and installing that would route the tunnel's own transport into the tunnel.
     */
    private final Map<String, PeerEgressRouteCommands.Hop> hops = new HashMap<>();

    public LinuxPeerEgressRouteCommander(String tun) {
        this.tun = tun;
    }

    @Override
    public PeerEgressRouteInstaller.Conflict conflict(Route route) {
        String output;
        try {
            output = runForOutput(PeerEgressRouteCommands.routeArgs(route.cidr(), "show", "exact", route.cidr()));
        } catch (IOException unableToAsk) {
            // Reporting no conflict lets the add proceed, and `ip route add` refuses an existing
            // prefix anyway, so the install path still fails safe.
            return PeerEgressRouteInstaller.Conflict.none();
        }
        PeerEgressRouteCommands.ExistingRoute existing = PeerEgressRouteCommands.parseShowExact(output);
        return existing.present()
                ? new PeerEgressRouteInstaller.Conflict(true, existing.description())
                : PeerEgressRouteInstaller.Conflict.none();
    }

    @Override
    public void install(Route route) throws IOException {
        if (route.kind() == Kind.BYPASS) {
            installBypass(route);
            return;
        }
        if (tun == null || tun.trim().isEmpty()) {
            throw new IOException("no TUN interface to route into");
        }
        run(PeerEgressRouteCommands.routeArgs(route.cidr(), "add", route.cidr(), "dev", tun));
    }

    private void installBypass(Route route) throws IOException {
        String address = PeerEgressRoutePlanner.bypassAddress(route.cidr());
        boolean ipv6 = PeerEgressRoutePlanner.isIpv6(route);
        PeerEgressRouteCommands.Hop hop = hops.get(address);
        if (hop == null) {
            String output = runForOutput(PeerEgressRouteCommands.routeArgs(route.cidr(), "get", address));
            hop = PeerEgressRouteCommands.parseRouteGet(output);
            if (hop == null) {
                throw new IOException("no route to " + address + " to bypass through");
            }
            if (PeerEgressRouteCommands.hopIsDevice(hop, tun)) {
                // A rule's route covers the address, so the query can only see the tunnel. Pinning
                // the bypass there would send the transport through the thing it carries; the main
                // table, read with the tunnel left out, says where it went before. Only the main
                // table: the query followed policy routing and this reading does not.
                PeerEgressSocketBinding.Route fallback = PeerEgressSocketBinding.bypassHopFromTable(address, tun,
                        ipv6 ? this::readMainTable6 : this::readMainTable);
                hop = new PeerEgressRouteCommands.Hop(fallback.gateway(), fallback.iface());
            }
            hops.put(address, hop);
        }
        if (hop.gateway().isEmpty()) {
            run(PeerEgressRouteCommands.routeArgs(route.cidr(), "add", route.cidr(), "dev", hop.device()));
            return;
        }
        run(PeerEgressRouteCommands.routeArgs(route.cidr(), "add", route.cidr(), "via", hop.gateway(),
                "dev", hop.device()));
    }

    private List<PeerEgressSocketBinding.Route> readMainTable() throws IOException {
        return PeerEgressRouteCommands.parseRouteTable(runForOutput(PeerEgressRouteCommands.showMainTableArgs()));
    }

    /** The IPv6 main table, for an IPv6 bypass hop and the IPv6 repair. */
    private List<PeerEgressSocketBinding.Route> readMainTable6() throws IOException {
        return PeerEgressRouteCommands.parseRouteTable6(runForOutput(PeerEgressRouteCommands.showMainTableArgs6()));
    }

    @Override
    public PeerEgressRouteInstaller.Table table() throws IOException {
        return new PeerEgressRouteInstaller.Table(readMainTable(), tun);
    }

    @Override
    public PeerEgressRouteInstaller.Table table6() throws IOException {
        return new PeerEgressRouteInstaller.Table(readMainTable6(), tun);
    }

    @Override
    public void remove(Route route) throws IOException {
        hops.remove(PeerEgressRoutePlanner.bypassAddress(route.cidr()));
        run(PeerEgressRouteCommands.routeArgs(route.cidr(), "del", route.cidr()));
    }

    private void run(List<String> command) throws IOException {
        runForOutput(command);
    }

    private String runForOutput(List<String> command) throws IOException {
        ProcessBuilder builder = new ProcessBuilder(command);
        builder.redirectErrorStream(true);
        Process process = builder.start();
        String output;
        try (var stream = process.getInputStream()) {
            output = new String(stream.readAllBytes(), StandardCharsets.UTF_8);
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
        if (process.exitValue() != 0) {
            throw new IOException(String.join(" ", command) + " failed: " + output.trim());
        }
        return output;
    }
}
