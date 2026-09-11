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
            output = runForOutput(List.of("ip", "route", "show", "exact", route.cidr()));
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
        run(List.of("ip", "route", "add", route.cidr(), "dev", tun));
    }

    private void installBypass(Route route) throws IOException {
        String address = route.cidr().endsWith("/32")
                ? route.cidr().substring(0, route.cidr().length() - 3)
                : route.cidr();
        PeerEgressRouteCommands.Hop hop = hops.get(address);
        if (hop == null) {
            String output = runForOutput(List.of("ip", "route", "get", address));
            hop = PeerEgressRouteCommands.parseRouteGet(output);
            if (hop == null) {
                throw new IOException("no route to " + address + " to bypass through");
            }
            if (PeerEgressRouteCommands.hopIsDevice(hop, tun)) {
                // Pinning it to the tunnel would send the transport through the thing it carries.
                throw new IOException("bypass for " + address + " already resolves to the tunnel");
            }
            hops.put(address, hop);
        }
        if (hop.gateway().isEmpty()) {
            run(List.of("ip", "route", "add", route.cidr(), "dev", hop.device()));
            return;
        }
        run(List.of("ip", "route", "add", route.cidr(), "via", hop.gateway(), "dev", hop.device()));
    }

    @Override
    public void remove(Route route) throws IOException {
        run(List.of("ip", "route", "del", route.cidr()));
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
