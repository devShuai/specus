package com.theshuai.specusclient.peer;

/**
 * Reading what the platform's routing tools say.
 *
 * <p>Kept free of any platform guard on purpose. These parsers depend on output formats nobody
 * controls, which makes them the part most likely to be wrong, and a Linux-only file would leave
 * them untested everywhere the developer and most of CI actually run.
 *
 * <p>Shared fixtures: the {@code routeCommands} section of
 * {@code protocol/test-vectors/peer-egress-routes-v1.json}.
 */
public final class PeerEgressRouteCommands {

    private PeerEgressRouteCommands() {
    }

    /**
     * Where a bypass address has to be sent to stay off the tunnel.
     *
     * @param gateway empty for an on-link destination, which is normal on a directly attached
     *                network and is not a failure to parse
     */
    public record Hop(String gateway, String device) {
    }

    /** Whether a prefix already has a route, and the line describing it. */
    public record ExistingRoute(boolean present, String description) {
    }

    /**
     * Reads one {@code ip route get <address>} line, returning null when there is no usable hop.
     *
     * <p>Two shapes matter. Through a router:
     * {@code 1.2.3.4 via 10.0.0.1 dev eth0 src 10.0.0.5 uid 1000}. Directly attached:
     * {@code 10.0.0.5 dev eth0 src 10.0.0.5}. The second has no via, and treating that as a parse
     * failure would refuse to bypass anything on the local network.
     */
    public static Hop parseRouteGet(String output) {
        if (output == null) {
            return null;
        }
        for (String line : output.split("\n", -1)) {
            String[] fields = line.trim().split("\\s+");
            if (fields.length == 0 || fields[0].isEmpty()) {
                continue;
            }
            // A destination that cannot be reached is reported as a route rather than as an error,
            // so it has to be recognised here or it would be read as one.
            if ("unreachable".equals(fields[0]) || "prohibit".equals(fields[0])
                    || "blackhole".equals(fields[0])) {
                return null;
            }
            String gateway = "";
            String device = "";
            for (int index = 0; index + 1 < fields.length; index++) {
                if ("via".equals(fields[index])) {
                    gateway = fields[index + 1];
                } else if ("dev".equals(fields[index])) {
                    device = fields[index + 1];
                }
            }
            if (!device.isEmpty()) {
                return new Hop(gateway, device);
            }
        }
        return null;
    }

    /**
     * Reads {@code ip route show exact <cidr>}.
     *
     * <p>Empty output means no route for that exact prefix, which is what lets one be installed.
     * Anything else is described back to the operator verbatim, because a summary of somebody
     * else's routing is less useful to them than the line they can go and look at.
     */
    public static ExistingRoute parseShowExact(String output) {
        if (output != null) {
            for (String line : output.split("\n", -1)) {
                String trimmed = line.trim();
                if (!trimmed.isEmpty()) {
                    return new ExistingRoute(true, trimmed);
                }
            }
        }
        return new ExistingRoute(false, "");
    }

    /**
     * Reports whether a hop leads through the named interface.
     *
     * <p>Used to refuse pinning a bypass address to the tunnel itself. That happens on a reapply,
     * once a rule's route is already installed and covers the address: asking the system where to
     * send it then answers "through the tunnel", and installing that would route the tunnel's own
     * transport into the tunnel.
     */
    public static boolean hopIsDevice(Hop hop, String device) {
        if (hop == null || device == null || device.trim().isEmpty()) {
            return false;
        }
        return hop.device().trim().equalsIgnoreCase(device.trim());
    }
}
