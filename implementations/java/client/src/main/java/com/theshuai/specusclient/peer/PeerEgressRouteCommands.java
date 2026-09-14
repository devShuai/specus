package com.theshuai.specusclient.peer;

import com.theshuai.common.peeregress.Ipv4Cidr;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

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
     * <p>That happens once a rule's route is already installed and covers the address: asking the
     * system where to send it then answers "through the tunnel", and installing that would route
     * the tunnel's own transport into the tunnel. The commander reads the table instead.
     */
    public static boolean hopIsDevice(Hop hop, String device) {
        if (hop == null || device == null || device.trim().isEmpty()) {
            return false;
        }
        return hop.device().trim().equalsIgnoreCase(device.trim());
    }

    /** Reads the main table, for a bypass hop {@code ip route get} could not give. */
    public static List<String> showMainTableArgs() {
        return List.of("ip", "-4", "route", "show", "table", "main");
    }

    private static final Set<String> LEADS_NOWHERE = Set.of("blackhole", "unreachable", "prohibit", "throw");
    private static final Set<String> NOT_FORWARDING = Set.of("local", "broadcast", "anycast", "multicast", "nat");

    /**
     * Reads {@code ip -4 route show table main} into candidate routes.
     *
     * <p>Sampled rather than assumed, in network namespaces with a real TUN: a multipath route prints
     * its destination alone followed by indented nexthop lines, two routes on one prefix are printed
     * lowest metric first but the metric is what counts, and every line ends with a space. A route
     * that leads nowhere -- blackhole, unreachable, prohibit, throw -- stays a candidate with no
     * interface, so the address it covers is not reached some other way. The first nexthop of a
     * multipath route is the one taken; one whose next hops cannot be read is not usable. A dead
     * route is not usable; linkdown is, as the kernel uses it too.
     *
     * <p>Shared vector: {@code protocol/test-vectors/peer-egress-socket-binding-v1.json}, linux.
     */
    public static List<PeerEgressSocketBinding.Route> parseRouteTable(String output) {
        List<PeerEgressSocketBinding.Route> routes = new ArrayList<>();
        int pending = -1;
        List<Integer> deviceless = new ArrayList<>();
        for (String line : (output == null ? "" : output).split("\n", -1)) {
            if (line.isBlank()) {
                continue;
            }
            String[] fields = line.trim().split("\\s+");
            if (line.charAt(0) == ' ' || line.charAt(0) == '\t') {
                if ("nexthop".equals(fields[0]) && pending >= 0 && routes.get(pending).iface().isEmpty()) {
                    String gateway = routes.get(pending).gateway();
                    String device = "";
                    for (int index = 1; index + 1 < fields.length; index++) {
                        if ("via".equals(fields[index]) && Ipv4Cidr.parseAddress(fields[index + 1]) != null) {
                            gateway = fields[index + 1];
                        } else if ("dev".equals(fields[index])) {
                            device = fields[index + 1];
                        }
                    }
                    PeerEgressSocketBinding.Route route = routes.get(pending);
                    routes.set(pending, new PeerEgressSocketBinding.Route(route.prefix(), device, gateway,
                            route.metric(), route.usable()));
                }
                continue;
            }
            pending = -1;
            if (NOT_FORWARDING.contains(fields[0])) {
                continue;
            }
            boolean nowhere = LEADS_NOWHERE.contains(fields[0]);
            int start = nowhere ? 1 : 0;
            if (start >= fields.length) {
                continue;
            }
            String prefix = prefixOf(fields[start]);
            if (prefix == null) {
                continue;
            }
            String device = "";
            String gateway = "";
            long metric = 0;
            boolean usable = true;
            for (int index = start + 1; index < fields.length; index++) {
                if ("dead".equals(fields[index])) {
                    usable = false;
                }
                if (index + 1 >= fields.length) {
                    continue;
                }
                switch (fields[index]) {
                    case "via" -> {
                        if (Ipv4Cidr.parseAddress(fields[index + 1]) != null) {
                            gateway = fields[index + 1];
                        }
                    }
                    case "dev" -> device = fields[index + 1];
                    case "metric" -> {
                        try {
                            metric = Long.parseLong(fields[index + 1]);
                        } catch (NumberFormatException ignored) {
                            // Not a number: the default of 0 stands, as it does when absent.
                        }
                    }
                    default -> {
                    }
                }
            }
            if (nowhere) {
                device = "";
                gateway = "";
            } else if (device.isEmpty()) {
                pending = routes.size();
                deviceless.add(pending);
            }
            routes.add(new PeerEgressSocketBinding.Route(prefix, device, gateway, metric, usable));
        }
        for (int index : deviceless) {
            PeerEgressSocketBinding.Route route = routes.get(index);
            if (route.iface().isEmpty()) {
                routes.set(index, new PeerEgressSocketBinding.Route(route.prefix(), "", route.gateway(),
                        route.metric(), false));
            }
        }
        return routes;
    }

    private static String prefixOf(String text) {
        if ("default".equals(text)) {
            return "0.0.0.0/0";
        }
        int slash = text.indexOf('/');
        Integer address = Ipv4Cidr.parseAddress(slash < 0 ? text : text.substring(0, slash));
        if (address == null) {
            return null;
        }
        int length = 32;
        if (slash >= 0) {
            try {
                length = Integer.parseInt(text.substring(slash + 1));
            } catch (NumberFormatException notALength) {
                return null;
            }
            if (length < 0 || length > 32) {
                return null;
            }
        }
        int mask = length == 0 ? 0 : (int) (0xFFFFFFFFL << (32 - length));
        return Ipv4Cidr.format(address & mask) + "/" + length;
    }
}
