package com.theshuai.specusclient.peer;

import com.theshuai.common.peeregress.Ipv4Cidr;
import com.theshuai.common.peeregress.Ipv6Cidr;
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

    /** Reads the IPv6 main table ({@code protocol/spec/peer-egress.md}, IPv6 数据面). */
    public static List<String> showMainTableArgs6() {
        return List.of("ip", "-6", "route", "show", "table", "main");
    }

    /**
     * An {@code ip route} command for a prefix or address of either family: {@code ip route ...} for
     * IPv4, exactly as it always was, and {@code ip -6 route ...} for IPv6. Argv entries, so nothing
     * here is ever seen by a shell.
     */
    public static List<String> routeArgs(String target, String... args) {
        List<String> command = new ArrayList<>(target != null && target.indexOf(':') >= 0
                ? List.of("ip", "-6", "route") : List.of("ip", "route"));
        command.addAll(List.of(args));
        return List.copyOf(command);
    }

    /**
     * The spec's {@code ip -6 address add <address>/128 dev <tun>}, which gives the TUN the device's
     * derived address. Add rather than replace: the interface was created a moment ago and dies with
     * the descriptor, so an address already on it is not this run's.
     */
    public static List<String> assignAddress6Args(String device, String address) {
        return List.of("ip", "-6", "address", "add", address + "/128", "dev", device);
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
        return parseRouteTable(output, false);
    }

    /**
     * Reads {@code ip -6 route show table main} the same way: the layout is the same, the
     * destinations and gateways are IPv6. A gateway is usually link-local; it is kept as written,
     * since {@code ip -6 route add ... via fe80::1 dev eth0} names the interface that scopes it.
     * Each reader is only ever given its own family's table, and reads the other's rows as nothing.
     */
    public static List<PeerEgressSocketBinding.Route> parseRouteTable6(String output) {
        return parseRouteTable(output, true);
    }

    private static List<PeerEgressSocketBinding.Route> parseRouteTable(String output, boolean ipv6) {
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
                        if ("via".equals(fields[index]) && gateway(fields[index + 1], ipv6)) {
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
            String prefix = ipv6 ? prefixOf6(fields[start]) : prefixOf(fields[start]);
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
                        if (gateway(fields[index + 1], ipv6)) {
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

    /** Whether a {@code via} names a next hop of the table's family. */
    private static boolean gateway(String text, boolean ipv6) {
        if (!ipv6) {
            return Ipv4Cidr.parseAddress(text) != null;
        }
        long[] address = Ipv6Cidr.parseAddress(text);
        // An IPv4-mapped address is no IPv6 next hop.
        return address != null && !(address[0] == 0 && (address[1] >>> 32) == 0xFFFFL);
    }

    /**
     * An IPv6 destination of {@code ip -6 route}: "default" is ::/0, a bare address a /128, and the
     * prefix is written the way this feature writes its own, so a row for a route it installed
     * compares equal to the journal's entry.
     */
    private static String prefixOf6(String text) {
        if ("default".equals(text)) {
            return "::/0";
        }
        int slash = text.indexOf('/');
        long[] address = Ipv6Cidr.parseAddress(slash < 0 ? text : text.substring(0, slash));
        if (address == null) {
            return null;
        }
        int length = Ipv6Cidr.MAX_PREFIX;
        if (slash >= 0) {
            try {
                length = Integer.parseInt(text.substring(slash + 1));
            } catch (NumberFormatException notALength) {
                return null;
            }
            if (length < 0 || length > Ipv6Cidr.MAX_PREFIX) {
                return null;
            }
        }
        long highMask = length <= 0 ? 0 : length >= 64 ? -1L : -1L << (64 - length);
        long lowMask = length <= 64 ? 0 : length >= 128 ? -1L : -1L << (128 - length);
        return Ipv6Cidr.formatAddress(address[0] & highMask, address[1] & lowMask) + "/" + length;
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
