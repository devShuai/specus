package com.theshuai.specusclient.peer;

import com.theshuai.common.peeregress.Ipv4Cidr;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Choosing the interface an egress socket is bound to, and reading the tables that choice is made
 * from.
 *
 * <p>The egress opens a real socket to the target on a consumer's behalf. If that socket followed
 * this node's own tunnel routes -- which a node that is also a consumer has, for its own rules --
 * the forwarded traffic would go back into the mesh instead of out of the machine. On Windows and
 * macOS the socket is bound to the interface the operating system would have picked had the
 * tunnel's routes not been there: {@code IP_UNICAST_IF} and {@code IP_BOUND_IF}. Neither needs
 * elevation, and the stack enforces both -- bound to an interface with no route to the destination,
 * connect fails rather than leaving by another one. That is also why the interface has to be chosen
 * per destination: binding everything to the default route's interface would break every target
 * reached through a second NIC or another VPN.
 *
 * <p>Everything here is pure and pinned by {@code protocol/test-vectors/peer-egress-socket-binding-v1.json};
 * the calls that fetch the tables and set the options are in {@link PeerEgressSocketBinder}.
 */
public final class PeerEgressSocketBinding {

    /** {@code IP_UNICAST_IF}, at level {@code IPPROTO_IP}. */
    public static final int WINDOWS_IP_UNICAST_IF = 31;
    /** {@code IP_BOUND_IF}, at level {@code IPPROTO_IP}. */
    public static final int MACOS_IP_BOUND_IF = 25;
    public static final int IPPROTO_IP = 0;

    /**
     * The layouts of MIB_IPFORWARD_ROW2 and MIB_IPINTERFACE_ROW on 64-bit Windows, measured against
     * Get-NetRoute and Get-NetIPInterface and checked against them again on every Windows CI run.
     */
    static final int WINDOWS_TABLE_HEADER = 8;
    static final int WINDOWS_FORWARD_ROW_SIZE = 104;
    static final int WINDOWS_INTERFACE_ROW_SIZE = 168;
    private static final int FORWARD_INTERFACE_INDEX = 8;
    private static final int FORWARD_PREFIX_FAMILY = 12;
    private static final int FORWARD_PREFIX_ADDRESS = 16;
    private static final int FORWARD_PREFIX_LENGTH = 40;
    private static final int FORWARD_METRIC = 84;
    private static final int INTERFACE_FAMILY = 0;
    private static final int INTERFACE_INDEX = 16;
    private static final int INTERFACE_METRIC = 148;
    private static final int INTERFACE_CONNECTED = 156;
    private static final int INTERFACE_DISABLE_DEFAULT_ROUTES = 166;
    private static final int AF_INET = 2;

    /**
     * A macOS route scoped to its interface. The kernel only uses one for a socket already bound to
     * that interface, so for choosing one it is not a candidate.
     */
    private static final String MACOS_SCOPED_FLAG = "I";

    private PeerEgressSocketBinding() {
    }

    /**
     * One route considered for the interface.
     *
     * @param iface the decimal interface index on Windows, the interface name on macOS
     * @param metric the effective metric: on Windows the route's plus its interface's, on macOS zero
     * @param usable false for a route the system would not use for an unbound socket
     */
    public record Route(String prefix, String iface, long metric, boolean usable) {
    }

    public record WindowsForwardRow(long interfaceIndex, String prefix, long metric) {
    }

    public record WindowsInterfaceRow(long interfaceIndex, long metric, boolean connected,
            boolean disableDefaultRoutes) {
    }

    /**
     * The interface for a socket to destination with the tunnel's routes left out, or null when
     * nothing else leads there.
     *
     * <p>Longest prefix, then the lowest metric, then the route listed first. The tunnel is compared
     * by exact equality -- utun30 is not utun3 -- and an empty tunnel leaves nothing out. Null means
     * the dial is refused rather than left unbound, because an unbound socket is exactly the one
     * that would follow the tunnel route.
     */
    public static String select(List<Route> routes, String tunnel, String destination) {
        Integer address = Ipv4Cidr.parseAddress(destination);
        if (address == null) {
            return null;
        }
        Route best = null;
        int bestBits = -1;
        for (Route route : routes) {
            if (!route.usable() || (tunnel != null && !tunnel.isEmpty() && route.iface().equals(tunnel))) {
                continue;
            }
            Ipv4Cidr prefix = Ipv4Cidr.parse(route.prefix());
            if (prefix == null || !prefix.contains(address)) {
                continue;
            }
            int bits = prefix.prefixLength();
            // Strictly better only, so a full tie keeps the route listed first.
            if (bits > bestBits || (bits == bestBits && route.metric() < best.metric())) {
                best = route;
                bestBits = bits;
            }
        }
        return best == null ? null : best.iface();
    }

    /**
     * Cuts a MIB table into rows: a ULONG count, padding to offset 8, then the rows. Null when the
     * buffer is shorter than the count claims -- reading the rows it does hold would be reading a
     * table that is not the one the system returned.
     */
    private static List<ByteBuffer> rows(byte[] raw, int size) {
        if (raw == null || raw.length < WINDOWS_TABLE_HEADER) {
            return null;
        }
        long count = ByteBuffer.wrap(raw).order(ByteOrder.LITTLE_ENDIAN).getInt(0) & 0xFFFFFFFFL;
        if (raw.length < WINDOWS_TABLE_HEADER + count * size) {
            return null;
        }
        List<ByteBuffer> rows = new ArrayList<>((int) count);
        for (int i = 0; i < count; i++) {
            rows.add(ByteBuffer.wrap(raw, WINDOWS_TABLE_HEADER + i * size, size).slice()
                    .order(ByteOrder.LITTLE_ENDIAN));
        }
        return rows;
    }

    /** The IPv4 rows of a MIB_IPFORWARD_TABLE2, prefixes masked. Null when the table is refused. */
    public static List<WindowsForwardRow> parseWindowsForwardTable(byte[] raw) {
        List<ByteBuffer> rows = rows(raw, WINDOWS_FORWARD_ROW_SIZE);
        if (rows == null) {
            return null;
        }
        List<WindowsForwardRow> parsed = new ArrayList<>();
        for (ByteBuffer row : rows) {
            if ((row.getShort(FORWARD_PREFIX_FAMILY) & 0xFFFF) != AF_INET) {
                continue;
            }
            int length = row.get(FORWARD_PREFIX_LENGTH) & 0xFF;
            if (length > Ipv4Cidr.MAX_PREFIX) {
                continue;
            }
            // The address bytes are in network order inside a little-endian row.
            int address = ((row.get(FORWARD_PREFIX_ADDRESS) & 0xFF) << 24)
                    | ((row.get(FORWARD_PREFIX_ADDRESS + 1) & 0xFF) << 16)
                    | ((row.get(FORWARD_PREFIX_ADDRESS + 2) & 0xFF) << 8)
                    | (row.get(FORWARD_PREFIX_ADDRESS + 3) & 0xFF);
            int mask = length == 0 ? 0 : (int) (0xFFFFFFFFL << (Ipv4Cidr.MAX_PREFIX - length));
            parsed.add(new WindowsForwardRow(
                    row.getInt(FORWARD_INTERFACE_INDEX) & 0xFFFFFFFFL,
                    Ipv4Cidr.format(address & mask) + "/" + length,
                    row.getInt(FORWARD_METRIC) & 0xFFFFFFFFL));
        }
        return parsed;
    }

    /** The IPv4 rows of a MIB_IPINTERFACE_TABLE. Null when the table is refused. */
    public static List<WindowsInterfaceRow> parseWindowsInterfaceTable(byte[] raw) {
        List<ByteBuffer> rows = rows(raw, WINDOWS_INTERFACE_ROW_SIZE);
        if (rows == null) {
            return null;
        }
        List<WindowsInterfaceRow> parsed = new ArrayList<>();
        for (ByteBuffer row : rows) {
            if ((row.getShort(INTERFACE_FAMILY) & 0xFFFF) != AF_INET) {
                continue;
            }
            parsed.add(new WindowsInterfaceRow(
                    row.getInt(INTERFACE_INDEX) & 0xFFFFFFFFL,
                    row.getInt(INTERFACE_METRIC) & 0xFFFFFFFFL,
                    row.get(INTERFACE_CONNECTED) != 0,
                    row.get(INTERFACE_DISABLE_DEFAULT_ROUTES) != 0));
        }
        return parsed;
    }

    /**
     * Joins the two Windows tables into candidate routes.
     *
     * <p>Windows ranks two routes of equal length by the route's metric plus its interface's. A
     * route on an interface that is not connected is not used, nor is a default route on an
     * interface that sets DisableDefaultRoutes -- which a VPN does to keep its default from taking
     * over. A route whose interface has no IPv4 row is not used either: nothing says it is up.
     */
    public static List<Route> windowsRoutes(List<WindowsForwardRow> forward,
            List<WindowsInterfaceRow> interfaces) {
        Map<Long, WindowsInterfaceRow> byIndex = new HashMap<>();
        for (WindowsInterfaceRow row : interfaces) {
            byIndex.put(row.interfaceIndex(), row);
        }
        List<Route> routes = new ArrayList<>(forward.size());
        for (WindowsForwardRow row : forward) {
            WindowsInterfaceRow iface = byIndex.get(row.interfaceIndex());
            long metric = row.metric();
            boolean usable = false;
            if (iface != null) {
                metric += iface.metric();
                usable = iface.connected()
                        && !(row.prefix().equals("0.0.0.0/0") && iface.disableDefaultRoutes());
            }
            routes.add(new Route(row.prefix(), Long.toString(row.interfaceIndex()), metric, usable));
        }
        return routes;
    }

    /** Candidate routes from {@code netstat -rn -f inet}, as the route commander reads it. */
    public static List<Route> macosRoutes(String table) {
        List<Route> routes = new ArrayList<>();
        for (PeerEgressMacosRouteCommands.NetstatRoute row : PeerEgressMacosRouteCommands.parseTable(table)) {
            routes.add(new Route(row.prefix(), row.netif(), 0, !row.flags().contains(MACOS_SCOPED_FLAG)));
        }
        return routes;
    }

    /**
     * The {@code IP_UNICAST_IF} value: the index in network byte order. In host order setsockopt
     * refuses it outright; macOS takes the same kind of value in host order, which is why the two
     * are spelled out rather than shared.
     */
    public static byte[] windowsUnicastInterfaceOption(long index) {
        return ByteBuffer.allocate(4).order(ByteOrder.BIG_ENDIAN).putInt((int) index).array();
    }

    /** The {@code IP_BOUND_IF} value: the index as a host-order int. */
    public static byte[] macosBoundInterfaceOption(long index) {
        return ByteBuffer.allocate(4).order(ByteOrder.nativeOrder()).putInt((int) index).array();
    }
}
