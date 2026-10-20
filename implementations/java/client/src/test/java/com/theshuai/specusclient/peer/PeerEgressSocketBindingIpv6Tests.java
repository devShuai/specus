package com.theshuai.specusclient.peer;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.theshuai.common.peeregress.Ipv6Cidr;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * Binding egress sockets to IPv6 targets ({@code protocol/spec/peer-egress.md}, IPv6 数据面, 出站
 * socket), from synthetic tables on every platform. The choice and the option encodings are not in
 * {@code peer-egress-socket-binding-v1.json} yet; the real-table and real-socket halves are in
 * {@link PeerEgressSocketBinderTests}.
 */
class PeerEgressSocketBindingIpv6Tests {

    private static PeerEgressSocketBinding.Route route(String prefix, String iface, long metric, boolean usable) {
        return new PeerEgressSocketBinding.Route(prefix, iface, "", metric, usable);
    }

    /**
     * The IPv6 choice follows the IPv4 rules -- longest prefix, then metric, then the route listed
     * first, the tunnel and unusable routes left out -- and never mixes the families.
     */
    @Test
    void ipv6RoutesAreSelectedByTheSameRules() {
        List<PeerEgressSocketBinding.Route> routes = List.of(
                route("0.0.0.0/0", "4", 0, true),
                route("::/0", "3", 50, true),
                route("::/0", "5", 20, true),
                route("2001:db8::/32", "6", 99, true),
                route("2001:db8:1::/48", "tun", 0, true),
                route("2001:db8:2::/48", "7", 0, false),
                route("2001:db8:3::/48", "8", 5, true),
                route("2001:db8:3::/48", "9", 5, true));
        Map<String, String> want = new LinkedHashMap<>();
        want.put("2400:cb00::1", "5"); // the default with the lower metric
        want.put("2001:db8:9::1", "6"); // a longer prefix beats a lower metric
        want.put("2001:db8:1::c8", "6"); // the tunnel's /48 is left out
        want.put("2001:db8:2::1", "6"); // so is an unusable route
        want.put("2001:db8:3::1", "8"); // a full tie keeps the route listed first
        want.put("203.0.113.10", "4"); // an IPv4 destination sees only IPv4 routes
        want.put("::ffff:10.0.0.1", null); // an IPv4-mapped destination is neither
        want.put("::ffff:a00:1", null); // in either spelling
        want.put("fe80::1%eth0", null); // nor is a zoned one
        for (Map.Entry<String, String> entry : want.entrySet()) {
            assertEquals(entry.getValue(), PeerEgressSocketBinding.select(routes, "tun", entry.getKey()), entry.getKey());
        }
        // ::/0 does not cover an IPv4 destination, nor 0.0.0.0/0 an IPv6 one.
        assertNull(PeerEgressSocketBinding.select(List.of(route("::/0", "3", 0, true)), "", "203.0.113.10"));
        assertNull(PeerEgressSocketBinding.select(List.of(route("0.0.0.0/0", "4", 0, true)), "", "2001:db8::1"));
    }

    /**
     * The binder reads the table of the target's family, and with nothing outside the tunnel refuses
     * the dial as it does for IPv4, rather than leaving the socket unbound.
     */
    @Test
    void theBinderChoosesFromTheTargetsFamily() throws IOException {
        PeerEgressSocketBinder binder = new PeerEgressSocketBinder(() -> "utun3",
                () -> List.of(route("0.0.0.0/0", "en0", 0, true)),
                () -> List.of(route("::/0", "en1", 0, true), route("2001:db8:1::/48", "utun3", 0, true)),
                name -> name, (handle, iface, ipv6) -> { }, null);
        assertEquals("en0", binder.choose("203.0.113.10"));
        assertEquals("en1", binder.choose("2001:db8::10"));
        // The tunnel's own route covers it, so the default outside the tunnel is what is left.
        assertEquals("en1", binder.choose("2001:db8:1::c8"));

        binder.routes6 = () -> List.of(route("::/0", "utun3", 0, true));
        assertInstanceOf(PeerEgressSocketBinder.NoPhysicalRouteException.class,
                assertThrows(IOException.class, () -> binder.choose("2001:db8::10")),
                "only the tunnel leads there");
        binder.routes6 = null;
        IOException missing = assertThrows(IOException.class, () -> binder.choose("2001:db8::10"),
                "a binder without an IPv6 table reader chose an interface for an IPv6 target");
        assertFalse(missing instanceof PeerEgressSocketBinder.NoPhysicalRouteException);
        // The IPv4 choice does not need the IPv6 reader.
        assertEquals("en0", binder.choose("203.0.113.10"));
    }

    /**
     * The binder hands the applier the family of the socket it binds, so the IPv6 option goes on an
     * IPv6 socket and the IPv4 one on an IPv4 socket. Real channels, nothing connects.
     */
    @Test
    void theApplierIsToldTheFamily() throws IOException {
        List<String> applied = new ArrayList<>();
        PeerEgressSocketBinder binder = new PeerEgressSocketBinder(() -> "",
                () -> List.of(route("0.0.0.0/0", "4", 0, true)),
                () -> List.of(route("::/0", "6", 0, true)),
                name -> name, (handle, iface, ipv6) -> applied.add(iface + (ipv6 ? " ipv6" : " ipv4")), null);
        assertTrue(binder.binds());
        try (var stream = java.nio.channels.SocketChannel.open(java.net.StandardProtocolFamily.INET)) {
            binder.bind(stream, new java.net.InetSocketAddress("203.0.113.10", 443));
        }
        try (var stream = java.nio.channels.SocketChannel.open(java.net.StandardProtocolFamily.INET6)) {
            binder.bind(stream, new java.net.InetSocketAddress("2001:db8::10", 443));
        } catch (UnsupportedOperationException noIpv6) {
            applied.add("6 ipv6"); // A JVM without IPv6 sockets has nothing to bind; the choice is covered above.
        }
        assertEquals(List.of("4 ipv4", "6 ipv6"), applied);
    }

    /** One MIB_IPFORWARD_ROW2 the way GetIpForwardTable2(AF_INET6) lays it out. */
    private static byte[] forwardRow6(long index, String prefix, String nextHop, long metric) {
        ByteBuffer row = ByteBuffer.allocate(PeerEgressSocketBinding.WINDOWS_FORWARD_ROW_SIZE).order(ByteOrder.LITTLE_ENDIAN);
        Ipv6Cidr cidr = Ipv6Cidr.parse(prefix);
        assertNotNull(cidr, prefix);
        row.putInt(8, (int) index);
        row.putShort(12, (short) PeerEgressSocketBinding.AF_INET6);
        putAddress(row, 20, cidr.high(), cidr.low());
        row.put(40, (byte) cidr.prefixLength());
        row.putShort(44, (short) PeerEgressSocketBinding.AF_INET6);
        long[] hop = Ipv6Cidr.parseAddress(nextHop);
        putAddress(row, 52, hop[0], hop[1]);
        row.putInt(84, (int) metric);
        return row.array();
    }

    private static void putAddress(ByteBuffer row, int offset, long high, long low) {
        for (int index = 0; index < 8; index++) {
            row.put(offset + index, (byte) (high >>> (56 - 8 * index)));
            row.put(offset + 8 + index, (byte) (low >>> (56 - 8 * index)));
        }
    }

    private static byte[] interfaceRow(int family, long index, long metric, boolean connected, boolean disableDefault) {
        ByteBuffer row = ByteBuffer.allocate(PeerEgressSocketBinding.WINDOWS_INTERFACE_ROW_SIZE).order(ByteOrder.LITTLE_ENDIAN);
        row.putShort(0, (short) family);
        row.putInt(16, (int) index);
        row.putInt(148, (int) metric);
        row.put(156, (byte) (connected ? 1 : 0));
        row.put(166, (byte) (disableDefault ? 1 : 0));
        return row.array();
    }

    private static byte[] table(byte[]... rows) {
        int size = rows.length == 0 ? 0 : rows[0].length;
        ByteBuffer table = ByteBuffer.allocate(PeerEgressSocketBinding.WINDOWS_TABLE_HEADER + rows.length * size)
                .order(ByteOrder.LITTLE_ENDIAN);
        table.putInt(0, rows.length);
        for (int index = 0; index < rows.length; index++) {
            table.put(PeerEgressSocketBinding.WINDOWS_TABLE_HEADER + index * size, rows[index]);
        }
        return table.array();
    }

    /**
     * The IPv6 rows of the two Windows tables: the address eight bytes into its SOCKADDR_IN6, a
     * length up to 128, each interface's IPv6 row on its own, and DisableDefaultRoutes applied to ::/0.
     */
    @Test
    void windowsIpv6TablesParse() {
        byte[] ipv4Row = new byte[PeerEgressSocketBinding.WINDOWS_FORWARD_ROW_SIZE];
        ByteBuffer.wrap(ipv4Row).order(ByteOrder.LITTLE_ENDIAN).putShort(12, (short) PeerEgressSocketBinding.AF_INET);
        byte[] tooLong = forwardRow6(3, "2001:db8::/64", "::", 0);
        tooLong[40] = (byte) 129;
        byte[] hostBits = forwardRow6(3, "2001:db8:5::/64", "::", 7);
        hostBits[20 + 15] = 1;

        var forward = PeerEgressSocketBinding.parseWindowsForwardTable6(table(
                forwardRow6(3, "::/0", "fe80::1", 0),
                forwardRow6(3, "2001:db8::/32", "::", 256),
                forwardRow6(1, "::1/128", "::", 256),
                forwardRow6(7, "2001:db8:7::/48", "::", 16),
                forwardRow6(9, "::/0", "fe80::9", 0),
                forwardRow6(11, "2001:db8:11::/48", "::", 0),
                ipv4Row, tooLong, hostBits));
        assertNotNull(forward, "the forward table did not parse");
        var interfaces = PeerEgressSocketBinding.parseWindowsInterfaceTable6(table(
                interfaceRow(PeerEgressSocketBinding.AF_INET, 3, 99, true, false),
                interfaceRow(PeerEgressSocketBinding.AF_INET6, 3, 20, true, false),
                interfaceRow(PeerEgressSocketBinding.AF_INET6, 1, 75, true, false),
                interfaceRow(PeerEgressSocketBinding.AF_INET6, 7, 5, false, false),
                interfaceRow(PeerEgressSocketBinding.AF_INET6, 9, 1, true, true)));
        assertNotNull(interfaces);
        assertEquals(4, interfaces.size(), "the interface table's IPv6 rows: " + interfaces);

        List<PeerEgressSocketBinding.Route> routes = PeerEgressSocketBinding.windowsRoutes(forward, interfaces);
        assertEquals(List.of(
                new PeerEgressSocketBinding.Route("::/0", "3", "fe80::1", 20, true),
                new PeerEgressSocketBinding.Route("2001:db8::/32", "3", "", 276, true),
                new PeerEgressSocketBinding.Route("::1/128", "1", "", 331, true),
                new PeerEgressSocketBinding.Route("2001:db8:7::/48", "7", "", 21, false),
                new PeerEgressSocketBinding.Route("::/0", "9", "fe80::9", 1, false),
                new PeerEgressSocketBinding.Route("2001:db8:11::/48", "11", "", 0, false),
                new PeerEgressSocketBinding.Route("2001:db8:5::/64", "3", "", 27, true)), routes);
        assertEquals("3", PeerEgressSocketBinding.select(routes, "", "2400:cb00::1"));

        // The IPv4 readers of the same bytes find nothing of their own.
        assertEquals(List.of(), PeerEgressSocketBinding.parseWindowsForwardTable(table(forwardRow6(3, "::/0", "::", 0))));
        assertEquals(1, PeerEgressSocketBinding.parseWindowsInterfaceTable(table(
                interfaceRow(PeerEgressSocketBinding.AF_INET, 3, 99, true, false),
                interfaceRow(PeerEgressSocketBinding.AF_INET6, 3, 20, true, false))).size());
        // A table shorter than its count is refused, as for IPv4.
        byte[] short_ = table(forwardRow6(3, "::/0", "::", 0));
        assertNull(PeerEgressSocketBinding.parseWindowsForwardTable6(java.util.Arrays.copyOf(short_, short_.length - 1)));
    }

    /** IPV6_UNICAST_IF takes the index in host order, the opposite of IP_UNICAST_IF; IPV6_BOUND_IF too. */
    @Test
    void ipv6OptionsAreHostOrder() {
        byte[] host = ByteBuffer.allocate(4).order(ByteOrder.nativeOrder()).putInt(12).array();
        assertArrayEquals(host, PeerEgressSocketBinding.windowsUnicastInterfaceOption6(12));
        assertArrayEquals(host, PeerEgressSocketBinding.macosBoundInterfaceOption(12));
        if (ByteOrder.nativeOrder() == ByteOrder.LITTLE_ENDIAN) {
            assertFalse(java.util.Arrays.equals(PeerEgressSocketBinding.windowsUnicastInterfaceOption6(12),
                    PeerEgressSocketBinding.windowsUnicastInterfaceOption(12)),
                    "the IPv6 option is encoded like the IPv4 one, in network order");
        }
        assertEquals(31, PeerEgressSocketBinding.WINDOWS_IPV6_UNICAST_IF);
        assertEquals(125, PeerEgressSocketBinding.MACOS_IPV6_BOUND_IF);
        assertEquals(41, PeerEgressSocketBinding.IPPROTO_IPV6);
    }

    /**
     * netstat -rn on macOS, both sections. Only "Internet6:" is read, destinations normalised --
     * default, host routes without a length, zones dropped -- and a route scoped to its interface is
     * not a candidate.
     */
    @Test
    void macosIpv6Routes() {
        String table = String.join("\n",
                "Routing tables",
                "",
                "Internet:",
                "Destination        Gateway            Flags               Netif Expire",
                "default            192.168.1.1        UGScg                 en0",
                "127                127.0.0.1          UCS                   lo0",
                "",
                "Internet6:",
                "Destination                             Gateway                                 Flags               Netif Expire",
                "default                                 fe80::%utun0                            UGcIg               utun0",
                "default                                 fe80::1%en0                             UGcg                  en0",
                "::1                                     ::1                                     UHL                   lo0",
                "2001:db8:1::/64                         link#6                                  UC                    en0",
                "2001:db8:1::1                           a4:83:e7:0:0:1                          UHLWIi                en0",
                "fe80::%lo0/64                           fe80::1%lo0                             UcI                   lo0",
                "fe80::1%lo0                             link#1                                  UHLI                  lo0",
                "ff00::/8                                ::1                                     UmCI                  lo0",
                "2001:db8:2::/48                         utun4                                   USc                 utun4",
                "");
        List<PeerEgressSocketBinding.Route> routes = PeerEgressSocketBinding.macosRoutes6(table);
        assertEquals(List.of(
                route("::/0", "utun0", 0, false),
                route("::/0", "en0", 0, true),
                route("::1/128", "lo0", 0, true),
                route("2001:db8:1::/64", "en0", 0, true),
                route("2001:db8:1::1/128", "en0", 0, false),
                route("fe80::/64", "lo0", 0, false),
                route("fe80::1/128", "lo0", 0, false),
                route("ff00::/8", "lo0", 0, false),
                route("2001:db8:2::/48", "utun4", 0, true)), routes);
        assertEquals("en0", PeerEgressSocketBinding.select(routes, "utun4", "2400:cb00::1"));
        assertEquals("en0", PeerEgressSocketBinding.select(routes, "utun4", "2001:db8:2::10"), "utun4 is the tunnel");
        assertEquals("lo0", PeerEgressSocketBinding.select(routes, "utun4", "::1"));
        // The IPv4 reading of the same output is untouched.
        assertEquals(2, PeerEgressSocketBinding.macosRoutes(table).size());

        Map<String, String> normalised = new LinkedHashMap<>();
        normalised.put("default", "::/0");
        normalised.put("2001:DB8::/32", "2001:db8::/32");
        normalised.put("2001:db8::1/64", "2001:db8::/64");
        normalised.put("fe80::%en0/64", "fe80::/64");
        normalised.put("192.168.1", "");
        normalised.put("2001:db8::/129", "");
        normalised.put("2001:db8::/064", "");
        normalised.put("link#6", "");
        for (Map.Entry<String, String> entry : normalised.entrySet()) {
            assertEquals(entry.getValue(), PeerEgressSocketBinding.normaliseMacosPrefix6(entry.getKey()), entry.getKey());
        }
        assertEquals(List.of("netstat", "-rn", "-f", "inet6"), PeerEgressSocketBinding.macosShowTableArgs6());
    }
}
