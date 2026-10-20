package com.theshuai.specusclient.peer;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.theshuai.common.clientauth.ClientAuthLoginResponse;
import com.theshuai.common.peeregress.PeerEgressCodes;
import com.theshuai.common.peeregress.PeerEgressRule;
import com.theshuai.common.peeregress.PeerEgressRules;
import com.theshuai.specusclient.peer.PeerEgressRoutePlanner.Kind;
import com.theshuai.specusclient.peer.PeerEgressRoutePlanner.Route;
import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * Route takeover for IPv6 ({@code protocol/spec/peer-egress.md}, IPv6 数据面, 消费端): the plan, the
 * journal, the repair against the IPv6 table, and each platform's commands and readings, against
 * synthetic tables and against output sampled from the real tools. No route on this machine is
 * touched.
 */
class PeerEgressRoutesIpv6Tests {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    @TempDir
    Path directory;

    private static PeerEgressRule rule(String match, String action, Long egress) {
        PeerEgressRule rule = new PeerEgressRule();
        rule.setMatch(match);
        rule.setAction(action);
        rule.setEgressClientId(egress);
        return rule;
    }

    private static List<PeerEgressRule> planRules() {
        return List.of(
                rule("203.0.113.0/24", PeerEgressRule.ACTION_EGRESS, 2L),
                rule("2001:DB8:1:0::/48", PeerEgressRule.ACTION_EGRESS, 2L),
                rule("2001:db8:2::/48", PeerEgressRule.ACTION_BLOCK, null),
                rule("2001:db8:3::/48", PeerEgressRule.ACTION_DIRECT, null),
                rule("2001:db8:1::/48", PeerEgressRule.ACTION_BLOCK, null),
                rule("fd53:7065:6375:7300::/96", PeerEgressRule.ACTION_EGRESS, 2L),
                rule("::/0", PeerEgressRule.ACTION_EGRESS, 2L),
                rule("::/1", PeerEgressRule.ACTION_BLOCK, null));
    }

    private static Route tun(String cidr, String origin) {
        return new Route(cidr, Kind.TUN, origin);
    }

    private static Route bypass(String cidr) {
        return new Route(cidr, Kind.BYPASS, "bypass");
    }

    /**
     * Exact IPv6 prefixes, written canonically; nothing for a direct rule; a route for a block rule;
     * one route for two rules over one prefix; the refusals returned; and a /128 bypass for an IPv6
     * endpoint an IPv6 rule covers, first.
     */
    @Test
    void planCarriesIpv6Routes() {
        // fd00::1 is covered by no rule; everything in 2001::/16 is, by ::/1 at least.
        List<String> endpoints = List.of("198.51.100.7", "2001:db8:1::9", "2001:db8:1:0::9", "2001:db8:9::1",
                "2001:db8:2::5", "203.0.113.4", "fd00::1");
        PeerEgressRoutePlanner.Plan plan = PeerEgressRoutePlanner.plan(planRules(), endpoints,
                PeerEgressRules.DEFAULT_MESH_CIDR, null, true);
        assertEquals(List.of(
                bypass("203.0.113.4/32"),
                bypass("2001:db8:1::9/128"),
                bypass("2001:db8:2::5/128"),
                bypass("2001:db8:9::1/128"),
                tun("203.0.113.0/24", "rule:203.0.113.0/24"),
                // ::/1 is not invented; written by hand it is a rule like any other.
                tun("::/1", "rule:::/1"),
                tun("2001:db8:1::/48", "rule:2001:DB8:1:0::/48"),
                tun("2001:db8:2::/48", "rule:2001:db8:2::/48")), plan.routes());
        Map<Integer, String> refused = new HashMap<>();
        plan.refused().forEach(entry -> refused.put(entry.index(), entry.code()));
        assertEquals(Map.of(5, PeerEgressCodes.RULE_MESH_OVERLAP, 6, PeerEgressCodes.RULE_DEFAULT_ROUTE), refused);

        // Without the data plane the IPv6 rules are refused and the plan is the IPv4 one alone,
        // exactly what it was before IPv6.
        PeerEgressRoutePlanner.Plan without = PeerEgressRoutePlanner.plan(planRules(), endpoints,
                PeerEgressRules.DEFAULT_MESH_CIDR, null, false);
        assertEquals(PeerEgressRoutePlanner.plan(List.of(planRules().get(0)), endpoints,
                PeerEgressRules.DEFAULT_MESH_CIDR).routes(), without.routes());
        assertEquals(without.routes(), PeerEgressRoutePlanner.plan(planRules(), endpoints,
                PeerEgressRules.DEFAULT_MESH_CIDR).routes(), "the entry point without the data plane differs");
        for (PeerEgressRoutePlanner.Refusal refusal : without.refused()) {
            assertTrue(refusal.code().equals(PeerEgressCodes.RULE_IPV6_UNSUPPORTED)
                    || refusal.code().equals(PeerEgressCodes.RULE_DEFAULT_ROUTE), refusal.toString());
        }
    }

    /**
     * One order across both families: bypass first, IPv4 before IPv6, by value within a family.
     * Sorted as text across families and by value within one, these three would each sort before
     * the next.
     */
    @Test
    void oneOrderAcrossFamilies() {
        List<Route> routes = new ArrayList<>(List.of(
                tun("2001:db8::/32", ""), tun("10.0.0.0/8", ""), tun("9.0.0.0/8", ""),
                bypass("2001:db8::1/128"), tun("fd00::/8", ""), tun("::/1", ""), bypass("9.0.0.9/32")));
        PeerEgressRoutePlanner.sort(routes);
        assertEquals(List.of("9.0.0.9/32", "2001:db8::1/128", "9.0.0.0/8", "10.0.0.0/8", "::/1", "2001:db8::/32",
                "fd00::/8"), routes.stream().map(Route::cidr).toList());
    }

    /**
     * The journal carries IPv6 prefixes in the shared format, written first and read back, and a
     * restart takes them back like any other.
     */
    @Test
    void journalAndWithdraw() throws IOException {
        Path path = directory.resolve("egress-routes.json");
        PeerEgressDriftTests.TableCommander commander = new PeerEgressDriftTests.TableCommander();
        PeerEgressRouteInstaller installer = new PeerEgressRouteInstaller(commander, path);
        List<Route> plan = PeerEgressRoutePlanner.plan(planRules(), List.of("2001:db8:1::9"),
                PeerEgressRules.DEFAULT_MESH_CIDR, null, true).routes();
        PeerEgressRouteInstaller.ApplyResult result = installer.apply(plan);
        assertNull(result.error());
        assertEquals(plan.size(), result.added().size());
        // Installed in the plan's order: the bypass first, then IPv4, then IPv6.
        assertEquals(plan.stream().map(Route::cidr).toList(), commander.installLog);

        JsonNode journal = MAPPER.readTree(Files.readString(path));
        assertEquals(1, journal.path("version").asInt());
        Map<String, String> found = new HashMap<>();
        journal.path("routes").forEach(entry -> found.put(entry.path("cidr").asText(),
                entry.path("kind").asText() + "|" + entry.path("origin").asText()));
        assertEquals("bypass|bypass", found.get("2001:db8:1::9/128"));
        assertEquals("tun|rule:2001:DB8:1:0::/48", found.get("2001:db8:1::/48"));
        // The bypass went where the IPv6 table says, through the link-local gateway.
        PeerEgressSocketBinding.Route hop = commander.hops.get("2001:db8:1::9/128");
        assertEquals("eth0", hop.iface());
        assertEquals("fe80::1", hop.gateway());

        PeerEgressRouteInstaller restarted = new PeerEgressRouteInstaller(commander, path);
        restarted.load();
        assertEquals(plan.size(), restarted.withdrawAll().size());
        assertTrue(commander.table.isEmpty(), "left in the table: " + commander.table.keySet());
        assertFalse(Files.exists(path), "the journal is still there");
    }

    /**
     * The IPv6 routes are checked against the IPv6 table: one gone is put back, a bypass whose
     * gateway moved is re-pointed, and one on somebody else's interface is given up. A machine that
     * owns no IPv6 route never reads the IPv6 table.
     */
    @Test
    void repairAgainstTheIpv6Table() {
        PeerEgressDriftTests.TableCommander commander = new PeerEgressDriftTests.TableCommander();
        PeerEgressRouteInstaller installer = new PeerEgressRouteInstaller(commander, directory.resolve("j.json"));
        installer.apply(PeerEgressRoutePlanner.plan(List.of(planRules().get(0)), List.of("203.0.113.4"),
                PeerEgressRules.DEFAULT_MESH_CIDR).routes());
        PeerEgressRouteInstaller.RepairResult result = installer.repair();
        assertNull(result.tableError());
        assertTrue(result.repaired().isEmpty());
        assertEquals(0, commander.table6Reads, "an IPv4-only machine read the IPv6 table");

        installer.apply(PeerEgressRoutePlanner.plan(planRules(), List.of("2001:db8:1::9", "203.0.113.4"),
                PeerEgressRules.DEFAULT_MESH_CIDR, null, true).routes());
        result = installer.repair();
        assertNull(result.tableError());
        assertTrue(result.repaired().isEmpty() && result.lost().isEmpty(), "a whole table: " + result);

        commander.lose("2001:db8:2::/48");
        commander.physical6 = new ArrayList<>(List.of(
                new PeerEgressSocketBinding.Route("::/0", "wlan0", "fe80::9", 50, true)));
        result = installer.repair();
        assertNull(result.tableError());
        assertNull(result.error());
        assertEquals(2, result.repaired().size(), "repaired " + result.repaired());
        assertEquals("wlan0", commander.hops.get("2001:db8:1::9/128").iface(), "the bypass was not re-pointed");
        assertEquals("fe80::9", commander.hops.get("2001:db8:1::9/128").gateway());
        assertTrue(commander.table.containsKey("2001:db8:2::/48"), "the lost route was not put back");

        // Somebody else's route on one of ours is reported and given up.
        commander.lose("2001:db8:1::/48");
        commander.physical6.add(new PeerEgressSocketBinding.Route("2001:db8:1::/48", "eth1", "", 0, true));
        result = installer.repair();
        assertEquals(1, result.lost().size());
        assertEquals("2001:db8:1::/48", result.lost().get(0).route().cidr());
        assertFalse(installer.owns("2001:db8:1::/48"));

        // The IPv6 table unreadable is said like the IPv4 one.
        commander.table6Error = new IOException("no ip -6");
        assertNotNull(installer.repair().tableError(), "an unreadable IPv6 table went unsaid");
    }

    /** A bypass's own /128 is left out of the fallback lookup, as an IPv4 one's /32 is. */
    @Test
    void theBypassFallbackLeavesItsOwnHostRouteOut() throws IOException {
        List<PeerEgressSocketBinding.Route> table = List.of(
                new PeerEgressSocketBinding.Route("::/0", "eth0", "fe80::1", 0, true),
                new PeerEgressSocketBinding.Route("2001:db8:1::/48", "specus0", "", 0, true),
                new PeerEgressSocketBinding.Route("2001:db8:1::9/128", "eth9", "fe80::99", 0, true));
        PeerEgressSocketBinding.Route hop = PeerEgressSocketBinding.bypassHopFromTable("2001:db8:1::9", "specus0",
                () -> table);
        assertEquals("eth0", hop.iface());
        assertEquals("fe80::1", hop.gateway());
        // And drift reads the bypass's address without its /128.
        List<PeerEgressSocketBinding.Drift> drifts = PeerEgressSocketBinding.drifts(
                List.of(bypass("2001:db8:1::9/128")), table, "specus0");
        assertEquals(1, drifts.size());
        assertEquals(PeerEgressSocketBinding.DRIFT_MOVED, drifts.get(0).reason());
    }

    // ---- Linux ---------------------------------------------------------------------------------

    /** What `ip -6 route` says, sampled in a WSL 2 network namespace (iproute2 6.1.0) with a real TUN. */
    private static final String LINUX_TABLE6 = "2001:db8:1::/48 dev specus0 metric 1024 linkdown pref medium\n"
            + "2001:db8:64::/64 dev eth0 proto kernel metric 256 pref medium\n"
            + "2001:db8:65::/64 dev eth1 proto kernel metric 256 pref medium\n"
            + "2001:db8:77::/48 metric 1024 pref medium\n"
            + "\tnexthop via fe80::1 dev eth0 weight 1 \n"
            + "\tnexthop via fe80::2 dev eth1 weight 1 \n"
            + "blackhole 2001:db8:dead::/48 dev lo metric 1024 pref medium\n"
            + "fd53:7065:6375:7300::6460:5 dev specus0 proto kernel metric 256 linkdown pref medium\n"
            + "fe80::/64 dev eth0 proto kernel metric 256 pref medium\n"
            + "fe80::/64 dev eth1 proto kernel metric 256 pref medium\n"
            + "default via fe80::1 dev eth0 metric 1024 pref medium\n";

    @Test
    void linuxIpv6Readings() {
        List<PeerEgressSocketBinding.Route> routes = PeerEgressRouteCommands.parseRouteTable6(LINUX_TABLE6);
        assertEquals(List.of(
                new PeerEgressSocketBinding.Route("2001:db8:1::/48", "specus0", "", 1024, true),
                new PeerEgressSocketBinding.Route("2001:db8:64::/64", "eth0", "", 256, true),
                new PeerEgressSocketBinding.Route("2001:db8:65::/64", "eth1", "", 256, true),
                new PeerEgressSocketBinding.Route("2001:db8:77::/48", "eth0", "fe80::1", 1024, true),
                new PeerEgressSocketBinding.Route("2001:db8:dead::/48", "", "", 1024, true),
                new PeerEgressSocketBinding.Route("fd53:7065:6375:7300::6460:5/128", "specus0", "", 256, true),
                new PeerEgressSocketBinding.Route("fe80::/64", "eth0", "", 256, true),
                new PeerEgressSocketBinding.Route("fe80::/64", "eth1", "", 256, true),
                new PeerEgressSocketBinding.Route("::/0", "eth0", "fe80::1", 1024, true)), routes);
        // Each reader is only ever given its own family's table; an IPv4 prefix still reads as nothing
        // to the IPv6 one, and an IPv4 gateway is no gateway.
        List<PeerEgressSocketBinding.Route> mixed = PeerEgressRouteCommands.parseRouteTable6(
                "10.0.0.0/8 dev eth0 \n2001:db8::/32 via 192.168.64.1 dev eth0 \n");
        assertEquals(List.of(new PeerEgressSocketBinding.Route("2001:db8::/32", "eth0", "", 0, true)), mixed);

        // The fallback hop for an address the tunnel's own route covers: past the tunnel, the default
        // through the link-local gateway; behind the blackhole, nothing.
        PeerEgressSocketBinding.Route hop = PeerEgressSocketBinding.selectBypassHop(routes, "specus0", List.of(),
                "2001:db8:1::9");
        assertEquals("eth0", hop.iface());
        assertEquals("fe80::1", hop.gateway());
        assertNull(PeerEgressSocketBinding.selectBypassHop(routes, "specus0", List.of(), "2001:db8:dead::9"));

        assertEquals(new PeerEgressRouteCommands.Hop("", "specus0"), PeerEgressRouteCommands.parseRouteGet(
                "2001:db8:1::9 from :: dev specus0 src fd53:7065:6375:7300::6460:5 metric 1024 pref medium\n"));
        assertEquals(new PeerEgressRouteCommands.Hop("fe80::1", "eth0"), PeerEgressRouteCommands.parseRouteGet(
                "2001:db8:5::9 from :: via fe80::1 dev eth0 src 2001:db8:64::7 metric 1024 pref medium\n"));
        assertEquals(new PeerEgressRouteCommands.Hop("", "eth0"), PeerEgressRouteCommands.parseRouteGet(
                "2001:db8:64::9 from :: dev eth0 proto kernel src 2001:db8:64::7 metric 256 pref medium\n"));
        PeerEgressRouteCommands.ExistingRoute exact = PeerEgressRouteCommands.parseShowExact(
                "2001:db8:1::/48 dev specus0 metric 1024 linkdown pref medium\n");
        assertTrue(exact.present());
        assertEquals("2001:db8:1::/48 dev specus0 metric 1024 linkdown pref medium", exact.description());

        // The commands: IPv4 exactly as before, IPv6 with -6, and the address the device is given.
        Map<List<String>, String> commands = new java.util.LinkedHashMap<>();
        commands.put(PeerEgressRouteCommands.routeArgs("203.0.113.0/24", "add", "203.0.113.0/24", "dev", "specus0"),
                "ip route add 203.0.113.0/24 dev specus0");
        commands.put(PeerEgressRouteCommands.routeArgs("2001:db8:1::/48", "add", "2001:db8:1::/48", "dev", "specus0"),
                "ip -6 route add 2001:db8:1::/48 dev specus0");
        commands.put(PeerEgressRouteCommands.routeArgs("2001:db8:1::9/128", "add", "2001:db8:1::9/128", "via", "fe80::1",
                "dev", "eth0"), "ip -6 route add 2001:db8:1::9/128 via fe80::1 dev eth0");
        commands.put(PeerEgressRouteCommands.routeArgs("2001:db8:1::9/128", "get", "2001:db8:1::9"),
                "ip -6 route get 2001:db8:1::9");
        commands.put(PeerEgressRouteCommands.routeArgs("2001:db8:1::/48", "show", "exact", "2001:db8:1::/48"),
                "ip -6 route show exact 2001:db8:1::/48");
        commands.put(PeerEgressRouteCommands.routeArgs("2001:db8:1::/48", "del", "2001:db8:1::/48"),
                "ip -6 route del 2001:db8:1::/48");
        commands.put(PeerEgressRouteCommands.showMainTableArgs6(), "ip -6 route show table main");
        commands.put(PeerEgressRouteCommands.assignAddress6Args("specus0", "fd53:7065:6375:7300::6460:1"),
                "ip -6 address add fd53:7065:6375:7300::6460:1/128 dev specus0");
        commands.forEach((got, want) -> assertEquals(want, String.join(" ", got)));
    }

    // ---- Windows -------------------------------------------------------------------------------

    @Test
    void windowsIpv6Scripts() {
        assertEquals("try{New-NetRoute -AddressFamily IPv6 -DestinationPrefix '2001:db8:1::/48' -NextHop '::' "
                        + "-InterfaceIndex 9 -PolicyStore ActiveStore -ErrorAction Stop|Out-Null}catch{ConvertTo-Json -Compress "
                        + "-InputObject @{errorId=$_.FullyQualifiedErrorId};exit 1}",
                PeerEgressWindowsRouteCommands.installRouteScript6("2001:db8:1::/48", 9, ""));
        assertTrue(PeerEgressWindowsRouteCommands.installRouteScript6("2001:db8:1::9/128", 3, "fe80::1")
                .contains("-DestinationPrefix '2001:db8:1::9/128' -NextHop 'fe80::1' -InterfaceIndex 3 "));
        assertEquals("try{Remove-NetRoute -AddressFamily IPv6 -DestinationPrefix '2001:db8:1::/48' -Confirm:$false "
                        + "-PolicyStore ActiveStore -ErrorAction Stop|Out-Null}catch{ConvertTo-Json -Compress -InputObject "
                        + "@{errorId=$_.FullyQualifiedErrorId};exit 1}",
                PeerEgressWindowsRouteCommands.removeRouteScript6("2001:db8:1::/48"));
        assertEquals("foreach($a in @('2001:db8:1::9')){ConvertTo-Json -Compress -InputObject "
                        + "@(Find-NetRoute -RemoteIPAddress $a -ErrorAction SilentlyContinue|Select-Object "
                        + "InterfaceIndex,DestinationPrefix,NextHop,RouteMetric)}\nexit 0",
                PeerEgressWindowsRouteCommands.findRoutesScript6(List.of("2001:db8:1::9")));
        assertEquals(PeerEgressWindowsRouteCommands.showAllRoutesScript().replace("IPv4", "IPv6"),
                PeerEgressWindowsRouteCommands.showAllRoutesScript6());
        String assign = PeerEgressWindowsRouteCommands.assignAddress6Script(17, "fd53:7065:6375:7300::6460:1", 1280);
        assertTrue(assign.contains("New-NetIPAddress -AddressFamily IPv6 -IPAddress 'fd53:7065:6375:7300::6460:1' "
                + "-PrefixLength 128 -InterfaceIndex 17 -PolicyStore ActiveStore"), assign);
        assertTrue(assign.contains("Set-NetIPInterface -AddressFamily IPv6 -InterfaceIndex 17 -NlMtuBytes 1280 "
                + "-PolicyStore ActiveStore"), assign);
        // An address already there is not a failure: it is only added when absent.
        assertTrue(assign.contains("if(-not(Get-NetIPAddress -AddressFamily IPv6 -InterfaceIndex 17 "
                + "-IPAddress 'fd53:7065:6375:7300::6460:1' -PolicyStore ActiveStore -ErrorAction SilentlyContinue))"), assign);

        // Nothing but an IPv6 prefix in the canonical form reaches an IPv6 script, and nothing IPv6
        // reaches an IPv4 one.
        for (String bad : List.of("2001:db8:1::/48';Remove-NetRoute -DestinationPrefix '::/0", "2001:DB8:1::/48",
                "2001:db8:1:0::/48", "2001:db8:1::", "203.0.113.0/24", "$(Get-NetRoute)", "fe80::1%3/128", "")) {
            assertThrows(IllegalArgumentException.class,
                    () -> PeerEgressWindowsRouteCommands.installRouteScript6(bad, 9, ""), bad);
            assertThrows(IllegalArgumentException.class, () -> PeerEgressWindowsRouteCommands.removeRouteScript6(bad), bad);
        }
        for (String bad : List.of("fe80::1%3", "[2001:db8::1]", "::ffff:192.0.2.1", "2001:db8::1'", "203.0.113.9")) {
            assertThrows(IllegalArgumentException.class,
                    () -> PeerEgressWindowsRouteCommands.findRoutesScript6(List.of(bad)), bad);
            assertThrows(IllegalArgumentException.class,
                    () -> PeerEgressWindowsRouteCommands.installRouteScript6("2001:db8:1::9/128", 3, bad), bad);
        }
        assertThrows(IllegalArgumentException.class,
                () -> PeerEgressWindowsRouteCommands.installRouteScript("2001:db8:1::/48", 9, ""));
        assertThrows(IllegalArgumentException.class,
                () -> PeerEgressWindowsRouteCommands.assignAddress6Script(0, "fd53:7065:6375:7300::6460:1", 1280));
        assertThrows(IllegalArgumentException.class,
                () -> PeerEgressWindowsRouteCommands.assignAddress6Script(17, "fd53::1'", 1280));
    }

    /**
     * Get-NetRoute -AddressFamily IPv6 as it comes back (on-link is "::"): the conflict check compares
     * by value, and the find reads the route, not the source-address object.
     */
    @Test
    void windowsIpv6Readings() {
        String table = "[{\"InterfaceIndex\":44,\"DestinationPrefix\":\"ff00::/8\",\"NextHop\":\"::\",\"RouteMetric\":256},"
                + "{\"InterfaceIndex\":3,\"DestinationPrefix\":\"2001:db8:1::/48\",\"NextHop\":\"fe80::1\",\"RouteMetric\":0},"
                + "{\"InterfaceIndex\":3,\"DestinationPrefix\":\"2001:DB8:2:0::/48\",\"NextHop\":\"::\",\"RouteMetric\":5}]";
        PeerEgressRouteCommands.ExistingRoute conflict = PeerEgressWindowsRouteCommands.conflictFromTable6(table,
                "2001:db8:1::/48");
        assertTrue(conflict.present());
        assertEquals("2001:db8:1::/48 nexthop fe80::1 ifIndex 3 metric 0", conflict.description());
        conflict = PeerEgressWindowsRouteCommands.conflictFromTable6(table, "2001:db8:2::/48");
        assertTrue(conflict.present(), "a differently written prefix");
        assertEquals("2001:DB8:2:0::/48 on-link ifIndex 3 metric 5", conflict.description());
        assertFalse(PeerEgressWindowsRouteCommands.conflictFromTable6(table, "2001:db8:3::/48").present());
        assertFalse(PeerEgressWindowsRouteCommands.conflictFromTable6("[]", "2001:db8:1::/48").present());

        PeerEgressWindowsRouteCommands.Hop hop = PeerEgressWindowsRouteCommands.parseRouteFind(
                "[{\"InterfaceIndex\":3,\"DestinationPrefix\":null,\"NextHop\":null,\"RouteMetric\":null},"
                        + "{\"InterfaceIndex\":3,\"DestinationPrefix\":\"::/0\",\"NextHop\":\"fe80::1\",\"RouteMetric\":0}]");
        assertEquals(new PeerEgressWindowsRouteCommands.Hop("fe80::1", 3), hop);
        hop = PeerEgressWindowsRouteCommands.parseRouteFind(
                "[{\"InterfaceIndex\":3,\"DestinationPrefix\":\"2001:db8:64::/64\",\"NextHop\":\"::\",\"RouteMetric\":256}]");
        assertEquals(new PeerEgressWindowsRouteCommands.Hop("", 3), hop);
    }

    // ---- macOS ---------------------------------------------------------------------------------

    @Test
    void macosIpv6CommandsAndReadings() {
        assertEquals("route -n add -inet6 -net 2001:db8:1::/48 -interface utun4",
                String.join(" ", PeerEgressMacosRouteCommands.installInterfaceArgs6("2001:db8:1::/48", "utun4")));
        assertEquals("route -n add -inet6 -net 2001:db8:1::9/128 fe80::1%en0",
                String.join(" ", PeerEgressMacosRouteCommands.installGatewayArgs6("2001:db8:1::9/128", "fe80::1%en0")));
        assertEquals("route -n delete -inet6 -net 2001:db8:1::/48",
                String.join(" ", PeerEgressMacosRouteCommands.removeArgs6("2001:db8:1::/48")));
        assertEquals("route -n get -inet6 2001:db8:1::9",
                String.join(" ", PeerEgressMacosRouteCommands.findRouteArgs6("2001:db8:1::9")));
        assertEquals("ifconfig utun4 inet6 fd53:7065:6375:7300::6460:1 prefixlen 128",
                String.join(" ", PeerEgressMacosRouteCommands.assignAddress6Args("utun4", "fd53:7065:6375:7300::6460:1")));
        assertEquals("netstat -rn -f inet6", String.join(" ", PeerEgressSocketBinding.macosShowTableArgs6()));
        for (String bad : List.of("2001:DB8:1::/48", "2001:db8:1::/129", "2001:db8:1::", "-net", "203.0.113.0/24")) {
            assertThrows(IllegalArgumentException.class,
                    () -> PeerEgressMacosRouteCommands.installInterfaceArgs6(bad, "utun4"), bad);
        }
        for (String bad : List.of("fe80::1%-x", "fe80::1%en0 extra", "[fe80::1]", "-inet6")) {
            assertThrows(IllegalArgumentException.class,
                    () -> PeerEgressMacosRouteCommands.installGatewayArgs6("2001:db8:1::9/128", bad), bad);
        }
        assertThrows(IllegalArgumentException.class, () -> PeerEgressMacosRouteCommands.findRouteArgs6("fe80::1%en0"));
        assertThrows(IllegalArgumentException.class,
                () -> PeerEgressMacosRouteCommands.assignAddress6Args("-utun4", "fd53:7065:6375:7300::6460:1"));
        assertThrows(IllegalArgumentException.class,
                () -> PeerEgressMacosRouteCommands.installInterfaceArgs("2001:db8:1::/48", "utun4"));

        String get = "   route to: 2001:db8:1::9\ndestination: default\n       mask: default\n    gateway: fe80::1%en0\n"
                + "  interface: en0\n      flags: <UP,GATEWAY,DONE,STATIC,PRCLONING>\n";
        assertEquals(new PeerEgressRouteCommands.Hop("fe80::1%en0", "en0"), PeerEgressMacosRouteCommands.parseRouteGet6(get, ""));
        assertEquals(new PeerEgressRouteCommands.Hop("", "en0"), PeerEgressMacosRouteCommands.parseRouteGet6(
                "   route to: 2001:db8:64::9\n    gateway: link#6\n  interface: en0\n", ""));
        assertNull(PeerEgressMacosRouteCommands.parseRouteGet6("", "route: writing to routing socket: not in table\n"));

        String table = "Routing tables\n\nInternet:\nDestination        Gateway            Flags               Netif Expire\n"
                + "default            192.168.1.1        UGScg                 en0\n\nInternet6:\n"
                + "Destination                             Gateway                                 Flags               Netif Expire\n"
                + "default                                 fe80::1%en0                             UGcg                  en0\n"
                + "2001:db8:1::/48                         utun4                                   USc                 utun4\n"
                + "2001:db8:5::9                           fe80::1%en0                             UGHS                  en0\n"
                + "2001:db8:64::9                          a4:83:e7:0:0:1                          UHLWIi                en0\n";
        PeerEgressRouteCommands.ExistingRoute conflict = PeerEgressMacosRouteCommands.conflictFromTable6(table,
                "2001:db8:1::/48");
        assertTrue(conflict.present());
        assertEquals("2001:db8:1::/48 gateway utun4 netif utun4 flags USc", conflict.description());
        assertFalse(PeerEgressMacosRouteCommands.conflictFromTable6(table, "2001:db8:64::9/128").present(),
                "a kernel-generated neighbour entry conflicted");
        assertTrue(PeerEgressMacosRouteCommands.conflictFromTable6(table, "::/0").present());
        assertTrue(PeerEgressMacosRouteCommands.conflictFromTable(table, "0.0.0.0/0").present(),
                "the IPv4 default lost its conflict");
        assertFalse(PeerEgressMacosRouteCommands.conflictFromTable6(table, "0.0.0.0/0").present());

        PeerEgressSocketBinding.Route hop = PeerEgressSocketBinding.selectBypassHop(
                PeerEgressSocketBinding.macosBypassRoutes6(table), "utun4", List.of(), "2001:db8:1::9");
        assertEquals("en0", hop.iface());
        assertEquals("fe80::1%en0", hop.gateway());
    }

    // ---- the device and the bypass list --------------------------------------------------------

    /** The derived address goes to the TUN only for a consumer with the IPv6 data plane. */
    @Test
    void theDevicesAddressFollowsTheConsumer() {
        boolean carries = PeerEgressRouteCommanders.consumerCarriesIpv6(1280);
        String address = PeerDeviceIpv6.address(new PeerVirtualDeviceOptions("auto", "specus0", 1280, true), "100.96.0.1");
        assertEquals(carries ? "fd53:7065:6375:7300::6460:1" : null, address);
        assertNull(PeerDeviceIpv6.address(new PeerVirtualDeviceOptions("auto", "specus0", 1280), "100.96.0.1"));
        assertNull(PeerDeviceIpv6.address(new PeerVirtualDeviceOptions("auto", "specus0", 1200, true), "100.96.0.1"));
        assertNull(PeerDeviceIpv6.address(new PeerVirtualDeviceOptions("auto", "specus0", 1280, true), ""));
    }

    /**
     * A device whose address could not be assigned says why and stays without IPv6; one whose
     * address went on carries it until it closes.
     */
    @Test
    void theDeviceReportsWhetherItsAddressWentOn() {
        ClientAuthLoginResponse.PeerMeshConfig config = new ClientAuthLoginResponse.PeerMeshConfig();
        config.setVirtualIp("100.96.0.1");
        PeerDeviceIpv6 ipv6 = new PeerDeviceIpv6(new PeerVirtualDeviceOptions("auto", "specus0", 1280, true), config);
        org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(PeerEgressRoutesIpv6Tests.class);
        if (ipv6.address() == null) {
            // A platform without the IPv6 data plane gives no address and asks for nothing.
            ipv6.configure(address -> { throw new AssertionError("asked to assign " + address); }, "TUN", log);
            assertFalse(ipv6.readiness().ready());
            assertEquals(PeerDeviceIpv6.NOT_ASKED, ipv6.readiness().reason());
            return;
        }
        List<String> assigned = new ArrayList<>();
        ipv6.configure(address -> {
            throw new IllegalStateException("RTNETLINK answers: Permission denied");
        }, "TUN", log);
        assertFalse(ipv6.readiness().ready());
        assertEquals("the TUN's IPv6 address could not be assigned: RTNETLINK answers: Permission denied",
                ipv6.readiness().reason());
        ipv6.configure(assigned::add, "TUN", log);
        assertEquals(List.of("fd53:7065:6375:7300::6460:1"), assigned);
        assertTrue(ipv6.readiness().ready());
        ipv6.closed("TUN");
        assertFalse(ipv6.readiness().ready());
        assertEquals("the TUN is closed", ipv6.readiness().reason());
        // The noop device carries no IPv6.
        assertFalse(new NoopPeerVirtualDevice().ipv6Readiness().ready());
    }

    /** The bypass resolver gives IPv6 answers and literals only through resolve6, in RFC 5952 form. */
    @Test
    void theBypassResolverResolvesIpv6Apart() throws UnknownHostException {
        int[] calls = {0};
        InetAddress v6 = InetAddress.getByName("2001:DB8:0::1");
        InetAddress v4 = InetAddress.getByName("203.0.113.60");
        PeerEgressBypassResolver resolver = new PeerEgressBypassResolver(host -> {
            calls[0]++;
            if (host.equals("stun.example.test")) {
                return new InetAddress[] {v6, v4};
            }
            throw new UnknownHostException(host);
        });
        List<String> entries = List.of("https://[2001:db8::443]:8443/login", "stun.example.test:3478", "[2001:db8::2]:3478",
                "2001:db8::3", "198.51.100.1", "[fe80::1%eth0]:3478", "::ffff:192.0.2.1");
        long now = 1_800_000_000_000L;
        assertEquals(List.of("203.0.113.60", "198.51.100.1"), resolver.resolve(entries, now).addresses());
        assertEquals(List.of("2001:db8::443", "2001:db8::1", "2001:db8::2", "2001:db8::3"), resolver.resolve6(entries, now));
        assertEquals(1, calls[0], "the name was looked up once for both families");
    }

    /** Whether a device carries IPv6 as configured is its platform's support and an MTU of at least 1280. */
    @Test
    void theConfiguredDataPlaneNeedsThePlatformAndTheMinimumMtu() {
        boolean platform = PeerEgressRouteCommanders.platformCarriesIpv6();
        assertEquals(platform, PeerEgressRouteCommanders.consumerCarriesIpv6(1280));
        assertEquals(platform, PeerEgressRouteCommanders.consumerCarriesIpv6(0), "unset reads as the default");
        assertFalse(PeerEgressRouteCommanders.consumerCarriesIpv6(1279));
        assertFalse(PeerEgressRouteCommanders.consumerCarriesIpv6(PeerVirtualDeviceOptions.MIN_MTU));
        assertEquals(PeerEgressRouteCommanders.takeoverSupported(), platform);
    }
}
