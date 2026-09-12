package com.theshuai.specusclient.peer;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.theshuai.specusclient.peer.PeerEgressRoutePlanner.Kind;
import com.theshuai.specusclient.peer.PeerEgressRoutePlanner.Route;
import java.io.IOException;
import java.util.Locale;
import org.junit.jupiter.api.Test;

/**
 * Which routing table this process ends up talking to, and what the Windows and macOS ones refuse
 * before they talk to anything.
 *
 * <p>These assertions are worth more than they look because CI runs the suite on ubuntu, windows
 * and macOS: every branch of the platform choice is exercised for real, on the platform it claims,
 * rather than all three being asserted from one machine's point of view.
 */
class PeerEgressRouteCommandersTests {

    private static String operatingSystem() {
        return System.getProperty("os.name", "").toLowerCase(Locale.ROOT);
    }

    @Test
    void theCommanderMatchesThePlatformThisIsRunningOn() {
        PeerEgressRouteInstaller.Commander commander =
                PeerEgressRouteCommanders.forPlatform("specus0");
        String name = operatingSystem();
        if (name.contains("linux")) {
            assertInstanceOf(LinuxPeerEgressRouteCommander.class, commander);
        } else if (name.contains("win")) {
            assertInstanceOf(WindowsPeerEgressRouteCommander.class, commander);
        } else if (name.contains("mac") || name.contains("darwin")) {
            assertInstanceOf(MacosPeerEgressRouteCommander.class, commander);
        } else {
            // Anything else: refusing beats installing nothing while reporting that the rules
            // were applied, which would send every destination out locally.
            assertInstanceOf(PeerEgressRouteCommanders.UnsupportedPeerEgressRouteCommander.class,
                    commander);
        }
    }

    /**
     * The macOS commander refuses an argument the builders would refuse, before starting a process.
     *
     * <p>Runs on every platform: the check happens in shared code, ahead of anything that needs
     * {@code route} to exist. The prefix that matters is 203.0.113.0/33 -- {@code route} accepts
     * it, prints a success line naming 203.0.113.0, exits 0, and installs 128.0/1, which is half
     * the IPv4 address space pointed at the gateway. Only the routing table says so, so this check
     * is not defence in depth on this platform; it is the defence.
     */
    @Test
    void theMacosCommanderRefusesAMalformedPrefixBeforeRunningAnything() {
        var commander = new MacosPeerEgressRouteCommander("utun3");
        for (String cidr : new String[] {"203.0.113.0/33", "203.0.113.0", "203.0.113.256/24",
                "010.0.113.0/24", "-net", ""}) {
            Route route = new Route(cidr, Kind.TUN, "rule:" + cidr);
            assertTrue(assertThrows(IllegalArgumentException.class,
                    () -> commander.install(route), cidr).getMessage().contains(REFUSAL),
                    cidr + " install");
            assertTrue(assertThrows(IllegalArgumentException.class,
                    () -> commander.remove(route), cidr).getMessage().contains(REFUSAL),
                    cidr + " remove");
        }
    }

    /**
     * On macOS, a prefix that is certainly taken is reported as taken.
     *
     * <p>Goes all the way to the operating system: it runs netstat, reads the whole table,
     * normalises the destination column and finds the default route. Any machine with working
     * networking has one, CI runners included; if this fails on a machine that has one, the reading
     * is wrong rather than the assumption.
     */
    @Test
    void onMacosTheDefaultRouteIsFoundAsAConflict() {
        if (!isMacos()) {
            return;
        }
        var commander = new MacosPeerEgressRouteCommander("utun3");
        PeerEgressRouteInstaller.Conflict conflict = commander.conflict(
                new Route("0.0.0.0/0", Kind.TUN, "rule:0.0.0.0/0"));
        assertTrue(conflict.present(), "the default route was not reported as a conflict");
        assertTrue(conflict.existing().startsWith("0.0.0.0/0 "),
                "conflict describes " + conflict.existing() + " rather than the default route");
        assertTrue(conflict.existing().contains("netif "),
                "conflict description carries no interface: " + conflict.existing());
    }

    /**
     * On macOS, an install that cannot work reports that rather than reporting success.
     *
     * <p>The most useful thing here that needs no privileges, and the one the Windows side has no
     * equivalent of. {@code route} answers a non-root caller with "must be root to alter routing
     * table" on stderr, exit 77, and nothing at all on stdout -- so this exercises the real binary,
     * the real streams and the real classification, and it is the one case where a classifier that
     * read only stdout would call the failure a success.
     */
    @Test
    void onMacosAnInstallWithoutRootFailsRatherThanReportingSuccess() {
        if (!isMacos() || "root".equals(System.getProperty("user.name", ""))) {
            return;
        }
        var commander = new MacosPeerEgressRouteCommander("lo0");
        Route route = new Route("203.0.113.0/24", Kind.TUN, "rule:203.0.113.0/24");
        IOException failure = assertThrows(IOException.class, () -> commander.install(route));
        assertTrue(failure.getMessage().contains("needs root"),
                "install failed without naming the missing privilege: " + failure.getMessage());
        // And the route is not there, which is the claim the error is making.
        assertTrue(!commander.conflict(route).present(),
                "203.0.113.0/24 was installed anyway");
    }

    private static boolean isMacos() {
        String name = operatingSystem();
        return name.contains("mac") || name.contains("darwin");
    }

    @Test
    void aPlatformWithoutTakeoverRefusesRatherThanDoingNothing() {
        var commander = new PeerEgressRouteCommanders.UnsupportedPeerEgressRouteCommander();
        Route route = new Route("203.0.113.0/24", Kind.TUN, "rule:203.0.113.0/24");

        // No conflict, because there is no table being read -- but neither install nor remove may
        // quietly succeed.
        assertTrue(!commander.conflict(route).present());
        assertThrows(IOException.class, () -> commander.install(route));
        assertThrows(IOException.class, () -> commander.remove(route));
    }

    /** What the argument check says when it refuses, so a refusal is told apart from a failure. */
    private static final String REFUSAL = "refusing to build a route command from this argument";

    /**
     * The Windows commander refuses an argument the script builder would refuse, and refuses it
     * before starting a process.
     *
     * <p>Runs on every platform: the check happens in shared code, ahead of anything that would
     * need powershell.exe to exist. That is the point of doing it in this order -- a prefix
     * carrying a quote is a second PowerShell command, and paying half a second to look up an
     * interface index before rejecting it would be the wrong way round.
     *
     * <p>Asserted on what the exception says rather than on how long the call took. Elapsed time
     * cannot tell these apart: a second PowerShell process starts in well under the 175 ms the
     * first one costs once its module is warm, so a run that happened can look exactly like one
     * that did not.
     */
    @Test
    void theWindowsCommanderRefusesAnInjectedPrefixBeforeRunningAnything() {
        var commander = new WindowsPeerEgressRouteCommander("specus0");
        Route injected = new Route(
                "10.0.0.0/8';Remove-NetRoute -DestinationPrefix '0.0.0.0/0",
                Kind.TUN, "rule:injected");

        assertTrue(assertThrows(IOException.class, () -> commander.install(injected))
                .getMessage().contains(REFUSAL), "install did not refuse the argument itself");
        assertTrue(assertThrows(IOException.class, () -> commander.remove(injected))
                .getMessage().contains(REFUSAL), "remove did not refuse the argument itself");
    }

    @Test
    void theWindowsCommanderRefusesAMalformedPrefix() {
        var commander = new WindowsPeerEgressRouteCommander("specus0");
        for (String cidr : new String[] {"10.0.0.0", "10.0.0.0/33", "10.0.0.256/24", ""}) {
            Route route = new Route(cidr, Kind.TUN, "rule:" + cidr);
            assertTrue(assertThrows(IOException.class, () -> commander.install(route), cidr)
                    .getMessage().contains(REFUSAL), cidr + " install");
            assertTrue(assertThrows(IOException.class, () -> commander.remove(route), cidr)
                    .getMessage().contains(REFUSAL), cidr + " remove");
        }
    }

    /**
     * The conflict check cannot report a conflict it was unable to look up.
     *
     * <p>Asserted on every platform because the shape matters more than the platform: on a machine
     * where the query cannot run at all, the answer has to be "no conflict" so the install itself
     * gets to refuse an existing prefix. The alternative, treating an unreadable table as a
     * conflict, would disable every rule on any machine where the lookup broke.
     */
    @Test
    void theWindowsConflictCheckFailsOpenWhenItCannotAsk() {
        var commander = new WindowsPeerEgressRouteCommander("specus0");
        Route route = new Route("203.0.113.0/24", Kind.TUN, "rule:203.0.113.0/24");
        PeerEgressRouteInstaller.Conflict conflict = commander.conflict(route);
        // On Windows this really reads the table and 203.0.113.0/24 is not in it; on Linux the
        // query cannot run. Both answers are the same, which is what this is asserting.
        assertEquals(false, conflict.present());
        assertEquals("", conflict.existing());
    }

    /**
     * On Windows, a prefix that is certainly taken is reported as taken.
     *
     * <p>The one assertion here that goes all the way to the operating system: it starts
     * PowerShell, reads the whole routing table, parses it and finds the default route. Every other
     * test in this class stops before the process boundary, and the install path cannot be
     * exercised at all without administrator rights, so this is where the query side gets proven
     * end to end rather than only against fixtures.
     *
     * <p>Any machine with working networking has a default route, CI runners included. If this ever
     * fails on a machine that has one, the reading is wrong, not the assumption.
     */
    @Test
    void onWindowsTheDefaultRouteIsFoundAsAConflict() {
        if (!operatingSystem().contains("win")) {
            return;
        }
        var commander = new WindowsPeerEgressRouteCommander("specus0");
        PeerEgressRouteInstaller.Conflict conflict = commander.conflict(
                new Route("0.0.0.0/0", Kind.TUN, "rule:0.0.0.0/0"));
        assertTrue(conflict.present(), "the default route was not reported as a conflict");
        assertTrue(conflict.existing().startsWith("0.0.0.0/0 "),
                "conflict describes " + conflict.existing() + " rather than the default route");
        assertTrue(conflict.existing().contains("ifIndex "),
                "conflict description carries no interface index: " + conflict.existing());
    }
}
