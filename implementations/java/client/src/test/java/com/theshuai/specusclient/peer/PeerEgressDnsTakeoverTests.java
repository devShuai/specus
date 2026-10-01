package com.theshuai.specusclient.peer;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * The system DNS takeover's order of events, driven against a fake machine per platform: nothing
 * here runs a command or touches a file outside a temporary directory.
 */
class PeerEgressDnsTakeoverTests {

    private static final String LISTEN = "198.18.0.1";
    private static final String TUNNEL = "specus0";
    private static final String POOL = "198.18.0.0/15";
    private static final String MESH = "100.96.0.0/11";
    private static final long EPOCH = 1_800_000_000_000L;
    private static final long PID = 4242;

    @TempDir
    Path directory;

    /** A machine that answers commands from a script and records everything done to it. */
    static final class FakeMachine implements PeerEgressDnsTakeover.Machine {
        final String platform;
        final Map<String, String> outputs = new HashMap<>();
        final Map<String, String> failures = new HashMap<>();
        final Map<String, String> files = new HashMap<>();
        final Set<String> symlinks = new HashSet<>();
        final Set<String> links = new HashSet<>(Set.of(TUNNEL));
        final List<String> ran = new ArrayList<>();
        final List<String> written = new ArrayList<>();
        List<PeerEgressDnsTakeoverParse.LocalInterface> interfaces = List.of();

        FakeMachine(String platform) {
            this.platform = platform;
        }

        static String key(List<String> argv) {
            return String.join(" ", argv);
        }

        FakeMachine answer(List<String> argv, String output) {
            outputs.put(key(argv), output);
            return this;
        }

        FakeMachine fail(List<String> argv, String output) {
            failures.put(key(argv), output);
            return this;
        }

        @Override
        public String platform() {
            return platform;
        }

        @Override
        public String run(List<String> argv) throws IOException {
            String key = key(argv);
            ran.add(key);
            if (failures.containsKey(key)) {
                throw new PeerEgressDnsTakeover.CommandFailure(argv, failures.get(key));
            }
            return outputs.getOrDefault(key, "");
        }

        @Override
        public String readFile(String path) throws IOException {
            String content = files.get(path);
            if (content == null) {
                throw new NoSuchFileException(path);
            }
            return content;
        }

        @Override
        public void writeFile(String path, String content) {
            written.add(path);
            files.put(path, content);
        }

        @Override
        public boolean isSymlink(String path) {
            return symlinks.contains(path);
        }

        @Override
        public boolean linkExists(String name) {
            return links.contains(name);
        }

        @Override
        public List<PeerEgressDnsTakeoverParse.LocalInterface> interfaces() {
            return interfaces;
        }

        /** The commands that changed something, reads left out. */
        List<String> changes() {
            List<String> out = new ArrayList<>();
            for (String command : ran) {
                if (!command.equals("resolvectl dns") && !command.startsWith("networksetup -listallnetworkservices")
                        && !command.startsWith("networksetup -getdnsservers") && !command.equals("scutil --dns")
                        && !command.contains("ConvertTo-Json")) {
                    out.add(command);
                }
            }
            return out;
        }
    }

    static final List<String> RESOLVECTL_DNS = List.of("resolvectl", "dns");

    static FakeMachine resolved() {
        FakeMachine machine = new FakeMachine("linux")
                .answer(RESOLVECTL_DNS, "Global:\nLink 2 (eth0): 192.168.1.1 fe80::1%eth0\nLink 9 (specus0):\n");
        machine.files.put("/etc/resolv.conf", "nameserver 127.0.0.53\noptions edns0\n");
        return machine;
    }

    static FakeMachine resolvConf(String content) {
        FakeMachine machine = new FakeMachine("linux").fail(RESOLVECTL_DNS, "resolvectl: command not found");
        machine.files.put("/etc/resolv.conf", content);
        return machine;
    }

    private Path journal() {
        return directory.resolve("egress-dns-journal.json");
    }

    private PeerEgressDnsTakeover takeover(FakeMachine machine) {
        return new PeerEgressDnsTakeover(machine, journal(), PID, pid -> false, null);
    }

    private static PeerEgressDnsTakeover.Request request(boolean poolRouteInstalled) {
        return new PeerEgressDnsTakeover.Request(LISTEN, TUNNEL, POOL, MESH, poolRouteInstalled);
    }

    /**
     * systemd-resolved through its stub: the TUN link is pointed at the responder and made the
     * default route for every name, the journal is committed with the upstreams read from the other
     * links, and giving back reverts the link.
     */
    @Test
    void takesOverAndGivesBackThroughResolved() throws IOException {
        FakeMachine machine = resolved();
        PeerEgressDnsTakeover takeover = takeover(machine);

        takeover.engage(request(true), EPOCH);

        assertEquals(List.of("resolvectl dns specus0 198.18.0.1", "resolvectl domain specus0 ~.", "resolvectl flush-caches"),
                machine.changes());
        PeerEgressDnsTakeover.Status status = takeover.status();
        assertTrue(status.takeover());
        assertNull(status.code());
        assertEquals("committed", status.journal());
        assertEquals(List.of("192.168.1.1"), takeover.upstreams());
        PeerEgressDnsTakeover.Journal written = PeerEgressDnsTakeover.readJournal(journal());
        assertNotNull(written);
        assertEquals("committed", written.state());
        assertEquals("linux-resolved", written.platform());
        assertEquals(PID, written.pid());
        assertEquals(List.of("192.168.1.1"), written.upstreams());
        assertEquals(EPOCH, written.startedAtUnixMs());

        machine.ran.clear();
        takeover.engage(request(true), EPOCH + 5_000);
        assertTrue(machine.ran.isEmpty(), "a takeover in place was taken again");

        takeover.release("the client is stopping");
        assertEquals(List.of("resolvectl revert specus0", "resolvectl flush-caches"), machine.changes());
        assertFalse(Files.exists(journal()), "the journal outlived the give-back");
        assertEquals(PeerEgressDnsTakeover.Status.none(), takeover.status());
        // Kept after giving back, for a system whose DNS someone points at the listen address by hand.
        assertEquals(List.of("192.168.1.1"), takeover.upstreams());
    }

    /**
     * Without resolved's stub the file is rewritten, its original kept in the journal and put back
     * when the file still holds what was written -- and someone else's version kept otherwise.
     */
    @Test
    void rewritesResolvConfAndKeepsSomeoneElsesVersion() throws IOException {
        String original = "nameserver 192.168.1.1\nsearch lan\n";
        FakeMachine machine = resolvConf(original);
        PeerEgressDnsTakeover takeover = takeover(machine);

        takeover.engage(request(true), EPOCH);
        assertEquals(PeerEgressDnsTakeoverParse.resolvConfWritten(LISTEN), machine.files.get("/etc/resolv.conf"));
        assertEquals(original, PeerEgressDnsTakeover.readJournal(journal()).resolvConf());
        assertEquals("linux-resolvconf", PeerEgressDnsTakeover.readJournal(journal()).platform());

        takeover.release("stopping");
        assertEquals(original, machine.files.get("/etc/resolv.conf"), "the original was not put back");

        takeover.forgetAttempt();
        takeover.engage(request(true), EPOCH + 1);
        machine.files.put("/etc/resolv.conf", "nameserver 10.0.0.1\n");
        takeover.release("stopping");
        assertEquals("nameserver 10.0.0.1\n", machine.files.get("/etc/resolv.conf"), "someone else's version was overwritten");
        assertFalse(Files.exists(journal()), "keeping their version is a finished give-back");
    }

    /** macOS: every enabled service pointed at the responder, each put back to exactly what it had. */
    @Test
    void takesOverEveryMacServiceAndPutsBackEachAsItWas() throws IOException {
        FakeMachine machine = new FakeMachine("macos")
                .answer(List.of("networksetup", "-listallnetworkservices"),
                        "An asterisk (*) denotes that a network service is disabled.\nWi-Fi\n*Bluetooth PAN\nEthernet\n")
                .answer(List.of("networksetup", "-getdnsservers", "Wi-Fi"), "There aren't any DNS Servers set on Wi-Fi.\n")
                .answer(List.of("networksetup", "-getdnsservers", "Ethernet"), "1.1.1.1\n")
                .answer(List.of("scutil", "--dns"), "DNS configuration\n\nresolver #1\n  nameserver[0] : 192.168.1.1\n");
        PeerEgressDnsTakeover takeover = takeover(machine);

        takeover.engage(request(true), EPOCH);
        assertEquals(List.of("networksetup -setdnsservers Wi-Fi 198.18.0.1", "networksetup -setdnsservers Ethernet 198.18.0.1",
                "dscacheutil -flushcache", "killall -HUP mDNSResponder"), machine.changes());
        PeerEgressDnsTakeover.Journal written = PeerEgressDnsTakeover.readJournal(journal());
        assertEquals(List.of(new PeerEgressDnsTakeover.Service("Wi-Fi", List.of("Empty")),
                new PeerEgressDnsTakeover.Service("Ethernet", List.of("1.1.1.1"))), written.services());

        machine.ran.clear();
        // Wi-Fi still points at the responder alone; Ethernet was changed by someone meanwhile.
        machine.answer(List.of("networksetup", "-getdnsservers", "Wi-Fi"), LISTEN + "\n");
        machine.answer(List.of("networksetup", "-getdnsservers", "Ethernet"), "9.9.9.9\n");
        takeover.release("stopping");
        assertEquals(List.of("networksetup -setdnsservers Wi-Fi Empty", "dscacheutil -flushcache",
                "killall -HUP mDNSResponder"), machine.changes());
        assertFalse(Files.exists(journal()));
    }

    /** Windows: an NRPT rule for the root namespace, marked as ours, and removed by that mark. */
    @Test
    void addsAndRemovesTheNrptRule() {
        FakeMachine machine = windows()
                .answer(PeerEgressDnsTakeoverParse.powershell(PeerEgressDnsTakeoverParse.WINDOWS_READ_SERVERS),
                        "[{\"InterfaceAlias\":\"Ethernet\",\"InterfaceIndex\":12,\"ServerAddresses\":[\"192.168.1.1\"]},"
                                + "{\"InterfaceAlias\":\"specus\",\"InterfaceIndex\":17,\"ServerAddresses\":[\"198.18.0.1\"]}]");
        PeerEgressDnsTakeover takeover = takeover(machine);

        takeover.engage(request(true), EPOCH);
        PeerEgressDnsTakeoverParse.Plan plan = PeerEgressDnsTakeoverParse.plan("windows", LISTEN, TUNNEL, List.of());
        assertEquals(List.of(FakeMachine.key(plan.apply().get(0).argv())), machine.changes());
        assertEquals(List.of("192.168.1.1"), takeover.upstreams(), "the TUN's own server was read as an upstream");

        machine.ran.clear();
        takeover.release("stopping");
        assertEquals(List.of(FakeMachine.key(plan.revert().get(0).argv())), machine.changes());
    }

    private static FakeMachine windows() {
        return new FakeMachine("windows")
                .answer(PeerEgressDnsTakeoverParse.powershell(PeerEgressDnsTakeoverParse.WINDOWS_READ_NRPT), "")
                .answer(PeerEgressDnsTakeoverParse.powershell(PeerEgressWindowsRouteCommands.interfaceIndexScript(TUNNEL)),
                        "[{\"InterfaceIndex\":17}]");
    }

    /**
     * A step that fails mid-way gives everything back, deletes the journal, and reports the first
     * line of what the failing command printed.
     */
    @Test
    void givesEverythingBackWhenAStepFails() {
        FakeMachine machine = resolved().fail(List.of("resolvectl", "domain", TUNNEL, "~."),
                "Failed to set DNS configuration: Unit dbus-org.freedesktop.resolve1.service not found.\nsecond line\n");
        PeerEgressDnsTakeover takeover = takeover(machine);

        takeover.engage(request(true), EPOCH);

        assertEquals(List.of("resolvectl dns specus0 198.18.0.1", "resolvectl domain specus0 ~.",
                "resolvectl revert specus0", "resolvectl flush-caches"), machine.changes());
        PeerEgressDnsTakeover.Status status = takeover.status();
        assertFalse(status.takeover());
        assertEquals("EGRESS_DNS_TAKEOVER_FAILED", status.code());
        assertEquals("Failed to set DNS configuration: Unit dbus-org.freedesktop.resolve1.service not found.", status.error());
        assertEquals("none", status.journal());
        assertFalse(Files.exists(journal()), "the journal of a given-back takeover stayed");
        assertTrue(takeover.upstreams().isEmpty());
    }

    /** A give-back that fails too keeps the journal, the only record of what to put back. */
    @Test
    void keepsTheJournalWhenGivingBackFails() throws IOException {
        FakeMachine machine = resolved()
                .fail(List.of("resolvectl", "flush-caches"), "Failed to flush caches: Access denied\n");
        PeerEgressDnsTakeover takeover = takeover(machine);

        takeover.engage(request(true), EPOCH);

        assertEquals("EGRESS_DNS_TAKEOVER_FAILED", takeover.status().code());
        assertEquals("Failed to flush caches: Access denied", takeover.status().error());
        assertEquals("pending", takeover.status().journal());
        assertEquals("pending", PeerEgressDnsTakeover.readJournal(journal()).state());

        // The next attempt gives the leftover back first; with the cache flush working again it
        // succeeds, and the takeover is made afresh.
        machine.failures.clear();
        machine.ran.clear();
        takeover.engage(request(true), EPOCH + PeerEgressDnsTakeover.RETRY_MS);
        assertEquals(List.of("resolvectl revert specus0", "resolvectl flush-caches", "resolvectl dns specus0 198.18.0.1",
                "resolvectl domain specus0 ~.", "resolvectl flush-caches"), machine.changes());
        assertTrue(takeover.status().takeover());
    }

    /** Each refusal leaves the system untouched and writes no journal. */
    @Test
    void refusesWithoutTouchingAnything() {
        record Case(String reason, FakeMachine machine, boolean poolRoute) {
        }
        FakeMachine managed = resolvConf("nameserver 192.168.1.1\n");
        managed.symlinks.add("/etc/resolv.conf");
        FakeMachine tunnelDns = resolvConf("nameserver 10.8.0.1\n");
        tunnelDns.interfaces = List.of(new PeerEgressDnsTakeoverParse.LocalInterface("wg0", 5, true, -1, List.of("10.8.0.1")));
        FakeMachine nrpt = windows().answer(PeerEgressDnsTakeoverParse.powershell(PeerEgressDnsTakeoverParse.WINDOWS_READ_NRPT),
                "{\"Namespace\":\".\",\"Comment\":\"corp-vpn\",\"NameServers\":\"10.0.0.1\"}");
        for (Case testCase : List.of(
                new Case("pool-route-not-installed", resolved(), false),
                new Case("system-dns-loopback", resolvConf("nameserver 127.0.0.1\n"), true),
                new Case("system-dns-virtual", tunnelDns, true),
                new Case("system-dns-virtual", resolvConf("nameserver 100.96.0.9\n"), true),
                new Case("no-upstream", resolvConf("nameserver 2001:db8::53\n"), true),
                new Case("resolv-conf-managed", managed, true),
                new Case("nrpt-root-occupied", nrpt, true),
                new Case("unsupported-platform", new FakeMachine("plan9"), true))) {
            PeerEgressDnsTakeover takeover = takeover(testCase.machine());
            takeover.engage(request(testCase.poolRoute()), EPOCH);
            PeerEgressDnsTakeover.Status status = takeover.status();
            assertEquals("EGRESS_DNS_TAKEOVER_REFUSED", status.code(), testCase.reason());
            assertEquals(testCase.reason(), status.reason());
            assertFalse(status.takeover());
            assertTrue(testCase.machine().changes().isEmpty(), testCase.reason() + ": something was changed");
            assertTrue(testCase.machine().written.isEmpty(), testCase.reason() + ": a file was written");
            assertFalse(Files.exists(journal()), testCase.reason() + ": a journal was written");
        }
    }

    /** A refusal is not re-read every tick: the system is read again after a minute, or when asked anew. */
    @Test
    void waitsBeforeReadingARefusedSystemAgain() {
        FakeMachine machine = resolvConf("nameserver 127.0.0.1\n");
        PeerEgressDnsTakeover takeover = takeover(machine);
        takeover.engage(request(true), EPOCH);
        takeover.engage(request(true), EPOCH + 5_000);
        assertEquals(1, machine.ran.size(), "the system was read again within the minute");
        takeover.engage(request(true), EPOCH + PeerEgressDnsTakeover.RETRY_MS);
        assertEquals(2, machine.ran.size());
        takeover.forgetAttempt();
        takeover.engage(request(true), EPOCH + PeerEgressDnsTakeover.RETRY_MS + 1);
        assertEquals(3, machine.ran.size());
    }

    /**
     * A journal a killed client left is given back at start, pending or committed; one whose client
     * is still running is left alone.
     */
    @Test
    void givesBackWhatAKilledClientLeft() throws IOException {
        FakeMachine machine = resolved();
        PeerEgressDnsTakeover.writeJournal(journal(), new PeerEgressDnsTakeover.Journal("committed", "linux-resolved", 1111,
                LISTEN, TUNNEL, List.of("192.168.1.1"), EPOCH, null, List.of()));

        PeerEgressDnsTakeover.recoverLeftover(machine, journal(), PID, pid -> pid == 2222);
        assertEquals(List.of("resolvectl revert specus0", "resolvectl flush-caches"), machine.changes());
        assertFalse(Files.exists(journal()));

        machine.ran.clear();
        PeerEgressDnsTakeover.writeJournal(journal(), new PeerEgressDnsTakeover.Journal("pending", "linux-resolved", 2222,
                LISTEN, TUNNEL, List.of("192.168.1.1"), EPOCH, null, List.of()));
        PeerEgressDnsTakeover.recoverLeftover(machine, journal(), PID, pid -> pid == 2222);
        assertTrue(machine.ran.isEmpty(), "a running client's takeover was given back");
        assertTrue(Files.exists(journal()));

        // With its link gone there is nothing to revert on the link, and the journal still goes.
        machine.links.clear();
        PeerEgressDnsTakeover.recoverLeftover(machine, journal(), PID, pid -> false);
        assertEquals(List.of("resolvectl flush-caches"), machine.changes());
        assertFalse(Files.exists(journal()));
    }

    /** The journal as written: private, pretty, and read back the same. */
    @Test
    void writesAndReadsTheJournal() throws IOException {
        PeerEgressDnsTakeover.Journal journal = new PeerEgressDnsTakeover.Journal("committed", "macos", 99, LISTEN,
                "utun3", List.of("192.168.1.1"), EPOCH, null,
                List.of(new PeerEgressDnsTakeover.Service("Wi-Fi", List.of("Empty"))));
        PeerEgressDnsTakeover.writeJournal(journal(), journal);
        assertEquals(journal, PeerEgressDnsTakeover.readJournal(journal()));
        String text = Files.readString(journal());
        assertTrue(text.contains("\"version\" : 1"), text);
        assertTrue(text.indexOf("\"state\"") < text.indexOf("\"platform\"") && text.indexOf("\"platform\"") < text.indexOf("\"pid\""), text);

        Files.writeString(journal(), "{\"version\":2,\"state\":\"committed\"}");
        IOException refused = null;
        try {
            PeerEgressDnsTakeover.readJournal(journal());
        } catch (IOException expected) {
            refused = expected;
        }
        assertNotNull(refused, "a journal of another version was read");
        assertNull(PeerEgressDnsTakeover.readJournal(directory.resolve("absent.json")));
    }

    /** egress dns restore: nothing to do, refused for a running client unless forced, done, or failed. */
    @Test
    void restoresFromTheCommandLine() throws IOException {
        FakeMachine machine = resolved();
        PeerEgressDnsTakeover.RestoreResult nothing = PeerEgressDnsTakeover.restore(machine, journal(), false, pid -> true);
        assertEquals(0, nothing.exitCode());
        assertTrue(nothing.message().contains("nothing to restore"), nothing.message());

        PeerEgressDnsTakeover.writeJournal(journal(), new PeerEgressDnsTakeover.Journal("committed", "linux-resolved", 3333,
                LISTEN, TUNNEL, List.of("192.168.1.1"), EPOCH, null, List.of()));
        PeerEgressDnsTakeover.RestoreResult running = PeerEgressDnsTakeover.restore(machine, journal(), false, pid -> pid == 3333);
        assertEquals(1, running.exitCode());
        assertTrue(running.message().contains("PID 3333"), running.message());
        assertTrue(machine.ran.isEmpty());

        machine.fail(List.of("resolvectl", "revert", TUNNEL), "Failed to revert interface configuration: Access denied\n");
        PeerEgressDnsTakeover.RestoreResult failed = PeerEgressDnsTakeover.restore(machine, journal(), true, pid -> pid == 3333);
        assertEquals(1, failed.exitCode());
        assertTrue(failed.message().contains("resolvectl revert specus0: Failed to revert interface configuration: Access denied"),
                failed.message());
        assertTrue(Files.exists(journal()), "a failed restore dropped the journal");

        machine.failures.clear();
        PeerEgressDnsTakeover.RestoreResult done = PeerEgressDnsTakeover.restore(machine, journal(), true, pid -> pid == 3333);
        assertEquals(0, done.exitCode(), done.message());
        assertFalse(Files.exists(journal()));
    }

    /** The network is compared every ten seconds; the first reading is the baseline. */
    @Test
    void noticesANewNetwork() {
        AtomicReference<String> network = new AtomicReference<>("eth0|192.168.1.5");
        PeerEgressDnsTakeover takeover = new PeerEgressDnsTakeover(resolved(), journal(), PID, pid -> false, network::get);
        assertFalse(takeover.networkChanged(EPOCH), "the baseline read as a change");
        network.set("wlan0|10.0.0.7");
        assertFalse(takeover.networkChanged(EPOCH + 9_999), "compared before ten seconds");
        assertTrue(takeover.networkChanged(EPOCH + 10_000));
        assertFalse(takeover.networkChanged(EPOCH + 20_000), "the same network read as a change");
    }

    /** The fingerprint: the default route's interface, off the tunnel, and every IPv4 address sorted. */
    @Test
    void fingerprintsTheNetwork() {
        List<PeerEgressSocketBinding.Route> routes = List.of(
                new PeerEgressSocketBinding.Route("0.0.0.0/0", "specus0", "", 0, true),
                new PeerEgressSocketBinding.Route("0.0.0.0/0", "wlan0", "10.0.0.1", 600, true),
                new PeerEgressSocketBinding.Route("0.0.0.0/0", "eth0", "192.168.1.1", 100, true),
                new PeerEgressSocketBinding.Route("0.0.0.0/0", "dead0", "", 1, false),
                new PeerEgressSocketBinding.Route("192.168.1.0/24", "eth0", "", 0, true));
        assertEquals("eth0|10.0.0.7,100.96.0.1,192.168.1.5", PeerEgressDnsTakeover.fingerprint(routes, "specus0",
                List.of("192.168.1.5", "100.96.0.1", "10.0.0.7", "192.168.1.5", "fe80::1")));
        assertEquals("|", PeerEgressDnsTakeover.fingerprint(List.of(), "specus0", List.of()));
    }

    /** Phase two stopping gives back, and a failed give-back stays reported until it is retried. */
    @Test
    void idlesWhenPhaseTwoStops() {
        FakeMachine machine = resolved();
        PeerEgressDnsTakeover takeover = takeover(machine);
        takeover.engage(request(true), EPOCH);
        machine.ran.clear();
        takeover.idle("phase two is not running");
        assertEquals(List.of("resolvectl revert specus0", "resolvectl flush-caches"), machine.changes());
        assertEquals(PeerEgressDnsTakeover.Status.none(), takeover.status());

        takeover.engage(request(true), EPOCH + 1);
        machine.fail(List.of("resolvectl", "flush-caches"), "flush denied\n");
        takeover.idle("phase two is not running");
        assertEquals("EGRESS_DNS_TAKEOVER_FAILED", takeover.status().code(), "a failed give-back was not reported");
        assertEquals("committed", takeover.status().journal());
    }
}
