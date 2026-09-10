package com.theshuai.specusclient.peer;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.theshuai.specusclient.peer.PeerEgressRoutePlanner.Kind;
import com.theshuai.specusclient.peer.PeerEgressRoutePlanner.Route;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * Route installation and the journal.
 *
 * <p>The routing table is injected, so the paths that matter here -- a failed install halfway
 * through, a prefix somebody else already owns, a journal left by a process that was killed -- are
 * driven deterministically instead of waiting for a machine to be in the wrong state.
 *
 * <p>The journal's on-disk shape is asserted against the shared vector rather than against this
 * class's own output, because a round trip through one implementation agrees with whatever that
 * implementation happens to write.
 */
class PeerEgressRouteInstallerTests {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    @TempDir
    Path directory;

    private Path journalPath() {
        return directory.resolve("egress-routes.json");
    }

    private static final class FakeCommander implements PeerEgressRouteInstaller.Commander {
        final Map<String, Route> table = new LinkedHashMap<>();
        final Map<String, String> foreign = new HashMap<>();
        final Map<String, IOException> installErr = new HashMap<>();
        final Map<String, IOException> removeErr = new HashMap<>();
        final List<String> installLog = new ArrayList<>();
        final List<String> removeLog = new ArrayList<>();

        @Override
        public PeerEgressRouteInstaller.Conflict conflict(Route route) {
            String existing = foreign.get(route.cidr());
            return existing == null
                    ? PeerEgressRouteInstaller.Conflict.none()
                    : new PeerEgressRouteInstaller.Conflict(true, existing);
        }

        @Override
        public void install(Route route) throws IOException {
            IOException failure = installErr.get(route.cidr());
            if (failure != null) {
                throw failure;
            }
            table.put(route.cidr(), route);
            installLog.add(route.cidr());
        }

        @Override
        public void remove(Route route) throws IOException {
            IOException failure = removeErr.get(route.cidr());
            if (failure != null) {
                throw failure;
            }
            table.remove(route.cidr());
            removeLog.add(route.cidr());
        }
    }

    private static Route tun(String cidr) {
        return new Route(cidr, Kind.TUN, "rule:" + cidr);
    }

    private static Route bypass(String cidr) {
        return new Route(cidr, Kind.BYPASS, "bypass");
    }

    private static JsonNode readVector() throws IOException {
        Path candidate = Path.of("").toAbsolutePath();
        for (int depth = 0; depth < 8 && candidate != null; depth++) {
            Path file = candidate.resolve("protocol").resolve("test-vectors")
                    .resolve("peer-egress-routes-v1.json");
            if (Files.exists(file)) {
                return MAPPER.readTree(Files.readString(file));
            }
            candidate = candidate.getParent();
        }
        throw new IOException("cannot locate peer-egress-routes-v1.json");
    }

    @Test
    void appliesAndWithdraws() throws IOException {
        FakeCommander commander = new FakeCommander();
        PeerEgressRouteInstaller installer = new PeerEgressRouteInstaller(commander, journalPath());

        PeerEgressRouteInstaller.ApplyResult result =
                installer.apply(List.of(bypass("198.51.100.7/32"), tun("203.0.113.0/24")));
        assertNull(result.error());
        assertEquals(2, result.added().size());
        assertEquals(2, commander.table.size());
        assertTrue(Files.exists(journalPath()), "the journal was not written");

        // The bypass entry is installed first, so the transport that carries the tunnel keeps
        // working before anything is pointed into it.
        assertEquals(List.of("198.51.100.7/32", "203.0.113.0/24"), commander.installLog);

        installer.withdrawAll();
        assertTrue(commander.table.isEmpty(), "routes survived a full withdrawal");
        assertFalse(Files.exists(journalPath()), "the journal survived a full withdrawal");
    }

    /**
     * A failure halfway through a rule set must not leave the machine routing some traffic into a
     * tunnel that was never finished being set up.
     */
    @Test
    void rollsBackAPartialInstall() {
        FakeCommander commander = new FakeCommander();
        commander.installErr.put("203.0.113.0/24", new IOException("no such device"));
        PeerEgressRouteInstaller installer = new PeerEgressRouteInstaller(commander, journalPath());

        PeerEgressRouteInstaller.ApplyResult result =
                installer.apply(List.of(bypass("198.51.100.7/32"), tun("203.0.113.0/24")));

        assertNotNull(result.error());
        assertTrue(result.rolledBack(), "a failed install was not rolled back");
        assertTrue(result.added().isEmpty(), "a rolled back call still reported additions");
        assertTrue(commander.table.isEmpty(), "the earlier route of this call was left installed");
        assertTrue(installer.installed().isEmpty(), "the journal still claims routes");
    }

    /**
     * Only this call's additions come back out. Routes from earlier calls are still wanted, and a
     * failure now is not a reason to tear down a configuration that was working a minute ago.
     */
    @Test
    void rollbackSparesEarlierRoutes() {
        FakeCommander commander = new FakeCommander();
        PeerEgressRouteInstaller installer = new PeerEgressRouteInstaller(commander, journalPath());
        assertNull(installer.apply(List.of(tun("203.0.113.0/24"))).error());

        commander.installErr.put("192.0.2.0/24", new IOException("no such device"));
        PeerEgressRouteInstaller.ApplyResult result =
                installer.apply(List.of(tun("203.0.113.0/24"), tun("192.0.2.0/24")));

        assertTrue(result.rolledBack());
        assertTrue(commander.table.containsKey("203.0.113.0/24"), "an earlier route was withdrawn");
        assertTrue(installer.owns("203.0.113.0/24"), "an earlier route left the journal");
    }

    /**
     * One contested prefix should not disable every other rule, and the operator is told which of
     * their own routes is in the way rather than having it silently replaced.
     */
    @Test
    void refusesConflictsAndKeepsGoing() {
        FakeCommander commander = new FakeCommander();
        commander.foreign.put("203.0.113.0/24", "203.0.113.0/24 via 10.0.0.1 dev eth0");
        PeerEgressRouteInstaller installer = new PeerEgressRouteInstaller(commander, journalPath());

        PeerEgressRouteInstaller.ApplyResult result =
                installer.apply(List.of(tun("203.0.113.0/24"), tun("192.0.2.0/24")));

        assertEquals(1, result.conflicts().size());
        assertEquals("203.0.113.0/24 via 10.0.0.1 dev eth0", result.conflicts().get(0).existing());
        assertEquals(1, result.added().size());
        assertTrue(commander.table.containsKey("192.0.2.0/24"), "the uncontested route was not installed");
        assertFalse(installer.owns("203.0.113.0/24"), "a refused prefix was recorded as ours");
    }

    /**
     * A restart has to take back what the previous run installed, and only that. Withdrawing
     * somebody else's route is worse than leaving our own behind.
     */
    @Test
    void withdrawsAJournalFromAPreviousRun() throws IOException {
        FakeCommander commander = new FakeCommander();
        PeerEgressRouteInstaller previous = new PeerEgressRouteInstaller(commander, journalPath());
        assertNull(previous.apply(List.of(bypass("198.51.100.7/32"), tun("203.0.113.0/24"))).error());
        // Something the user installed, which the journal never mentions.
        commander.table.put("10.0.0.0/8", tun("10.0.0.0/8"));

        PeerEgressRouteInstaller restarted = new PeerEgressRouteInstaller(commander, journalPath());
        restarted.load();
        assertEquals(2, restarted.installed().size());
        restarted.withdrawAll();

        assertTrue(commander.table.containsKey("10.0.0.0/8"), "a foreign route was withdrawn");
        assertEquals(1, commander.table.size());
        assertFalse(Files.exists(journalPath()), "the journal survived a full withdrawal");
    }

    /**
     * A missing journal is the ordinary first run. Refusing to start gains nothing, and the
     * alternative to an empty set is guessing which of the machine's routes might have been ours.
     */
    @Test
    void treatsAMissingJournalAsEmpty() throws IOException {
        PeerEgressRouteInstaller installer = new PeerEgressRouteInstaller(new FakeCommander(), journalPath());
        installer.load();
        assertTrue(installer.installed().isEmpty());
    }

    /** The journal another runtime wrote has to be readable, or its routes stay in the table forever. */
    @Test
    void readsAndWritesTheSharedJournal() throws IOException {
        JsonNode journal = readVector().path("journal");
        String text = journal.path("text").asText();
        assertFalse(text.isEmpty(), "routes vector carried no journal text");

        List<Route> expected = new ArrayList<>();
        for (JsonNode node : journal.path("routes")) {
            expected.add(new Route(node.path("cidr").asText(),
                    Kind.fromWireName(node.path("kind").asText()),
                    node.path("origin").asText()));
        }

        Files.writeString(journalPath(), text, StandardCharsets.UTF_8);
        PeerEgressRouteInstaller reader = new PeerEgressRouteInstaller(new FakeCommander(), journalPath());
        reader.load();
        assertEquals(expected, reader.installed());

        // And back out as the same bytes, so a Go or .NET consumer reads what this one wrote.
        assertEquals(text, PeerEgressRouteInstaller.render(expected));
    }

    /**
     * Every refusal leaves the installed set empty. Adopting a journal that could not be read would
     * mean withdrawing prefixes by guess, and treating it as empty would mean the routes it
     * describes are never taken back at all.
     */
    @Test
    void refusesTheJournalsTheVectorRejects() throws IOException {
        JsonNode rejects = readVector().path("journal").path("rejects");
        assertFalse(rejects.isEmpty(), "routes vector carried no journal rejects");

        for (JsonNode reject : rejects) {
            Files.writeString(journalPath(), reject.path("text").asText(), StandardCharsets.UTF_8);
            PeerEgressRouteInstaller installer =
                    new PeerEgressRouteInstaller(new FakeCommander(), journalPath());
            assertThrows(Exception.class, installer::load, reject.path("name").asText());
            assertTrue(installer.installed().isEmpty(), reject.path("name").asText());
        }
    }
}
