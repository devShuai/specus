package com.theshuai.specusclient.cli;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.fasterxml.jackson.databind.JsonNode;
import com.theshuai.specusclient.peer.PeerEgressDnsTakeover;
import com.theshuai.specusclient.peer.PeerEgressDnsTakeoverParse;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * The egress dns commands, their exact lines and exit codes. Commands run as isolated processes
 * with the home and the state directory in a temporary directory; giving a journal back runs in
 * process against a fake machine, so no test touches this machine's DNS.
 */
class EgressDnsCommandTests {

    @TempDir
    Path temporary;

    private record Run(int exit, String out, String err) { }

    private Run run(String... args) throws Exception {
        var command = new ArrayList<>(List.of(Path.of(System.getProperty("java.home"), "bin", "java").toString(),
                "-Duser.home=" + temporary, "-cp", System.getProperty("java.class.path"),
                "com.theshuai.specusclient.SpecusClientApplication"));
        command.addAll(List.of(args));
        Path out = Files.createTempFile(temporary, "out", ".txt");
        Path err = Files.createTempFile(temporary, "err", ".txt");
        ProcessBuilder builder = new ProcessBuilder(command).directory(temporary.toFile())
                .redirectOutput(out.toFile()).redirectError(err.toFile());
        builder.environment().put("SPECUS_CLI_STATE_DIR", temporary.resolve("state").toString());
        Process process = builder.start();
        try {
            assertThat(process.waitFor(20, TimeUnit.SECONDS)).as("hung: %s", List.of(args)).isTrue();
            return new Run(process.exitValue(), Files.readString(out), Files.readString(err));
        } finally {
            if (process.isAlive()) {
                process.destroyForcibly();
                process.waitFor();
            }
        }
    }

    private Path config(String extra) throws IOException {
        Path config = temporary.resolve("client.jsonc");
        Files.writeString(config, "{\n  // kept across edits\n  \"serverBaseUrl\": \"http://127.0.0.1:1\",\n"
                + "  \"apiKey\": \"test\",\n  \"secret\": \"secret\"" + extra + "\n}\n");
        return config;
    }

    /**
     * Writes a state file the way a running client does -- private, in the state directory the
     * commands run here read -- for another configuration, so only the process id can match.
     */
    private Path publishState(String name, long pid, long updatedAtUnixMs, int schemaVersion) throws IOException {
        Path root = CliState.ensureRoot(temporary.resolve("state"));
        Path file = root.resolve(name);
        Files.writeString(file, CliOutput.JSON.writeValueAsString(Map.of("schemaVersion", schemaVersion, "pid", pid,
                "updatedAtUnixMs", updatedAtUnixMs, "configPath", root.resolve("another.jsonc").toString(),
                "processRunning", true)));
        if (CliState.posix()) {
            Files.setPosixFilePermissions(file, PosixFilePermissions.fromString("rw-------"));
        }
        CliState.protectNew(file, false);
        return file;
    }

    /**
     * A client runs as a process id when fresh state from that process is in the state directory: the
     * status command's rule, for any configuration and runtime, matched on the id inside the file.
     */
    @Test
    void aClientRunsWhileItPublishesFreshState() throws Exception {
        Path root = temporary.resolve("state");
        long self = ProcessHandle.current().pid();
        assertThat(CliState.clientRunning(self, root)).as("no state directory").isFalse();
        // Named for another process: the id inside is what counts.
        publishState("go-0123-1.json", self, System.currentTimeMillis(), 1);
        assertThat(CliState.clientRunning(self, root)).isTrue();
        assertThat(CliState.clientRunning(self + 1, root)).isFalse();
        assertThat(CliState.clientRunning(0, root)).isFalse();

        publishState("go-0123-1.json", self, System.currentTimeMillis() - 6_000, 1);
        assertThat(CliState.clientRunning(self, root)).as("stale").isFalse();
        publishState("go-0123-1.json", self, System.currentTimeMillis() + 60_000, 1);
        assertThat(CliState.clientRunning(self, root)).as("from later").isFalse();
        publishState("go-0123-1.json", self, System.currentTimeMillis(), 2);
        assertThat(CliState.clientRunning(self, root)).as("version 2").isFalse();
        // No such process: an id Windows never hands out and far above any Unix pid_max.
        publishState("dotnet-4567-1.json", Integer.MAX_VALUE, System.currentTimeMillis(), 1);
        assertThat(CliState.clientRunning(Integer.MAX_VALUE, root)).as("exited").isFalse();
        if (CliState.posix()) {
            Path open = publishState("java-89ab-1.json", self, System.currentTimeMillis(), 1);
            Files.setPosixFilePermissions(open, PosixFilePermissions.fromString("rw-r--r--"));
            assertThat(CliState.clientRunning(self, root)).as("readable by others").isFalse();
        }
    }

    /** A message as the CLI prints it: its lines joined by \n, then println's own line separator. */
    private static String lines(List<String> lines) {
        return String.join("\n", lines) + System.lineSeparator();
    }

    @Test
    void parsesTheCommandsAndKeepsEachFlagToItsCommand() {
        assertThat(ClientCli.parse(new String[] {"egress", "dns", "enable", "--yes"}).egress().yes()).isTrue();
        assertThat(ClientCli.parse(new String[] {"egress", "dns", "restore", "--force"}).egress().force()).isTrue();
        assertThat(ClientCli.parse(new String[] {"egress", "dns", "status", "--config", "x.jsonc"}).command())
                .isEqualTo("egress dns status");
        for (String[] args : new String[][] {{"egress", "dns"}, {"egress", "dns", "bogus"},
                {"egress", "dns", "status", "--force"}, {"egress", "dns", "disable", "--yes"}, {"egress", "enable", "--force"}}) {
            assertThatThrownBy(() -> ClientCli.parse(args)).as(String.join(" ", args)).isInstanceOf(IllegalArgumentException.class);
        }
        assertThat(ClientCli.HELP).contains("Domain rules do not match applications that bring their own DoH/DoT, use the"
                + " system cache, or connect to hard-coded IP addresses; that traffic is covered only by IP/CIDR rules.");
    }

    @Test
    void enableSaysWhatItChangesAndNeedsConfirmation() throws Exception {
        Path config = config("");
        String before = Files.readString(config);
        Run refused = run("egress", "dns", "enable", "--config", config.toString());
        assertThat(refused.exit()).isEqualTo(2);
        assertThat(refused.out()).isEmpty();
        var expected = new ArrayList<>(EgressDns.ENABLE_NOTICE);
        expected.add("Not changed. Re-run with --yes to confirm.");
        assertThat(refused.err()).isEqualTo(lines(expected));
        assertThat(Files.readString(config)).isEqualTo(before);

        Run enabled = run("egress", "dns", "enable", "--yes", "--config", config.toString());
        assertThat(enabled.exit()).as(enabled.err()).isEqualTo(0);
        var saved = new ArrayList<>(EgressDns.ENABLE_NOTICE);
        saved.add("Warning: peerEgressEnabled is false, so domain rules take effect only after egress enable.");
        saved.add("Saved " + config + ". A running client applies the change after a restart.");
        saved.add("dns takeover: on (pool 198.18.0.0/15)");
        assertThat(enabled.out()).isEqualTo(lines(saved));
        assertThat(Files.readString(config)).contains("\"peerEgressDnsTakeover\": true", "// kept across edits");

        Run disabled = run("egress", "dns", "disable", "--config", config.toString(), "--json");
        assertThat(disabled.exit()).isEqualTo(0);
        JsonNode envelope = CliOutput.JSON.readTree(disabled.out());
        assertThat(envelope.path("data").path("configPath").asText()).isEqualTo(config.toString());
        assertThat(envelope.path("data").path("dnsTakeover").asBoolean(true)).isFalse();
        assertThat(envelope.path("data").path("pool").asText()).isEqualTo("198.18.0.0/15");
        assertThat(Files.readString(config)).contains("\"peerEgressDnsTakeover\": false");

        Path enabledConsumer = config(",\n  \"peerEgressEnabled\": true,\n  \"peerEgressFakeIpCidr\": \"10.64.0.0/16\"");
        Run quiet = run("egress", "dns", "enable", "--yes", "--config", enabledConsumer.toString());
        assertThat(quiet.out()).doesNotContain("Warning:").endsWith("dns takeover: on (pool 10.64.0.0/16)" + System.lineSeparator());
    }

    @Test
    void statusReadsTheJournalWithoutARunningClient() throws Exception {
        Path config = config("");
        Run none = run("egress", "dns", "status", "--config", config.toString());
        assertThat(none.exit()).as(none.err()).isEqualTo(0);
        assertThat(none.out()).isEqualTo(lines(List.of("No running client for this config.",
                "journal: none (the system DNS is not taken over)")));

        Path journal = temporary.resolve(".specus").resolve("egress-dns-journal.json");
        Files.createDirectories(journal.getParent());
        Files.writeString(journal, "{\"version\":1,\"state\":\"committed\",\"platform\":\"linux-resolved\",\"pid\":999999,"
                + "\"listen\":\"198.18.0.1\",\"tunnel\":\"specus0\",\"upstreams\":[\"192.168.1.1\"],\"startedAtUnixMs\":1}");
        Run held = run("egress", "dns", "status", "--config", config.toString(), "--json");
        assertThat(held.exit()).isEqualTo(0);
        JsonNode data = CliOutput.JSON.readTree(held.out()).path("data");
        assertThat(data.path("configPath").asText()).isEqualTo(config.toString());
        assertThat(data.path("instances").isArray()).isTrue();
        assertThat(data.path("instances")).isEmpty();
        assertThat(data.path("journal").path("path").asText()).isEqualTo(journal.toString());
        assertThat(data.path("journal").path("state").asText()).isEqualTo("committed");

        Run text = run("egress", "dns", "status", "--config", config.toString());
        assertThat(text.out()).contains("journal: committed (linux-resolved, taken over by PID 999999, upstreams 192.168.1.1)",
                "run egress dns restore");

        // A client publishing fresh state as that process id gives it back itself, whatever
        // configuration it runs: restore is not suggested.
        long self = ProcessHandle.current().pid();
        Files.writeString(journal, "{\"version\":1,\"state\":\"committed\",\"platform\":\"linux-resolved\",\"pid\":" + self
                + ",\"listen\":\"198.18.0.1\",\"tunnel\":\"specus0\",\"upstreams\":[\"192.168.1.1\"],\"startedAtUnixMs\":1}");
        publishState("go-0123-1.json", self, System.currentTimeMillis(), 1);
        Run elsewhere = run("egress", "dns", "status", "--config", config.toString());
        assertThat(elsewhere.out()).contains("No running client for this config.", "taken over by PID " + self)
                .doesNotContain("run egress dns restore");
    }

    @Test
    void restoreSaysThereIsNothingToDoOrThatTheClientStillRuns() throws Exception {
        Run nothing = run("egress", "dns", "restore");
        Path journal = temporary.resolve(".specus").resolve("egress-dns-journal.json");
        assertThat(nothing.exit()).isEqualTo(0);
        assertThat(nothing.out()).isEqualTo(lines(List.of(
                "No DNS takeover journal at " + journal + "; there is nothing to restore.")));

        // Recorded by this test's own process, which is running; the platform is one no client knows,
        // so even a broken check could run nothing.
        long pid = ProcessHandle.current().pid();
        Files.createDirectories(journal.getParent());
        Files.writeString(journal, "{\"version\":1,\"state\":\"committed\",\"platform\":\"plan9\",\"pid\":" + pid
                + ",\"listen\":\"198.18.0.1\",\"tunnel\":\"specus0\",\"upstreams\":[],\"startedAtUnixMs\":1}");
        // A running process id is not a running client: without its state, restore goes on to give
        // back, which the unknown platform stops before anything runs.
        Run reused = run("egress", "dns", "restore");
        assertThat(reused.exit()).isEqualTo(1);
        assertThat(reused.err()).startsWith("Giving the system DNS back failed at the journal names platform plan9");
        assertThat(journal).exists();

        publishState("dotnet-0123-1.json", pid, System.currentTimeMillis(), 1);
        Run running = run("egress", "dns", "restore");
        assertThat(running.exit()).isEqualTo(1);
        assertThat(running.err()).isEqualTo(lines(List.of("The client that took over the system DNS (PID " + pid
                + ") is still running, and gives it back itself when it stops. Stop it, or set peerEgressDnsTakeover to"
                + " false and restart it. --force skips this check, for when that PID now belongs to another client.")));
        assertThat(journal).exists();
    }

    /** A machine that runs nothing: it only records, and fails what it is told to. */
    private static final class Fake implements PeerEgressDnsTakeover.Machine {
        final List<String> ran = new ArrayList<>();
        String failing;

        @Override public String platform() { return "linux"; }

        @Override public String run(List<String> argv) throws IOException {
            String key = String.join(" ", argv);
            ran.add(key);
            if (key.equals(failing)) {
                throw new PeerEgressDnsTakeover.CommandFailure(argv, "Failed to revert interface configuration: Access denied\n");
            }
            return "";
        }

        @Override public String readFile(String path) throws IOException { throw new NoSuchFileException(path); }

        @Override public void writeFile(String path, String content) { }

        @Override public boolean isSymlink(String path) { return false; }

        @Override public boolean linkExists(String name) { return true; }

        @Override public List<PeerEgressDnsTakeoverParse.LocalInterface> interfaces() { return List.of(); }
    }

    private static String captured(java.util.function.IntSupplier command, int[] exit) {
        PrintStream original = System.out;
        PrintStream originalErr = System.err;
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        PrintStream stream = new PrintStream(buffer, true, StandardCharsets.UTF_8);
        System.setOut(stream);
        System.setErr(stream);
        try {
            exit[0] = command.getAsInt();
        } finally {
            System.setOut(original);
            System.setErr(originalErr);
        }
        return buffer.toString(StandardCharsets.UTF_8);
    }

    @Test
    void restoreGivesBackOrSaysWhichStepFailed() throws Exception {
        Path journal = temporary.resolve("egress-dns-journal.json");
        Files.writeString(journal, "{\"version\":1,\"state\":\"committed\",\"platform\":\"linux-resolved\",\"pid\":1111,"
                + "\"listen\":\"198.18.0.1\",\"tunnel\":\"specus0\",\"upstreams\":[\"192.168.1.1\"],\"startedAtUnixMs\":1}");
        Fake machine = new Fake();
        machine.failing = "resolvectl revert specus0";
        var options = ClientCli.parse(new String[] {"egress", "dns", "restore"});
        int[] exit = new int[1];
        String failed = captured(() -> EgressDns.restore(options, machine, journal, pid -> false), exit);
        assertThat(exit[0]).isEqualTo(1);
        assertThat(failed).isEqualTo(lines(List.of("Giving the system DNS back failed at resolvectl revert specus0: Failed to"
                + " revert interface configuration: Access denied. The journal is kept; fix what the step reports and run"
                + " egress dns restore again.")));
        assertThat(machine.ran).containsExactly("resolvectl revert specus0", "resolvectl flush-caches");
        assertThat(journal).exists();

        machine.failing = null;
        var json = ClientCli.parse(new String[] {"egress", "dns", "restore", "--json"});
        String done = captured(() -> EgressDns.restore(json, machine, journal, pid -> false), exit);
        assertThat(exit[0]).isEqualTo(0);
        JsonNode envelope = CliOutput.JSON.readTree(done);
        assertThat(envelope.path("data").path("journal").asText()).isEqualTo(journal.toString());
        assertThat(envelope.path("data").path("restored").asBoolean()).isTrue();
        assertThat(journal).doesNotExist();

        Files.writeString(journal, "{\"version\":1,\"state\":\"pending\",\"platform\":\"linux-resolved\",\"pid\":2222,"
                + "\"listen\":\"198.18.0.1\",\"tunnel\":\"specus0\",\"upstreams\":[],\"startedAtUnixMs\":1}");
        var forced = ClientCli.parse(new String[] {"egress", "dns", "restore", "--force"});
        String text = captured(() -> EgressDns.restore(forced, machine, journal, pid -> true), exit);
        assertThat(exit[0]).isEqualTo(0);
        assertThat(text).isEqualTo(lines(List.of("System DNS given back (linux-resolved, taken over by PID 2222); journal removed.")));
    }
}
