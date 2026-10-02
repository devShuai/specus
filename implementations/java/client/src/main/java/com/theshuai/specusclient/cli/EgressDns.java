package com.theshuai.specusclient.cli;

import com.fasterxml.jackson.databind.JsonNode;
import com.theshuai.common.peeregress.Ipv4Cidr;
import com.theshuai.specusclient.bean.ClientStartupConfig;
import com.theshuai.specusclient.peer.PeerEgressDnsSystem;
import com.theshuai.specusclient.peer.PeerEgressDnsTakeover;
import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.LongPredicate;

/**
 * The {@code egress dns} commands (protocol/spec/peer-egress-dns.md, section six, "commands"):
 * enable and disable set {@code peerEgressDnsTakeover} in the configuration file, status reads the
 * state a running client publishes and the takeover journal, restore gives the system's DNS back
 * from the journal. None needs a running client. The pinned lines are the ones the Go and .NET
 * clients print, word for word.
 */
public final class EgressDns {
    private EgressDns() { }

    /** What turning DNS takeover on means, said every time it is turned on. */
    static final List<String> ENABLE_NOTICE = List.of(
            "Turning on DNS takeover for domain rules:",
            "  - points the system DNS at this client while it runs and gives it back when it stops (resolvectl or"
                    + " /etc/resolv.conf on Linux, networksetup on macOS, an NRPT rule on Windows)",
            "  - keeps a journal in ~/.specus, so a change left by a killed client is undone at its next start or by"
                    + " egress dns restore",
            "  - domain rules do not match applications that bring their own DoH/DoT, use the system cache, or connect"
                    + " to hard-coded IP addresses; that traffic is covered only by IP/CIDR rules");

    // ----------------------------------------------------------------------------------------------
    // enable / disable
    // ----------------------------------------------------------------------------------------------

    static int toggle(ClientCli.Options options) {
        boolean enable = options.command().equals("egress dns enable");
        Path path = options.config();
        UiConfig.Snapshot snapshot;
        ClientStartupConfig config;
        try {
            snapshot = UiConfig.read(path);
        } catch (LocalUi.Failure failure) {
            return fail(options, failure.getMessage());
        } catch (Exception error) {
            return fail(options, "Cannot read " + path + ": " + error.getMessage());
        }
        if (snapshot.revision().equals("missing")) {
            return fail(options, "Configuration file not found: " + path);
        }
        try {
            config = ClientCli.parse(snapshot.text(), ignored -> { });
        } catch (Exception error) {
            return fail(options, "invalid config " + path + ": " + error.getMessage() + "; fix it first (config validate)");
        }
        if (enable && !options.egress().yes()) {
            // Confirmed by a flag rather than a prompt, as egress enable is.
            return fail(options, String.join("\n", ENABLE_NOTICE) + "\nNot changed. Re-run with --yes to confirm.");
        }
        String patched;
        ClientStartupConfig edited;
        try {
            patched = EgressEdit.patch(snapshot.text(), "peerEgressDnsTakeover", enable ? "true" : "false");
            edited = ClientCli.parse(patched, ignored -> { });
        } catch (LocalUi.Failure failure) {
            return fail(options, failure.getMessage());
        } catch (Exception error) {
            return fail(options, "the edited configuration would not load (" + error.getMessage() + "); nothing was written");
        }
        try {
            UiConfig.save(path, snapshot.revision(), patched);
        } catch (LocalUi.Failure failure) {
            return fail(options, failure.getMessage());
        } catch (Exception error) {
            return fail(options, "Cannot write " + path + ": " + error.getMessage());
        }
        List<String> lines = new ArrayList<>();
        if (enable) {
            lines.addAll(ENABLE_NOTICE);
            if (!config.isPeerEgressEnabled()) {
                lines.add("Warning: peerEgressEnabled is false, so domain rules take effect only after egress enable.");
            }
        }
        lines.add("Saved " + path + ". " + EgressEdit.RESTART_NOTE);
        lines.add(enable ? "dns takeover: on (pool " + edited.getPeerEgressFakeIpCidr() + ")" : "dns takeover: off");
        var data = new LinkedHashMap<String, Object>();
        data.put("configPath", path.toString());
        data.put("dnsTakeover", enable);
        data.put("pool", edited.getPeerEgressFakeIpCidr());
        return CliOutput.result(options.json(), options.command(), 0, data, String.join("\n", lines));
    }

    private static int fail(ClientCli.Options options, String message) {
        return CliOutput.result(options.json(), options.command(), 2, null, message);
    }

    // ----------------------------------------------------------------------------------------------
    // status
    // ----------------------------------------------------------------------------------------------

    static int status(ClientCli.Options options) {
        return status(options, PeerEgressDnsTakeover.defaultJournalPath(), CliState::clientRunning);
    }

    /**
     * With the journal and the client check a test chose. Restore is suggested when no client runs as
     * the journal's process id, whatever configuration it runs.
     */
    static int status(ClientCli.Options options, Path journalPath, LongPredicate clientRunning) {
        List<JsonNode> states;
        try {
            states = CliState.liveStates(options.config());
        } catch (IOException | RuntimeException unsafe) {
            return CliOutput.result(options.json(), options.command(), 2, null,
                    "Unsafe or unreadable local state. Use an owner-only local directory via SPECUS_CLI_STATE_DIR.");
        }
        List<String> lines = new ArrayList<>();
        List<Map<String, Object>> instances = new ArrayList<>();
        for (JsonNode state : states) {
            long pid = state.path("pid").asLong();
            JsonNode dns = state.path("egress").path("consumer").path("dns");
            var instance = new LinkedHashMap<String, Object>();
            instance.put("pid", pid);
            instance.put("dns", dns.isObject() ? dns : null);
            instances.add(instance);
            lines.add("PID " + pid);
            lines.addAll(dnsLines(dns.isObject() ? dns : null));
        }
        if (states.isEmpty()) {
            lines.add("No running client for this config.");
        }

        var journal = new LinkedHashMap<String, Object>();
        journal.put("path", journalPath.toString());
        try {
            PeerEgressDnsTakeover.Journal recorded = PeerEgressDnsTakeover.readJournal(journalPath);
            if (recorded == null) {
                journal.put("state", PeerEgressDnsTakeover.JOURNAL_NONE);
                lines.add("journal: none (the system DNS is not taken over)");
            } else {
                journal.put("state", recorded.state());
                journal.put("platform", recorded.platform());
                journal.put("pid", recorded.pid());
                journal.put("upstreams", recorded.upstreams());
                lines.add("journal: " + recorded.state() + " (" + recorded.platform() + ", taken over by PID "
                        + recorded.pid() + ", upstreams " + joinOrNone(recorded.upstreams()) + ")");
                if (!clientRunning.test(recorded.pid())) {
                    // Nothing is running to give it back when it stops: that is what restore is for.
                    lines.add("  the system DNS may still point at the responder; run egress dns restore");
                }
            }
        } catch (IOException unreadable) {
            journal.put("state", "unreadable");
            journal.put("error", unreadable.getMessage());
            lines.add("journal: unreadable (" + unreadable.getMessage() + ")");
        }

        var data = new LinkedHashMap<String, Object>();
        data.put("configPath", options.config().toString());
        data.put("instances", instances);
        data.put("journal", journal);
        return CliOutput.result(options.json(), options.command(), 0, data, String.join("\n", lines));
    }

    /** What a running client's status says about phase two and the takeover. */
    private static List<String> dnsLines(JsonNode dns) {
        List<String> lines = new ArrayList<>();
        if (dns == null) {
            lines.add("  dns takeover: off (peerEgressDnsTakeover is false)");
            return lines;
        }
        String code = dns.path("code").asText("");
        boolean active = dns.path("active").asBoolean(false);
        lines.add(active ? "  phase two: running" : "  phase two: not running" + (code.isEmpty() ? "" : " (" + code + ")"));
        if (dns.path("takeover").asBoolean(false)) {
            lines.add("  system DNS: taken over, answered at " + dns.path("listen").asText(""));
        } else if (active) {
            String detail = dns.hasNonNull("reason") ? dns.path("reason").asText() : dns.path("error").asText("");
            lines.add("  system DNS: not taken over" + (code.isEmpty() ? "" : " (" + code
                    + (detail.isEmpty() ? "" : ": " + detail) + ")"));
        }
        List<String> upstreams = new ArrayList<>();
        dns.path("upstreams").forEach(upstream -> upstreams.add(upstream.asText()));
        lines.add("  upstreams: " + joinOrNone(upstreams));
        long mappings = dns.path("mappings").asLong(0);
        long capacity = poolCapacity(dns.path("pool").asText(""));
        lines.add("  mappings: " + mappings + (capacity > 0
                ? String.format(" of %d (%.1f%% of the pool %s)", capacity, mappings * 100.0 / capacity,
                        dns.path("pool").asText(""))
                : "") + ", " + dns.path("quarantined").asLong(0) + " quarantined");
        JsonNode queries = dns.path("queries");
        if (queries.isObject()) {
            lines.add("  queries: " + queries.path("answered").asLong(0) + " answered, "
                    + queries.path("forwarded").asLong(0) + " forwarded, " + queries.path("failed").asLong(0) + " failed");
        }
        return lines;
    }

    /** The addresses a pool can hand out: all but the network, broadcast and responder addresses. */
    private static long poolCapacity(String cidr) {
        Ipv4Cidr pool = Ipv4Cidr.parse(cidr);
        return pool == null || pool.prefixLength() > 30 ? 0 : (1L << (32 - pool.prefixLength())) - 3;
    }

    private static String joinOrNone(List<String> values) {
        return values == null || values.isEmpty() ? "none" : String.join(", ", values);
    }

    // ----------------------------------------------------------------------------------------------
    // restore
    // ----------------------------------------------------------------------------------------------

    /**
     * The client that took over runs when it publishes fresh state ({@link CliState#clientRunning}):
     * a process id alone may belong to another program since a reboot.
     */
    static int restore(ClientCli.Options options) {
        return restore(options, new PeerEgressDnsSystem(), PeerEgressDnsTakeover.defaultJournalPath(),
                CliState::clientRunning);
    }

    /** With the machine, journal and client check a test chose. */
    static int restore(ClientCli.Options options, PeerEgressDnsTakeover.Machine machine, Path journalPath,
            LongPredicate clientRunning) {
        PeerEgressDnsTakeover.RestoreResult result =
                PeerEgressDnsTakeover.restore(machine, journalPath, options.egress().force(), clientRunning);
        Map<String, Object> data = new LinkedHashMap<>();
        data.put("journal", journalPath.toString());
        data.put("restored", result.exitCode() == 0 && result.journal() != null);
        if (result.journal() != null) {
            data.put("platform", result.journal().platform());
            data.put("pid", result.journal().pid());
        }
        return CliOutput.result(options.json(), options.command(), result.exitCode(), data, result.message());
    }
}
