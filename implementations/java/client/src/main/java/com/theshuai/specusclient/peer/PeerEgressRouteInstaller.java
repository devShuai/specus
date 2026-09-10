package com.theshuai.specusclient.peer;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.theshuai.specusclient.peer.PeerEgressRoutePlanner.Kind;
import com.theshuai.specusclient.peer.PeerEgressRoutePlanner.Route;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/**
 * Installing routes without leaving any behind.
 *
 * <p>Two problems this class exists to solve. A partial install has to come back out, or a failure
 * halfway through a rule set leaves the machine routing some traffic into a tunnel that was never
 * finished being set up. And a route this feature owns has to be distinguishable from one the user
 * or another tool installed, across a clean exit, a crash and a restart, because withdrawing
 * someone else's route is worse than leaving our own behind.
 *
 * <p>The journal is what answers the second question. It records what was installed, on disk,
 * before the install is attempted. Written first on purpose: a journal entry for a route that
 * failed to install costs one harmless removal attempt at cleanup, while a route installed without
 * a journal entry is one nobody will ever take back.
 *
 * <p>Its on-disk shape is shared with the Go and .NET consumers, and pinned by
 * {@code protocol/test-vectors/peer-egress-routes-v1.json}. A user who switches implementations on
 * one machine has to have their routes adopted and withdrawn rather than left behind by a reader
 * that did not recognise the file.
 *
 * <p>Not safe for concurrent use; the caller that owns the rule configuration drives it.
 */
public final class PeerEgressRouteInstaller {

    static final int JOURNAL_VERSION = 1;

    private static final ObjectMapper MAPPER = new ObjectMapper();

    /**
     * The platform's routing table. Injected so the failure and rollback paths can be driven
     * without touching the real one.
     */
    public interface Commander {
        /**
         * Reports an existing route for this exact prefix that this feature does not own. The
         * description is what an operator reads, so it should say what is already there.
         */
        Conflict conflict(Route route);

        void install(Route route) throws IOException;

        void remove(Route route) throws IOException;
    }

    /** Whether a prefix is already taken, and by what. */
    public record Conflict(boolean present, String existing) {
        private static final Conflict NONE = new Conflict(false, "");

        public static Conflict none() {
            return NONE;
        }
    }

    /** A route refused because something else already owns the prefix. */
    public record RouteConflict(Route route, String existing) {
    }

    /**
     * What happened, in enough detail for an operator to act.
     *
     * @param conflicts routes refused because something else already owns the prefix; the rest of
     *                  the plan is applied regardless, since one contested prefix should not
     *                  disable every other rule
     * @param rolledBack set when an install failed for a reason other than a conflict and the
     *                   additions from this call were undone
     */
    public record ApplyResult(
            List<Route> added,
            List<Route> removed,
            List<RouteConflict> conflicts,
            boolean rolledBack,
            Exception error) {
    }

    private final Commander commander;
    private final Path journalPath;
    private final List<Route> installed = new ArrayList<>();

    public PeerEgressRouteInstaller(Commander commander, Path journalPath) {
        this.commander = commander;
        this.journalPath = journalPath;
    }

    /** The routes this feature currently owns, in the order they were installed. */
    public List<Route> installed() {
        return List.copyOf(installed);
    }

    /**
     * Reads the journal from a previous run.
     *
     * <p>A missing journal yields an empty set: there is nothing to be gained by refusing to start,
     * and the alternative to an empty set is guessing which of the machine's routes might have been
     * ours. A journal that exists but cannot be read is an error rather than an empty set, because
     * treating it as empty would mean the routes it describes are never taken back at all.
     */
    public void load() throws IOException {
        installed.clear();
        if (journalPath == null) {
            return;
        }
        if (!Files.exists(journalPath)) {
            return;
        }
        JsonNode journal = MAPPER.readTree(Files.readString(journalPath, StandardCharsets.UTF_8));
        if (!journal.isObject()) {
            throw new IOException("egress route journal is not an object");
        }
        int version = journal.path("version").asInt(-1);
        if (version != JOURNAL_VERSION) {
            // A journal from a version that wrote entries differently cannot be trusted to
            // describe what is actually installed, and acting on it would mean removing prefixes
            // by guess.
            throw new IOException("egress route journal version " + version + " is not " + JOURNAL_VERSION);
        }
        List<Route> adopted = new ArrayList<>();
        for (JsonNode node : journal.path("routes")) {
            String cidr = node.path("cidr").asText("");
            String kind = node.path("kind").asText("");
            if (cidr.isEmpty()) {
                throw new IOException("egress route journal carries a route with no prefix");
            }
            if (!"tun".equals(kind) && !"bypass".equals(kind)) {
                // Refused rather than defaulted: guessing would mean withdrawing a prefix the
                // previous run may have installed as the other kind.
                throw new IOException("unknown egress route kind " + kind);
            }
            adopted.add(new Route(cidr, Kind.fromWireName(kind), node.path("origin").asText("")));
        }
        PeerEgressRoutePlanner.sort(adopted);
        installed.addAll(adopted);
    }

    private void save() throws IOException {
        if (journalPath == null) {
            return;
        }
        if (installed.isEmpty()) {
            Files.deleteIfExists(journalPath);
            return;
        }
        PeerEgressRoutePlanner.sort(installed);
        // Written through a temporary file and renamed into place: a journal truncated by a crash
        // mid-write would describe fewer routes than are installed, and the difference is what gets
        // left behind.
        SecretFileWriter.writeSecret(journalPath, render(installed));
    }

    /**
     * Renders the journal.
     *
     * <p>Assembled by hand rather than through a pretty-printer so that the bytes are the ones the
     * shared vector pins, whatever a JSON library's default spacing happens to be this year. The
     * values still go through the encoder, because an origin carries a rule's match string and a
     * malformed configuration can put a quote in it.
     */
    static String render(List<Route> routes) throws IOException {
        StringBuilder text = new StringBuilder(128);
        text.append("{\n  \"version\": ").append(JOURNAL_VERSION).append(",\n  \"routes\": [");
        for (int index = 0; index < routes.size(); index++) {
            Route route = routes.get(index);
            text.append(index == 0 ? "\n" : ",\n");
            text.append("    {\n      \"cidr\": ").append(MAPPER.writeValueAsString(route.cidr()))
                    .append(",\n      \"kind\": ").append(MAPPER.writeValueAsString(route.kind().wireName()))
                    .append(",\n      \"origin\": ").append(MAPPER.writeValueAsString(route.origin()))
                    .append("\n    }");
        }
        text.append(routes.isEmpty() ? "]" : "\n  ]").append("\n}");
        return text.toString();
    }

    /**
     * Moves the routing table to the desired set.
     *
     * <p>Withdrawals happen first, so a prefix that changed kind loses its old entry before the new
     * one goes in. Then additions, each preceded by a conflict check.
     */
    public ApplyResult apply(List<Route> desired) {
        List<Route> added = new ArrayList<>();
        List<Route> removed = new ArrayList<>();
        List<RouteConflict> conflicts = new ArrayList<>();
        Exception error = null;

        PeerEgressRoutePlanner.Difference difference = PeerEgressRoutePlanner.diff(installed(), desired);
        for (Route route : difference.remove()) {
            try {
                commander.remove(route);
            } catch (Exception failure) {
                // A route we cannot remove is dropped from the journal anyway. Keeping it would
                // mean retrying forever against a table that no longer has it, which is the more
                // likely explanation than a table refusing us.
                error = failure;
            }
            forget(route);
            removed.add(route);
        }

        List<Route> appliedThisCall = new ArrayList<>();
        for (Route route : difference.add()) {
            Conflict conflict = commander.conflict(route);
            if (conflict.present()) {
                // Phase one does not preempt and does not compare metrics. Refusing one prefix and
                // telling the operator beats quietly winning an argument with their own routing.
                conflicts.add(new RouteConflict(route, conflict.existing()));
                continue;
            }
            // Journal before install, so a crash between the two leaves a removable record rather
            // than an unowned route.
            installed.add(route);
            try {
                save();
            } catch (Exception failure) {
                forget(route);
                rollback(appliedThisCall);
                return new ApplyResult(List.of(), List.copyOf(removed), List.copyOf(conflicts), true, failure);
            }
            try {
                commander.install(route);
            } catch (Exception failure) {
                forget(route);
                saveQuietly();
                rollback(appliedThisCall);
                return new ApplyResult(List.of(), List.copyOf(removed), List.copyOf(conflicts), true, failure);
            }
            appliedThisCall.add(route);
            added.add(route);
        }

        try {
            save();
        } catch (Exception failure) {
            if (error == null) {
                error = failure;
            }
        }
        return new ApplyResult(List.copyOf(added), List.copyOf(removed), List.copyOf(conflicts), false, error);
    }

    /**
     * Withdraws the additions from the current call only.
     *
     * <p>Only this call's, because routes from earlier calls are still wanted; a failure now is not
     * a reason to tear down a configuration that was working a minute ago.
     */
    private void rollback(List<Route> applied) {
        for (int index = applied.size() - 1; index >= 0; index--) {
            Route route = applied.get(index);
            try {
                commander.remove(route);
            } catch (Exception ignored) {
                // Already failing; the journal entry is what makes a retry possible.
            }
            forget(route);
        }
        saveQuietly();
    }

    /**
     * Removes every route this feature owns, for shutdown or for a restart that found a journal
     * from a previous run.
     */
    public List<Route> withdrawAll() {
        List<Route> owned = new ArrayList<>(installed);
        // Reverse order, so the bypass entries that keep the transport working outlive the routes
        // that point into the tunnel.
        PeerEgressRoutePlanner.sort(owned);
        for (int index = owned.size() - 1; index >= 0; index--) {
            try {
                commander.remove(owned.get(index));
            } catch (Exception ignored) {
                // Shutdown path: a route the table no longer has is the common reason to fail.
            }
        }
        installed.clear();
        saveQuietly();
        return owned;
    }

    /**
     * Reports whether a prefix is one of ours, which is what keeps a conflict check from treating
     * this feature's own route as somebody else's.
     */
    public boolean owns(String cidr) {
        for (Route route : installed) {
            if (route.cidr().equals(cidr)) {
                return true;
            }
        }
        return false;
    }

    private void forget(Route route) {
        installed.removeIf(existing -> existing.cidr().equals(route.cidr()));
    }

    private void saveQuietly() {
        try {
            save();
        } catch (Exception ignored) {
            // The caller is already on a failure path and has an error to report.
        }
    }
}
