package com.theshuai.specusclient.peer;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.theshuai.common.peeregress.Ipv4Cidr;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.function.LongPredicate;
import java.util.function.Supplier;
import lombok.extern.slf4j.Slf4j;

/**
 * Pointing the system's DNS at the responder, and putting it back (protocol/spec/peer-egress-dns.md,
 * section six; step five).
 *
 * <p>This is the one place the feature changes the user's system configuration, so it is built
 * around being able to undo itself from any point. The journal is written, private and atomically,
 * before anything is touched, with everything giving back needs; the takeover is marked committed
 * only once every step succeeded; any failure runs the whole give-back, which is safe whatever part
 * of the takeover happened; and a journal found at start is given back before anything else, which
 * is how a killed process's takeover is undone. Giving back leaves alone what somebody else wrote
 * after us.
 *
 * <p>The decisions -- what to read, what refuses, the exact commands -- are the pure functions of
 * {@link PeerEgressDnsTakeoverParse}, pinned by the shared vector. What is here is the order they
 * run in and what is kept on disk, behind {@link Machine}, so the tests drive it against fakes and
 * never touch the machine they run on.
 *
 * <p>Not safe for concurrent use except {@link #status()} and {@link #upstreams()}: the mesh drives
 * it under its plan lock.
 */
@Slf4j
public final class PeerEgressDnsTakeover {

    /** What the takeover needs from the machine. */
    public interface Machine {
        /** {@code linux}, {@code macos} or {@code windows}; anything else is not supported. */
        String platform();

        /** Runs a command line without a shell and returns its standard output. */
        String run(List<String> argv) throws IOException;

        /** A file's text; {@link NoSuchFileException} when there is none. */
        String readFile(String path) throws IOException;

        void writeFile(String path, String content) throws IOException;

        boolean isSymlink(String path) throws IOException;

        /** Whether a network interface of that name is there. */
        boolean linkExists(String name);

        /** This machine's interfaces, for finding the tunnel-type ones. */
        List<PeerEgressDnsTakeoverParse.LocalInterface> interfaces() throws IOException;
    }

    /** A command that failed, with what it printed. */
    public static final class CommandFailure extends IOException {
        private final String output;

        public CommandFailure(List<String> argv, String output) {
            super(String.join(" ", argv) + ": " + firstLine(output, "failed"));
            this.output = output == null ? "" : output;
        }

        /** The first line the command printed: usually the one that says why. */
        public String firstLine() {
            return firstLine(output, "failed");
        }

        private static String firstLine(String text, String otherwise) {
            for (String line : PeerEgressDnsTakeoverParse.lines(text)) {
                if (!line.isBlank()) {
                    return line.trim();
                }
            }
            return otherwise;
        }
    }

    /** One macOS network service the takeover changed, with the DNS it had. */
    public record Service(String name, List<String> servers) {
    }

    /**
     * The record, on disk, of a takeover: enough to give it back after a crash.
     *
     * @param resolvConf the original /etc/resolv.conf, for linux-resolvconf
     * @param services   the macOS services changed and what each had, for macos
     */
    public record Journal(String state, String platform, long pid, String listen, String tunnel, List<String> upstreams,
            long startedAtUnixMs, String resolvConf, List<Service> services) {

        Journal withState(String next) {
            return new Journal(next, platform, pid, listen, tunnel, upstreams, startedAtUnixMs, resolvConf, services);
        }

        List<String> serviceNames() {
            List<String> names = new ArrayList<>();
            for (Service service : services == null ? List.<Service>of() : services) {
                names.add(service.name());
            }
            return names;
        }
    }

    /** What the mesh asks for while phase two runs. */
    public record Request(String listen, String tunnel, String pool, String mesh, boolean poolRouteInstalled) {
        String key() {
            return listen + "|" + tunnel + "|" + pool + "|" + mesh;
        }
    }

    /**
     * What the status reports: whether the system's DNS points at the responder now (the journal is
     * committed), EGRESS_DNS_TAKEOVER_REFUSED with a reason or EGRESS_DNS_TAKEOVER_FAILED with the
     * failing command's first line, and the journal's state.
     */
    public record Status(boolean takeover, String code, String reason, String error, String journal) {
        public static Status none() {
            return new Status(false, null, null, null, JOURNAL_NONE);
        }
    }

    /** The outcome of giving a journal back from the command line. */
    public record RestoreResult(int exitCode, String message, Journal journal) {
    }

    public static final int JOURNAL_VERSION = 1;
    public static final String JOURNAL_NONE = "none";
    public static final String JOURNAL_PENDING = "pending";
    public static final String JOURNAL_COMMITTED = "committed";
    public static final String JOURNAL_FILE = "egress-dns-journal.json";
    /** How often the network is compared with the one the takeover was made on. */
    static final long NETWORK_CHECK_MS = 10_000L;
    /**
     * How long a refused or failed takeover waits before the system is read again, unless the
     * request or the network changed first: reading runs commands, and the answer rarely changes by
     * itself between ticks.
     */
    static final long RETRY_MS = 60_000L;

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private final Machine machine;
    private final Path path;
    private final long pid;
    /** The network's fingerprint; null means no check. */
    private final Supplier<String> fingerprint;

    /** The journal of the takeover in place, or null. */
    private Journal held;
    private String attemptKey = "";
    private long attemptAtMs;
    private String network;
    private long networkAtMs;
    private boolean networkChecked;
    private volatile Status status = Status.none();
    private volatile List<String> heldUpstreams = List.of();

    public PeerEgressDnsTakeover(Machine machine, Path path, long pid, Supplier<String> fingerprint) {
        this.machine = machine;
        this.path = path;
        this.pid = pid;
        this.fingerprint = fingerprint;
    }

    // ----------------------------------------------------------------------------------------------
    // The journal
    // ----------------------------------------------------------------------------------------------

    /** Beside the route install record, in the same private directory. */
    public static Path defaultJournalPath() {
        return Path.of(System.getProperty("user.home", "."), ".specus", JOURNAL_FILE);
    }

    /** The journal, or null when there is none; an unreadable one is an error, never "none". */
    public static Journal readJournal(Path path) throws IOException {
        String text;
        try {
            text = Files.readString(path);
        } catch (NoSuchFileException absent) {
            return null;
        }
        JsonNode node;
        try {
            node = MAPPER.readTree(text);
        } catch (IOException malformed) {
            throw new IOException("DNS takeover journal " + path + " is not JSON");
        }
        if (node == null || !node.isObject()) {
            throw new IOException("DNS takeover journal " + path + " is not an object");
        }
        int version = node.path("version").asInt(-1);
        if (version != JOURNAL_VERSION) {
            // Acting on a journal written differently would mean giving back by guess.
            throw new IOException("DNS takeover journal version " + version + " is not " + JOURNAL_VERSION);
        }
        List<Service> services = new ArrayList<>();
        for (JsonNode service : node.path("services")) {
            services.add(new Service(service.path("name").asText(""), strings(service.path("servers"))));
        }
        return new Journal(node.path("state").asText(""), node.path("platform").asText(""), node.path("pid").asLong(0),
                node.path("listen").asText(""), node.path("tunnel").asText(""), strings(node.path("upstreams")),
                node.path("startedAtUnixMs").asLong(0),
                node.hasNonNull("resolvConf") ? node.path("resolvConf").asText() : null, List.copyOf(services));
    }

    private static List<String> strings(JsonNode array) {
        List<String> out = new ArrayList<>();
        for (JsonNode item : array) {
            out.add(item.asText());
        }
        return List.copyOf(out);
    }

    /**
     * Written the way the route install record is: through a private temporary file renamed into
     * place, so a crash mid-write cannot leave half a journal describing less than was done.
     */
    static void writeJournal(Path path, Journal journal) throws IOException {
        ObjectNode node = MAPPER.createObjectNode();
        node.put("version", JOURNAL_VERSION);
        node.put("state", journal.state());
        node.put("platform", journal.platform());
        node.put("pid", journal.pid());
        node.put("listen", journal.listen());
        node.put("tunnel", journal.tunnel());
        ArrayNode upstreams = node.putArray("upstreams");
        journal.upstreams().forEach(upstreams::add);
        node.put("startedAtUnixMs", journal.startedAtUnixMs());
        if (journal.resolvConf() != null) {
            node.put("resolvConf", journal.resolvConf());
        }
        if (journal.services() != null && !journal.services().isEmpty()) {
            ArrayNode services = node.putArray("services");
            for (Service service : journal.services()) {
                ObjectNode entry = services.addObject();
                entry.put("name", service.name());
                ArrayNode servers = entry.putArray("servers");
                service.servers().forEach(servers::add);
            }
        }
        SecretFileWriter.writeSecret(path, MAPPER.writerWithDefaultPrettyPrinter().writeValueAsString(node));
    }

    /**
     * Gives a takeover back as its journal describes, and deletes the journal when every step
     * succeeded. Every step is tried even after one fails, so as much is given back as can be; the
     * result names the first that failed, and then the journal stays for another try. Null means
     * done.
     *
     * <p>Somebody else's change is kept: a resolv.conf that no longer holds what we wrote, or a
     * macOS service that no longer points at the responder alone, is left as it is, with a warning.
     */
    static String revert(Machine machine, Path path, Journal journal) {
        PeerEgressDnsTakeoverParse.Plan plan = PeerEgressDnsTakeoverParse.plan(
                journal.platform(), journal.listen(), journal.tunnel(), journal.serviceNames());
        if (plan == null) {
            return "the journal names platform " + journal.platform() + ", which this client cannot give back";
        }
        String failed = null;
        for (PeerEgressDnsTakeoverParse.Step step : plan.revert()) {
            String failure = revertStep(machine, journal, step);
            if (failure != null && failed == null) {
                failed = failure;
            }
        }
        if (failed != null) {
            return failed;
        }
        try {
            Files.deleteIfExists(path);
        } catch (IOException undeletable) {
            return "delete " + path + ": " + undeletable.getMessage();
        }
        return null;
    }

    private static String revertStep(Machine machine, Journal journal, PeerEgressDnsTakeoverParse.Step step) {
        if (step.restore() != null) {
            String current;
            try {
                current = machine.readFile(step.restore());
            } catch (NoSuchFileException absent) {
                current = "";
            } catch (IOException unreadable) {
                return "read " + step.restore() + ": " + describe(unreadable);
            }
            PeerEgressDnsTakeoverParse.Revert decision = PeerEgressDnsTakeoverParse.revertResolvConf(
                    current, journal.resolvConf() == null ? "" : journal.resolvConf(), journal.listen());
            if (!decision.restore()) {
                log.warn("[peer-egress-consumer] {} was changed by someone else during the DNS takeover and is kept"
                        + " as it is ({})", step.restore(), decision.warning());
                return null;
            }
            try {
                machine.writeFile(step.restore(), decision.content());
                return null;
            } catch (IOException unwritable) {
                return "restore " + step.restore() + ": " + describe(unwritable);
            }
        }
        if (step.restoreService() != null) {
            String output;
            try {
                output = machine.run(List.of("networksetup", "-getdnsservers", step.restoreService()));
            } catch (IOException unreadable) {
                return "read the DNS of " + step.restoreService() + ": " + describe(unreadable);
            }
            List<String> original = List.of("Empty");
            for (Service service : journal.services() == null ? List.<Service>of() : journal.services()) {
                if (service.name().equals(step.restoreService())) {
                    original = service.servers();
                }
            }
            PeerEgressDnsTakeoverParse.Revert decision = PeerEgressDnsTakeoverParse.revertMacService(
                    step.restoreService(), PeerEgressDnsTakeoverParse.parseMacDnsServers(output), original,
                    journal.listen());
            if (!decision.restore()) {
                log.warn("[peer-egress-consumer] the DNS of {} was changed by someone else during the takeover and is"
                        + " kept as it is ({})", step.restoreService(), decision.warning());
                return null;
            }
            return runStep(machine, decision.command());
        }
        List<String> argv = step.argv();
        if (PeerEgressDnsTakeoverParse.PLATFORM_RESOLVED.equals(journal.platform()) && argv.size() > 2
                && argv.get(1).equals("revert") && !machine.linkExists(journal.tunnel())) {
            // A link's settings live and die with the link: with the tunnel gone there is nothing to
            // revert, and asking resolvectl about a link it cannot find would keep the journal forever.
            return null;
        }
        return runStep(machine, argv);
    }

    private static String runStep(Machine machine, List<String> argv) {
        try {
            machine.run(argv);
            return null;
        } catch (IOException failed) {
            return String.join(" ", argv) + ": " + describe(failed);
        }
    }

    /** What a failure is reported by: a command's first line, or the exception's own message. */
    private static String describe(IOException failure) {
        if (failure instanceof CommandFailure command) {
            return command.firstLine();
        }
        String message = failure.getMessage();
        return message == null || message.isBlank() ? failure.getClass().getSimpleName() : message.lines().findFirst().orElse("");
    }

    /**
     * Gives back a takeover a previous run left, pending or committed, before anything else is
     * decided: a process that was killed never gave back, and this is where it happens. Whether the
     * journal's process id is running does not matter here: after a crash and a reboot that id most
     * likely belongs to another program, and leaving the journal alone would keep the system pointed
     * at a responder nobody runs. Only one client per machine takes the DNS over; the liveness check
     * belongs to {@code egress dns restore}, which a person runs.
     */
    public static void recoverLeftover(Machine machine, Path path) {
        Journal journal;
        try {
            journal = readJournal(path);
        } catch (IOException unreadable) {
            log.warn("[peer-egress-consumer] DNS takeover journal left in place: {}", unreadable.getMessage());
            return;
        }
        if (journal == null) {
            return;
        }
        String failure = revert(machine, path, journal);
        if (failure != null) {
            log.warn("[peer-egress-consumer] DNS takeover left by process {} not given back, the journal stays for the"
                    + " next start or `egress dns restore`: {}", journal.pid(), failure);
            return;
        }
        log.info("[peer-egress-consumer] DNS takeover left by process {} given back", journal.pid());
    }

    /**
     * {@code egress dns restore}: gives the journal back without a running client. No journal is
     * nothing to do (0); a journal whose process is still running is refused unless forced (1), as
     * the process id may since belong to another program; a step that fails keeps the journal (1).
     */
    public static RestoreResult restore(Machine machine, Path path, boolean force, LongPredicate processAlive) {
        Journal journal;
        try {
            journal = readJournal(path);
        } catch (IOException unreadable) {
            return new RestoreResult(1, "The DNS takeover journal cannot be read: " + unreadable.getMessage()
                    + "; nothing was changed.", null);
        }
        if (journal == null) {
            return new RestoreResult(0, "No DNS takeover journal at " + path + "; there is nothing to restore.", null);
        }
        if (!force && processAlive.test(journal.pid())) {
            return new RestoreResult(1, "The client that took over the system DNS (PID " + journal.pid()
                    + ") is still running, and gives it back itself when it stops. Stop it, or set peerEgressDnsTakeover"
                    + " to false and restart it. --force skips this check, for when that PID now belongs to another"
                    + " process.", journal);
        }
        String failure = revert(machine, path, journal);
        if (failure != null) {
            return new RestoreResult(1, "Giving the system DNS back failed at " + failure
                    + ". The journal is kept; fix what the step reports and run egress dns restore again.", journal);
        }
        return new RestoreResult(0, "System DNS given back (" + journal.platform() + ", taken over by PID "
                + journal.pid() + "); journal removed.", journal);
    }

    // ----------------------------------------------------------------------------------------------
    // The takeover over time
    // ----------------------------------------------------------------------------------------------

    public Status status() {
        return status;
    }

    /**
     * The upstreams the responder forwards to: set when a takeover commits, and kept after it is
     * given back, so a system whose DNS someone points at the listen address by hand still gets
     * answers for the names nothing claims. Empty until a takeover has committed.
     */
    public List<String> upstreams() {
        return heldUpstreams;
    }

    private void hold(Journal journal) {
        held = journal;
        if (journal != null) {
            heldUpstreams = List.copyOf(journal.upstreams());
        }
    }

    private String journalState() {
        return held == null ? JOURNAL_NONE : held.state();
    }

    /** At start: a journal a previous run left is given back first. */
    public void recoverLeftover() {
        recoverLeftover(machine, path);
    }

    /**
     * Gives back the takeover in place, if any. A give-back that fails keeps the journal -- the only
     * record of what to restore -- for the next start or the command, and says so in the status.
     */
    public void release(String why) {
        if (held == null) {
            return;
        }
        Journal journal = held;
        hold(null);
        String failure = revert(machine, path, journal);
        if (failure != null) {
            log.warn("[peer-egress-consumer] system DNS not fully given back ({}), the journal stays: {}", why, failure);
            status = new Status(false, PeerEgressDnsTakeoverParse.CODE_FAILED, null, failure, journal.state());
            return;
        }
        log.info("[peer-egress-consumer] system DNS given back ({})", why);
        status = Status.none();
    }

    /** Phase two is not running: nothing held, and nothing refused or failed to report. */
    public void idle(String why) {
        release(why);
        Status current = status;
        if (!PeerEgressDnsTakeoverParse.CODE_FAILED.equals(current.code()) || JOURNAL_NONE.equals(current.journal())) {
            status = Status.none();
        }
        forgetAttempt();
    }

    /** The next engage tries at once: the network or the setup changed. */
    public void forgetAttempt() {
        attemptKey = "";
        attemptAtMs = 0;
    }

    /**
     * Compares the network with the last reading, at most every ten seconds; the first reading is
     * the baseline. A fingerprint that cannot be read changes nothing.
     */
    public boolean networkChanged(long nowMs) {
        if (fingerprint == null
                || (networkChecked && nowMs - networkAtMs < NETWORK_CHECK_MS && nowMs >= networkAtMs)) {
            return false;
        }
        String current;
        try {
            current = fingerprint.get();
        } catch (RuntimeException unreadable) {
            return false;
        }
        if (current == null) {
            return false;
        }
        networkAtMs = nowMs;
        boolean changed = networkChecked && !current.equals(network);
        network = current;
        networkChecked = true;
        return changed;
    }

    /** Takes the system's DNS over for a request, or keeps the takeover in place. */
    public void engage(Request request, long nowMs) {
        if (held != null) {
            if (request.poolRouteInstalled() && held.listen().equals(request.listen())
                    && held.tunnel().equals(request.tunnel())) {
                return;
            }
            // The pool's route went, or the responder moved: the system would be sending its
            // queries where nothing answers.
            release("the pool's route or the listen address changed");
        }
        if (!request.poolRouteInstalled()) {
            // Checked every tick without reading anything, so the takeover follows the route in.
            forgetAttempt();
            refuse(PeerEgressDnsTakeoverParse.REFUSED_POOL_ROUTE);
            return;
        }
        String key = request.key();
        if (key.equals(attemptKey) && nowMs - attemptAtMs < RETRY_MS && nowMs >= attemptAtMs) {
            return;
        }
        attemptKey = key;
        attemptAtMs = nowMs;
        attempt(request, nowMs);
    }

    private void refuse(String reason) {
        Status current = status;
        if (!reason.equals(current.reason())) {
            log.warn("[peer-egress-consumer] system DNS not taken over: {}", reason);
        }
        status = new Status(false, PeerEgressDnsTakeoverParse.CODE_REFUSED, reason, null, journalState());
    }

    private void fail(String error, String journal) {
        status = new Status(false, PeerEgressDnsTakeoverParse.CODE_FAILED, null, error, journal);
    }

    /** What reading the system found: the servers, what giving back needs, or why it is refused. */
    private record Reading(String platform, List<String> servers, List<String> virtual, String resolvConf,
            List<Service> services, String refusal) {
        static Reading refused(String reason) {
            return new Reading(null, List.of(), List.of(), null, List.of(), reason);
        }
    }

    /** Reads the system, decides, and takes over. */
    private void attempt(Request request, long nowMs) {
        // A journal still on disk is a give-back that failed, or one a killed process left. It is
        // the only record of what the system had, so it is given back first and never written over.
        Journal leftover;
        try {
            leftover = readJournal(path);
        } catch (IOException unreadable) {
            fail(unreadable.getMessage(), JOURNAL_PENDING);
            return;
        }
        if (leftover != null) {
            String failure = revert(machine, path, leftover);
            if (failure != null) {
                fail(failure, leftover.state());
                return;
            }
        }
        Reading reading;
        try {
            reading = readSystem(request.tunnel());
        } catch (IOException unreadable) {
            log.warn("[peer-egress-consumer] system DNS not taken over, reading it failed: {}", describe(unreadable));
            fail(describe(unreadable), JOURNAL_NONE);
            return;
        }
        if (reading.refusal() != null) {
            refuse(reading.refusal());
            return;
        }
        PeerEgressDnsTakeoverParse.Upstreams upstreams = PeerEgressDnsTakeoverParse.classifyUpstreams(
                reading.servers(), reading.virtual(), request.pool(), request.mesh());
        if (upstreams.code() != null) {
            refuse(upstreams.reason());
            return;
        }
        Journal journal = new Journal(JOURNAL_PENDING, reading.platform(), pid, request.listen(), request.tunnel(),
                upstreams.upstreams(), nowMs, reading.resolvConf(), reading.services());

        // Written before anything is changed: whatever happens from here, the record of what to put
        // back is on disk first.
        try {
            writeJournal(path, journal);
        } catch (IOException unwritable) {
            log.warn("[peer-egress-consumer] system DNS not taken over, the journal could not be written: {}",
                    unwritable.getMessage());
            fail(describe(unwritable), JOURNAL_NONE);
            return;
        }
        status = new Status(false, null, null, null, JOURNAL_PENDING);
        PeerEgressDnsTakeoverParse.Plan plan = PeerEgressDnsTakeoverParse.plan(
                journal.platform(), journal.listen(), journal.tunnel(), journal.serviceNames());
        String failure = null;
        for (PeerEgressDnsTakeoverParse.Step step : plan.apply()) {
            failure = applyStep(step);
            if (failure != null) {
                break;
            }
        }
        Journal committed = journal.withState(JOURNAL_COMMITTED);
        if (failure == null) {
            try {
                writeJournal(path, committed);
            } catch (IOException unwritable) {
                failure = "record the takeover as done: " + describe(unwritable);
            }
        }
        if (failure != null) {
            // The whole give-back, whatever part of the takeover happened: it is safe from any point.
            log.warn("[peer-egress-consumer] system DNS takeover failed, giving back: {}", failure);
            String revertFailure = revert(machine, path, journal);
            String kept = JOURNAL_NONE;
            if (revertFailure != null) {
                log.warn("[peer-egress-consumer] giving back the failed DNS takeover failed too, the journal stays: {}",
                        revertFailure);
                kept = JOURNAL_PENDING;
            }
            fail(failure, kept);
            return;
        }
        hold(committed);
        status = new Status(true, null, null, null, JOURNAL_COMMITTED);
        // Said every time, as egress enable says it: this is the one change to the system's own
        // configuration, and the person running the client should never have to discover it.
        log.info("[peer-egress-consumer] system DNS now points at {} ({}); forwarding to {}. It is given back when the"
                        + " client stops, or by `egress dns restore`", journal.listen(), journal.platform(),
                String.join(", ", journal.upstreams()));
    }

    /** The first line of what failed, as the status's {@code error} carries it. */
    private String applyStep(PeerEgressDnsTakeoverParse.Step step) {
        if (step.write() != null) {
            try {
                machine.writeFile(step.write(), step.content());
                return null;
            } catch (IOException unwritable) {
                return describe(unwritable);
            }
        }
        try {
            machine.run(step.argv());
            return null;
        } catch (IOException failed) {
            return describe(failed);
        }
    }

    /** Reads the platform's DNS: the servers the upstreams come from, and what giving back needs. */
    private Reading readSystem(String tunnel) throws IOException {
        String platform = machine.platform();
        switch (platform) {
            case "linux" -> {
                String resolvectl = null;
                boolean resolvectlOk;
                try {
                    resolvectl = machine.run(List.of("resolvectl", "dns"));
                    resolvectlOk = true;
                } catch (IOException notRunning) {
                    resolvectlOk = false;
                }
                String conf;
                try {
                    conf = machine.readFile(PeerEgressDnsTakeoverParse.RESOLV_CONF);
                } catch (NoSuchFileException absent) {
                    conf = "";
                }
                boolean symlink;
                try {
                    symlink = machine.isSymlink(PeerEgressDnsTakeoverParse.RESOLV_CONF);
                } catch (IOException unknown) {
                    symlink = false;
                }
                PeerEgressDnsTakeoverParse.LinuxMode mode = PeerEgressDnsTakeoverParse.linuxMode(
                        resolvectlOk, PeerEgressDnsTakeoverParse.parseResolvConf(conf), symlink);
                if (mode.reason() != null) {
                    return Reading.refused(mode.reason());
                }
                List<String> virtual = tunnelAddresses(platform, tunnel, 0);
                if (PeerEgressDnsTakeoverParse.MODE_RESOLVED.equals(mode.mode())) {
                    return new Reading(mode.platform(), PeerEgressDnsTakeoverParse.parseResolvectl(resolvectl, tunnel),
                            virtual, null, List.of(), null);
                }
                return new Reading(mode.platform(), PeerEgressDnsTakeoverParse.parseResolvConf(conf), virtual, conf,
                        List.of(), null);
            }
            case "macos" -> {
                List<Service> services = new ArrayList<>();
                for (String service : PeerEgressDnsTakeoverParse.parseMacServices(
                        machine.run(List.of("networksetup", "-listallnetworkservices")))) {
                    services.add(new Service(service, PeerEgressDnsTakeoverParse.parseMacDnsServers(
                            machine.run(List.of("networksetup", "-getdnsservers", service)))));
                }
                List<String> servers = PeerEgressDnsTakeoverParse.parseScutil(machine.run(List.of("scutil", "--dns")));
                return new Reading(PeerEgressDnsTakeoverParse.PLATFORM_MACOS, servers,
                        tunnelAddresses(platform, tunnel, 0), null, List.copyOf(services), null);
            }
            case "windows" -> {
                if (PeerEgressDnsTakeoverParse.parseWindowsNrpt(machine.run(
                        PeerEgressDnsTakeoverParse.powershell(PeerEgressDnsTakeoverParse.WINDOWS_READ_NRPT)))) {
                    return Reading.refused(PeerEgressDnsTakeoverParse.REFUSED_NRPT);
                }
                // The TUN's own index, so its server -- the responder -- is not read back as an upstream.
                int tunnelIndex = 0;
                try {
                    tunnelIndex = PeerEgressWindowsRouteCommands.parseInterfaceIndex(machine.run(
                            PeerEgressDnsTakeoverParse.powershell(PeerEgressWindowsRouteCommands.interfaceIndexScript(tunnel))));
                } catch (IOException unknown) {
                    // Read as no index: our adapter's server is in the pool and refused by that.
                }
                List<String> servers = PeerEgressDnsTakeoverParse.parseWindowsServers(machine.run(
                        PeerEgressDnsTakeoverParse.powershell(PeerEgressDnsTakeoverParse.WINDOWS_READ_SERVERS)), tunnelIndex);
                return new Reading(PeerEgressDnsTakeoverParse.PLATFORM_WINDOWS, servers,
                        tunnelAddresses(platform, tunnel, tunnelIndex), null, List.of(), null);
            }
            default -> {
                return Reading.refused(PeerEgressDnsTakeoverParse.REFUSED_UNSUPPORTED);
            }
        }
    }

    /** The tunnel-type interfaces' addresses; a list the machine will not give is taken as none. */
    private List<String> tunnelAddresses(String platform, String tunnel, long tunnelIndex) {
        try {
            return PeerEgressDnsTakeoverParse.tunnelAddresses(platform, machine.interfaces(), tunnel, tunnelIndex);
        } catch (IOException | RuntimeException unavailable) {
            log.debug("[peer-egress-consumer] interfaces not listed for the DNS takeover check: {}", unavailable.getMessage());
            return List.of();
        }
    }

    /**
     * The network as the change check sees it: the interface the default route leaves by (lowest
     * metric, the tunnel's own left out) and every local IPv4 address in order. A new network
     * changes one or the other.
     */
    public static String fingerprint(List<PeerEgressSocketBinding.Route> routes, String tunnel, List<String> addresses) {
        String defaultInterface = "";
        long best = Long.MAX_VALUE;
        for (PeerEgressSocketBinding.Route route : routes == null ? List.<PeerEgressSocketBinding.Route>of() : routes) {
            if (!"0.0.0.0/0".equals(route.prefix()) || !route.usable() || route.iface() == null
                    || route.iface().isEmpty() || route.iface().equals(tunnel)) {
                continue;
            }
            if (defaultInterface.isEmpty() || route.metric() < best) {
                defaultInterface = route.iface();
                best = route.metric();
            }
        }
        List<Integer> sorted = new ArrayList<>();
        for (String text : addresses == null ? List.<String>of() : addresses) {
            Integer address = Ipv4Cidr.parseAddress(text);
            if (address != null && !sorted.contains(address)) {
                sorted.add(address);
            }
        }
        sorted.sort(Integer::compareUnsigned);
        List<String> texts = new ArrayList<>();
        sorted.forEach(address -> texts.add(Ipv4Cidr.format(address)));
        return defaultInterface + "|" + String.join(",", texts);
    }
}
