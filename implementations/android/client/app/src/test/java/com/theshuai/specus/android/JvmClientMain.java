package com.theshuai.specus.android;

import android.content.ContextWrapper;
import android.content.Intent;
import android.content.SharedPreferences;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.FileDescriptor;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.DirectoryStream;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Runs the Android client core as a command-line client on a plain JVM.
 *
 * <p>The C server's E2E scripts drive every client through {@code SPECUS_CLIENT_COMMAND} with the
 * same arguments ({@code run --config <file> --no-update-check [--debug]}). The Android app has no
 * such process, so this entry point starts {@link SpecusCore.Runtime} -- the code the foreground
 * service runs on a device, from HTTP login to control/data, Direct HTTP, WebSocket and the Peer
 * Mesh control and UDP path -- with a stand-in {@link android.content.Context} and without a VPN
 * platform, the {@code peerMeshDevice=noop} path. It lives with the unit tests because that
 * classpath already has what the core needs off-device: Netty, the standalone org.json and AGP's
 * mockable android.jar. {@code :app:jvmClientLauncher} writes a launcher script for it.</p>
 *
 * <p>The process runs until it is terminated; it exits with status 1 when the runtime stops on its
 * own, for example after a login the server rejects for good. Like the app, it keeps its machine id
 * and Peer Mesh key pair across restarts, under {@code ~/.specus-android-jvm} ({@code user.home}),
 * so a restarted client is the same device. While it runs it publishes its state once a second,
 * as the other clients do, for {@code peers --config <file> [--json]}: the roster the server pushed
 * to it.</p>
 */
public final class JvmClientMain {
    private JvmClientMain() {
    }

    public static void main(String[] args) throws Exception {
        Command command = Command.parse(args);
        if ("peers".equals(command.name)) {
            System.exit(CliState.queryPeers(CliState.root(), command.config, command.json, System.out));
        }
        String config = new String(Files.readAllBytes(command.config), StandardCharsets.UTF_8);
        // Status details are partly Chinese; keep the log UTF-8 whatever the platform charset.
        PrintStream log = new PrintStream(new FileOutputStream(FileDescriptor.out), true, StandardCharsets.UTF_8);
        CliState state = new CliState(CliState.root(), command.config);
        SpecusCore.Runtime runtime = new SpecusCore.Runtime(
                new JvmContext(stateHome()),
                config,
                (status, detail, running) -> {
                    state.phase = status;
                    log.println(Instant.now() + " " + status + (detail.isEmpty() ? "" : ": " + detail));
                },
                null);
        state.start(runtime);
        AtomicBoolean terminating = new AtomicBoolean();
        CountDownLatch finished = new CountDownLatch(1);
        java.lang.Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            terminating.set(true);
            state.close();
            runtime.stop();
            try {
                finished.await(5, TimeUnit.SECONDS);
            } catch (InterruptedException ignored) {
                Thread.currentThread().interrupt();
            }
        }, "specus-shutdown"));
        try {
            runtime.run();
        } finally {
            finished.countDown();
        }
        if (!terminating.get()) {
            state.close();
            System.exit(1);
        }
    }

    /** Where the stand-in preferences live: per user home, as an app's live per installation. */
    static Path stateHome() {
        return Path.of(System.getProperty("user.home"), ".specus-android-jvm");
    }

    /**
     * The arguments the other clients take: {@code run --config <file> [--no-update-check]
     * [--debug]} and {@code peers --config <file> [--json]}. Android checks for updates only from
     * its UI, and every status is printed already, so those two flags change nothing here.
     */
    static final class Command {
        final String name;
        final Path config;
        final boolean json;

        private Command(String name, Path config, boolean json) {
            this.name = name;
            this.config = config;
            this.json = json;
        }

        static Command parse(String[] args) {
            if (args.length == 0 || !("run".equals(args[0]) || "peers".equals(args[0]))) {
                throw usage("expected the run or peers command");
            }
            String name = args[0];
            Path config = null;
            boolean json = false;
            for (int i = 1; i < args.length; i++) {
                String argument = args[i];
                if ("--config".equals(argument)) {
                    if (++i >= args.length) {
                        throw usage("--config needs a file");
                    }
                    config = Path.of(args[i]);
                } else if ("run".equals(name)
                        && ("--no-update-check".equals(argument) || "--debug".equals(argument))) {
                    continue;
                } else if ("peers".equals(name) && "--json".equals(argument)) {
                    json = true;
                } else {
                    throw usage("unknown argument " + argument);
                }
            }
            if (config == null) {
                throw usage("missing --config");
            }
            return new Command(name, config, json);
        }

        private static IllegalArgumentException usage(String problem) {
            return new IllegalArgumentException(problem + "; usage: run --config <client.jsonc>"
                    + " [--no-update-check] [--debug] | peers --config <client.jsonc> [--json]");
        }
    }

    /**
     * The running client's state for {@code peers}, in the directory the other clients publish to
     * ({@code SPECUS_CLI_STATE_DIR}, or {@code ~/.specus-cli}): one file per process, named by the
     * configuration's path, rewritten once a second and removed on exit. A query reads only state
     * written in the last five seconds by a process that is still alive.
     */
    static final class CliState {
        private static final long FRESH_MILLIS = 5_000L;

        private final String configPath;
        private final Path file;
        private final ScheduledExecutorService publisher = Executors.newSingleThreadScheduledExecutor(task -> {
            Thread thread = new Thread(task, "specus-cli-state");
            thread.setDaemon(true);
            return thread;
        });
        private volatile SpecusCore.Runtime runtime;
        volatile String phase = "starting";
        private boolean failing;
        private boolean closed;

        CliState(Path root, Path config) {
            configPath = canonical(config);
            file = root.resolve(prefix(configPath) + Processes.currentPid() + ".json");
        }

        void start(SpecusCore.Runtime observed) {
            runtime = observed;
            publisher.scheduleWithFixedDelay(this::publishOnce, 0, 1, TimeUnit.SECONDS);
        }

        /** One publication; a failure is said once and retried, never fatal to the client. */
        private void publishOnce() {
            try {
                publish(snapshot());
                if (failing) {
                    System.err.println("State publication recovered.");
                }
                failing = false;
            } catch (Exception error) {
                if (!failing) {
                    System.err.println("State publication failed (" + error + "); retrying every second.");
                }
                failing = true;
            }
        }

        JSONObject snapshot() throws Exception {
            SpecusCore.Runtime current = runtime;
            JSONArray peers = new JSONArray();
            if (current != null) {
                for (PeerMeshEngine.RosterEntry peer : current.peerRoster()) {
                    peers.put(new JSONObject()
                            .put("clientName", peer.clientName)
                            .put("virtualIp", peer.virtualIp)
                            .put("online", peer.online));
                }
            }
            return new JSONObject()
                    .put("schemaVersion", 1)
                    .put("configPath", configPath)
                    .put("pid", Processes.currentPid())
                    .put("updatedAtUnixMs", System.currentTimeMillis())
                    .put("phase", phase)
                    .put("controlAuthenticated", current != null && current.controlConnected())
                    .put("peers", peers);
        }

        synchronized void publish(JSONObject state) throws IOException {
            if (closed) {
                return;
            }
            Path root = file.getParent();
            createPrivateDirectory(root);
            Path temporary = Files.createTempFile(root, ".state-", ".tmp");
            try {
                restrictToOwner(temporary);
                Files.write(temporary, state.toString().getBytes(StandardCharsets.UTF_8));
                Files.move(temporary, file, StandardCopyOption.ATOMIC_MOVE,
                        StandardCopyOption.REPLACE_EXISTING);
            } finally {
                Files.deleteIfExists(temporary);
            }
        }

        synchronized void close() {
            closed = true;
            publisher.shutdownNow();
            try {
                Files.deleteIfExists(file);
            } catch (IOException ignored) {
            }
        }

        /**
         * Answers {@code peers}: the roster of every fresh running instance for the configuration,
         * in the envelope the other clients print. Exit status 0, or 5 when no instance runs.
         */
        static int queryPeers(Path root, Path config, boolean json, PrintStream out) throws Exception {
            List<JSONObject> instances = liveStates(root, canonical(config));
            JSONArray data = new JSONArray();
            for (JSONObject state : instances) {
                data.put(new JSONObject()
                        .put("pid", state.optLong("pid"))
                        .put("phase", state.optString("phase"))
                        .put("catalogAvailable", state.optBoolean("controlAuthenticated"))
                        .put("peers", state.optJSONArray("peers") == null
                                ? new JSONArray() : state.optJSONArray("peers")));
            }
            int code = instances.isEmpty() ? 5 : 0;
            String problem = "No fresh running CLI state for this config. No login was attempted.";
            if (json) {
                out.println(new JSONObject()
                        .put("schemaVersion", 1)
                        .put("command", "peers")
                        .put("ok", code == 0)
                        .put("exitCode", code)
                        .put("data", new JSONObject().put("instances", data))
                        .put("error", code == 0 ? JSONObject.NULL : problem));
            } else if (code != 0) {
                System.err.println(problem);
            } else {
                for (int i = 0; i < data.length(); i++) {
                    JSONArray peers = data.getJSONObject(i).getJSONArray("peers");
                    for (int j = 0; j < peers.length(); j++) {
                        JSONObject peer = peers.getJSONObject(j);
                        out.println(peer.optString("clientName") + " " + peer.optString("virtualIp")
                                + " " + (peer.optBoolean("online") ? "online" : "offline"));
                    }
                }
            }
            return code;
        }

        static List<JSONObject> liveStates(Path root, String configPath) throws IOException {
            List<JSONObject> states = new ArrayList<>();
            if (!Files.isDirectory(root)) {
                return states;
            }
            try (DirectoryStream<Path> files = Files.newDirectoryStream(root, prefix(configPath) + "*.json")) {
                for (Path candidate : files) {
                    try {
                        JSONObject state = new JSONObject(
                                new String(Files.readAllBytes(candidate), StandardCharsets.UTF_8));
                        if (state.optInt("schemaVersion") == 1
                                && configPath.equals(state.optString("configPath"))
                                && fresh(state)) {
                            states.add(state);
                        }
                    } catch (NoSuchFileException ignored) {
                        // Removed by its process between the listing and the read.
                    } catch (Exception ignored) {
                        // Not a state this format writes, or unreadable.
                    }
                }
            }
            return states;
        }

        private static boolean fresh(JSONObject state) {
            long age = System.currentTimeMillis() - state.optLong("updatedAtUnixMs");
            return age >= 0 && age <= FRESH_MILLIS
                    && Processes.alive(state.optLong("pid"));
        }

        static Path root() {
            String override = System.getenv("SPECUS_CLI_STATE_DIR");
            Path root = override == null || override.isEmpty()
                    ? Path.of(System.getProperty("user.home"), ".specus-cli") : Path.of(override);
            return root.toAbsolutePath().normalize();
        }

        static String canonical(Path config) {
            String path = config.toAbsolutePath().normalize().toString();
            return windows() ? path.toLowerCase(Locale.ROOT) : path;
        }

        static String prefix(String configPath) {
            try {
                byte[] digest = MessageDigest.getInstance("SHA-256")
                        .digest(configPath.getBytes(StandardCharsets.UTF_8));
                return "android-jvm-" + HexFormat.of().formatHex(digest) + "-";
            } catch (Exception error) {
                throw new IllegalStateException(error);
            }
        }

        private static boolean windows() {
            return System.getProperty("os.name", "").toLowerCase(Locale.ROOT).contains("win");
        }
    }

    /**
     * Process ids through {@code java.lang.ProcessHandle}, by reflection: these sources compile
     * against android.jar, which does not have it, and run on a JVM, which does.
     */
    static final class Processes {
        private Processes() {
        }

        static long currentPid() {
            try {
                Class<?> type = Class.forName("java.lang.ProcessHandle");
                return (Long) type.getMethod("pid").invoke(type.getMethod("current").invoke(null));
            } catch (ReflectiveOperationException error) {
                throw new IllegalStateException(error);
            }
        }

        static boolean alive(long pid) {
            try {
                Class<?> type = Class.forName("java.lang.ProcessHandle");
                java.util.Optional<?> handle =
                        (java.util.Optional<?>) type.getMethod("of", long.class).invoke(null, pid);
                return handle.isPresent() && (Boolean) type.getMethod("isAlive").invoke(handle.get());
            } catch (ReflectiveOperationException error) {
                throw new IllegalStateException(error);
            }
        }
    }

    static boolean posix() {
        return FileSystems.getDefault().supportedFileAttributeViews().contains("posix");
    }

    static void createPrivateDirectory(Path directory) throws IOException {
        if (Files.isDirectory(directory)) {
            return;
        }
        if (posix()) {
            Files.createDirectories(directory,
                    PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")));
        } else {
            Files.createDirectories(directory);
        }
    }

    static void restrictToOwner(Path file) throws IOException {
        if (posix()) {
            Files.setPosixFilePermissions(file, PosixFilePermissions.fromString("rw-------"));
        }
    }

    /**
     * The parts of {@link android.content.Context} the runtime reaches: the application context
     * and the preferences that keep the machine id and the peer key pair. Peer service snapshots,
     * broadcast to the UI on a device, have no receiver here.
     */
    static final class JvmContext extends ContextWrapper {
        private final Path home;
        private final Map<String, SharedPreferences> preferences = new ConcurrentHashMap<>();

        /** Preferences under {@code home}, kept across runs; null keeps them in memory only. */
        JvmContext(Path home) {
            super(null);
            this.home = home;
        }

        @Override
        public android.content.Context getApplicationContext() {
            return this;
        }

        @Override
        public String getPackageName() {
            return "com.theshuai.specus.android";
        }

        @Override
        public SharedPreferences getSharedPreferences(String name, int mode) {
            return preferences.computeIfAbsent(name, ignored ->
                    new MemoryPreferences(home == null ? null : home.resolve(name + ".json")));
        }

        @Override
        public void sendBroadcast(Intent intent) {
        }
    }

    /**
     * {@link SharedPreferences} held in memory; edits apply when committed, as on a device. With a
     * file, its string values -- all the runtime keeps across runs -- are loaded from it and every
     * commit writes them back; other values last as long as the process.
     */
    static final class MemoryPreferences implements SharedPreferences {
        private final Map<String, Object> values = new HashMap<>();
        private final Path file;

        MemoryPreferences(Path file) {
            this.file = file;
            if (file == null || !Files.isRegularFile(file)) {
                return;
            }
            try {
                JSONObject saved = new JSONObject(
                        new String(Files.readAllBytes(file), StandardCharsets.UTF_8));
                for (Iterator<String> keys = saved.keys(); keys.hasNext(); ) {
                    String key = keys.next();
                    values.put(key, saved.getString(key));
                }
            } catch (Exception unreadable) {
                throw new IllegalStateException("cannot read saved preferences " + file, unreadable);
            }
        }

        @Override
        public synchronized Map<String, ?> getAll() {
            return new HashMap<>(values);
        }

        @Override
        public String getString(String key, String defaultValue) {
            return (String) get(key, defaultValue);
        }

        @Override
        @SuppressWarnings("unchecked")
        public Set<String> getStringSet(String key, Set<String> defaultValues) {
            Set<String> value = (Set<String>) get(key, null);
            return value == null ? defaultValues : new HashSet<>(value);
        }

        @Override
        public int getInt(String key, int defaultValue) {
            return (Integer) get(key, defaultValue);
        }

        @Override
        public long getLong(String key, long defaultValue) {
            return (Long) get(key, defaultValue);
        }

        @Override
        public float getFloat(String key, float defaultValue) {
            return (Float) get(key, defaultValue);
        }

        @Override
        public boolean getBoolean(String key, boolean defaultValue) {
            return (Boolean) get(key, defaultValue);
        }

        @Override
        public synchronized boolean contains(String key) {
            return values.containsKey(key);
        }

        @Override
        public Editor edit() {
            return new MemoryEditor();
        }

        @Override
        public void registerOnSharedPreferenceChangeListener(OnSharedPreferenceChangeListener listener) {
        }

        @Override
        public void unregisterOnSharedPreferenceChangeListener(OnSharedPreferenceChangeListener listener) {
        }

        private synchronized Object get(String key, Object defaultValue) {
            return values.getOrDefault(key, defaultValue);
        }

        /** Writes the string values, replacing the file in one step; called holding the lock. */
        private void save() throws IOException {
            JSONObject saved = new JSONObject();
            for (Map.Entry<String, Object> entry : values.entrySet()) {
                if (entry.getValue() instanceof String) {
                    try {
                        saved.put(entry.getKey(), entry.getValue());
                    } catch (Exception impossible) {
                        throw new IOException(impossible);
                    }
                }
            }
            Path directory = file.getParent();
            createPrivateDirectory(directory);
            Path temporary = Files.createTempFile(directory, ".prefs-", ".tmp");
            try {
                restrictToOwner(temporary);
                Files.write(temporary, saved.toString().getBytes(StandardCharsets.UTF_8));
                Files.move(temporary, file, StandardCopyOption.ATOMIC_MOVE,
                        StandardCopyOption.REPLACE_EXISTING);
            } finally {
                Files.deleteIfExists(temporary);
            }
        }

        private final class MemoryEditor implements Editor {
            private final Map<String, Object> changes = new HashMap<>();
            private final Set<String> removals = new HashSet<>();
            private boolean clear;

            @Override
            public Editor putString(String key, String value) {
                return put(key, value);
            }

            @Override
            public Editor putStringSet(String key, Set<String> value) {
                return put(key, value == null ? null : new HashSet<>(value));
            }

            @Override
            public Editor putInt(String key, int value) {
                return put(key, value);
            }

            @Override
            public Editor putLong(String key, long value) {
                return put(key, value);
            }

            @Override
            public Editor putFloat(String key, float value) {
                return put(key, value);
            }

            @Override
            public Editor putBoolean(String key, boolean value) {
                return put(key, value);
            }

            @Override
            public Editor remove(String key) {
                removals.add(key);
                return this;
            }

            @Override
            public Editor clear() {
                clear = true;
                return this;
            }

            @Override
            public boolean commit() {
                synchronized (MemoryPreferences.this) {
                    if (clear) {
                        values.clear();
                    }
                    for (String key : removals) {
                        values.remove(key);
                    }
                    for (Map.Entry<String, Object> change : changes.entrySet()) {
                        if (change.getValue() == null) {
                            values.remove(change.getKey());
                        } else {
                            values.put(change.getKey(), change.getValue());
                        }
                    }
                    if (file == null) {
                        return true;
                    }
                    try {
                        save();
                        return true;
                    } catch (IOException error) {
                        System.err.println("Cannot save preferences " + file + ": " + error);
                        return false;
                    }
                }
            }

            @Override
            public void apply() {
                commit();
            }

            private Editor put(String key, Object value) {
                changes.put(key, value);
                return this;
            }
        }
    }
}
