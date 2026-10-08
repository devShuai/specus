package com.theshuai.specus.android;

import android.content.ContextWrapper;
import android.content.Intent;
import android.content.SharedPreferences;

import java.io.FileDescriptor;
import java.io.FileOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Runs the Android client core as a command-line client on a plain JVM.
 *
 * <p>The C server's E2E scripts drive every client through {@code SPECUS_CLIENT_COMMAND} with the
 * same arguments ({@code run --config <file> --no-update-check}). The Android app has no such
 * process, so this entry point starts {@link SpecusCore.Runtime} -- the code the foreground
 * service runs on a device, from HTTP login to control/data, Direct HTTP and WebSocket -- with a
 * stand-in {@link android.content.Context} and without a VPN platform, the {@code
 * peerMeshDevice=noop} path. It lives with the unit tests because that classpath already has
 * what the core needs off-device: Netty, the standalone org.json and AGP's mockable android.jar.
 * {@code :app:jvmClientLauncher} writes a launcher script for it.</p>
 *
 * <p>The process runs until it is terminated; it exits with status 1 when the runtime stops on its
 * own, for example after a login the server rejects for good.</p>
 */
public final class JvmClientMain {
    private JvmClientMain() {
    }

    public static void main(String[] args) throws Exception {
        Path configPath = configPath(args);
        String config = new String(Files.readAllBytes(configPath), StandardCharsets.UTF_8);
        // Status details are partly Chinese; keep the log UTF-8 whatever the platform charset.
        PrintStream log = new PrintStream(new FileOutputStream(FileDescriptor.out), true, StandardCharsets.UTF_8);
        SpecusCore.Runtime runtime = new SpecusCore.Runtime(
                new JvmContext(),
                config,
                (status, detail, running) -> log.println(
                        Instant.now() + " " + status + (detail.isEmpty() ? "" : ": " + detail)),
                null);
        AtomicBoolean terminating = new AtomicBoolean();
        CountDownLatch finished = new CountDownLatch(1);
        java.lang.Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            terminating.set(true);
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
            System.exit(1);
        }
    }

    /** Accepts the arguments the other clients take; Android checks for updates only from its UI. */
    static Path configPath(String[] args) {
        if (args.length == 0 || !"run".equals(args[0])) {
            throw usage("expected the run command");
        }
        Path config = null;
        for (int i = 1; i < args.length; i++) {
            switch (args[i]) {
                case "--config":
                    if (++i >= args.length) {
                        throw usage("--config needs a file");
                    }
                    config = Path.of(args[i]);
                    break;
                case "--no-update-check":
                    break;
                default:
                    throw usage("unknown argument " + args[i]);
            }
        }
        if (config == null) {
            throw usage("missing --config");
        }
        return config;
    }

    private static IllegalArgumentException usage(String problem) {
        return new IllegalArgumentException(
                problem + "; usage: run --config <client.jsonc> [--no-update-check]");
    }

    /**
     * The parts of {@link android.content.Context} the runtime reaches: the application context
     * and the preferences that keep the machine id and the peer key pair, here for the life of the
     * process. Peer service snapshots, broadcast to the UI on a device, have no receiver here.
     */
    static final class JvmContext extends ContextWrapper {
        private final Map<String, SharedPreferences> preferences = new ConcurrentHashMap<>();

        JvmContext() {
            super(null);
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
            return preferences.computeIfAbsent(name, ignored -> new MemoryPreferences());
        }

        @Override
        public void sendBroadcast(Intent intent) {
        }
    }

    /** {@link SharedPreferences} held in memory; edits apply when committed, as on a device. */
    static final class MemoryPreferences implements SharedPreferences {
        private final Map<String, Object> values = new HashMap<>();

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
                }
                return true;
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
