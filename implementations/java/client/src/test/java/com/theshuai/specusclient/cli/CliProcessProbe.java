package com.theshuai.specusclient.cli;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.concurrent.TimeUnit;

/** Keep evidence even when the functional process deadline fails. No command/env is recorded. */
final class CliProcessProbe {
    private static final int OUTPUT_LIMIT = 1024 * 1024;
    private static final Duration DIAGNOSTIC_BUDGET = Duration.ofSeconds(5);
    private static final Duration REAP_BUDGET = Duration.ofSeconds(5);

    record Result(boolean finishedInBudget, int exitCode, String stdout, String stderr,
                  boolean secretFound, boolean outputTooLarge, boolean reaped, String diagnostic) { }

    static Result run(List<String> command, Path directory, String name, Duration budget) throws Exception {
        Path stdout = directory.resolve(name + "-stdout");
        Path stderr = directory.resolve(name + "-stderr");
        Path stacks = directory.resolve(name + "-threads");
        long started = System.nanoTime();
        Instant wallStart = Instant.now();
        Process process = new ProcessBuilder(command).directory(directory.toFile())
                .redirectOutput(stdout.toFile()).redirectError(stderr.toFile()).start();
        boolean finished = false;
        boolean reaped;
        String stackStatus = "not requested (process completed within budget)";
        try {
            // The original functional deadline is unchanged. Diagnostic/reap time never turns
            // an over-budget process into a passing result, even if it exits while attaching.
            finished = process.waitFor(budget.toNanos(), TimeUnit.NANOSECONDS);
            if (!finished) {
                try { stackStatus = captureThreads(process, stacks); }
                catch (IOException unavailable) {
                    // A missing JDK diagnostic tool must not erase the original timeout/output.
                    stackStatus = "thread capture unavailable: " + unavailable.getClass().getSimpleName();
                }
            }
        } finally {
            if (process.isAlive()) process.destroyForcibly();
            reaped = process.waitFor(REAP_BUDGET.toNanos(), TimeUnit.NANOSECONDS);
        }
        Captured out = read(stdout);
        Captured err = read(stderr);
        Captured threads = read(stacks);
        boolean secret = containsSecret(out.text) || containsSecret(err.text);
        int exitCode = reaped ? process.exitValue() : -1;
        String diagnostic = "case=" + name + "\nownedPid=" + process.pid()
                + "\nstarted=" + wallStart + "\nfunctionalBudgetMs=" + budget.toMillis()
                + "\nfinishedInBudget=" + finished + "\nexitCode=" + exitCode
                + "\nownedProcessReaped=" + reaped
                + "\nelapsedIncludingDiagnosticsMs=" + Duration.ofNanos(System.nanoTime() - started).toMillis()
                + "\nsecretMarkerDetected=" + secret
                + "\nstdoutTruncated=" + out.truncated + "\nstderrTruncated=" + err.truncated
                + "\nthreadCapture=" + stackStatus + "\n--- stdout ---\n" + out.text
                + "\n--- stderr ---\n" + err.text + "\n--- threads ---\n" + threads.text;
        diagnostic = sanitize(diagnostic, directory);
        // Keep only sanitized evidence outside @TempDir, so JUnit cleanup cannot erase a timeout.
        Path reports = Path.of("target", "cli-process-diagnostics");
        Files.createDirectories(reports);
        Files.writeString(reports.resolve(name + ".txt"), diagnostic, StandardCharsets.UTF_8);
        return new Result(finished, exitCode, sanitize(out.text, directory), sanitize(err.text, directory),
                secret, out.truncated || err.truncated, reaped, diagnostic);
    }

    private static String captureThreads(Process child, Path output) throws Exception {
        if (!child.isAlive()) return "child exited after deadline, before capture";
        // Read-only diagnostics use only the still-live child launched above, never a process
        // name/global search. Destruction below uses its original Process object, not this PID.
        Path jcmd = Path.of(System.getProperty("java.home"), "bin", "jcmd");
        Process diagnostic = new ProcessBuilder(jcmd.toString(), Long.toString(child.pid()), "Thread.print", "-l")
                .redirectErrorStream(true).redirectOutput(output.toFile()).start();
        try {
            if (!diagnostic.waitFor(DIAGNOSTIC_BUDGET.toNanos(), TimeUnit.NANOSECONDS))
                return "jcmd diagnostic deadline exceeded";
            return "jcmd exit=" + diagnostic.exitValue();
        } finally {
            if (diagnostic.isAlive()) diagnostic.destroyForcibly();
            if (!diagnostic.waitFor(REAP_BUDGET.toNanos(), TimeUnit.NANOSECONDS))
                throw new IOException("Owned jcmd process could not be reaped");
        }
    }

    private record Captured(String text, boolean truncated) { }

    private static Captured read(Path file) throws IOException {
        if (!Files.exists(file)) return new Captured("", false);
        try (var stream = Files.newInputStream(file)) {
            byte[] bytes = stream.readNBytes(OUTPUT_LIMIT + 1);
            return new Captured(new String(bytes, 0, Math.min(bytes.length, OUTPUT_LIMIT), StandardCharsets.UTF_8),
                    bytes.length > OUTPUT_LIMIT);
        }
    }

    private static boolean containsSecret(String text) { return text.contains("DO_NOT_PRINT_"); }

    private static String sanitize(String text, Path directory) {
        String value = text.replaceAll("DO_NOT_PRINT_[A-Za-z0-9_]+", "<redacted-secret>");
        for (String path : List.of(directory.toAbsolutePath().toString(), System.getProperty("user.dir"),
                System.getProperty("user.home"), System.getProperty("java.home"))) {
            if (!path.isBlank()) {
                value = value.replace(path, "<local-path>").replace(path.replace('\\', '/'), "<local-path>");
            }
        }
        String user = System.getProperty("user.name", "");
        if (!user.isBlank()) value = value.replaceAll("(?<![A-Za-z0-9_])" + java.util.regex.Pattern.quote(user)
                + "(?![A-Za-z0-9_])", "<local-user>");
        return value;
    }
}
