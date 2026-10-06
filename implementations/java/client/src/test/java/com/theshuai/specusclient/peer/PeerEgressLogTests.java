package com.theshuai.specusclient.peer;

import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.net.ConnectException;
import java.net.NoRouteToHostException;
import java.net.SocketTimeoutException;
import java.nio.channels.SocketChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.List;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;

/** The egress logs why a dial failed and never where it went: exception messages carry the address. */
class PeerEgressLogTests {

    @Test
    void connectReasonNamesTheCauseWithoutTheAddress() {
        assertThat(PeerEgressRuntime.connectReason(new ConnectException("Connection refused"))).isEqualTo("refused");
        assertThat(PeerEgressRuntime.connectReason(
                new IOException("connect /203.0.113.10:80", new ConnectException("Connection refused")))).isEqualTo("refused");
        assertThat(PeerEgressRuntime.connectReason(new SocketTimeoutException("Connect timed out"))).isEqualTo("timed out");
        assertThat(PeerEgressRuntime.connectReason(new NoRouteToHostException("No route to host"))).isEqualTo("unreachable");
        assertThat(PeerEgressRuntime.connectReason(new ConnectException("Network is unreachable"))).isEqualTo("unreachable");
        assertThat(PeerEgressRuntime.connectReason(
                new PeerEgressSocketBinder.NoPhysicalRouteException("203.0.113.10"))).isEqualTo("no route outside the tunnel");
        assertThat(PeerEgressRuntime.connectReason(new IOException("203.0.113.10:80 went wrong"))).isEqualTo("error");
        assertThat(PeerEgressRuntime.connectReason(null)).isEqualTo("no socket");
    }

    private static final String MISSING_EXPORT = " missing=\"--add-exports java.base/sun.nio.ch=ALL-UNNAMED\"";

    /**
     * A JVM started without the export refuses every dial on Windows and macOS, so the line says which
     * option is missing. The reason stays one of the shared words; the option follows it.
     */
    @Test
    void aMissingExportKeepsTheReasonAndNamesTheOption() {
        IOException missing = new PeerEgressSocketHandles.MissingExportException(new IllegalAccessException("denied"));
        assertThat(PeerEgressRuntime.connectReason(missing)).isEqualTo("error");
        assertThat(PeerEgressRuntime.connectDetail(missing)).isEqualTo(MISSING_EXPORT);
        assertThat(PeerEgressRuntime.connectDetail(new IOException("connect", missing))).isEqualTo(MISSING_EXPORT);

        assertThat(PeerEgressRuntime.connectDetail(new IOException("203.0.113.10:80 went wrong"))).isEmpty();
        assertThat(PeerEgressRuntime.connectDetail(
                new PeerEgressSocketBinder.NoPhysicalRouteException("203.0.113.10"))).isEmpty();
        assertThat(PeerEgressRuntime.connectDetail(null)).isEmpty();
    }

    /**
     * The real thing: a JVM started without the export cannot reach the handle, and what it throws is
     * what the log line recognises. This JVM has the export, so the probe runs in a child that does not.
     */
    @Test
    void aJvmWithoutTheExportIsToldWhichOptionItLacks() throws Exception {
        ProcessBuilder builder = new ProcessBuilder(
                Path.of(System.getProperty("java.home"), "bin", "java").toString(),
                "-cp", System.getProperty("java.class.path"),
                MissingExportProbe.class.getName())
                .redirectError(ProcessBuilder.Redirect.DISCARD);
        // Either would hand the child the option this test is about.
        builder.environment().remove("JDK_JAVA_OPTIONS");
        builder.environment().remove("JAVA_TOOL_OPTIONS");
        Process process = builder.start();
        String output;
        try (var out = process.getInputStream()) {
            output = new String(out.readAllBytes(), StandardCharsets.UTF_8);
        }
        assertThat(process.waitFor(60, TimeUnit.SECONDS)).as("probe finished").isTrue();
        assertThat(output.lines().toList()).isEqualTo(List.of("error" + MISSING_EXPORT));
    }

    /** Run by the test above in a JVM without the export. */
    static final class MissingExportProbe {
        public static void main(String[] args) throws IOException {
            try (SocketChannel channel = SocketChannel.open()) {
                PeerEgressSocketHandles.of(channel);
                System.out.println("reached the handle");
            } catch (IOException failure) {
                System.out.println(PeerEgressRuntime.connectReason(failure) + PeerEgressRuntime.connectDetail(failure));
            }
        }
    }
}
