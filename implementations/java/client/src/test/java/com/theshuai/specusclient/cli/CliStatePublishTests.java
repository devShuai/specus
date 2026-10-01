package com.theshuai.specusclient.cli;

import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.AccessDeniedException;

import static org.assertj.core.api.Assertions.assertThat;

class CliStatePublishTests {
    /**
     * A failed write must not end publication: the next tick writes again, and the failure and the
     * recovery are each said once rather than once a second.
     */
    @Test
    void publicationKeepsWritingAfterAFailure() {
        boolean[] results = {true, false, false, true, true};
        int[] calls = {0};
        var out = new ByteArrayOutputStream();
        var report = new PrintStream(out, true, StandardCharsets.UTF_8);
        boolean failing = false;
        for (int i = 0; i < results.length; i++) {
            failing = CliState.publishOnce(() -> {
                if (!results[calls[0]++]) throw new AccessDeniedException("state.json");
            }, failing, report);
        }
        assertThat(calls[0]).isEqualTo(results.length);
        assertThat(failing).isFalse();
        assertThat(out.toString(StandardCharsets.UTF_8).lines().toList()).containsExactly(
                "State publication failed (AccessDeniedException: state.json); retrying every second, so status may be stale meanwhile.",
                "State publication recovered.");
    }
}
