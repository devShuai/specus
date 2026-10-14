package com.theshuai.specusclient.cli;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.time.Duration;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class CliProcessProbeTests {
    @TempDir Path temporary;

    @Test void timeoutRemainsFailureAndKeepsRedactedOutputThreadsAndReapEvidence() throws Exception {
        var result = CliProcessProbe.run(List.of(Path.of(System.getProperty("java.home"), "bin", "java").toString(),
                "-cp", System.getProperty("java.class.path"), BlockedChild.class.getName()), temporary,
                "negative-blocked-child", Duration.ofSeconds(3));
        // The old helper throws its waitFor assertion before it reads either output file.
        // This deterministic deadline failure must stay a failure, even after diagnostics.
        assertThat(result.finishedInBudget()).isFalse();
        assertThat(result.secretFound()).isTrue();
        assertThat(result.reaped()).isTrue();
        assertThat(result.diagnostic()).contains("fixture-before-block", "jcmd exit=0", "BlockedChild.main",
                "ownedProcessReaped=true", "finishedInBudget=false", "<redacted-secret>")
                .doesNotContain("DO_NOT_PRINT_", temporary.toString(), System.getProperty("user.home"));
    }

    public static final class BlockedChild {
        public static void main(String[] args) throws Exception {
            System.out.println("fixture-before-block DO_NOT_PRINT_SECRET");
            System.err.println("fixture-stderr DO_NOT_PRINT_TOKEN");
            Thread.sleep(60_000);
        }
    }
}
