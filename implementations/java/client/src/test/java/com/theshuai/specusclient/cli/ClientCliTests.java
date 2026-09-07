package com.theshuai.specusclient.cli;

import com.theshuai.specusclient.bean.SpecusBean;
import com.theshuai.specusclient.client.NettyClient;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.context.event.ContextClosedEvent;
import org.springframework.context.support.GenericApplicationContext;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.*;

class ClientCliTests {
    @TempDir Path temporary;

    @Test void isolatedProcessesHandleHelpVersionErrorsAndOfflineValidation() throws Exception {
        Path config = temporary.resolve("path with spaces.jsonc");
        Files.writeString(config, "{\"serverBaseUrl\":\"http://127.0.0.1:1\",\"apiKey\":\"test\",\"secret\":\"DO_NOT_PRINT_SECRET\"}");
        Path diagnosticConfig = temporary.resolve("diagnostics.jsonc");
        Files.writeString(diagnosticConfig, "{\"serverBaseUrl\":\"http://127.0.0.1:1\",\"apiKey\":\"test\",\"secret\":\"DO_NOT_PRINT_SECRET\",\"peerMeshMtu\":9999,\"typo\":\"DO_NOT_PRINT_SECRET\"}");
        List<List<String>> cases = List.of(List.of("--help"), List.of("--version"), List.of("unknown-command"),
                List.of("--config"), List.of("--config=missing.jsonc"),
                List.of("config", "validate", "--config", config.toString()),
                List.of("--config", config.toString(), "--no-update-check", "--login-timeout", "1"),
                List.of("config", "validate", "--config", diagnosticConfig.toString()));
        int index = 0;
        for (var args : cases) {
            int expected = index == 6 ? 4 : index == 0 || index == 1 || index >= 5 ? 0 : 2;
            var command = new ArrayList<>(List.of(Path.of(System.getProperty("java.home"), "bin", "java").toString(),
                    "-Duser.home=" + temporary,
                    "-cp", System.getProperty("java.class.path"),
                    "com.theshuai.specusclient.SpecusClientApplication"));
            command.addAll(args);
            Path stdout = temporary.resolve("stdout-" + index);
            Path stderr = temporary.resolve("stderr-" + index++);
            var process = new ProcessBuilder(command).directory(temporary.toFile())
                    .redirectOutput(stdout.toFile()).redirectError(stderr.toFile()).start();
            try {
                assertThat(process.waitFor(10, TimeUnit.SECONDS)).as("CLI must not connect/hang: %s", args).isTrue();
                String output = Files.readString(stdout);
                String errors = Files.readString(stderr);
                assertThat(process.exitValue()).as("stdout=%s stderr=%s", output, errors).isEqualTo(expected);
                assertThat(output + errors).doesNotContain("DO_NOT_PRINT_SECRET");
                if (args.contains(diagnosticConfig.toString())) {
                    assertThat(errors).contains("Warning:", "peerMeshMtu normalized to 1280");
                    assertThat(output).doesNotContain("Warning:");
                } else assertThat(expected == 0 ? errors : output).isEmpty();
                if (args.contains("validate")) assertThat(output).contains("offline");
            } finally {
                if (process.isAlive()) { process.destroyForcibly(); process.waitFor(); }
            }
        }
    }

    @Test void invalidArgumentsFailWithoutStartingSpring() {
        for (String[] args : new String[][]{{"unknown-command"}, {"--unknown"}, {"--config"}, {"--config="},
                {"--config", "--version"}, {"--help", "extra"}, {"config"}, {"config", "unknown"},
                {"--login-timeout"}, {"--login-timeout=0"}, {"--login-timeout", "3601"}, {"--login-timeout=NaN"}}) {
            assertThatThrownBy(() -> ClientCli.parse(args)).isInstanceOf(IllegalArgumentException.class);
        }
    }

    @Test void helpVersionAndConfigPathAreIndependentOfConfigExistence() {
        assertThat(ClientCli.parse(new String[]{"--help"}).help()).isTrue();
        assertThat(ClientCli.parse(new String[]{"--version"}).version()).isTrue();
        var options = ClientCli.parse(new String[]{"config", "validate", "-c", "path with spaces/client.jsonc"});
        assertThat(options.command()).isEqualTo("validate");
        assertThat(options.config()).isEqualTo(Path.of("path with spaces/client.jsonc").toAbsolutePath());
    }

    @Test void validationAcceptsJsoncAndDoesNotConnect() throws Exception {
        Path config = temporary.resolve("client.jsonc");
        Files.writeString(config, """
                { // deliberately unreachable: validation must be offline
                  "serverBaseUrl":"http://127.0.0.1:1", "apiKey":"test", "secret":"private", }
                """);
        assertThat(ClientCli.load(config).getApiKey()).isEqualTo("test");
    }

    @Test void malformedConfigurationDoesNotIncludeSecretInError() throws Exception {
        Path config = temporary.resolve("client.jsonc");
        Files.writeString(config, "{\"secret\":DO_NOT_PRINT_SECRET}");
        assertThatThrownBy(() -> ClientCli.load(config)).hasMessageContaining("line")
                .hasMessageNotContaining("DO_NOT_PRINT_SECRET");
    }

    @Test void diagnosticsWarnWithoutPrintingValues() throws Exception {
        Path config = temporary.resolve("diagnostics.jsonc");
        Files.writeString(config, """
                {"serverBaseUrl":"http://127.0.0.1:1","apiKey":"DO_NOT_PRINT_KEY","secret":"DO_NOT_PRINT_SECRET",
                 "peerMeshMtu":9999,"updateCheckIntervalHours":9999,"typo":"DO_NOT_PRINT_UNKNOWN",
                 "controlTls":{"serverNmae":"DO_NOT_PRINT_HOST"},"upstreamTls":{"bad":"DO_NOT_PRINT_PIN"},"autoUpdate":true}
                """);
        var warnings = new ArrayList<String>();
        var effective = ClientCli.load(config, warnings::add);
        assertThat(effective.getPeerMeshMtu()).isEqualTo(1280);
        assertThat(effective.getUpdateCheckIntervalHours()).isEqualTo(168);
        assertThat(String.join("|", warnings)).contains("typo", "controlTls.serverNmae", "upstreamTls.bad",
                "peerMeshMtu normalized to 1280", "updateCheckIntervalHours normalized to 168", "never installs")
                .doesNotContain("DO_NOT_PRINT");
    }

    @Test void terminalFailureNotifiesMainExactlyOnce() {
        var bean = new SpecusBean();
        bean.setClientName("cli-test");
        bean.setClientSessionId(1L);
        bean.setAccessToken("test-token");
        bean.setRemoteAddress("127.0.0.1");
        bean.setRemotePort(1);
        var client = new NettyClient(bean, null, null, false);
        var calls = new AtomicInteger();
        var exit = new ClientExitStatus();
        client.setTerminalFailureListener(() -> { calls.incrementAndGet(); exit.fail(); });
        client.stopReconnecting("terminal test");
        client.stopReconnecting("duplicate");
        assertThat(calls.get()).isEqualTo(1);
        assertThat(exit.await()).isEqualTo(3);
        client.shutdown();
    }

    @Test void gracefulContextShutdownSignalsSuccess() {
        var exit = new ClientExitStatus();
        try (var context = new GenericApplicationContext()) {
            exit.onApplicationEvent(new ContextClosedEvent(context));
            assertThat(exit.await()).isZero();
        }
    }
}
