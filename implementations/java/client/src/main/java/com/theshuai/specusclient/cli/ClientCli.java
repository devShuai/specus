package com.theshuai.specusclient.cli;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.json.JsonReadFeature;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.json.JsonMapper;
import com.theshuai.specusclient.bean.ClientStartupConfig;
import com.theshuai.specusclient.bean.ControlTlsConfig;
import com.theshuai.specusclient.bean.MachineCredential;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.function.Consumer;
import com.theshuai.specusclient.peer.PeerVirtualDeviceOptions;

/** CLI-only parsing and offline validation, before Spring or any login/update side effect. */
public final class ClientCli {
    private ClientCli() { }

    public static final String HELP = """
            Usage: java -jar specus-client-exec.jar [run] [options]
                   java -jar specus-client-exec.jar config validate|show --config PATH [--json]
                   java -jar specus-client-exec.jar status|peers|services --config PATH [--json]
                   java -jar specus-client-exec.jar doctor --config PATH [--probe] [--json]

            Options:
              -h, --help            Show help without loading configuration or connecting
              --version             Print version and exit
              -c, --config PATH     JSONC configuration (default: ./client.jsonc)
              --no-update-check     Disable update checks (--no-update is an alias)
              --debug               Include diagnostic details
              --login-timeout SEC   Initial HTTP login budget, 1..3600 seconds (default: 60)
              --json               Versioned JSON for one-shot commands; logs stay on stderr
              --probe              doctor only: 5-second server TCP probe; never authenticates

            Example:
              java -jar specus-client-exec.jar --config "/path with spaces/client.jsonc"

            Java reports available updates; it does not automatically replace the jar.
            Exit codes: 0 success/user stop, 1 runtime failure, 2 arguments/configuration,
                        3 authentication/policy rejection, 4 timeout/probe failure, 5 no live state.
            """;

    public record Options(Path config, String command, boolean help, boolean version,
                          boolean noUpdate, boolean debug, int loginTimeoutSeconds, boolean json, boolean probe) { }

    public static Options parse(String[] args) {
        Path config = Path.of("client.jsonc");
        String command = "run";
        boolean help = false, version = false, noUpdate = false, debug = false;
        int loginTimeoutSeconds = 60;
        boolean json = false, probe = false;
        int i = 0;
        if (args.length > 0 && "run".equals(args[0])) i++;
        else if (args.length > 0 && "config".equals(args[0])) {
            if (args.length < 2 || !("validate".equals(args[1]) || "show".equals(args[1])))
                throw new IllegalArgumentException("Expected: config validate|show --config PATH");
            command = args[1];
            i = 2;
        }
        else if (args.length > 0 && java.util.Set.of("status", "peers", "services", "doctor").contains(args[0])) { command = args[0]; i = 1; }
        for (; i < args.length; i++) {
            String arg = args[i];
            switch (arg) {
                case "--help", "-h" -> help = true;
                case "--version" -> version = true;
                case "--debug" -> debug = true;
                case "--json" -> json = true;
                case "--probe" -> probe = true;
                case "--no-update", "--no-update-check" -> noUpdate = true;
                case "--login-timeout" -> {
                    if (++i >= args.length) throw new IllegalArgumentException("--login-timeout requires seconds (1..3600)");
                    loginTimeoutSeconds = loginTimeout(args[i]);
                }
                case "--config", "-c" -> {
                    if (++i >= args.length) throw new IllegalArgumentException("--config requires a path");
                    config = configPath(args[i]);
                }
                default -> {
                    if (arg.startsWith("--config=")) config = configPath(arg.substring("--config=".length()));
                    else if (arg.startsWith("--login-timeout=")) loginTimeoutSeconds = loginTimeout(arg.substring("--login-timeout=".length()));
                    else throw new IllegalArgumentException("Unknown command or option; run --help for usage");
                }
            }
        }
        if (probe && !command.equals("doctor")) throw new IllegalArgumentException("--probe is only valid for doctor");
        if (json && command.equals("run") && !help && !version) throw new IllegalArgumentException("--json is for help/version/config/status/doctor/peers/services; use status --json to observe a running client");
        return new Options(config.toAbsolutePath().normalize(), command, help, version, noUpdate, debug, loginTimeoutSeconds, json, probe);
    }

    private static int loginTimeout(String value) {
        try {
            int seconds = Integer.parseInt(value);
            if (seconds >= 1 && seconds <= 3600) return seconds;
        } catch (NumberFormatException ignored) { }
        throw new IllegalArgumentException("--login-timeout requires seconds (1..3600)");
    }

    private static Path configPath(String value) {
        if (value.isBlank() || value.startsWith("-"))
            throw new IllegalArgumentException("--config requires a path; use ./ for a filename starting with '-'");
        return Path.of(value);
    }

    public static ClientStartupConfig load(Path path) throws IOException {
        return load(path, ignored -> { });
    }

    public static ClientStartupConfig load(Path path, Consumer<String> warning) throws IOException {
        var mapper = JsonMapper.builder()
                .enable(JsonReadFeature.ALLOW_JAVA_COMMENTS, JsonReadFeature.ALLOW_YAML_COMMENTS,
                        JsonReadFeature.ALLOW_TRAILING_COMMA)
                .disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES).build();
        ClientStartupConfig config;
        com.fasterxml.jackson.databind.JsonNode raw;
        try {
            raw = mapper.readTree(Files.readString(path));
            if (raw == null || !raw.isObject()) throw new IOException("Configuration must be a JSON object");
            config = mapper.treeToValue(raw, ClientStartupConfig.class);
        } catch (JsonProcessingException error) {
            // Jackson messages can contain source fragments: do not print credential values.
            var at = error.getLocation();
            throw new IOException("Invalid JSONC" + (at == null ? "" : " at line " + at.getLineNr()
                    + ", column " + at.getColumnNr()));
        }
        if (config == null) throw new IOException("Configuration must be a JSON object");
        if (config.getApiKey() == null || config.getApiKey().isBlank())
            throw new IOException("apiKey is required");
        if (config.getSecret() == null || config.getSecret().isBlank())
            throw new IOException("secret is required (inline, env: or file: reference)");
        if (config.getControlTls() == null) config.setControlTls(new ControlTlsConfig());
        config.getControlTls().validate(config.getServerBaseUrl());
        MachineCredential.resolve(config.getSecret());
        var peer = new PeerVirtualDeviceOptions(config.getPeerMeshDevice(), config.getPeerMeshTunName(), config.getPeerMeshMtu());
        config.setPeerMeshDevice(peer.mode());
        config.setPeerMeshTunName(peer.tunName());
        config.setPeerMeshMtu(peer.mtu());
        config.setUpdateCheckIntervalHours(config.getUpdateCheckIntervalHours() <= 0 ? 24 : Math.min(168, config.getUpdateCheckIntervalHours()));
        ConfigDiagnostics.report(raw, mapper.valueToTree(new ClientStartupConfig()), config, warning);
        return config;
    }
}
