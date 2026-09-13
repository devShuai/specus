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
                   java -jar specus-client-exec.jar status|peers|services|egress --config PATH [--json]
                   java -jar specus-client-exec.jar doctor --config PATH [--probe] [--json]
                   java -jar specus-client-exec.jar ui --config PATH [--no-open] [--port PORT]

            Options:
              -h, --help            Show help without loading configuration or connecting
              --version             Print version and exit
              -c, --config PATH     JSONC configuration (default: ./client.jsonc)
              --no-update-check     Disable update checks (--no-update is an alias)
              --debug               Include diagnostic details
              --login-timeout SEC   Initial HTTP login budget, 1..3600 seconds (default: 60)
              --json               Versioned JSON for one-shot commands; logs stay on stderr
              --probe              doctor only: 5-second server TCP probe; never authenticates
              --no-open            ui only: print local address without opening a browser
              --port PORT          ui only: loopback port, 0..65535 (default: random)

            The egress command reports which of this node's egress rules are actually in force,
            which routes were installed, and which were refused because something already owned
            the prefix.

            Example:
              java -jar specus-client-exec.jar --config "/path with spaces/client.jsonc"

            Java reports available updates; it does not automatically replace the jar.
            Exit codes: 0 success/user stop, 1 runtime failure, 2 arguments/configuration,
                        3 authentication/policy rejection, 4 timeout/probe failure, 5 no live state.
            """;

    public record Options(Path config, String command, boolean help, boolean version,
                          boolean noUpdate, boolean debug, int loginTimeoutSeconds, boolean json, boolean probe,
                          boolean noOpen, int uiPort) { }

    public static Options parse(String[] args) {
        Path config = Path.of("client.jsonc");
        String command = "run";
        boolean help = false, version = false, noUpdate = false, debug = false;
        int loginTimeoutSeconds = 60;
        boolean json = false, probe = false;
        boolean noOpen = false, portSet = false;
        int uiPort = 0;
        int i = 0;
        if (args.length > 0 && "run".equals(args[0])) i++;
        else if (args.length > 0 && "config".equals(args[0])) {
            if (args.length < 2 || !("validate".equals(args[1]) || "show".equals(args[1])))
                throw new IllegalArgumentException("Expected: config validate|show --config PATH");
            command = args[1];
            i = 2;
        }
        else if (args.length > 0 && java.util.Set.of("ui", "status", "peers", "services", "egress", "doctor").contains(args[0])) { command = args[0]; i = 1; }
        for (; i < args.length; i++) {
            String arg = args[i];
            switch (arg) {
                case "--help", "-h" -> help = true;
                case "--version" -> version = true;
                case "--debug" -> debug = true;
                case "--json" -> json = true;
                case "--probe" -> probe = true;
                case "--no-open" -> noOpen = true;
                case "--port" -> {
                    if (++i >= args.length) throw new IllegalArgumentException("--port requires 0..65535");
                    uiPort = port(args[i]); portSet = true;
                }
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
                    else if (arg.startsWith("--port=")) { uiPort = port(arg.substring(7)); portSet = true; }
                    else throw new IllegalArgumentException("Unknown command or option; run --help for usage");
                }
            }
        }
        if (probe && !command.equals("doctor")) throw new IllegalArgumentException("--probe is only valid for doctor");
        if ((noOpen || portSet) && !command.equals("ui")) throw new IllegalArgumentException("--no-open/--port are only valid for ui");
        if (command.equals("ui") && (json || debug || noUpdate) && !help && !version) throw new IllegalArgumentException("ui does not accept --json/--debug/update options");
        if (json && command.equals("run") && !help && !version) throw new IllegalArgumentException("--json is for help/version/config/status/doctor/peers/services/egress; use status --json to observe a running client");
        return new Options(config.toAbsolutePath().normalize(), command, help, version, noUpdate, debug, loginTimeoutSeconds, json, probe, noOpen, uiPort);
    }

    private static int port(String value) {
        try { int port = Integer.parseInt(value); if (port >= 0 && port <= 65535) return port; }
        catch (NumberFormatException ignored) { }
        throw new IllegalArgumentException("--port requires 0..65535");
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
        return parse(Files.readString(path), warning);
    }

    public static ClientStartupConfig parse(String text, Consumer<String> warning) throws IOException {
        var mapper = JsonMapper.builder()
                .enable(JsonReadFeature.ALLOW_JAVA_COMMENTS, JsonReadFeature.ALLOW_YAML_COMMENTS,
                        JsonReadFeature.ALLOW_TRAILING_COMMA)
                .disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES).build();
        ClientStartupConfig config;
        com.fasterxml.jackson.databind.JsonNode raw;
        try {
            raw = mapper.readTree(text);
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
