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
                   java -jar specus-client-exec.jar egress rules --config PATH [--json]
                   java -jar specus-client-exec.jar egress rule add --config PATH --match CIDR --action egress|direct|block
                                 [--egress-client-id ID] [--at INDEX] [--disabled] [--json]
                   java -jar specus-client-exec.jar egress rule remove|enable|disable --config PATH --index INDEX [--json]
                   java -jar specus-client-exec.jar egress rule move --config PATH --index INDEX --to INDEX [--json]
                   java -jar specus-client-exec.jar egress enable --config PATH [--yes] [--json]
                   java -jar specus-client-exec.jar egress disable --config PATH [--json]
                   java -jar specus-client-exec.jar egress test ADDRESS --config PATH [--connect PORT] [--json]
                   java -jar specus-client-exec.jar egress dns enable --config PATH [--yes] [--json]
                   java -jar specus-client-exec.jar egress dns disable --config PATH [--json]
                   java -jar specus-client-exec.jar egress dns status --config PATH [--json]
                   java -jar specus-client-exec.jar egress dns restore [--force] [--json]

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
              --force              egress dns restore only: give back even if the recorded client still runs

            The egress command reports which of this node's egress rules are actually in force,
            which routes were installed, and which were refused because something already owned
            the prefix.

            The egress rules/rule/enable/disable commands edit the configuration file and never a
            running client, which applies the change after a restart. Saving rules and taking over
            traffic are separate: rules take nothing over until egress enable. egress test previews
            what the rules decide for an IPv4 address or a domain name, which it never resolves; only
            --connect PORT makes a connection, to an address, and that shows reachability, not the
            path taken.

            egress dns enable|disable sets peerEgressDnsTakeover, which lets domain rules take effect
            by pointing the system DNS at this client while it runs. egress dns status reports
            whether it does, why not, the upstreams and the takeover journal; egress dns restore
            gives the system DNS back from the journal without a running client.
            Domain rules do not match applications that bring their own DoH/DoT, use the system cache, or connect to hard-coded IP addresses; that traffic is covered only by IP/CIDR rules.

            Example:
              java -jar specus-client-exec.jar --config "/path with spaces/client.jsonc"

            Java reports available updates; it does not automatically replace the jar.
            Exit codes: 0 success/user stop, 1 runtime failure, 2 arguments/configuration,
                        3 authentication/policy rejection, 4 timeout/probe failure, 5 no live state.
            """;

    public record Options(Path config, String command, boolean help, boolean version,
                          boolean noUpdate, boolean debug, int loginTimeoutSeconds, boolean json, boolean probe,
                          boolean noOpen, int uiPort, EgressOptions egress) { }

    /** The egress editing commands' flags; -1 marks an index that was not given. */
    public record EgressOptions(String address, String match, String action, long egressClientId,
                                int at, int index, int to, boolean disabled, boolean yes, int connect, boolean force) { }

    /** Each editing flag belongs to the commands it means something to. */
    private static final java.util.Map<String, java.util.Set<String>> EGRESS_FLAGS = java.util.Map.of(
            "egress rule add", java.util.Set.of("match", "action", "egress-client-id", "at", "disabled"),
            "egress rule remove", java.util.Set.of("index"),
            "egress rule enable", java.util.Set.of("index"),
            "egress rule disable", java.util.Set.of("index"),
            "egress rule move", java.util.Set.of("index", "to"),
            "egress enable", java.util.Set.of("yes"),
            "egress test", java.util.Set.of("connect"),
            "egress dns enable", java.util.Set.of("yes"),
            "egress dns restore", java.util.Set.of("force"));
    private static final java.util.List<String> EGRESS_FLAG_ORDER = java.util.List.of(
            "match", "action", "egress-client-id", "at", "disabled", "index", "to", "yes", "connect", "force");

    public static Options parse(String[] args) {
        Path config = Path.of("client.jsonc");
        String command = "run";
        boolean help = false, version = false, noUpdate = false, debug = false;
        int loginTimeoutSeconds = 60;
        boolean json = false, probe = false;
        boolean noOpen = false, portSet = false;
        int uiPort = 0;
        String egressAddress = "", egressMatch = "", egressAction = "";
        long egressClientId = 0;
        int egressAt = -1, egressIndex = -1, egressTo = -1, egressConnect = 0;
        boolean egressDisabled = false, egressYes = false, egressForce = false;
        var given = new java.util.HashSet<String>();
        int i = 0;
        if (args.length > 0 && "run".equals(args[0])) i++;
        else if (args.length > 1 && "egress".equals(args[0]) && !args[1].startsWith("-")) {
            // The words after "egress" that name an editing command. The plain egress command,
            // which reports a running client's state, is what is left when none of them follows.
            switch (args[1]) {
                case "rules", "enable", "disable" -> { command = "egress " + args[1]; i = 2; }
                case "test" -> {
                    if (args.length < 3 || args[2].startsWith("-"))
                        throw new IllegalArgumentException("expected: egress test ADDRESS --config PATH");
                    command = "egress test"; egressAddress = args[2]; i = 3;
                }
                case "dns" -> {
                    if (args.length < 3 || !java.util.Set.of("enable", "disable", "status", "restore").contains(args[2]))
                        throw new IllegalArgumentException("expected: egress dns enable|disable|status|restore");
                    command = "egress dns " + args[2]; i = 3;
                }
                case "rule" -> {
                    if (args.length < 3 || !java.util.Set.of("add", "remove", "move", "enable", "disable").contains(args[2]))
                        throw new IllegalArgumentException("expected: egress rule add|remove|move|enable|disable --config PATH");
                    command = "egress rule " + args[2]; i = 3;
                }
                default -> throw new IllegalArgumentException("unknown egress command; see --help");
            }
        }
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
                case "--disabled" -> { egressDisabled = true; given.add("disabled"); }
                case "--yes" -> { egressYes = true; given.add("yes"); }
                case "--force" -> { egressForce = true; given.add("force"); }
                case "--match", "--action", "--egress-client-id", "--at", "--index", "--to", "--connect" -> {
                    String name = arg.substring(2);
                    if (++i >= args.length) throw new IllegalArgumentException(arg + " requires a value");
                    given.add(name);
                    switch (name) {
                        case "match" -> egressMatch = args[i];
                        case "action" -> egressAction = args[i];
                        case "egress-client-id" -> egressClientId = integer(arg, args[i]);
                        case "at" -> egressAt = (int) integer(arg, args[i]);
                        case "index" -> egressIndex = (int) integer(arg, args[i]);
                        case "to" -> egressTo = (int) integer(arg, args[i]);
                        default -> egressConnect = (int) integer(arg, args[i]);
                    }
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
        var egress = new EgressOptions(egressAddress, egressMatch, egressAction, egressClientId,
                egressAt, egressIndex, egressTo, egressDisabled, egressYes, egressConnect, egressForce);
        checkEgressFlags(command, egress, given);
        return new Options(config.toAbsolutePath().normalize(), command, help, version, noUpdate, debug, loginTimeoutSeconds, json, probe, noOpen, uiPort, egress);
    }

    /**
     * Keeps each editing flag to the command it means something to, and each command to the flags
     * it needs, before anything reads the configuration.
     */
    private static void checkEgressFlags(String command, EgressOptions egress, java.util.Set<String> given) {
        for (String name : EGRESS_FLAG_ORDER) {
            if (given.contains(name) && !EGRESS_FLAGS.getOrDefault(command, java.util.Set.of()).contains(name))
                throw new IllegalArgumentException("--" + name + " is not valid for " + command + "; see --help");
        }
        switch (command) {
            case "egress rule add" -> {
                if (egress.match().isBlank() || egress.action().isBlank())
                    throw new IllegalArgumentException("egress rule add requires --match and --action");
            }
            case "egress rule remove", "egress rule enable", "egress rule disable" -> {
                if (!given.contains("index") || egress.index() < 0)
                    throw new IllegalArgumentException(command + " requires --index INDEX (0 or more)");
            }
            case "egress rule move" -> {
                if (!given.contains("index") || !given.contains("to") || egress.index() < 0 || egress.to() < 0)
                    throw new IllegalArgumentException("egress rule move requires --index INDEX and --to INDEX (0 or more)");
            }
            case "egress test" -> {
                if (given.contains("connect") && (egress.connect() < 1 || egress.connect() > 65535))
                    throw new IllegalArgumentException("--connect requires a port (1..65535)");
            }
            default -> { }
        }
        if (given.contains("at") && egress.at() < 0) throw new IllegalArgumentException("--at requires an index (0 or more)");
    }

    private static long integer(String flag, String value) {
        try { return Long.parseLong(value.trim()); }
        catch (NumberFormatException error) { throw new IllegalArgumentException(flag + " requires an integer"); }
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
        // Filled in rather than left empty, so what the configuration shows is the pool in use. Not
        // checked here: an unusable pool stops phase two, not the client.
        config.setPeerEgressFakeIpCidr(com.theshuai.common.peeregress.PeerEgressDns.effectivePool(config.getPeerEgressFakeIpCidr()));
        ConfigDiagnostics.report(raw, mapper.valueToTree(new ClientStartupConfig()), config, warning);
        return config;
    }
}
