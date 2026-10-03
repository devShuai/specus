package com.theshuai.specusclient.cli;

import com.theshuai.common.peeregress.Ipv4Cidr;
import com.theshuai.common.peeregress.PeerEgressCodes;
import com.theshuai.common.peeregress.PeerEgressDns;
import com.theshuai.common.peeregress.PeerEgressNames;
import com.theshuai.common.peeregress.PeerEgressRule;
import com.theshuai.common.peeregress.PeerEgressRules;
import com.theshuai.specusclient.bean.ClientStartupConfig;

import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * The egress editing commands: list the rules, add, remove, move and switch them, turn takeover on
 * and off, and preview what the rules do for one address or name.
 *
 * <p>They edit the configuration file the way the local page does: the one top-level value they
 * own is replaced in place and everything else in the file is kept, the write is atomic and refused
 * if the file changed underneath. They never touch a running client, which reads its configuration
 * once at start; every write says so. Comments inside peerEgressRules do not survive an edit,
 * because the list is written back whole.
 *
 * <p>The Go and .NET clients print the same lines and the same JSON for the same file; the CLI
 * process matrix holds them to it.
 */
public final class EgressEdit {
    private EgressEdit() { }

    static final String RESTART_NOTE = "A running client applies the change after a restart.";

    /** What turning takeover on means, printed every time it is turned on. */
    static final List<String> ENABLE_NOTICE = List.of(
            "Turning on egress takeover:",
            "  - needs permission to create a virtual interface and install routes (administrator or root; peerMeshDevice must not be noop)",
            "  - takes over only the destinations a rule covers; everything else stays local",
            "  - blocks a destination covered by an egress rule while its egress is unavailable, instead of sending it locally");

    private record Loaded(UiConfig.Snapshot snapshot, ClientStartupConfig config) { }

    /** A command that ended early, carrying the exit code it already reported. */
    private static final class Done extends RuntimeException {
        final int code;
        Done(int code) { super(null, null, false, false); this.code = code; }
    }

    public static int run(ClientCli.Options options) {
        try {
            return switch (options.command()) {
                case "egress rules" -> list(options);
                case "egress test" -> test(options);
                case "egress enable", "egress disable" -> toggle(options);
                case "egress dns enable", "egress dns disable" -> EgressDns.toggle(options);
                case "egress dns status" -> EgressDns.status(options);
                case "egress dns restore" -> EgressDns.restore(options);
                default -> editRule(options);
            };
        } catch (Done done) {
            return done.code;
        }
    }

    private static int fail(ClientCli.Options options, String message) {
        throw new Done(CliOutput.result(options.json(), options.command(), 2, null, message));
    }

    private static Loaded load(ClientCli.Options options) {
        Path path = options.config();
        UiConfig.Snapshot snapshot;
        try {
            snapshot = UiConfig.read(path);
        } catch (LocalUi.Failure failure) {
            return failWith(options, failure.getMessage());
        } catch (Exception error) {
            return failWith(options, "Cannot read " + path + ": " + error.getMessage());
        }
        if (snapshot.revision().equals("missing")) {
            return failWith(options, "Configuration file not found: " + path);
        }
        try {
            return new Loaded(snapshot, ClientCli.parse(snapshot.text(), ignored -> { }));
        } catch (Exception error) {
            return failWith(options, "invalid config " + path + ": " + error.getMessage() + "; fix it first (config validate)");
        }
    }

    private static Loaded failWith(ClientCli.Options options, String message) {
        fail(options, message);
        return null;
    }

    private static List<PeerEgressRule> rules(ClientStartupConfig config) {
        return config.getPeerEgressRules() == null ? List.of() : config.getPeerEgressRules();
    }

    private static String trim(String value) {
        return value == null ? "" : value.trim();
    }

    private static long id(Long value) {
        return value == null ? 0L : value;
    }

    /**
     * Why a rule is not in force as configured, or null; the master switch is not part of it. Judged
     * against the fake-IP pool when phase two is asked for over a usable one, as the running client
     * would judge it.
     */
    static String ruleCode(ClientStartupConfig config, PeerEgressRule rule) {
        return PeerEgressRules.validate(rule, PeerEgressRules.DEFAULT_MESH_CIDR, pool(config));
    }

    /** The pool phase two would run with as configured, or null. */
    private static String pool(ClientStartupConfig config) {
        return PeerEgressDns.configuredPool(config.isPeerEgressDnsTakeover(), config.getPeerEgressFakeIpCidr());
    }

    /** The code a rule reports in status: the master switch off names itself unless the rule was switched off. */
    static String statusCode(ClientStartupConfig config, PeerEgressRule rule) {
        if (!config.isPeerEgressEnabled() && !rule.switchedOff()) return PeerEgressCodes.CONSUMER_DISABLED;
        return ruleCode(config, rule);
    }

    /** One line a person can act on for a rule's code, in the words the Go and .NET clients use too. */
    static String explanation(String code) {
        return switch (code) {
            case PeerEgressCodes.RULE_DOMAIN_UNSUPPORTED -> "domain rules are not supported yet; use an IPv4 address or CIDR range";
            case PeerEgressCodes.RULE_IPV6_UNSUPPORTED -> "IPv6 rules are not supported; use an IPv4 address or CIDR range";
            case PeerEgressCodes.RULE_MALFORMED -> "not an IPv4 address or CIDR range with zero host bits, or an unknown action";
            case PeerEgressCodes.RULE_DEFAULT_ROUTE -> "0.0.0.0/0 would take over the default route, which is not allowed";
            case PeerEgressCodes.RULE_MESH_OVERLAP -> "overlaps the Peer Mesh network";
            case PeerEgressCodes.RULE_FAKE_IP_OVERLAP -> "overlaps the fake-IP pool (peerEgressFakeIpCidr), whose addresses only domain rules hand out";
            case PeerEgressCodes.RULE_PORT_UNSUPPORTED -> "a rule cannot be limited to a port; port limits belong on the egress policy";
            case PeerEgressCodes.RULE_MISSING_TARGET -> "an egress rule needs a positive egress device id";
            case PeerEgressCodes.RULE_DISABLED -> "switched off";
            case PeerEgressCodes.CONSUMER_DISABLED -> "takeover is off (peerEgressEnabled is false)";
            default -> "";
        };
    }

    /** What every egress command that reads or writes the rules reports. */
    private static Map<String, Object> listing(Path path, ClientStartupConfig config, List<String> lines) {
        var rules = rules(config);
        boolean enabled = config.isPeerEgressEnabled();
        if (enabled) lines.add("takeover: on");
        else if (!rules.isEmpty()) lines.add("takeover: off (peerEgressEnabled is false); rules are saved, none is in force");
        else lines.add("takeover: off (peerEgressEnabled is false)");
        if (rules.isEmpty()) lines.add("  No egress rules configured.");
        var views = new ArrayList<Map<String, Object>>();
        for (int index = 0; index < rules.size(); index++) {
            PeerEgressRule rule = rules.get(index);
            String status = statusCode(config, rule);
            // The rule's own problem, told apart from being off: worth fixing before takeover is on.
            var content = new PeerEgressRule();
            content.setMatch(rule.getMatch());
            content.setAction(rule.getAction());
            content.setEgressClientId(rule.getEgressClientId());
            content.setPort(rule.getPort());
            String refusal = ruleCode(config, content);
            var view = new LinkedHashMap<String, Object>();
            view.put("index", index);
            view.put("match", trim(rule.getMatch()));
            view.put("action", trim(rule.getAction()));
            view.put("enabled", !rule.switchedOff());
            view.put("inForce", status == null);
            if (id(rule.getEgressClientId()) != 0) view.put("egressClientId", rule.getEgressClientId());
            if (rule.getPort() != null && rule.getPort() != 0) view.put("port", rule.getPort());
            if (status != null) view.put("code", status);
            if (refusal != null) view.put("refusal", refusal);
            views.add(view);

            var line = new StringBuilder("  [").append(index).append("] ").append(rule.switchedOff() ? "off" : "on")
                    .append(' ').append(trim(rule.getMatch())).append(' ').append(trim(rule.getAction()));
            if (id(rule.getEgressClientId()) != 0) line.append(' ').append(rule.getEgressClientId());
            if (refusal != null) line.append(" -- not in force: ").append(refusal).append(" (").append(explanation(refusal)).append(')');
            lines.add(line.toString());
        }
        var data = new LinkedHashMap<String, Object>();
        data.put("configPath", path.toString());
        data.put("enabled", enabled);
        data.put("rules", views);
        return data;
    }

    private static int list(ClientCli.Options options) {
        Loaded loaded = load(options);
        var lines = new ArrayList<String>();
        var data = listing(options.config(), loaded.config(), lines);
        return CliOutput.result(options.json(), options.command(), 0, data, String.join("\n", lines));
    }

    /** One edit to the rules or the switch, as the commands and the local page ask for it. */
    record Change(String op, String match, String action, long egressClientId, int at, int index, int to,
                  boolean disabled, boolean enabled, boolean confirmed) { }

    /**
     * What a change writes: one top-level value, already encoded, and what to say before the save.
     * Unchanged means the file already says what was asked; needsConfirmation means takeover was asked
     * for without the notice being accepted.
     */
    record Planned(String key, String value, List<String> preface, boolean unchanged, boolean needsConfirmation) { }

    /** A change that cannot be made, with a message a person can act on. */
    static final class PlanFailure extends RuntimeException {
        PlanFailure(String message) { super(message, null, false, false); }
    }

    /** Works out a change against the configuration as loaded, the same way in every runtime. */
    static Planned plan(ClientStartupConfig config, Change change) {
        var rules = new ArrayList<PeerEgressRule>();
        for (PeerEgressRule rule : rules(config)) rules.add(copy(rule));
        int count = rules.size();
        switch (change.op()) {
            case "takeover" -> {
                if (change.enabled() == config.isPeerEgressEnabled()) return new Planned(null, null, List.of(), true, false);
                if (!change.enabled()) return new Planned("peerEgressEnabled", "false", List.of(), false, false);
                var preface = new ArrayList<>(ENABLE_NOTICE);
                if (!change.confirmed()) return new Planned(null, null, preface, false, true);
                String device = trim(config.getPeerMeshDevice());
                if (device.isEmpty() || device.equalsIgnoreCase("noop"))
                    preface.add("Warning: peerMeshDevice is noop, so there is no interface to route into; set it to auto.");
                return new Planned("peerEgressEnabled", "true", preface, false, false);
            }
            case "add" -> {
                var rule = new PeerEgressRule();
                rule.setMatch(trim(change.match()));
                rule.setAction(trim(change.action()));
                if (change.egressClientId() != 0) rule.setEgressClientId(change.egressClientId());
                // Refused rules are allowed in the file, where they are warned about, but an edit
                // that adds one on request would only be writing a rule that steers nothing.
                String code = ruleCode(config, rule);
                if (code != null) throw new PlanFailure("Rule not added: " + code + " (" + explanation(code) + ")");
                if (change.disabled()) rule.setEnabled(false);
                int at = count;
                if (change.at() >= 0) {
                    if (change.at() > count) throw new PlanFailure("--at " + change.at() + " is past the end; there are " + count + " rule(s).");
                    at = change.at();
                }
                rules.add(at, rule);
            }
            case "remove", "move", "enable", "disable" -> {
                requireIndex(change.index(), count);
                switch (change.op()) {
                    case "remove" -> rules.remove(change.index());
                    case "move" -> {
                        requireIndex(change.to(), count);
                        rules.add(change.to(), rules.remove(change.index()));
                    }
                    case "enable" -> rules.get(change.index()).setEnabled(null);
                    default -> rules.get(change.index()).setEnabled(false);
                }
            }
            default -> throw new PlanFailure("unknown egress change: " + change.op());
        }
        return new Planned("peerEgressRules", encodeRules(rules), List.of(), false, false);
    }

    private static PeerEgressRule copy(PeerEgressRule rule) {
        var copy = new PeerEgressRule();
        copy.setMatch(rule.getMatch());
        copy.setAction(rule.getAction());
        copy.setEgressClientId(rule.getEgressClientId());
        copy.setPort(rule.getPort());
        copy.setEnabled(rule.getEnabled());
        return copy;
    }

    private static void requireIndex(int index, int count) {
        if (index < 0 || index >= count)
            throw new PlanFailure("No rule at index " + index + "; there are " + count + " rule(s). List them with egress rules.");
    }

    /** The change an editing command asks for. */
    private static Change change(ClientCli.Options options) {
        var egress = options.egress();
        String command = options.command();
        boolean takeover = command.equals("egress enable") || command.equals("egress disable");
        return new Change(takeover ? "takeover" : command.substring("egress rule ".length()), egress.match(), egress.action(),
                egress.egressClientId(), egress.at(), egress.index(), egress.to(), egress.disabled(),
                command.equals("egress enable"), egress.yes());
    }

    private static int editRule(ClientCli.Options options) {
        Loaded loaded = load(options);
        Planned planned;
        try {
            planned = plan(loaded.config(), change(options));
        } catch (PlanFailure failure) {
            return fail(options, failure.getMessage());
        }
        return write(options, loaded, planned.key(), planned.value(), planned.preface());
    }

    private static int toggle(ClientCli.Options options) {
        Loaded loaded = load(options);
        ClientStartupConfig config = loaded.config();
        Planned planned = plan(config, change(options));
        if (planned.unchanged()) {
            var lines = new ArrayList<String>();
            var data = listing(options.config(), config, lines);
            return CliOutput.result(options.json(), options.command(), 0, data,
                    "Takeover is already " + (config.isPeerEgressEnabled() ? "on" : "off") + "; nothing was changed.\n" + String.join("\n", lines));
        }
        // Confirmed by a flag rather than a prompt: whether a prompt could be answered depends on a
        // terminal the three runtimes cannot all detect the same way, and a command that waits in one
        // of them and fails in another is not the same command.
        if (planned.needsConfirmation())
            return fail(options, String.join("\n", planned.preface()) + "\nNot changed. Re-run with --yes to confirm.");
        return write(options, loaded, planned.key(), planned.value(), planned.preface());
    }

    private static int write(ClientCli.Options options, Loaded loaded, String key, String value, List<String> preface) {
        Path path = options.config();
        String patched;
        try {
            patched = patch(loaded.snapshot().text(), key, value);
        } catch (LocalUi.Failure failure) {
            return fail(options, failure.getMessage());
        }
        ClientStartupConfig config;
        try {
            config = ClientCli.parse(patched, ignored -> { });
        } catch (Exception error) {
            return fail(options, "the edited configuration would not load (" + error.getMessage() + "); nothing was written");
        }
        try {
            UiConfig.save(path, loaded.snapshot().revision(), patched);
        } catch (LocalUi.Failure failure) {
            return fail(options, failure.getMessage());
        } catch (Exception error) {
            return fail(options, "Cannot write " + path + ": " + error.getMessage());
        }
        var lines = new ArrayList<String>();
        var data = listing(path, config, lines);
        data.put("saved", true);
        var message = new ArrayList<>(preface);
        message.add("Saved " + path + ". " + RESTART_NOTE);
        message.addAll(lines);
        return CliOutput.result(options.json(), options.command(), 0, data, String.join("\n", message));
    }

    static final String NOT_AN_ADDRESS = "ADDRESS must be an IPv4 address.";
    static final String UNUSABLE_NAME = "ADDRESS is not a name a domain rule can match: use labels of a-z, 0-9 and -,"
            + " with punycode (xn--) for international names.";
    static final String CONNECT_NEEDS_ADDRESS = "--connect needs an IPv4 address: a name would be resolved here, not by the egress.";

    /** Whether ADDRESS is an IPv4 address rather than a name. */
    static boolean isAddress(String address) {
        return Ipv4Cidr.parseAddress(address) != null && !address.contains("/");
    }

    /**
     * Why an address cannot be previewed, or null when it can: an IPv4 address, or a name a domain
     * rule could match exactly, judged as a rule's match is (trailing dots and case ignored, IDN as
     * punycode). A wildcard is a rule's pattern rather than a name, so it is refused as one.
     */
    static String addressProblem(String address) {
        if (isAddress(address)) return null;
        if (!PeerEgressNames.namesDomain(address) || address.contains(":")) return NOT_AN_ADDRESS;
        return PeerEgressNames.validMatch(address) && !address.startsWith("*") ? null : UNUSABLE_NAME;
    }

    private static int test(ClientCli.Options options) {
        String address = trim(options.egress().address());
        String problem = addressProblem(address);
        if (problem != null) return fail(options, problem);
        // This device's DNS answering for a name says nothing of what the egress would resolve it to.
        if (!isAddress(address) && options.egress().connect() > 0) return fail(options, CONNECT_NEEDS_ADDRESS);
        Loaded loaded = load(options);
        var lines = new ArrayList<String>();
        var data = preview(options.config(), loaded.config(), address, lines);
        int code = 0;
        int port = options.egress().connect();
        if (port > 0) {
            var probe = connectProbe(address, port, lines);
            if (!Boolean.TRUE.equals(probe.get("ok"))) code = 4;
            data.put("connect", probe);
        }
        String last = lines.get(lines.size() - 1);
        if (code != 0 && options.json()) return CliOutput.result(true, options.command(), code, data, last);
        if (code != 0) {
            System.out.println(String.join("\n", lines.subList(0, lines.size() - 1)));
            return CliOutput.result(false, options.command(), code, null, last);
        }
        return CliOutput.result(options.json(), options.command(), 0, data, String.join("\n", lines));
    }

    /**
     * Connects to address:port once, within five seconds, and adds the line that reports it. It shows
     * the address is reachable from this device, not which path carried the connection; the preview
     * says that. The command and the local page run the same probe and report it the same way.
     */
    static LinkedHashMap<String, Object> connectProbe(String address, int port, List<String> lines) {
        String target = address + ":" + port;
        long started = System.nanoTime();
        var probe = new LinkedHashMap<String, Object>();
        probe.put("port", port);
        try (var socket = new Socket()) {
            socket.connect(new InetSocketAddress(address, port), 5_000);
            long elapsed = (System.nanoTime() - started) / 1_000_000;
            probe.put("ok", true);
            probe.put("millis", elapsed);
            lines.add("Connection test to " + target + ": connected in " + elapsed
                    + " ms. This shows the address is reachable, not which path carried it.");
        } catch (Exception error) {
            long elapsed = (System.nanoTime() - started) / 1_000_000;
            probe.put("ok", false);
            probe.put("millis", elapsed);
            probe.put("error", String.valueOf(error.getMessage()));
            lines.add("Connection test to " + target + ": failed (" + error.getMessage() + ")");
        }
        return probe;
    }

    /**
     * What the configuration does with an ADDRESS addressProblem accepted, an IPv4 address or a name.
     * The command and the local page preview through here, so they say the same.
     */
    static LinkedHashMap<String, Object> preview(Path path, ClientStartupConfig config, String address, List<String> lines) {
        return isAddress(address) ? addressPreview(path, config, address, lines) : namePreview(path, config, address, lines);
    }

    /** What the configured rules decide for one IPv4 address, and what takeover being on would change. */
    private static LinkedHashMap<String, Object> addressPreview(Path path, ClientStartupConfig config, String address, List<String> lines) {
        var rules = rules(config);
        var match = PeerEgressRules.match(rules, address, PeerEgressRules.DEFAULT_MESH_CIDR, pool(config));
        int matched = match.matched() ? match.matchedRuleIndex() : -1;
        boolean takeover = config.isPeerEgressEnabled();
        var data = new LinkedHashMap<String, Object>();
        data.put("configPath", path.toString());
        data.put("address", address);
        data.put("kind", "address");
        data.put("takeover", takeover);
        data.put("matchedRuleIndex", matched);
        lines.add("Preview for " + address + " from the configuration (no connection is made; --connect PORT tests one)");
        lines.add(takeover ? "  takeover: on" : "  takeover: off");
        String would = "stays local (direct)";
        String result = "direct";
        if (matched < 0) {
            lines.add("  rule: none");
            would = "not covered by any rule; stays local (direct)";
        } else {
            String action = trim(match.action());
            var line = new StringBuilder("  rule: [").append(matched).append("] ")
                    .append(trim(rules.get(matched).getMatch())).append(' ').append(action);
            if (id(match.egressClientId()) != 0) line.append(' ').append(match.egressClientId());
            lines.add(line.toString());
            data.put("ruleAction", action);
            if (action.equals(PeerEgressRule.ACTION_EGRESS)) {
                would = "through egress " + id(match.egressClientId());
                result = "egress";
                data.put("egressClientId", id(match.egressClientId()));
            } else if (action.equals(PeerEgressRule.ACTION_BLOCK)) {
                would = "blocked";
                result = "block";
            }
        }
        if (takeover || matched < 0) {
            lines.add("  result: " + would);
            data.put("result", result);
        } else {
            lines.add("  result: takeover is off, so it stays local (direct); with takeover on: " + would);
            data.put("result", "direct");
            data.put("resultWithTakeover", result);
        }
        return data;
    }

    /**
     * What the configuration does with one name: the domain rule the responder would select, what it
     * would do with the query, and where the name ends up. Nothing is resolved. Phase two is judged
     * offline, as config validate judges it: peerEgressDnsTakeover on and the pool usable against
     * the default mesh, the master switch taken as on. Whether the egress announced
     * domainTargetCapable is only known once connected, so it is not judged here.
     */
    private static LinkedHashMap<String, Object> namePreview(Path path, ClientStartupConfig config, String address, List<String> lines) {
        String name = PeerEgressNames.normalize(address);
        var rules = rules(config);
        boolean takeover = config.isPeerEgressEnabled();
        boolean dnsTakeover = config.isPeerEgressDnsTakeover();
        String running = pool(config);
        // Selected as though phase two ran, so that what turning it on would do can be said; with it
        // running this is the pool it runs with, and only domain rules take part either way.
        Integer selected = PeerEgressDns.selectDomainRule(rules, name, PeerEgressRules.DEFAULT_MESH_CIDR,
                PeerEgressDns.effectivePool(config.getPeerEgressFakeIpCidr()));
        int matched = selected == null ? -1 : selected;
        var data = new LinkedHashMap<String, Object>();
        data.put("configPath", path.toString());
        data.put("address", name);
        data.put("kind", "domain");
        data.put("takeover", takeover);
        data.put("dnsTakeover", dnsTakeover);
        data.put("matchedRuleIndex", matched);
        lines.add("Preview for " + name + " from the configuration (no connection is made)");
        lines.add("  takeover: " + (takeover ? "on" : "off") + " | dns takeover: " + (dnsTakeover ? "on" : "off"));
        String action = PeerEgressRule.ACTION_DIRECT;
        long egress = 0;
        if (matched < 0) {
            lines.add("  rule: none");
        } else {
            PeerEgressRule rule = rules.get(matched);
            action = trim(rule.getAction());
            var line = new StringBuilder("  rule: [").append(matched).append("] ")
                    .append(trim(rule.getMatch())).append(' ').append(action);
            data.put("ruleAction", action);
            if (action.equals(PeerEgressRule.ACTION_EGRESS)) {
                egress = id(rule.getEgressClientId());
                line.append(' ').append(egress);
                data.put("egressClientId", egress);
            }
            lines.add(line.toString());
        }
        // A name under an egress or block rule gets a fake IP; anything else is handed on untouched.
        boolean claimed = action.equals(PeerEgressRule.ACTION_EGRESS) || action.equals(PeerEgressRule.ACTION_BLOCK);
        if (running == null) {
            lines.add("  dns: not taken over (" + (dnsTakeover ? "peerEgressFakeIpCidr is not usable" : "peerEgressDnsTakeover is off")
                    + "), so the name is resolved by the system's DNS");
            data.put("dns", "local");
        } else if (claimed) {
            lines.add("  dns: answered with a fake IP from " + running
                    + (action.equals(PeerEgressRule.ACTION_EGRESS) ? "; the egress resolves the name" : ""));
            data.put("dns", "fake");
        } else {
            lines.add("  dns: forwarded to the system's DNS; the address it returns is then decided by the IPv4 rules");
            data.put("dns", "forward");
        }
        String result = claimed ? action : PeerEgressRule.ACTION_DIRECT;
        String would = switch (result) {
            case PeerEgressRule.ACTION_EGRESS -> "through egress " + egress + ", which resolves the name itself";
            case PeerEgressRule.ACTION_BLOCK -> "blocked";
            default -> "resolved by the system's DNS; egress test <that address> previews where it goes";
        };
        // Of the reasons that hold, the first in the order the spec gives them.
        String reason = !claimed ? null
                : !takeover ? "takeover is off"
                : !dnsTakeover ? "dns takeover is off"
                : running == null ? "peerEgressFakeIpCidr is not usable"
                : null;
        if (reason == null) {
            lines.add("  result: " + would);
            data.put("result", result);
        } else {
            lines.add("  result: domain rules are not in force (" + reason + "); with them on: " + would);
            data.put("result", PeerEgressRule.ACTION_DIRECT);
            data.put("resultWithTakeover", result);
        }
        return data;
    }

    // The local page's egress editor: the same changes through plan, written the same way, with the
    // revision the page was showing checked first so an edit is never applied to a file that moved.
    // The Go and .NET management pages serve the same routes with the same answers.

    private static Loaded uiLoad(Path path) throws Exception {
        var snapshot = UiConfig.read(path);
        if (snapshot.revision().equals("missing")) throw new LocalUi.Failure(422, "配置文件不存在；请先在「连接设置」保存配置");
        try {
            return new Loaded(snapshot, ClientCli.parse(snapshot.text(), ignored -> { }));
        } catch (Exception error) {
            throw new LocalUi.Failure(422, "配置无法加载（" + error.getMessage() + "）；请先修正后再编辑出口规则");
        }
    }

    static Map<String, Object> uiRules(Path path) throws Exception {
        Loaded loaded = uiLoad(path);
        var data = listing(path, loaded.config(), new ArrayList<>());
        data.put("schemaVersion", 1);
        data.put("revision", loaded.snapshot().revision());
        return data;
    }

    private static int index(com.fasterxml.jackson.databind.JsonNode body, String field) {
        return body.path(field).isIntegralNumber() ? body.path(field).asInt() : -1;
    }

    static Map<String, Object> uiChange(Path path, com.fasterxml.jackson.databind.JsonNode body) throws Exception {
        Loaded loaded = uiLoad(path);
        UiConfig.checkRevision(loaded.snapshot(), body.path("revision").asText());
        Planned planned;
        try {
            planned = plan(loaded.config(), new Change(body.path("op").asText(), body.path("match").asText(""),
                    body.path("action").asText(""), body.path("egressClientId").asLong(0), index(body, "at"),
                    index(body, "index"), index(body, "to"), body.path("disabled").asBoolean(false),
                    body.path("enabled").asBoolean(false), body.path("confirmed").asBoolean(false)));
        } catch (PlanFailure failure) {
            throw new LocalUi.Failure(422, failure.getMessage());
        }
        if (planned.needsConfirmation()) throw new LocalUi.Failure(422, "开启接管前需要确认其影响；未做任何修改");
        if (planned.unchanged()) {
            var data = listing(path, loaded.config(), new ArrayList<>());
            data.put("schemaVersion", 1);
            data.put("revision", loaded.snapshot().revision());
            data.put("saved", false);
            return data;
        }
        String patched = patch(loaded.snapshot().text(), planned.key(), planned.value());
        ClientStartupConfig edited;
        try {
            edited = ClientCli.parse(patched, ignored -> { });
        } catch (Exception error) {
            throw new LocalUi.Failure(422, "修改后的配置无法加载（" + error.getMessage() + "）；未写入");
        }
        UiConfig.save(path, loaded.snapshot().revision(), patched);
        var data = listing(path, edited, new ArrayList<>());
        data.put("schemaVersion", 1);
        data.put("revision", UiConfig.read(path).revision());
        data.put("saved", true);
        // Only what the page does not already say itself: the notice is shown before it asks.
        data.put("warnings", planned.preface().stream().filter(line -> line.startsWith("Warning: ")).toList());
        return data;
    }

    static Map<String, Object> uiTest(Path path, com.fasterxml.jackson.databind.JsonNode body) throws Exception {
        String address = trim(body.path("address").asText(""));
        String problem = addressProblem(address);
        if (problem != null) throw new LocalUi.Failure(422, problem);
        // A port asks for a real connection as well; without one the answer is the preview alone.
        var connect = body.get("connect");
        int port = connect != null && connect.isInt() ? connect.asInt() : -1;
        if (connect != null && (port < 1 || port > 65535)) {
            throw new LocalUi.Failure(422, "connect must be a TCP port between 1 and 65535");
        }
        if (connect != null && !isAddress(address)) throw new LocalUi.Failure(422, CONNECT_NEEDS_ADDRESS);
        Loaded loaded = uiLoad(path);
        var data = preview(path, loaded.config(), address, new ArrayList<>());
        if (connect != null) data.put("connect", connectProbe(address, port, new ArrayList<>()));
        data.put("schemaVersion", 1);
        return data;
    }

    /**
     * The rule list written the same way in every runtime: one rule per line, fields in a fixed
     * order, only what the rule carries. Strings escape only what JSON requires, so a file one
     * runtime wrote reads the same when another rewrites it.
     */
    static String encodeRules(List<PeerEgressRule> rules) {
        if (rules.isEmpty()) return "[]";
        var b = new StringBuilder("[\n");
        for (int index = 0; index < rules.size(); index++) {
            PeerEgressRule rule = rules.get(index);
            b.append("    {\"match\": ").append(jsonString(trim(rule.getMatch())))
                    .append(", \"action\": ").append(jsonString(trim(rule.getAction())));
            if (id(rule.getEgressClientId()) != 0) b.append(", \"egressClientId\": ").append(rule.getEgressClientId());
            if (rule.getPort() != null && rule.getPort() != 0) b.append(", \"port\": ").append(rule.getPort());
            if (rule.switchedOff()) b.append(", \"enabled\": false");
            b.append('}');
            if (index < rules.size() - 1) b.append(',');
            b.append('\n');
        }
        return b.append("  ]").toString();
    }

    static String jsonString(String value) {
        var b = new StringBuilder("\"");
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (c == '"') b.append("\\\"");
            else if (c == '\\') b.append("\\\\");
            else if (c < 0x20) b.append(String.format("\\u%04x", (int) c));
            else b.append(c);
        }
        return b.append('"').toString();
    }

    /**
     * Replaces or adds one top-level value the egress commands own, with the encoded JSON given.
     * Only peerEgressEnabled, peerEgressRules and peerEgressDnsTakeover; everything else goes through
     * the local page's checks.
     */
    static String patch(String text, String key, String value) {
        if (!key.equals("peerEgressRules") && !key.equals("peerEgressEnabled") && !key.equals("peerEgressDnsTakeover"))
            throw UiConfig.invalid();
        UiConfig.Document doc;
        try {
            doc = UiConfig.document(text);
        } catch (LocalUi.Failure failure) {
            throw failure;
        } catch (Exception error) {
            throw UiConfig.invalid();
        }
        // A differently cased duplicate would leave two readings of the same switch.
        for (String existing : doc.spans().keySet()) {
            if (existing.equalsIgnoreCase(key) && !existing.equals(key)) throw UiConfig.invalid();
        }
        // What is written follows the file's line breaks, so a CRLF file stays CRLF. The values carry
        // no raw line break inside a string, since control characters are escaped.
        String newline = text.contains("\r\n") ? "\r\n" : "\n";
        value = value.replace("\n", newline);
        var span = doc.spans().get(key);
        if (span != null) {
            return text.substring(0, span.start()) + value + text.substring(span.end());
        }
        int at = doc.opening() + 1;
        String insert = newline + "  \"" + key + "\": " + value;
        if (!doc.spans().isEmpty()) insert += ",";
        // The brace is usually followed by its own line break already; a second would leave a blank line.
        if (at >= text.length() || (text.charAt(at) != '\n' && text.charAt(at) != '\r')) insert += newline;
        return text.substring(0, at) + insert + text.substring(at);
    }
}
