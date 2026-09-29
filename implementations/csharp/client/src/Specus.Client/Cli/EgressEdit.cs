using System.Diagnostics;
using System.Net.Sockets;
using System.Text;
using System.Text.Json.Nodes;
using Specus.Client.Configuration;
using Specus.Protocol.PeerEgress;

namespace Specus.Client.Cli;

/// <summary>
/// The egress editing commands: list the rules, add, remove, move and switch them, turn takeover on
/// and off, and preview what the rules do for one address.
/// </summary>
/// <remarks>
/// They edit the configuration file the way the local page does: the one top-level value they own is
/// replaced in place and everything else in the file is kept, the write is atomic and refused if the
/// file changed underneath. They never touch a running client, which reads its configuration once at
/// start; every write says so. Comments inside peerEgressRules do not survive an edit, because the
/// list is written back whole.
///
/// The Go and Java clients print the same lines and the same JSON for the same file; the CLI process
/// matrix holds them to it.
/// </remarks>
internal static class EgressEdit
{
    internal const string RestartNote = "A running client applies the change after a restart.";

    /// <summary>What turning takeover on means, printed every time it is turned on.</summary>
    internal static readonly string[] EnableNotice =
    [
        "Turning on egress takeover:",
        "  - needs permission to create a virtual interface and install routes (administrator or root; peerMeshDevice must not be noop)",
        "  - takes over only the destinations a rule covers; everything else stays local",
        "  - blocks a destination covered by an egress rule while its egress is unavailable, instead of sending it locally",
    ];

    private sealed record Loaded(UiConfig.Snapshot Snapshot, SpecusClientConfig Config);

    /// <summary>A command that ended early, carrying the exit code it already reported.</summary>
    private sealed class Done(int code) : Exception
    {
        public int Code { get; } = code;
    }

    internal static int Run(ClientCliOptions options, string path)
    {
        try
        {
            return options.Command switch
            {
                "egress rules" => List(options, path),
                "egress test" => Test(options, path),
                "egress enable" or "egress disable" => Toggle(options, path),
                _ => EditRule(options, path),
            };
        }
        catch (Done done)
        {
            return done.Code;
        }
    }

    private static Done Fail(ClientCliOptions options, string message) =>
        new(CliOutput.Result(options.Json, options.Command, 2, null, message));

    private static Loaded Load(ClientCliOptions options, string path)
    {
        UiConfig.Snapshot snapshot;
        try
        {
            snapshot = UiConfig.Read(path);
        }
        catch (LocalUi.Failure failure)
        {
            throw Fail(options, failure.Message);
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException)
        {
            throw Fail(options, $"Cannot read {path}: {error.Message}");
        }
        if (snapshot.Revision == "missing") throw Fail(options, "Configuration file not found: " + path);
        try
        {
            var text = new UTF8Encoding(false, true).GetString(snapshot.Bytes);
            return new Loaded(snapshot, SpecusClientConfigLoader.Parse(text, path, _ => { }));
        }
        catch (Exception error)
        {
            throw Fail(options, $"invalid config {path}: {error.Message}; fix it first (config validate)");
        }
    }

    private static long Id(long? value) => value ?? 0;

    /// <summary>Why a rule is not in force as configured, or null; the master switch is not part of it.</summary>
    internal static string? RuleCode(PeerEgressRule rule) => PeerEgressRules.Validate(rule, PeerEgressRules.DefaultMeshCidr);

    /// <summary>The code a rule reports in status: the master switch off names itself unless the rule was switched off.</summary>
    internal static string? StatusCode(bool enabled, PeerEgressRule rule) =>
        !enabled && !rule.SwitchedOff ? PeerEgressCodes.ConsumerDisabled : RuleCode(rule);

    /// <summary>One line a person can act on for a rule's code, in the words the Go and Java clients use too.</summary>
    internal static string Explanation(string code) => code switch
    {
        PeerEgressCodes.RuleDomainUnsupported => "domain rules are not supported yet; use an IPv4 address or CIDR range",
        PeerEgressCodes.RuleIpv6Unsupported => "IPv6 rules are not supported; use an IPv4 address or CIDR range",
        PeerEgressCodes.RuleMalformed => "not an IPv4 address or CIDR range with zero host bits, or an unknown action",
        PeerEgressCodes.RuleDefaultRoute => "0.0.0.0/0 would take over the default route, which is not allowed",
        PeerEgressCodes.RuleMeshOverlap => "overlaps the Peer Mesh network",
        PeerEgressCodes.RulePortUnsupported => "a rule cannot be limited to a port; port limits belong on the egress policy",
        PeerEgressCodes.RuleMissingTarget => "an egress rule needs a positive egress device id",
        PeerEgressCodes.RuleDisabled => "switched off",
        PeerEgressCodes.ConsumerDisabled => "takeover is off (peerEgressEnabled is false)",
        _ => "",
    };

    /// <summary>What every egress command that reads or writes the rules reports.</summary>
    private static Dictionary<string, object?> Listing(string path, SpecusClientConfig config, List<string> lines)
    {
        var rules = config.PeerEgressRules;
        var enabled = config.PeerEgressEnabled;
        if (enabled) lines.Add("takeover: on");
        else if (rules.Count > 0) lines.Add("takeover: off (peerEgressEnabled is false); rules are saved, none is in force");
        else lines.Add("takeover: off (peerEgressEnabled is false)");
        if (rules.Count == 0) lines.Add("  No egress rules configured.");
        var views = new List<Dictionary<string, object?>>();
        for (var index = 0; index < rules.Count; index++)
        {
            var rule = rules[index];
            var status = StatusCode(enabled, rule);
            // The rule's own problem, told apart from being off: worth fixing before takeover is on.
            var refusal = RuleCode(rule with { Enabled = null });
            var view = new Dictionary<string, object?>
            {
                ["index"] = index,
                ["match"] = rule.Match.Trim(),
                ["action"] = rule.Action.Trim(),
                ["enabled"] = !rule.SwitchedOff,
                ["inForce"] = status is null,
            };
            if (Id(rule.EgressClientId) != 0) view["egressClientId"] = rule.EgressClientId;
            if (rule.Port is { } port && port != 0) view["port"] = port;
            if (status is not null) view["code"] = status;
            if (refusal is not null) view["refusal"] = refusal;
            views.Add(view);

            var line = $"  [{index}] {(rule.SwitchedOff ? "off" : "on")} {rule.Match.Trim()} {rule.Action.Trim()}";
            if (Id(rule.EgressClientId) != 0) line += " " + rule.EgressClientId;
            if (refusal is not null) line += $" -- not in force: {refusal} ({Explanation(refusal)})";
            lines.Add(line);
        }
        return new Dictionary<string, object?> { ["configPath"] = path, ["enabled"] = enabled, ["rules"] = views };
    }

    private static int List(ClientCliOptions options, string path)
    {
        var loaded = Load(options, path);
        var lines = new List<string>();
        var data = Listing(path, loaded.Config, lines);
        return CliOutput.Result(options.Json, options.Command, 0, data, string.Join("\n", lines));
    }

    /// <summary>One edit to the rules or the switch, as the commands and the local page ask for it.</summary>
    internal sealed record Change(string Op, string Match = "", string Action = "", long EgressClientId = 0,
        int At = -1, int Index = -1, int To = -1, bool Disabled = false, bool Enabled = false, bool Confirmed = false);

    /// <summary>
    /// What a change writes: one top-level value, already encoded, and what to say before the save.
    /// Unchanged means the file already says what was asked; NeedsConfirmation means takeover was asked
    /// for without the notice being accepted.
    /// </summary>
    internal sealed record Planned(string? Key, string? Value, IReadOnlyList<string> Preface, bool Unchanged = false,
        bool NeedsConfirmation = false);

    /// <summary>A change that cannot be made, with a message a person can act on.</summary>
    internal sealed class PlanFailure(string message) : Exception(message);

    /// <summary>Works out a change against the configuration as loaded, the same way in every runtime.</summary>
    internal static Planned Plan(SpecusClientConfig config, Change change)
    {
        var rules = config.PeerEgressRules.ToList();
        var count = rules.Count;
        switch (change.Op)
        {
            case "takeover":
            {
                if (change.Enabled == config.PeerEgressEnabled) return new Planned(null, null, [], Unchanged: true);
                if (!change.Enabled) return new Planned("peerEgressEnabled", "false", []);
                var preface = new List<string>(EnableNotice);
                if (!change.Confirmed) return new Planned(null, null, preface, NeedsConfirmation: true);
                var device = config.PeerMeshDevice.Trim();
                if (device.Length == 0 || device.Equals("noop", StringComparison.OrdinalIgnoreCase))
                    preface.Add("Warning: peerMeshDevice is noop, so there is no interface to route into; set it to auto.");
                return new Planned("peerEgressEnabled", "true", preface);
            }
            case "add":
            {
                var rule = new PeerEgressRule
                {
                    Match = change.Match.Trim(),
                    Action = change.Action.Trim(),
                    EgressClientId = change.EgressClientId != 0 ? change.EgressClientId : null,
                };
                // Refused rules are allowed in the file, where they are warned about, but an edit that
                // adds one on request would only be writing a rule that steers nothing.
                if (RuleCode(rule) is { } code) throw new PlanFailure($"Rule not added: {code} ({Explanation(code)})");
                if (change.Disabled) rule = rule with { Enabled = false };
                var at = count;
                if (change.At >= 0)
                {
                    if (change.At > count) throw new PlanFailure($"--at {change.At} is past the end; there are {count} rule(s).");
                    at = change.At;
                }
                rules.Insert(at, rule);
                break;
            }
            case "remove" or "move" or "enable" or "disable":
                RequireIndex(change.Index, count);
                switch (change.Op)
                {
                    case "remove":
                        rules.RemoveAt(change.Index);
                        break;
                    case "move":
                        RequireIndex(change.To, count);
                        var moved = rules[change.Index];
                        rules.RemoveAt(change.Index);
                        rules.Insert(change.To, moved);
                        break;
                    case "enable":
                        rules[change.Index] = rules[change.Index] with { Enabled = null };
                        break;
                    default:
                        rules[change.Index] = rules[change.Index] with { Enabled = false };
                        break;
                }
                break;
            default:
                throw new PlanFailure("unknown egress change: " + change.Op);
        }
        return new Planned("peerEgressRules", EncodeRules(rules), []);
    }

    private static void RequireIndex(int index, int count)
    {
        if (index < 0 || index >= count)
            throw new PlanFailure($"No rule at index {index}; there are {count} rule(s). List them with egress rules.");
    }

    /// <summary>The change an editing command asks for.</summary>
    private static Change ChangeFrom(ClientCliOptions options)
    {
        var egress = options.Egress;
        var takeover = options.Command is "egress enable" or "egress disable";
        return new Change(takeover ? "takeover" : options.Command["egress rule ".Length..], egress.Match, egress.Action,
            egress.EgressClientId, egress.At, egress.Index, egress.To, egress.Disabled,
            options.Command == "egress enable", egress.Yes);
    }

    private static int EditRule(ClientCliOptions options, string path)
    {
        var loaded = Load(options, path);
        Planned planned;
        try
        {
            planned = Plan(loaded.Config, ChangeFrom(options));
        }
        catch (PlanFailure failure)
        {
            throw Fail(options, failure.Message);
        }
        return Write(options, path, loaded, planned.Key!, planned.Value!, planned.Preface);
    }

    private static int Toggle(ClientCliOptions options, string path)
    {
        var loaded = Load(options, path);
        var config = loaded.Config;
        var planned = Plan(config, ChangeFrom(options));
        if (planned.Unchanged)
        {
            var lines = new List<string>();
            var data = Listing(path, config, lines);
            return CliOutput.Result(options.Json, options.Command, 0, data,
                $"Takeover is already {(config.PeerEgressEnabled ? "on" : "off")}; nothing was changed.\n" + string.Join("\n", lines));
        }
        // Confirmed by a flag rather than a prompt: whether a prompt could be answered depends on a
        // terminal the three runtimes cannot all detect the same way, and a command that waits in one of
        // them and fails in another is not the same command.
        if (planned.NeedsConfirmation)
            throw Fail(options, string.Join("\n", planned.Preface) + "\nNot changed. Re-run with --yes to confirm.");
        return Write(options, path, loaded, planned.Key!, planned.Value!, planned.Preface);
    }

    private static int Write(ClientCliOptions options, string path, Loaded loaded, string key, string value, IReadOnlyList<string> preface)
    {
        byte[] patched;
        try
        {
            patched = Patch(loaded.Snapshot.Bytes, key, value);
        }
        catch (LocalUi.Failure failure)
        {
            throw Fail(options, failure.Message);
        }
        SpecusClientConfig config;
        try
        {
            config = SpecusClientConfigLoader.Parse(new UTF8Encoding(false, true).GetString(patched), path, _ => { });
        }
        catch (Exception error)
        {
            throw Fail(options, $"the edited configuration would not load ({error.Message}); nothing was written");
        }
        try
        {
            UiConfig.Save(path, loaded.Snapshot.Revision, patched);
        }
        catch (LocalUi.Failure failure)
        {
            throw Fail(options, failure.Message);
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException)
        {
            throw Fail(options, $"Cannot write {path}: {error.Message}");
        }
        var lines = new List<string>();
        var data = Listing(path, config, lines);
        data["saved"] = true;
        var message = new List<string>(preface) { $"Saved {path}. {RestartNote}" };
        message.AddRange(lines);
        return CliOutput.Result(options.Json, options.Command, 0, data, string.Join("\n", message));
    }

    /// <summary>Why an address cannot be previewed, or null when it can.</summary>
    internal static string? AddressProblem(string address)
    {
        if (Ipv4Cidr.TryParseAddress(address, out _) && !address.Contains('/')) return null;
        return LooksLikeDomain(address) && !address.Contains(':')
            ? "ADDRESS is a domain name; rules match IPv4 addresses only for now. Give the address it resolves to."
            : "ADDRESS must be an IPv4 address.";
    }

    private static int Test(ClientCliOptions options, string path)
    {
        var address = options.Egress.Address.Trim();
        if (AddressProblem(address) is { } problem) throw Fail(options, problem);
        var loaded = Load(options, path);
        var lines = new List<string>();
        var data = Preview(path, loaded.Config, address, lines);
        var code = 0;
        var port = options.Egress.Connect;
        if (port > 0)
        {
            var target = $"{address}:{port}";
            var watch = Stopwatch.StartNew();
            var probe = new Dictionary<string, object?> { ["port"] = port };
            try
            {
                using var client = new TcpClient();
                if (!client.ConnectAsync(address, port).Wait(TimeSpan.FromSeconds(5)))
                    throw new TimeoutException("timed out after 5 s");
                var elapsed = watch.ElapsedMilliseconds;
                probe["ok"] = true;
                probe["millis"] = elapsed;
                lines.Add($"Connection test to {target}: connected in {elapsed} ms. This shows the address is reachable, not which path carried it.");
            }
            catch (Exception error)
            {
                var reason = error is AggregateException aggregate && aggregate.InnerException is { } inner ? inner.Message : error.Message;
                probe["ok"] = false;
                probe["millis"] = watch.ElapsedMilliseconds;
                probe["error"] = reason;
                lines.Add($"Connection test to {target}: failed ({reason})");
                code = 4;
            }
            data["connect"] = probe;
        }
        var last = lines[^1];
        if (code != 0 && options.Json) return CliOutput.Result(true, options.Command, code, data, last);
        if (code != 0)
        {
            Console.WriteLine(string.Join("\n", lines.Take(lines.Count - 1)));
            return CliOutput.Result(false, options.Command, code, null, last);
        }
        return CliOutput.Result(options.Json, options.Command, 0, data, string.Join("\n", lines));
    }

    /// <summary>What the configured rules decide for one IPv4 address, and what takeover being on would change.</summary>
    private static Dictionary<string, object?> Preview(string path, SpecusClientConfig config, string address, List<string> lines)
    {
        var rules = config.PeerEgressRules;
        var match = PeerEgressRules.Match(rules, address, PeerEgressRules.DefaultMeshCidr);
        var matched = match.Matched ? match.MatchedRuleIndex : -1;
        var takeover = config.PeerEgressEnabled;
        var data = new Dictionary<string, object?>
        {
            ["configPath"] = path, ["address"] = address, ["takeover"] = takeover, ["matchedRuleIndex"] = matched,
        };
        lines.Add($"Preview for {address} from the configuration (no connection is made; --connect PORT tests one)");
        lines.Add(takeover ? "  takeover: on" : "  takeover: off");
        var would = "stays local (direct)";
        var result = "direct";
        if (matched < 0)
        {
            lines.Add("  rule: none");
            would = "not covered by any rule; stays local (direct)";
        }
        else
        {
            var action = match.Action.Trim();
            var line = $"  rule: [{matched}] {rules[matched].Match.Trim()} {action}";
            if (Id(match.EgressClientId) != 0) line += " " + match.EgressClientId;
            lines.Add(line);
            data["ruleAction"] = action;
            if (action == PeerEgressRules.ActionEgress)
            {
                would = "through egress " + Id(match.EgressClientId);
                result = "egress";
                data["egressClientId"] = Id(match.EgressClientId);
            }
            else if (action == PeerEgressRules.ActionBlock)
            {
                would = "blocked";
                result = "block";
            }
        }
        if (takeover || matched < 0)
        {
            lines.Add("  result: " + would);
            data["result"] = result;
        }
        else
        {
            lines.Add("  result: takeover is off, so it stays local (direct); with takeover on: " + would);
            data["result"] = "direct";
            data["resultWithTakeover"] = result;
        }
        return data;
    }

    // The local page's egress editor: the same changes through Plan, written the same way, with the
    // revision the page was showing checked first so an edit is never applied to a file that moved.
    // The Go and Java management pages serve the same routes with the same answers.

    private static Loaded UiLoad(string path)
    {
        var snapshot = UiConfig.Read(path);
        if (snapshot.Revision == "missing") throw new LocalUi.Failure(422, "配置文件不存在；请先在「连接设置」保存配置");
        try
        {
            return new Loaded(snapshot, SpecusClientConfigLoader.Parse(new UTF8Encoding(false, true).GetString(snapshot.Bytes), path, _ => { }));
        }
        catch (Exception error)
        {
            throw new LocalUi.Failure(422, $"配置无法加载（{error.Message}）；请先修正后再编辑出口规则");
        }
    }

    internal static Dictionary<string, object?> UiRules(string path)
    {
        var loaded = UiLoad(path);
        var data = Listing(path, loaded.Config, []);
        data["schemaVersion"] = 1;
        data["revision"] = loaded.Snapshot.Revision;
        return data;
    }

    private static int UiIndex(JsonObject body, string field) =>
        body[field] is JsonValue value && value.TryGetValue<int>(out var index) ? index : -1;

    private static T UiValue<T>(JsonObject body, string field, T fallback) =>
        body[field] is JsonValue value && value.TryGetValue<T>(out var result) ? result : fallback;

    internal static Dictionary<string, object?> UiChange(string path, JsonObject body)
    {
        var loaded = UiLoad(path);
        UiConfig.CheckRevision(loaded.Snapshot, UiValue(body, "revision", ""));
        Planned planned;
        try
        {
            planned = Plan(loaded.Config, new Change(UiValue(body, "op", ""), UiValue(body, "match", ""),
                UiValue(body, "action", ""), UiValue(body, "egressClientId", 0L), UiIndex(body, "at"),
                UiIndex(body, "index"), UiIndex(body, "to"), UiValue(body, "disabled", false),
                UiValue(body, "enabled", false), UiValue(body, "confirmed", false)));
        }
        catch (PlanFailure failure)
        {
            throw new LocalUi.Failure(422, failure.Message);
        }
        if (planned.NeedsConfirmation) throw new LocalUi.Failure(422, "开启接管前需要确认其影响；未做任何修改");
        Dictionary<string, object?> data;
        if (planned.Unchanged)
        {
            data = Listing(path, loaded.Config, []);
            data["schemaVersion"] = 1;
            data["revision"] = loaded.Snapshot.Revision;
            data["saved"] = false;
            return data;
        }
        var patched = Patch(loaded.Snapshot.Bytes, planned.Key!, planned.Value!);
        SpecusClientConfig edited;
        try
        {
            edited = SpecusClientConfigLoader.Parse(new UTF8Encoding(false, true).GetString(patched), path, _ => { });
        }
        catch (Exception error)
        {
            throw new LocalUi.Failure(422, $"修改后的配置无法加载（{error.Message}）；未写入");
        }
        UiConfig.Save(path, loaded.Snapshot.Revision, patched);
        data = Listing(path, edited, []);
        data["schemaVersion"] = 1;
        data["revision"] = UiConfig.Read(path).Revision;
        data["saved"] = true;
        // Only what the page does not already say itself: the notice is shown before it asks.
        data["warnings"] = planned.Preface.Where(line => line.StartsWith("Warning: ", StringComparison.Ordinal)).ToList();
        return data;
    }

    internal static Dictionary<string, object?> UiTest(string path, JsonObject body)
    {
        var address = UiValue(body, "address", "").Trim();
        if (AddressProblem(address) is { } problem) throw new LocalUi.Failure(422, problem);
        var loaded = UiLoad(path);
        var data = Preview(path, loaded.Config, address, []);
        data["schemaVersion"] = 1;
        return data;
    }

    private static bool LooksLikeDomain(string value) =>
        value.StartsWith('*') || value.Any(c => c is >= 'a' and <= 'z' or >= 'A' and <= 'Z');

    /// <summary>
    /// The rule list written the same way in every runtime: one rule per line, fields in a fixed order,
    /// only what the rule carries. Strings escape only what JSON requires, so a file one runtime wrote
    /// reads the same when another rewrites it.
    /// </summary>
    internal static string EncodeRules(IReadOnlyList<PeerEgressRule> rules)
    {
        if (rules.Count == 0) return "[]";
        var builder = new StringBuilder("[\n");
        for (var index = 0; index < rules.Count; index++)
        {
            var rule = rules[index];
            builder.Append("    {\"match\": ").Append(JsonString(rule.Match.Trim()))
                .Append(", \"action\": ").Append(JsonString(rule.Action.Trim()));
            if (Id(rule.EgressClientId) != 0) builder.Append(", \"egressClientId\": ").Append(rule.EgressClientId);
            if (rule.Port is { } port && port != 0) builder.Append(", \"port\": ").Append(port);
            if (rule.SwitchedOff) builder.Append(", \"enabled\": false");
            builder.Append('}');
            if (index < rules.Count - 1) builder.Append(',');
            builder.Append('\n');
        }
        return builder.Append("  ]").ToString();
    }

    internal static string JsonString(string value)
    {
        var builder = new StringBuilder("\"");
        foreach (var c in value)
        {
            if (c == '"') builder.Append("\\\"");
            else if (c == '\\') builder.Append("\\\\");
            else if (c < 0x20) builder.Append("\\u").Append(((int)c).ToString("x4"));
            else builder.Append(c);
        }
        return builder.Append('"').ToString();
    }

    /// <summary>
    /// Replaces or adds one top-level value the egress commands own, with the encoded JSON given. Only
    /// peerEgressEnabled and peerEgressRules; everything else goes through the local page's checks.
    /// </summary>
    internal static byte[] Patch(byte[] bytes, string key, string value)
    {
        if (key is not ("peerEgressRules" or "peerEgressEnabled")) throw UiConfig.Invalid();
        var doc = UiConfig.Parse(bytes);
        // A differently cased duplicate would leave two readings of the same switch.
        if (doc.Spans.Keys.Any(existing => existing.Equals(key, StringComparison.OrdinalIgnoreCase) && existing != key))
            throw UiConfig.Invalid();
        // What is written follows the file's line breaks, so a CRLF file stays CRLF. The values carry no
        // raw line break inside a string, since control characters are escaped.
        var newline = bytes.AsSpan().IndexOf("\r\n"u8) >= 0 ? "\r\n" : "\n";
        value = value.Replace("\n", newline);
        var encoded = Encoding.UTF8.GetBytes(value);
        if (doc.Spans.TryGetValue(key, out var span))
            return [.. bytes.AsSpan(0, span.Start), .. encoded, .. bytes.AsSpan(span.End)];
        var at = doc.Opening + 1;
        var insert = $"{newline}  \"{key}\": {value}";
        if (doc.Spans.Count > 0) insert += ",";
        // The brace is usually followed by its own line break already; a second would leave a blank line.
        if (at >= bytes.Length || bytes[at] is not ((byte)'\n' or (byte)'\r')) insert += newline;
        return [.. bytes.AsSpan(0, at), .. Encoding.UTF8.GetBytes(insert), .. bytes.AsSpan(at)];
    }
}
