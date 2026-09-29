namespace Specus.Client.Cli;

/// <summary>The egress editing commands' flags; -1 marks an index that was not given.</summary>
internal sealed record EgressCliOptions(string Address = "", string Match = "", string Action = "",
    long EgressClientId = 0, int At = -1, int Index = -1, int To = -1, bool Disabled = false, bool Yes = false,
    int Connect = 0, bool Force = false);

internal sealed record ClientCliOptions(string? ConfigPath, string Command,
    bool Help, bool Version, bool AutoUpdate, bool NoUpdate, bool Debug, bool Json, bool Probe, int LoginTimeout,
    bool NoOpen = false, int UiPort = 0, EgressCliOptions? EgressFlags = null)
{
    internal EgressCliOptions Egress => EgressFlags ?? new EgressCliOptions();

    /// <summary>Each editing flag belongs to the commands it means something to.</summary>
    private static readonly Dictionary<string, string[]> EgressFlagOwners = new()
    {
        ["egress rule add"] = ["match", "action", "egress-client-id", "at", "disabled"],
        ["egress rule remove"] = ["index"],
        ["egress rule enable"] = ["index"],
        ["egress rule disable"] = ["index"],
        ["egress rule move"] = ["index", "to"],
        ["egress enable"] = ["yes"],
        ["egress test"] = ["connect"],
        ["egress dns restore"] = ["force"],
        ["egress dns enable"] = ["yes"],
    };
    private static readonly string[] EgressFlagOrder =
        ["match", "action", "egress-client-id", "at", "disabled", "index", "to", "yes", "connect", "force"];

    internal const string HelpText = """
        Usage: specus-client [run] [options]
               specus-client config validate|show --config PATH [--json]
               specus-client status|peers|services|egress --config PATH [--json]
               specus-client doctor --config PATH [--probe] [--json]
               specus-client ui --config PATH [--no-open] [--port PORT]
               specus-client egress rules --config PATH [--json]
               specus-client egress rule add --config PATH --match CIDR --action egress|direct|block
                             [--egress-client-id ID] [--at INDEX] [--disabled] [--json]
               specus-client egress rule remove|enable|disable --config PATH --index INDEX [--json]
               specus-client egress rule move --config PATH --index INDEX --to INDEX [--json]
               specus-client egress enable --config PATH [--yes] [--json]
               specus-client egress disable --config PATH [--json]
               specus-client egress test ADDRESS --config PATH [--connect PORT] [--json]
               specus-client egress dns enable --config PATH [--yes] [--json]
               specus-client egress dns disable --config PATH [--json]
               specus-client egress dns status --config PATH [--json]
               specus-client egress dns restore [--force] [--json]

        Options:
          -h, --help            Show help without loading configuration or connecting
          --version             Print version and exit
          -c, --config PATH     JSONC configuration (default: ./client.jsonc)
          --auto-update         Authorize automatic installation and restart
          --no-update-check     Disable update checks (--no-update is an alias)
          --debug               Include diagnostic details
          --login-timeout SEC   Initial HTTP login budget, 1..3600 seconds (default: 60)
          --json               Versioned JSON for one-shot commands; logs stay on stderr
          --probe              doctor only: 5-second server TCP probe; never authenticates
          --no-open            ui only: print local address without opening a browser
          --port PORT          ui only: loopback port, 0..65535 (default: random)

        The egress rules/rule/enable/disable commands edit the configuration file and never a running
        client, which applies the change after a restart. Saving rules and taking over traffic are
        separate: rules take nothing over until egress enable. egress test previews what the rules
        decide for an IPv4 address; only --connect PORT makes a connection, and that shows
        reachability, not the path taken.

        egress dns enable|disable sets peerEgressDnsTakeover, which lets domain rules take effect by
        pointing the system DNS at this client while it runs. egress dns status reports whether it is
        taken over; egress dns restore gives back a takeover a stopped or killed client left behind,
        and refuses while that client still runs unless --force is given. Domain rules do not match applications that bring their own DoH/DoT, use the system cache, or connect to hard-coded IP addresses; that traffic is covered only by IP/CIDR rules.

        Examples:
          specus-client --config "/path with spaces/client.jsonc"
          specus-client config validate --config ./client.jsonc

        Normal startup never prompts for updates. Press Ctrl+C to disconnect and exit.
        Exit codes: 0 success/user stop, 1 runtime failure, 2 arguments/configuration,
                    3 authentication/policy rejection, 4 timeout/probe failure, 5 no live state.
        """;

    internal static ClientCliOptions Parse(string[] args)
    {
        string? path = null;
        var command = "run";
        bool help = false, version = false, autoUpdate = false, noUpdate = false, debug = false;
        bool json = false, probe = false;
        bool noOpen = false, portSet = false;
        int uiPort = 0;
        int loginTimeout = 60;
        var egress = new EgressCliOptions();
        var given = new HashSet<string>();
        var i = 0;
        if (args.FirstOrDefault() == "run") i++;
        else if (args.Length > 1 && args[0] == "egress" && !args[1].StartsWith('-'))
        {
            // The words after "egress" that name an editing command. The plain egress command, which
            // reports a running client's state, is what is left when none of them follows.
            switch (args[1])
            {
                case "rules" or "enable" or "disable":
                    command = "egress " + args[1]; i = 2; break;
                case "test":
                    if (args.Length < 3 || args[2].StartsWith('-'))
                        throw new ArgumentException("expected: egress test ADDRESS --config PATH");
                    command = "egress test"; egress = egress with { Address = args[2] }; i = 3; break;
                case "rule":
                    if (args.Length < 3 || args[2] is not ("add" or "remove" or "move" or "enable" or "disable"))
                        throw new ArgumentException("expected: egress rule add|remove|move|enable|disable --config PATH");
                    command = "egress rule " + args[2]; i = 3; break;
                case "dns":
                    if (args.Length < 3 || args[2] is not ("status" or "restore" or "enable" or "disable"))
                        throw new ArgumentException("expected: egress dns status|restore|enable|disable");
                    command = "egress dns " + args[2]; i = 3; break;
                default:
                    throw new ArgumentException("unknown egress command; see --help");
            }
        }
        else if (args.FirstOrDefault() == "config")
        {
            if (args.Length < 2 || args[1] is not ("validate" or "show"))
                throw new ArgumentException("Expected: config validate|show --config PATH");
            command = args[1];
            i = 2;
        }
        else if (args.FirstOrDefault() is "ui" or "status" or "peers" or "services" or "egress" or "doctor") { command = args[0]; i = 1; }
        for (; i < args.Length; i++)
        {
            var arg = args[i];
            switch (arg)
            {
                case "-h": case "--help": help = true; break;
                case "--version": version = true; break;
                case "--auto-update": autoUpdate = true; break;
                case "--no-update": case "--no-update-check": noUpdate = true; break;
                case "--debug": debug = true; break;
                case "--json": json = true; break;
                case "--probe": probe = true; break;
                case "--no-open": noOpen = true; break;
                case "--disabled": egress = egress with { Disabled = true }; given.Add("disabled"); break;
                case "--yes": egress = egress with { Yes = true }; given.Add("yes"); break;
                case "--force": egress = egress with { Force = true }; given.Add("force"); break;
                case "--match" or "--action" or "--egress-client-id" or "--at" or "--index" or "--to" or "--connect":
                    var name = arg[2..];
                    if (++i >= args.Length) throw new ArgumentException(arg + " requires a value");
                    given.Add(name);
                    egress = name switch
                    {
                        "match" => egress with { Match = args[i] },
                        "action" => egress with { Action = args[i] },
                        "egress-client-id" => egress with { EgressClientId = ParseInteger(arg, args[i]) },
                        "at" => egress with { At = (int)ParseInteger(arg, args[i]) },
                        "index" => egress with { Index = (int)ParseInteger(arg, args[i]) },
                        "to" => egress with { To = (int)ParseInteger(arg, args[i]) },
                        _ => egress with { Connect = (int)ParseInteger(arg, args[i]) },
                    };
                    break;
                case "--port":
                    if (++i >= args.Length) throw new ArgumentException("--port requires 0..65535");
                    uiPort = ParsePort(args[i]); portSet = true; break;
                case "--login-timeout":
                    if (++i >= args.Length) throw new ArgumentException("--login-timeout requires seconds (1..3600)");
                    loginTimeout = ParseTimeout(args[i]); break;
                case "-c": case "--config":
                    if (++i >= args.Length || string.IsNullOrWhiteSpace(args[i]) || args[i].StartsWith('-'))
                        throw new ArgumentException("--config requires a path; use ./ for a filename starting with '-'");
                    path = args[i];
                    break;
                default:
                    if (arg.StartsWith("--config=", StringComparison.Ordinal))
                    {
                        path = arg["--config=".Length..];
                        if (string.IsNullOrWhiteSpace(path) || path.StartsWith('-'))
                            throw new ArgumentException("--config requires a path");
                    }
                    else if (arg.StartsWith("--login-timeout=")) loginTimeout = ParseTimeout(arg[16..]);
                    else if (arg.StartsWith("--port=")) { uiPort = ParsePort(arg[7..]); portSet = true; }
                    else throw new ArgumentException("Unknown command or option; run --help for usage");
                    break;
            }
        }
        if (probe && command != "doctor") throw new ArgumentException("--probe is only valid for doctor");
        if ((noOpen || portSet) && command != "ui") throw new ArgumentException("--no-open/--port are only valid for ui");
        if (command == "ui" && (json || debug || autoUpdate || noUpdate) && !help && !version) throw new ArgumentException("ui does not accept --json/--debug/update options");
        _ = Path.GetFullPath(path ?? "client.jsonc");
        if (json && command == "run" && !help && !version) throw new ArgumentException("--json is for help/version/config/status/doctor/peers/services/egress; use status --json to observe a running client");
        CheckEgressFlags(command, egress, given);
        return new(path, command, help, version, autoUpdate, noUpdate, debug, json, probe, loginTimeout, noOpen, uiPort, egress);
    }

    /// <summary>
    /// Keeps each editing flag to the command it means something to, and each command to the flags it
    /// needs, before anything reads the configuration.
    /// </summary>
    private static void CheckEgressFlags(string command, EgressCliOptions egress, HashSet<string> given)
    {
        var owned = EgressFlagOwners.GetValueOrDefault(command) ?? [];
        foreach (var name in EgressFlagOrder)
        {
            if (given.Contains(name) && !owned.Contains(name))
                throw new ArgumentException($"--{name} is not valid for {command}; see --help");
        }
        switch (command)
        {
            case "egress rule add":
                if (string.IsNullOrWhiteSpace(egress.Match) || string.IsNullOrWhiteSpace(egress.Action))
                    throw new ArgumentException("egress rule add requires --match and --action");
                break;
            case "egress rule remove" or "egress rule enable" or "egress rule disable":
                if (!given.Contains("index") || egress.Index < 0)
                    throw new ArgumentException($"{command} requires --index INDEX (0 or more)");
                break;
            case "egress rule move":
                if (!given.Contains("index") || !given.Contains("to") || egress.Index < 0 || egress.To < 0)
                    throw new ArgumentException("egress rule move requires --index INDEX and --to INDEX (0 or more)");
                break;
            case "egress test":
                if (given.Contains("connect") && egress.Connect is < 1 or > 65535)
                    throw new ArgumentException("--connect requires a port (1..65535)");
                break;
        }
        if (given.Contains("at") && egress.At < 0) throw new ArgumentException("--at requires an index (0 or more)");
    }

    private static long ParseInteger(string flag, string value) => long.TryParse(value.Trim(), out var parsed)
        ? parsed : throw new ArgumentException(flag + " requires an integer");

    private static int ParseTimeout(string value) => int.TryParse(value, out int seconds) && seconds is >= 1 and <= 3600
        ? seconds : throw new ArgumentException("--login-timeout requires seconds (1..3600)");
    private static int ParsePort(string value) => int.TryParse(value, out int port) && port is >= 0 and <= 65535
        ? port : throw new ArgumentException("--port requires 0..65535");
}
