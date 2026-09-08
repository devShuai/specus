namespace Specus.Client.Cli;

internal sealed record ClientCliOptions(string? ConfigPath, string Command,
    bool Help, bool Version, bool AutoUpdate, bool NoUpdate, bool Debug, bool Json, bool Probe, int LoginTimeout,
    bool NoOpen = false, int UiPort = 0)
{
    internal const string HelpText = """
        Usage: specus-client [run] [options]
               specus-client config validate|show --config PATH [--json]
               specus-client status|peers|services --config PATH [--json]
               specus-client doctor --config PATH [--probe] [--json]
               specus-client ui --config PATH [--no-open] [--port PORT]

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
        var i = 0;
        if (args.FirstOrDefault() == "run") i++;
        else if (args.FirstOrDefault() == "config")
        {
            if (args.Length < 2 || args[1] is not ("validate" or "show"))
                throw new ArgumentException("Expected: config validate|show --config PATH");
            command = args[1];
            i = 2;
        }
        else if (args.FirstOrDefault() is "ui" or "status" or "peers" or "services" or "doctor") { command = args[0]; i = 1; }
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
        if (json && command == "run" && !help && !version) throw new ArgumentException("--json is for help/version/config/status/doctor/peers/services; use status --json to observe a running client");
        return new(path, command, help, version, autoUpdate, noUpdate, debug, json, probe, loginTimeout, noOpen, uiPort);
    }

    private static int ParseTimeout(string value) => int.TryParse(value, out int seconds) && seconds is >= 1 and <= 3600
        ? seconds : throw new ArgumentException("--login-timeout requires seconds (1..3600)");
    private static int ParsePort(string value) => int.TryParse(value, out int port) && port is >= 0 and <= 65535
        ? port : throw new ArgumentException("--port requires 0..65535");
}
