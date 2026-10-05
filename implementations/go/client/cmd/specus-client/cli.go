package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"

	"github.com/devShuai/specus/implementations/go/client/internal/client"
)

const cliHelp = `Usage: specus-client [run] [options]
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
  --login-timeout SEC   Initial HTTP login budget, 1..3600 seconds (default: 60)
  --json               Versioned JSON for one-shot commands; logs stay on stderr
  --probe              doctor only: 5-second server TCP probe; never authenticates
  --debug              Include diagnostic source locations and timestamps
  --no-open            ui only: print the local address without opening a browser
  --port PORT          ui only: loopback port, 0..65535 (default: automatic)

The egress command reports which of this node's egress rules are actually in force, which
routes were installed, and which were refused because something already owned the prefix.

The egress rules/rule/enable/disable commands edit the configuration file and never a running
client, which applies the change after a restart. Saving rules and taking over traffic are separate:
rules take nothing over until egress enable. egress test previews what the rules decide for an IPv4
address or a domain name; only --connect PORT makes a connection, to an address and never a name,
and that shows reachability, not the path taken.

With peerEgressDnsTakeover on (egress dns enable), domain rules take effect by pointing the system
DNS at the client while it runs; that is the one change this feature makes to the system's own
settings, and it is given back when the client stops. egress dns status shows whether the takeover
holds and what it forwards to; egress dns restore gives the system DNS back from the journal when
the client cannot (it was killed), and refuses while that client still runs unless --force.
Domain rules do not match applications that bring their own DoH/DoT, use the system cache, or connect to hard-coded IP addresses; that traffic is covered only by IP/CIDR rules.

Examples:
  specus-client --config "/path with spaces/client.jsonc"
  specus-client config validate --config ./client.jsonc

Normal startup never prompts for updates. Press Ctrl+C to disconnect and exit.
Exit codes: 0 success/user stop, 1 runtime failure, 2 arguments/configuration,
            3 authentication/policy rejection, 4 timeout/probe failure, 5 no live state.
`

type cliOptions struct {
	configPath, command                 string
	help, version, autoUpdate, noUpdate bool
	helper                              bool
	parentPID                           int
	candidateHash                       string
	helperArgs                          []string
	json, probe, debug                  bool
	loginTimeout                        int
	noOpen                              bool
	uiPort                              int
	// The egress editing commands.
	egressMatch, egressAction, egressAddress string
	egressClientID                           int64
	egressAt, egressIndex, egressTo          int
	egressDisabled, egressYes                bool
	egressConnect                            int
	// egress dns restore: give back even though the journal's process looks alive.
	egressForce bool
}

// egressCommand reads the words after "egress" that name an editing command. The plain egress
// command, which reports a running client's state, is what is left when none of them follows.
func egressCommand(args []string) (string, []string, string, error) {
	if len(args) < 2 || strings.HasPrefix(args[1], "-") {
		return "egress", args[1:], "", nil
	}
	switch args[1] {
	case "rules", "enable", "disable":
		return "egress " + args[1], args[2:], "", nil
	case "test":
		if len(args) < 3 || strings.HasPrefix(args[2], "-") {
			return "", nil, "", errors.New("expected: egress test ADDRESS --config PATH")
		}
		return "egress test", args[3:], args[2], nil
	case "dns":
		if len(args) < 3 {
			return "", nil, "", errors.New("expected: egress dns enable|disable|status|restore")
		}
		switch args[2] {
		case "enable", "disable", "status", "restore":
		default:
			return "", nil, "", errors.New("expected: egress dns enable|disable|status|restore")
		}
		return "egress dns " + args[2], args[3:], "", nil
	case "rule":
		if len(args) < 3 {
			return "", nil, "", errors.New("expected: egress rule add|remove|move|enable|disable --config PATH")
		}
		switch args[2] {
		case "add", "remove", "move", "enable", "disable":
			return "egress rule " + args[2], args[3:], "", nil
		}
		return "", nil, "", errors.New("expected: egress rule add|remove|move|enable|disable --config PATH")
	}
	return "", nil, "", errors.New("unknown egress command; see --help")
}

// Parse everything before any config read, update cleanup or network operation.
func parseCLI(args []string) (cliOptions, error) {
	o := cliOptions{command: "run"}
	if len(args) > 0 && args[0] == "run" {
		args = args[1:]
	} else if len(args) > 0 && args[0] == "config" {
		if len(args) < 2 || (args[1] != "validate" && args[1] != "show") {
			return o, errors.New("expected: config validate|show --config PATH")
		}
		o.command = args[1]
		args = args[2:]
	} else if len(args) > 0 && args[0] == "egress" {
		command, rest, address, err := egressCommand(args)
		if err != nil {
			return o, err
		}
		o.command, o.egressAddress, args = command, address, rest
	} else if len(args) > 0 && (args[0] == "status" || args[0] == "peers" || args[0] == "services" || args[0] == "doctor" || args[0] == "ui") {
		o.command = args[0]
		args = args[1:]
	}
	fs := flag.NewFlagSet("specus-client", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.StringVar(&o.configPath, "config", client.DefaultConfigFileName, "")
	fs.StringVar(&o.configPath, "c", client.DefaultConfigFileName, "")
	fs.BoolVar(&o.help, "help", false, "")
	fs.BoolVar(&o.help, "h", false, "")
	fs.BoolVar(&o.version, "version", false, "")
	fs.BoolVar(&o.autoUpdate, "auto-update", false, "")
	fs.BoolVar(&o.noUpdate, "no-update-check", false, "")
	fs.BoolVar(&o.noUpdate, "no-update", false, "")
	fs.BoolVar(&o.json, "json", false, "")
	fs.BoolVar(&o.probe, "probe", false, "")
	fs.BoolVar(&o.debug, "debug", false, "")
	fs.BoolVar(&o.noOpen, "no-open", false, "")
	fs.IntVar(&o.uiPort, "port", 0, "")
	fs.IntVar(&o.loginTimeout, "login-timeout", 60, "")
	fs.StringVar(&o.egressMatch, "match", "", "")
	fs.StringVar(&o.egressAction, "action", "", "")
	fs.Int64Var(&o.egressClientID, "egress-client-id", 0, "")
	fs.IntVar(&o.egressAt, "at", -1, "")
	fs.IntVar(&o.egressIndex, "index", -1, "")
	fs.IntVar(&o.egressTo, "to", -1, "")
	fs.BoolVar(&o.egressDisabled, "disabled", false, "")
	fs.BoolVar(&o.egressYes, "yes", false, "")
	fs.IntVar(&o.egressConnect, "connect", 0, "")
	fs.BoolVar(&o.egressForce, "force", false, "")
	// Keep the existing verified Windows updater protocol, but hide it in public help.
	fs.BoolVar(&o.helper, client.UpdateHelperFlagName, false, "")
	fs.IntVar(&o.parentPID, client.UpdateParentPIDFlagName, 0, "")
	fs.StringVar(&o.candidateHash, client.UpdateCandidateHashFlagName, "", "")
	if err := fs.Parse(args); err != nil {
		return o, err
	}
	if o.helper {
		if o.command != "run" || o.help || o.version || o.parentPID <= 0 || o.candidateHash == "" {
			return o, errors.New("invalid internal update helper arguments")
		}
		o.helperArgs = fs.Args()
		return o, nil
	}
	if fs.NArg() != 0 {
		return o, errors.New("unexpected command or argument; see --help")
	}
	uiFlag := false
	given := map[string]bool{}
	fs.Visit(func(f *flag.Flag) {
		given[f.Name] = true
		if f.Name == "port" || f.Name == "no-open" {
			uiFlag = true
		}
	})
	if err := checkEgressFlags(o, given); err != nil {
		return o, err
	}
	if (uiFlag && o.command != "ui") || o.uiPort < 0 || o.uiPort > 65535 {
		return o, errors.New("--no-open and --port (0..65535) are only valid for ui")
	}
	if o.command == "ui" && (o.json || o.autoUpdate || o.noUpdate || o.debug) && !o.help && !o.version {
		return o, errors.New("ui does not accept --json, --debug or update overrides; ui never starts an updater")
	}
	if o.parentPID != 0 || o.candidateHash != "" {
		return o, errors.New("internal update options require the update helper")
	}
	if strings.TrimSpace(o.configPath) == "" || strings.HasPrefix(o.configPath, "-") {
		return o, errors.New("--config requires a path (use ./ for a filename starting with '-')")
	}
	// Disabling checks wins, including the rollback helper's injected flag.
	if o.loginTimeout < 1 || o.loginTimeout > 3600 {
		return o, errors.New("--login-timeout requires seconds (1..3600)")
	}
	if o.probe && o.command != "doctor" {
		return o, errors.New("--probe is only valid for doctor")
	}
	if o.json && o.command == "run" && !o.help && !o.version {
		return o, errors.New("--json is for help/version/config/status/doctor/peers/services; use status --json to observe a running client")
	}
	return o, nil
}

func printCLIError(err error) string {
	return fmt.Sprintf("specus-client: %v\nRun specus-client --help for usage.\n", err)
}

// checkEgressFlags keeps each editing flag to the command it means something to, and each command to
// the flags it needs, before anything reads the configuration.
func checkEgressFlags(o cliOptions, given map[string]bool) error {
	allowed := map[string][]string{
		"egress rule add":     {"match", "action", "egress-client-id", "at", "disabled"},
		"egress rule remove":  {"index"},
		"egress rule enable":  {"index"},
		"egress rule disable": {"index"},
		"egress rule move":    {"index", "to"},
		"egress enable":       {"yes"},
		"egress test":         {"connect"},
		"egress dns restore":  {"force"},
		"egress dns enable":   {"yes"},
	}
	for _, name := range []string{"match", "action", "egress-client-id", "at", "disabled", "index", "to", "yes", "connect", "force"} {
		if !given[name] {
			continue
		}
		permitted := false
		for _, candidate := range allowed[o.command] {
			permitted = permitted || candidate == name
		}
		if !permitted {
			return fmt.Errorf("--%s is not valid for %s; see --help", name, commandOrRun(o.command))
		}
	}
	switch o.command {
	case "egress rule add":
		if strings.TrimSpace(o.egressMatch) == "" || strings.TrimSpace(o.egressAction) == "" {
			return errors.New("egress rule add requires --match and --action")
		}
	case "egress rule remove", "egress rule enable", "egress rule disable":
		if !given["index"] || o.egressIndex < 0 {
			return fmt.Errorf("%s requires --index INDEX (0 or more)", o.command)
		}
	case "egress rule move":
		if !given["index"] || !given["to"] || o.egressIndex < 0 || o.egressTo < 0 {
			return errors.New("egress rule move requires --index INDEX and --to INDEX (0 or more)")
		}
	case "egress test":
		if given["connect"] && (o.egressConnect < 1 || o.egressConnect > 65535) {
			return errors.New("--connect requires a port (1..65535)")
		}
	}
	if given["at"] && o.egressAt < 0 {
		return errors.New("--at requires an index (0 or more)")
	}
	return nil
}

func commandOrRun(command string) string {
	if command == "" {
		return "run"
	}
	return command
}
