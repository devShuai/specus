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
       specus-client status|peers|services --config PATH [--json]
       specus-client doctor --config PATH [--probe] [--json]

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
	} else if len(args) > 0 && (args[0] == "status" || args[0] == "peers" || args[0] == "services" || args[0] == "doctor") {
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
	fs.IntVar(&o.loginTimeout, "login-timeout", 60, "")
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
