package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/devShuai/specus/implementations/go/client/internal/client"
)

// version is injected at package time via -ldflags "-X main.version=...". The release tag is the
// single source of truth, so the checked-in default only ever shows up in local builds.
var version = "dev"

func main() {
	os.Exit(runCLI(os.Args[1:]))
}

func runCLI(args []string) int {
	options, err := parseCLI(args)
	if err != nil {
		return resultOutput(wantsJSON(args), "arguments", 2, nil, printCLIError(err))
	}
	if options.helper {
		if err := client.RunDeferredUpdateHelper(options.parentPID, options.candidateHash, options.helperArgs); err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "apply deferred client update: %v\n", err)
			return 1
		}
		return 0
	}
	if options.help {
		return resultOutput(options.json, "help", 0, map[string]any{"help": cliHelp}, cliHelp)
	}
	if options.version {
		return resultOutput(options.json, "version", 0, map[string]any{"version": version}, version)
	}
	client.SetVersion(version)
	logger := log.New(os.Stderr, "", log.LstdFlags)
	if options.debug {
		logger.SetFlags(log.LstdFlags | log.Lmicroseconds | log.Lshortfile)
	}
	path, err := filepath.Abs(options.configPath)
	if err != nil {
		fmt.Fprint(os.Stderr, printCLIError(err))
		return 2
	}
	if options.command == "status" || options.command == "peers" || options.command == "services" {
		return queryState(options, path)
	}
	if options.command == "ui" {
		return runLocalUI(options, path)
	}
	config, err := client.LoadConfigWithDiagnostics(path, func(warning string) {
		fmt.Fprintln(os.Stderr, "Warning: "+warning)
	})
	if err != nil {
		return resultOutput(options.json, options.command, 2, nil, fmt.Sprintf("invalid config %s: %v; check the file or run --help", path, err))
	}
	if options.command == "validate" {
		return resultOutput(options.json, "config validate", 0, map[string]any{"configPath": path, "offline": true}, fmt.Sprintf("Configuration valid: %s (offline; connectivity not tested)", path))
	}
	if options.autoUpdate {
		config.AutoUpdate = true
		enabled := true
		config.UpdateCheckEnabled = &enabled
	}
	if options.noUpdate {
		config.AutoUpdate = false
		disabled := false
		config.UpdateCheckEnabled = &disabled
	}
	if options.command == "show" {
		config.APIKey = "<redacted>"
		config.Secret = "<redacted>"
		config.ServerBaseURL = safeURL(config.ServerBaseURL)
		encoded, _ := json.MarshalIndent(config, "", "  ")
		return resultOutput(options.json, "config show", 0, map[string]any{"configPath": path, "config": config}, path+"\n"+string(encoded))
	}
	if options.command == "doctor" {
		data := map[string]any{"configPath": path, "scope": "offline", "authenticationTested": false, "businessTested": false}
		if options.probe {
			data["scope"] = "server-tcp"
			u, _ := url.Parse(config.ServerBaseURL)
			port := u.Port()
			if port == "" {
				port = "80"
				if u.Scheme == "https" {
					port = "443"
				}
			}
			connection, probeErr := net.DialTimeout("tcp", net.JoinHostPort(u.Hostname(), port), 5*time.Second)
			if probeErr != nil {
				return resultOutput(options.json, "doctor", 4, data, "Server TCP probe failed or timed out. Check DNS, proxy, firewall and server availability; authentication was not attempted.")
			}
			connection.Close()
		}
		return resultOutput(options.json, "doctor", 0, data, "Doctor passed ("+data["scope"].(string)+"); authentication, TLS and business readiness not tested.")
	}
	logger.Printf("loaded config: %s", path)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if options.noUpdate {
		disabled := false
		config.UpdateCheckEnabled = &disabled
	}
	updater := client.NewUpdater(config, version, config.AutoUpdate || options.autoUpdate, logger)

	runCtx, cancelRun := context.WithCancel(ctx)
	defer cancelRun()
	runErrors := make(chan error, 1)
	appClient := client.New(config, logger)
	appClient.SetInitialLoginTimeout(time.Duration(options.loginTimeout) * time.Second)
	stopState, stateErr := publishState(path, appClient.DiagnosticSnapshot)
	if stateErr != nil {
		logger.Printf("Cannot create private CLI state. Check SPECUS_CLI_STATE_DIR permissions: %v", stateErr)
		return 2
	}
	defer stopState()
	go func() { runErrors <- appClient.Run(runCtx) }()
	type updateOutcome struct {
		result client.UpdateResult
		err    error
	}
	updates := make(chan updateOutcome, 1)
	updaterDone := make(chan struct{})
	defer func() { cancelRun(); <-updaterDone }()
	go func() {
		defer close(updaterDone)
		client.CleanupStaleUpdateHelperContext(runCtx, logger)
		if config.UpdatesEnabled() {
			// Cleanup and the initial check cannot delay starting the tunnel. Never read stdin.
			result, err := updater.CheckAndApply(runCtx)
			if result.Installed {
				updates <- updateOutcome{result: result, err: err}
				return
			}
			if err != nil && runCtx.Err() == nil {
				logger.Printf("startup client update check failed: %v", err)
			}
			result, err = updater.Monitor(runCtx, config.UpdateCheckInterval())
			updates <- updateOutcome{result: result, err: err}
		}
	}()
	select {
	case err := <-runErrors:
		if err != nil && !errors.Is(err, context.Canceled) {
			logger.Printf("client stopped: %v", err)
			return client.ExitCode(err)
		}
	case outcome := <-updates:
		if outcome.err != nil && !errors.Is(outcome.err, context.Canceled) {
			logger.Printf("client update monitor stopped: %v", outcome.err)
		}
		if !outcome.result.Installed && ctx.Err() == nil {
			// An updater failure is not a request to stop an otherwise healthy tunnel.
			err := <-runErrors
			if err != nil && !errors.Is(err, context.Canceled) {
				logger.Printf("client stopped: %v", err)
				return 1
			}
		}
		if outcome.result.Installed {
			cancelRun()
			<-runErrors
			if !outcome.result.RestartScheduled {
				if err := restartSelf(outcome.result.ExecutablePath, false); err != nil {
					logger.Printf("updated client installed, but restart failed: %v", err)
					if rollbackErr := client.RollbackInstalledUpdate(outcome.result.ExecutablePath, outcome.result.BackupPath); rollbackErr != nil {
						logger.Printf("client update rollback failed: %v", rollbackErr)
					} else {
						logger.Printf("client update rolled back to %s", outcome.result.PreviousVersion)
						if recoveryErr := restartSelf(outcome.result.ExecutablePath, true); recoveryErr != nil {
							logger.Printf("restarting the rolled-back client failed: %v", recoveryErr)
						}
					}
					return 1
				}
			}
		}
	case <-ctx.Done():
		cancelRun()
		<-runErrors
	}
	return 0
}

func restartSelf(executable string, disableUpdateCheck bool) error {
	if executable == "" {
		return errors.New("updated executable path is empty")
	}
	arguments := append([]string{executable}, os.Args[1:]...)
	if disableUpdateCheck {
		arguments = client.RestartArgumentsWithUpdateCheckDisabled(arguments)
	}
	process, err := os.StartProcess(executable, arguments, &os.ProcAttr{
		Dir:   "",
		Env:   os.Environ(),
		Files: []*os.File{os.Stdin, os.Stdout, os.Stderr},
	})
	if err != nil {
		return err
	}
	return process.Release()
}
