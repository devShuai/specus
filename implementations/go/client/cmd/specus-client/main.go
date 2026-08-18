package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/devShuai/specus/implementations/go/client/internal/client"
)

// version is injected at package time via -ldflags "-X main.version=...". The release tag is the
// single source of truth, so the checked-in default only ever shows up in local builds.
var version = "dev"

func main() {
	configPath := flag.String("config", client.DefaultConfigFileName, "path to the specus client JSONC config")
	showVersion := flag.Bool("version", false, "print the client version and exit")
	autoUpdate := flag.Bool("auto-update", false, "automatically install updates published by the connected server")
	disableUpdateCheck := flag.Bool(client.DisableUpdateCheckFlagName, false, "disable startup and 24-hour client update checks")
	applyUpdateHelper := flag.Bool(client.UpdateHelperFlagName, false, "internal: apply a verified Windows update after the parent exits")
	updateParentPID := flag.Int(client.UpdateParentPIDFlagName, 0, "internal: parent process id for deferred update")
	updateCandidateHash := flag.String(client.UpdateCandidateHashFlagName, "", "internal: verified candidate executable SHA-256")
	flag.Parse()
	if *applyUpdateHelper {
		if err := client.RunDeferredUpdateHelper(*updateParentPID, *updateCandidateHash, flag.Args()); err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "apply deferred client update: %v\n", err)
			os.Exit(1)
		}
		return
	}

	if *showVersion {
		fmt.Println(version)
		return
	}

	client.SetVersion(version)
	logger := log.New(os.Stdout, "", log.LstdFlags|log.Lmicroseconds)
	// Finish stale-helper cleanup before the startup update check so the cleanup retry loop cannot
	// race with creation of a fresh helper for this process.
	client.CleanupStaleUpdateHelper(logger)
	config, err := client.LoadConfig(*configPath)
	if err != nil {
		logger.Fatalf("load config failed: %v", err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if *disableUpdateCheck {
		disabled := false
		config.UpdateCheckEnabled = &disabled
	}
	updater := client.NewUpdater(config, version, config.AutoUpdate || *autoUpdate, logger)
	if config.UpdatesEnabled() {
		result, updateErr := updater.CheckAndApply(ctx)
		if updateErr != nil {
			logger.Printf("startup client update check failed: %v", updateErr)
		} else if result.Installed {
			if !result.RestartScheduled {
				if err := restartSelf(result.ExecutablePath, false); err != nil {
					logger.Printf("updated client installed, but restart failed: %v", err)
					if rollbackErr := client.RollbackInstalledUpdate(result.ExecutablePath, result.BackupPath); rollbackErr != nil {
						logger.Printf("client update rollback failed: %v", rollbackErr)
					} else {
						logger.Printf("client update rolled back to %s", result.PreviousVersion)
						if recoveryErr := restartSelf(result.ExecutablePath, true); recoveryErr != nil {
							logger.Printf("restarting the rolled-back client failed: %v", recoveryErr)
						}
					}
				}
			}
			return
		}
	}

	runCtx, cancelRun := context.WithCancel(ctx)
	defer cancelRun()
	runErrors := make(chan error, 1)
	appClient := client.New(config, logger)
	go func() { runErrors <- appClient.Run(runCtx) }()
	type updateOutcome struct {
		result client.UpdateResult
		err    error
	}
	updates := make(chan updateOutcome, 1)
	if config.UpdatesEnabled() {
		go func() {
			result, err := updater.Monitor(runCtx, config.UpdateCheckInterval())
			updates <- updateOutcome{result: result, err: err}
		}()
	}
	select {
	case err := <-runErrors:
		if err != nil && !errors.Is(err, context.Canceled) {
			logger.Fatalf("client stopped: %v", err)
		}
	case outcome := <-updates:
		if outcome.err != nil && !errors.Is(outcome.err, context.Canceled) {
			logger.Printf("client update monitor stopped: %v", outcome.err)
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
				}
			}
		}
	case <-ctx.Done():
		cancelRun()
		<-runErrors
	}
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
