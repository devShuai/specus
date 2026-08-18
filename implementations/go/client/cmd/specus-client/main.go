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
	flag.Parse()

	if *showVersion {
		fmt.Println(version)
		return
	}

	client.SetVersion(version)
	logger := log.New(os.Stdout, "", log.LstdFlags|log.Lmicroseconds)
	config, err := client.LoadConfig(*configPath)
	if err != nil {
		logger.Fatalf("load config failed: %v", err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := client.New(config, logger).Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
		logger.Fatalf("client stopped: %v", err)
	}
}
