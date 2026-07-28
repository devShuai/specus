package main

import (
	"context"
	"errors"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/devShuai/specus/implementations/go/client/internal/client"
)

func main() {
	configPath := flag.String("config", client.DefaultConfigFileName, "path to the specus client JSONC config")
	flag.Parse()

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
