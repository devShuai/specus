// Command shuai-tunnel-server is the Go implementation of the shuai-tunnel control/NAT server.
package main

import (
	"context"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/devShuai/shuai-tunnel/tunnel-server-go/internal/config"
	"github.com/devShuai/shuai-tunnel/tunnel-server-go/internal/server"
)

func main() {
	configPath := flag.String("config", "", "optional path to a JSON config file")
	flag.Parse()

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))

	cfg, err := config.Load(*configPath)
	if err != nil {
		logger.Error("load config", "err", err)
		os.Exit(1)
	}

	app, err := server.New(cfg, logger)
	if err != nil {
		logger.Error("init server", "err", err)
		os.Exit(1)
	}
	defer app.Close()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if err := app.Run(ctx); err != nil {
		logger.Error("server stopped", "err", err)
		os.Exit(1)
	}
}
