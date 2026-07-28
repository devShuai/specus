// Command specus-server is the Go implementation of the specus control/NAT server.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/devShuai/specus/implementations/go/server/internal/config"
	"github.com/devShuai/specus/implementations/go/server/internal/server"
)

func main() {
	os.Exit(run())
}

func run() int {
	configPath := flag.String("config", "", "optional path to a JSON config file")
	flag.Parse()

	logger, closeLog, err := newLogger()
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "initialize logger: %v\n", err)
		return 1
	}
	defer closeLog()

	cfg, err := config.Load(*configPath)
	if err != nil {
		logger.Error("load config", "err", err)
		return 1
	}

	app, err := server.New(cfg, logger)
	if err != nil {
		logger.Error("init server", "err", err)
		return 1
	}
	defer app.Close()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if err := app.Run(ctx); err != nil {
		logger.Error("server stopped", "err", err)
		return 1
	}
	return 0
}

func newLogger() (*slog.Logger, func(), error) {
	writer := io.Writer(os.Stdout)
	var logFile *os.File
	logPath := strings.TrimSpace(os.Getenv("SPECUS_LOG_FILE"))
	if logPath != "" {
		if !filepath.IsAbs(logPath) {
			return nil, func() {}, fmt.Errorf("SPECUS_LOG_FILE must be an absolute path")
		}
		file, err := os.OpenFile(filepath.Clean(logPath), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o640)
		if err != nil {
			return nil, func() {}, fmt.Errorf("open %s: %w", logPath, err)
		}
		logFile = file
		writer = io.MultiWriter(os.Stdout, file)
	}
	logger := slog.New(slog.NewTextHandler(writer, &slog.HandlerOptions{Level: slog.LevelInfo}))
	previousSlog := slog.Default()
	previousStandardLogWriter := log.Writer()
	slog.SetDefault(logger)
	log.SetOutput(writer)
	closeLog := func() {
		slog.SetDefault(previousSlog)
		log.SetOutput(previousStandardLogWriter)
		if logFile != nil {
			_ = logFile.Close()
		}
	}
	return logger, closeLog, nil
}
