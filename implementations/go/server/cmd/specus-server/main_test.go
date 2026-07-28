package main

import (
	"log"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNewLoggerWritesConfiguredFile(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "specus-server.log")
	t.Setenv("SPECUS_LOG_FILE", logPath)

	logger, closeLog, err := newLogger()
	if err != nil {
		t.Fatal(err)
	}
	logger.Info("file logging test", "component", "server")
	slog.Info("default slog test")
	log.Print("standard log test")
	closeLog()

	contents, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	text := string(contents)
	if !strings.Contains(text, "file logging test") || !strings.Contains(text, "component=server") ||
		!strings.Contains(text, "default slog test") || !strings.Contains(text, "standard log test") {
		t.Fatalf("unexpected log contents: %q", text)
	}
}

func TestNewLoggerRejectsRelativeFile(t *testing.T) {
	t.Setenv("SPECUS_LOG_FILE", "relative.log")
	if _, _, err := newLogger(); err == nil {
		t.Fatal("relative SPECUS_LOG_FILE was accepted")
	}
}
