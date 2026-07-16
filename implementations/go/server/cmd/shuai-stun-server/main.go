package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/devShuai/shuai-tunnel/implementations/go/server/internal/stunserver"
)

func main() {
	checkConfig := flag.Bool("check-config", false, "validate configuration and exit")
	flag.Usage = func() {
		fmt.Fprintln(flag.CommandLine.Output(), "Shuai Tunnel standalone RFC 5780 STUN server")
		fmt.Fprintln(flag.CommandLine.Output(), "Usage: shuai-stun-server [-check-config]")
		fmt.Fprintln(flag.CommandLine.Output(), "Configuration uses the STUN_* environment variables documented in deploy/stun-server.")
		flag.PrintDefaults()
	}
	flag.Parse()

	config, err := stunserver.ConfigFromEnvironment()
	if err != nil {
		fmt.Fprintf(os.Stderr, "STUN configuration is invalid: %v\n", err)
		os.Exit(1)
	}
	if *checkConfig {
		fmt.Printf("STUN configuration is valid: %s\n", config.Describe())
		return
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	server := stunserver.NewServer(config)
	if err := server.Run(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "STUN server failed: %v\n", err)
		os.Exit(1)
	}
}
