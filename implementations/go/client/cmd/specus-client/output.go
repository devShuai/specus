package main

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"strings"
)

func resultOutput(machine bool, command string, code int, data any, message string) int {
	if command == "show" || command == "validate" {
		command = "config " + command
	}
	if machine {
		var problem any
		if code != 0 {
			problem = message
		}
		_ = json.NewEncoder(os.Stdout).Encode(map[string]any{"schemaVersion": 1, "command": command, "ok": code == 0, "exitCode": code, "data": data, "error": problem})
	} else if code != 0 {
		fmt.Fprintln(os.Stderr, message)
	} else {
		fmt.Println(message)
	}
	return code
}
func wantsJSON(args []string) bool {
	for _, arg := range args {
		if arg == "--json" || arg == "--json=true" {
			return true
		}
	}
	return false
}
func safeURL(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "<invalid>"
	}
	u.User = nil
	u.RawQuery = ""
	u.Fragment = ""
	return u.String()
}
