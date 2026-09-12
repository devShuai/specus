package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

func stateRoot() (string, error) {
	if path := os.Getenv("SPECUS_CLI_STATE_DIR"); path != "" {
		return filepath.Abs(path)
	}
	home, err := os.UserHomeDir()
	return filepath.Join(home, ".specus-cli"), err
}
func statePrefix(config string) string {
	if runtime.GOOS == "windows" {
		config = strings.ToLower(config)
	}
	sum := sha256.Sum256([]byte(config))
	return "go-" + hex.EncodeToString(sum[:]) + "-"
}
func checkedStateRoot(create bool) (string, error) {
	root, err := stateRoot()
	if err != nil {
		return "", err
	}
	created := false
	if create {
		err = os.Mkdir(root, 0700)
		created = err == nil
		if err != nil && !os.IsExist(err) {
			return "", err
		}
	}
	if err = checkPrivate(root, created); err != nil {
		return "", err
	}
	return root, nil
}
func publishState(config string, snapshot func() map[string]any) (func(), error) {
	root, err := checkedStateRoot(true)
	if err != nil {
		return nil, err
	}
	path := filepath.Join(root, fmt.Sprintf("%s%d.json", statePrefix(config), os.Getpid()))
	write := func() error {
		data := snapshot()
		data["pid"] = os.Getpid()
		data["processRunning"] = true
		data["updatedAtUnixMs"] = time.Now().UnixMilli()
		data["schemaVersion"] = 1
		data["configPath"] = config
		bytes, e := json.Marshal(data)
		if e != nil {
			return e
		}
		file, e := os.CreateTemp(root, ".state-*")
		if e != nil {
			return e
		}
		name := file.Name()
		defer os.Remove(name)
		_, e = file.Write(bytes)
		closeErr := file.Close()
		if e != nil {
			return e
		}
		if closeErr != nil {
			return closeErr
		}
		if e = checkPrivate(name, true); e != nil {
			return e
		}
		return os.Rename(name, path)
	}
	if err = write(); err != nil {
		return nil, err
	}
	stop, done := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(done)
		timer := time.NewTicker(time.Second)
		defer timer.Stop()
		for {
			select {
			case <-stop:
				return
			case <-timer.C:
				if e := write(); e != nil {
					fmt.Fprintln(os.Stderr, "State publication failed; status will become stale.")
					return
				}
			}
		}
	}()
	return func() { close(stop); <-done; _ = os.Remove(path) }, nil
}
func queryState(options cliOptions, config string) int {
	root, err := checkedStateRoot(false)
	unavailable := func(message string) int {
		return resultOutput(options.json, options.command, 5, map[string]any{"instances": []any{}}, message)
	}
	if os.IsNotExist(err) {
		return unavailable("No running CLI instance for this config. Start it with run --config PATH.")
	}
	if err != nil {
		return resultOutput(options.json, options.command, 2, nil, "Unsafe or unreadable local state directory. Use an owner-only local directory via SPECUS_CLI_STATE_DIR.")
	}
	paths, err := filepath.Glob(filepath.Join(root, statePrefix(config)+"*.json"))
	if err != nil || len(paths) > 256 {
		return unavailable("Local state unavailable; too many instances or invalid directory.")
	}
	instances := []any{}
	for _, path := range paths {
		if err = checkPrivate(path, false); err != nil {
			return resultOutput(options.json, options.command, 2, nil, "Unsafe local state file; refusing to read it.")
		}
		info, e := os.Stat(path)
		if e != nil || info.Size() > 1024*1024 {
			continue
		}
		bytes, e := os.ReadFile(path)
		if e != nil {
			continue
		}
		var data map[string]any
		if json.Unmarshal(bytes, &data) != nil {
			continue
		}
		at, ok := data["updatedAtUnixMs"].(float64)
		pid, pidOK := data["pid"].(float64)
		age := time.Now().UnixMilli() - int64(at)
		storedConfig, _ := data["configPath"].(string)
		matches := storedConfig == config || runtime.GOOS == "windows" && strings.EqualFold(storedConfig, config)
		_, controlOK := data["controlAuthenticated"].(bool)
		_, readyOK := data["businessReady"].(bool)
		if !ok || !pidOK || !controlOK || !readyOK || age < 0 || age > 5000 || !processAlive(int(pid)) || !matches || data["schemaVersion"] != float64(1) {
			continue
		}
		if options.command != "status" {
			data = map[string]any{"pid": pid, "phase": data["phase"], "catalogAvailable": data["controlAuthenticated"], options.command: data[options.command]}
		}
		instances = append(instances, data)
	}
	if len(instances) == 0 {
		return unavailable("No fresh running CLI state for this config. No login was attempted.")
	}
	data := map[string]any{"instances": instances}
	var lines []string
	for _, instance := range instances {
		row := instance.(map[string]any)
		lines = append(lines, fmt.Sprintf("PID %.0f | %v", row["pid"], row["phase"]))
		if options.command == "status" {
			lines = append(lines, fmt.Sprintf("  control authenticated: %v | forwarding ready: %v (targets not probed)", row["controlAuthenticated"], row["businessReady"]))
		} else if options.command == "egress" {
			// Its own branch because the egress section is an object rather than a list,
			// and because what a person needs from it is the problems rather than an
			// item per entry.
			section, _ := row["egress"].(map[string]any)
			lines = append(lines, egressLines(section)...)
		} else {
			items, _ := row[options.command].([]any)
			if len(items) == 0 {
				lines = append(lines, "  No entries. Check status for channel readiness.")
			}
			for _, item := range items {
				p, valid := item.(map[string]any)
				if !valid {
					continue
				}
				if options.command == "peers" {
					lines = append(lines, fmt.Sprintf("  %q | %q | online=%v", p["clientName"], p["virtualIp"], p["online"]))
				} else {
					lines = append(lines, fmt.Sprintf("  %q | %q | %q | available=%v", p["name"], p["application"], p["accessTarget"], p["available"]))
				}
			}
		}
	}
	return resultOutput(options.json, options.command, 0, data, strings.Join(lines, "\n"))
}

var errUnsafeState = errors.New("state must be owned by the current user, private and not a symbolic link/reparse point")
