package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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
		publisher := statePublisher{write: write, report: os.Stderr}
		for {
			select {
			case <-stop:
				return
			case <-timer.C:
				publisher.tick()
			}
		}
	}()
	return func() { close(stop); <-done; _ = os.Remove(path) }, nil
}

// statePublisher writes the state file once a second and keeps doing so after a failure.
//
// One failed write is no reason to stop: on Windows a reader holding the file open, or a virus
// scanner, makes the replace fail now and then, and giving up would leave every status query
// refused for the rest of the run. The failure is said once, with its reason, and so is the
// recovery, rather than once a second.
type statePublisher struct {
	write   func() error
	report  io.Writer
	failing bool
}

func (p *statePublisher) tick() {
	if err := p.write(); err != nil {
		if !p.failing {
			p.failing = true
			fmt.Fprintf(p.report, "State publication failed (%v); retrying every second, so status may be stale meanwhile.\n", err)
		}
		return
	}
	if p.failing {
		p.failing = false
		fmt.Fprintln(p.report, "State publication recovered.")
	}
}

// freshStates reads the state every running instance for a config published: owner-only files,
// written in the last five seconds by a process still alive. code is non-zero with a message when
// the state could not be read at all: 5 when there is none, 2 when it is not safe to read.
func freshStates(config string) ([]map[string]any, int, string) {
	root, err := checkedStateRoot(false)
	if os.IsNotExist(err) {
		return nil, 5, "No running CLI instance for this config. Start it with run --config PATH."
	}
	if err != nil {
		return nil, 2, "Unsafe or unreadable local state directory. Use an owner-only local directory via SPECUS_CLI_STATE_DIR."
	}
	paths, err := filepath.Glob(filepath.Join(root, statePrefix(config)+"*.json"))
	if err != nil || len(paths) > 256 {
		return nil, 5, "Local state unavailable; too many instances or invalid directory."
	}
	var states []map[string]any
	for _, path := range paths {
		if err = checkPrivate(path, false); err != nil {
			return nil, 2, "Unsafe local state file; refusing to read it."
		}
		data, ok := readStateFile(path)
		if !ok {
			continue
		}
		storedConfig, _ := data["configPath"].(string)
		matches := storedConfig == config || runtime.GOOS == "windows" && strings.EqualFold(storedConfig, config)
		_, controlOK := data["controlAuthenticated"].(bool)
		_, readyOK := data["businessReady"].(bool)
		if _, fresh := freshStatePID(data); !fresh || !controlOK || !readyOK || !matches {
			continue
		}
		states = append(states, data)
	}
	return states, 0, ""
}

// readStateFile reads one state file: false for one that is gone, over 1 MiB or not JSON.
func readStateFile(path string) (map[string]any, bool) {
	info, err := os.Stat(path)
	if err != nil || info.Size() > 1024*1024 {
		return nil, false
	}
	bytes, err := os.ReadFile(path)
	if err != nil {
		return nil, false
	}
	var data map[string]any
	if json.Unmarshal(bytes, &data) != nil {
		return nil, false
	}
	return data, true
}

// freshStatePID is the process that published a state, when the state is fresh: format version 1,
// written in the last five seconds, by a process that is still alive.
func freshStatePID(data map[string]any) (int, bool) {
	at, atOK := data["updatedAtUnixMs"].(float64)
	pid, pidOK := data["pid"].(float64)
	age := time.Now().UnixMilli() - int64(at)
	if !atOK || !pidOK || age < 0 || age > 5000 || data["schemaVersion"] != float64(1) || !processAlive(int(pid)) {
		return 0, false
	}
	return int(pid), true
}

// stateClientRunning reports whether a client runs as pid: whether the state directory holds fresh
// state that process published, for any configuration and from any of the three runtimes, which
// share the directory. It is what "the client that took over the system DNS still runs" means
// (protocol/spec/peer-egress-dns.md, 六, 事务日志): after a crash and a reboot a journal's process id
// most likely belongs to another program, and that program publishes no state here. A file that is
// not private is no evidence and is passed over; so is a directory that is missing or not safe.
func stateClientRunning(pid int) bool {
	root, err := checkedStateRoot(false)
	if err != nil || pid <= 0 {
		return false
	}
	paths, err := filepath.Glob(filepath.Join(root, "*.json"))
	if err != nil {
		return false
	}
	for _, path := range paths {
		if checkPrivate(path, false) != nil {
			continue
		}
		if data, ok := readStateFile(path); ok {
			if published, fresh := freshStatePID(data); fresh && published == pid {
				return true
			}
		}
	}
	return false
}

func queryState(options cliOptions, config string) int {
	unavailable := func(message string) int {
		return resultOutput(options.json, options.command, 5, map[string]any{"instances": []any{}}, message)
	}
	states, code, problem := freshStates(config)
	if code == 5 {
		return unavailable(problem)
	}
	if code != 0 {
		return resultOutput(options.json, options.command, code, nil, problem)
	}
	instances := []any{}
	for _, data := range states {
		pid := data["pid"]
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
