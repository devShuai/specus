package client

import (
	"bytes"
	"context"
	"errors"
	"net"
	"os"
	"os/exec"
	"strings"
	"time"
)

// The machine the DNS takeover runs on: commands without a shell, one file, and the interfaces.

// egressDNSCommandTimeout bounds one command. PowerShell takes most of a second to start, and a
// takeover step that hangs must fail rather than hold the reconcile that runs it.
const egressDNSCommandTimeout = 15 * time.Second

// egressDNSSystemAllowed says whether a mesh with no host injected touches the real system DNS.
// The package's tests turn it off, so nothing a test runs can change the machine it runs on.
var egressDNSSystemAllowed = true

var errEgressDNSNoSystem = errors.New("the system DNS is not touched here")

// egressDNSSystemHost is the real machine.
type egressDNSSystemHost struct{}

// NewEgressDNSSystemHost is the machine this process runs on, for `egress dns restore`.
func NewEgressDNSSystemHost() EgressDNSHost { return egressDNSSystemHost{} }

// defaultEgressDNSHost is the real machine, or one that refuses everything where that is not
// allowed.
func defaultEgressDNSHost() EgressDNSHost {
	if !egressDNSSystemAllowed {
		return egressDNSRefusingHost{}
	}
	return egressDNSSystemHost{}
}

// Run keeps standard output and error apart, like the route commander on Windows: the readers parse
// standard output, and a warning on standard error must not end up in their JSON. A failure carries
// both, error first, since that is where tools say why.
func (egressDNSSystemHost) Run(argv []string) (string, error) {
	if len(argv) == 0 {
		return "", errors.New("no command")
	}
	ctx, cancel := context.WithTimeout(context.Background(), egressDNSCommandTimeout)
	defer cancel()
	command := exec.CommandContext(ctx, argv[0], argv[1:]...)
	var stdout, stderr bytes.Buffer
	command.Stdout, command.Stderr = &stdout, &stderr
	err := command.Run()
	if ctx.Err() != nil {
		err = errors.New("did not finish in time")
	}
	if err == nil && strings.EqualFold(argv[0], "powershell.exe") && strings.TrimSpace(stderr.String()) != "" {
		// PowerShell's exit status is that of the script's last statement: a cmdlet that failed
		// before a `Clear-DnsClientCache` that did not would pass for success. What it wrote to
		// the error stream is the failure.
		err = errors.New("wrote to its error stream")
	}
	if err != nil {
		return stdout.String(), &egressDNSCommandError{argv: argv, output: stderr.String() + "\n" + stdout.String(), err: err}
	}
	return stdout.String(), nil
}

func (egressDNSSystemHost) ReadFile(path string) (string, error) {
	raw, err := os.ReadFile(path)
	return string(raw), err
}

// WriteFile replaces the file's content in place, which keeps its owner and mode: /etc/resolv.conf
// is read by every process, and a copy renamed over it could come out readable by root alone.
func (egressDNSSystemHost) WriteFile(path, content string) error {
	return os.WriteFile(path, []byte(content), 0o644)
}

func (egressDNSSystemHost) IsSymlink(path string) (bool, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return false, err
	}
	return info.Mode()&os.ModeSymlink != 0, nil
}

func (egressDNSSystemHost) LinkExists(name string) bool {
	_, err := net.InterfaceByName(name)
	return err == nil
}

// egressDNSRefusingHost refuses every command and every file.
type egressDNSRefusingHost struct{}

func (egressDNSRefusingHost) Run(argv []string) (string, error) {
	return "", &egressDNSCommandError{argv: argv, err: errEgressDNSNoSystem}
}
func (egressDNSRefusingHost) ReadFile(string) (string, error) { return "", errEgressDNSNoSystem }
func (egressDNSRefusingHost) WriteFile(string, string) error  { return errEgressDNSNoSystem }
func (egressDNSRefusingHost) IsSymlink(string) (bool, error)  { return false, errEgressDNSNoSystem }
func (egressDNSRefusingHost) LinkExists(string) bool          { return false }

// egressTunnelTypeName reports whether an interface name is a tunnel's on macOS.
func egressTunnelTypeName(name string) bool {
	for _, prefix := range []string{"utun", "ipsec", "ppp"} {
		if strings.HasPrefix(name, prefix) {
			return true
		}
	}
	return false
}

// interfaceIPv4Addresses lists an interface's IPv4 addresses.
func interfaceIPv4Addresses(iface net.Interface) []string {
	addresses, err := iface.Addrs()
	if err != nil {
		return nil
	}
	var out []string
	for _, address := range addresses {
		if network, ok := address.(*net.IPNet); ok {
			if v4 := network.IP.To4(); v4 != nil {
				out = append(out, v4.String())
			}
		}
	}
	return out
}
