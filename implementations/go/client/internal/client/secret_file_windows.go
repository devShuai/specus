//go:build windows

package client

import (
	"os/exec"
	"os/user"
	"strings"
	"syscall"
)

// restrictSecretFile replaces the inherited ACL with one that grants the current user alone.
//
// Unix mode bits are ignored on Windows, so a key file otherwise inherits whatever the profile
// directory grants — which on a shared or domain-joined machine can include other principals.
// icacls is used rather than a Win32 ACL API because it ships with every supported release and
// keeps this to one well-understood call.
//
// Failure is deliberately not fatal. The file already lives under the user profile, which is
// user-scoped by default, and refusing to create a peer key at all would be a worse outcome than
// relying on that default. The caller keeps a usable client either way.
func restrictSecretFile(path string) error {
	account := currentAccountName()
	if account == "" {
		return nil
	}
	command := exec.Command("icacls", path, "/inheritance:r", "/grant:r", account+":F")
	command.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	_ = command.Run()
	return nil
}

// currentAccountName returns the DOMAIN\user form icacls expects. exec does not go through a
// shell, so environment placeholders such as %USERNAME% would be passed through literally.
func currentAccountName() string {
	current, err := user.Current()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(current.Username)
}
