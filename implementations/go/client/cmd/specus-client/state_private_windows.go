//go:build windows

package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"syscall"
	"time"
)

const stateAclScript = `$ErrorActionPreference='Stop'; $p=$env:SPECUS_STATE_PATH; $attributes=[IO.File]::GetAttributes($p); if($attributes -band [IO.FileAttributes]::ReparsePoint){exit 2}; $directory=($attributes -band [IO.FileAttributes]::Directory) -ne 0; $me=[Security.Principal.WindowsIdentity]::GetCurrent().User; $acl=if($directory){[IO.Directory]::GetAccessControl($p)}else{[IO.File]::GetAccessControl($p)}; if($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -ne $me.Value){exit 2}; if($env:SPECUS_STATE_CREATE -eq '1'){$acl.SetAccessRuleProtection($true,$false); foreach($r in @($acl.Access)){$acl.RemoveAccessRuleSpecific($r)}; $rule=[Security.AccessControl.FileSystemAccessRule]::new($me,'FullControl','ContainerInherit,ObjectInherit','None','Allow'); $acl.AddAccessRule($rule); [IO.Directory]::SetAccessControl($p,$acl)}; foreach($r in $acl.Access){if($r.AccessControlType -eq 'Allow' -and $r.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value -ne $me.Value){exit 2}}; exit 0`

func checkPrivate(path string, created bool) error {
	if _, err := os.Lstat(path); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-Command", stateAclScript)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	create := "0"
	if created {
		create = "1"
	}
	cmd.Env = append(os.Environ(), "SPECUS_STATE_PATH="+path, "SPECUS_STATE_CREATE="+create)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("%w: %v (%s)", errUnsafeState, err, string(output))
	}
	return nil
}
func processAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	handle, err := syscall.OpenProcess(0x1000, false, uint32(pid))
	if err != nil {
		return false
	}
	defer syscall.CloseHandle(handle)
	var code uint32
	return syscall.GetExitCodeProcess(handle, &code) == nil && code == 259
}
