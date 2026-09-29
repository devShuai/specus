//go:build windows

package main

import (
	"fmt"
	"os"
	"syscall"
	"unsafe"
)

// checkPrivate holds local state and the configuration to the same rule on Windows as the mode
// bits do elsewhere: owned by the current user, no allow entry for anyone else, not a reparse point.
//
// Only newly created objects may have their owner and ACL established. Existing state remains
// read-only checked; elevated Windows tokens may default new owners to Administrators.
//
// This used to run a PowerShell script per call. The state file is rewritten every second and each
// rewrite checked, so a running client started a PowerShell process every second, and one start
// that took longer than its ten seconds on a busy machine ended status publication for good or
// refused a configuration save. PowerShell restricted by policy refused them outright.
func checkPrivate(path string, created bool) error {
	if _, err := os.Lstat(path); err != nil {
		return err
	}
	if err := checkPrivateACL(path, created); err != nil {
		return fmt.Errorf("%w: %v", errUnsafeState, err)
	}
	return nil
}

var (
	advapi32                 = syscall.NewLazyDLL("advapi32.dll")
	procGetNamedSecurityInfo = advapi32.NewProc("GetNamedSecurityInfoW")
	procSetNamedSecurityInfo = advapi32.NewProc("SetNamedSecurityInfoW")
	procInitializeACL        = advapi32.NewProc("InitializeAcl")
	procAddAccessAllowedAce  = advapi32.NewProc("AddAccessAllowedAceEx")
	procGetAce               = advapi32.NewProc("GetAce")
	procEqualSid             = advapi32.NewProc("EqualSid")
	procGetLengthSid         = advapi32.NewProc("GetLengthSid")
)

const (
	seFileObject              = 1
	ownerSecurityInformation  = 0x00000001
	daclSecurityInformation   = 0x00000004
	protectedDACLInformation  = 0x80000000
	aclRevision               = 2
	objectInheritACE          = 0x1
	containerInheritACE       = 0x2
	fileAllAccess             = 0x001F01FF
	fileAttributeReparsePoint = 0x400

	accessAllowedACEType               = 0
	accessAllowedObjectACEType         = 5
	accessAllowedCallbackACEType       = 9
	accessAllowedCallbackObjectACEType = 11
)

// windowsACL is the ACL header; the entries follow it in the same allocation.
type windowsACL struct {
	revision byte
	sbz1     byte
	size     uint16
	count    uint16
	sbz2     uint16
}

// aceHeader starts every entry. An ACCESS_ALLOWED_ACE continues with a 32-bit mask and the SID.
type aceHeader struct {
	aceType  byte
	aceFlags byte
	size     uint16
}

func checkPrivateACL(path string, created bool) error {
	name, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	attributes, err := syscall.GetFileAttributes(name)
	if err != nil {
		return err
	}
	if attributes&fileAttributeReparsePoint != 0 {
		return fmt.Errorf("a reparse point")
	}
	token, err := syscall.OpenCurrentProcessToken()
	if err != nil {
		return err
	}
	defer token.Close()
	user, err := token.GetTokenUser()
	if err != nil {
		return err
	}
	me := user.User.Sid
	if created {
		if err := makeOwnerOnly(name, me, attributes&syscall.FILE_ATTRIBUTE_DIRECTORY != 0); err != nil {
			return err
		}
	}
	return verifyOwnerOnly(name, me)
}

// makeOwnerOnly sets the owner to the current user and replaces the DACL with one protected entry
// granting that user full control, inherited by what a directory will hold.
func makeOwnerOnly(name *uint16, me *syscall.SID, directory bool) error {
	sidLength, _, _ := procGetLengthSid.Call(uintptr(unsafe.Pointer(me)))
	// ACL header, then an ACCESS_ALLOWED_ACE whose last DWORD is the start of the SID.
	size := (8 + 12 - 4 + uint32(sidLength) + 3) &^ 3
	buffer := make([]byte, size)
	acl := (*windowsACL)(unsafe.Pointer(&buffer[0]))
	if ok, _, err := procInitializeACL.Call(uintptr(unsafe.Pointer(acl)), uintptr(size), aclRevision); ok == 0 {
		return fmt.Errorf("InitializeAcl: %w", err)
	}
	flags := uintptr(0)
	if directory {
		flags = objectInheritACE | containerInheritACE
	}
	if ok, _, err := procAddAccessAllowedAce.Call(uintptr(unsafe.Pointer(acl)), aclRevision, flags,
		fileAllAccess, uintptr(unsafe.Pointer(me))); ok == 0 {
		return fmt.Errorf("AddAccessAllowedAceEx: %w", err)
	}
	status, _, _ := procSetNamedSecurityInfo.Call(uintptr(unsafe.Pointer(name)), seFileObject,
		ownerSecurityInformation|daclSecurityInformation|protectedDACLInformation,
		uintptr(unsafe.Pointer(me)), 0, uintptr(unsafe.Pointer(acl)), 0)
	if status != 0 {
		return fmt.Errorf("SetNamedSecurityInfo: %w", syscall.Errno(status))
	}
	return nil
}

// verifyOwnerOnly requires the current user as owner and as the only principal any allow entry
// names, inherited ones included. A deny entry only takes access away, so any may stay. A null
// DACL grants everyone everything and is refused.
func verifyOwnerOnly(name *uint16, me *syscall.SID) error {
	var owner *syscall.SID
	var dacl *windowsACL
	var descriptor uintptr
	status, _, _ := procGetNamedSecurityInfo.Call(uintptr(unsafe.Pointer(name)), seFileObject,
		ownerSecurityInformation|daclSecurityInformation, uintptr(unsafe.Pointer(&owner)), 0,
		uintptr(unsafe.Pointer(&dacl)), 0, uintptr(unsafe.Pointer(&descriptor)))
	if status != 0 {
		return fmt.Errorf("GetNamedSecurityInfo: %w", syscall.Errno(status))
	}
	defer syscall.LocalFree(syscall.Handle(descriptor))
	if owner == nil || !equalSID(owner, me) {
		return fmt.Errorf("owned by someone else")
	}
	if dacl == nil {
		return fmt.Errorf("no DACL, which grants everyone access")
	}
	for index := uint16(0); index < dacl.count; index++ {
		var ace *aceHeader
		if ok, _, err := procGetAce.Call(uintptr(unsafe.Pointer(dacl)), uintptr(index),
			uintptr(unsafe.Pointer(&ace))); ok == 0 {
			return fmt.Errorf("GetAce: %w", err)
		}
		switch ace.aceType {
		case accessAllowedACEType:
			if !equalSID((*syscall.SID)(unsafe.Add(unsafe.Pointer(ace), 8)), me) {
				return fmt.Errorf("an allow entry for another principal")
			}
		case accessAllowedObjectACEType, accessAllowedCallbackACEType, accessAllowedCallbackObjectACEType:
			// Files do not carry these; one that does is not a shape this check can vouch for.
			return fmt.Errorf("an allow entry of type %d", ace.aceType)
		}
	}
	return nil
}

func equalSID(a, b *syscall.SID) bool {
	equal, _, _ := procEqualSid.Call(uintptr(unsafe.Pointer(a)), uintptr(unsafe.Pointer(b)))
	return equal != 0
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
