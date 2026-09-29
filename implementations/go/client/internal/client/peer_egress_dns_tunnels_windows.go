//go:build windows

package client

import (
	"strings"
	"syscall"
	"unsafe"
)

// Interface types, as IANA numbers them, that Windows gives virtual and tunnel adapters.
const (
	windowsIfTypePropVirtual = 53
	windowsIfTypeTunnel      = 131
)

// egressTunnelInterfaceAddresses lists the IPv4 addresses of this device's virtual and tunnel
// adapters (interface types 53 and 131). A system DNS server on one of them is another VPN's
// resolver, and taking the system over from it is the rollback trap.
//
// own is not matched here: the adapter list names adapters by GUID, not by the alias the TUN was
// created with. It makes no difference to the answer. This client's TUN carries its mesh address,
// and a DNS server in the mesh is refused as virtual by the mesh check whether or not it is listed.
func egressTunnelInterfaceAddresses(_ string) []string {
	size := uint32(unsafe.Sizeof(syscall.IpAdapterInfo{})) * 16
	var adapters []syscall.IpAdapterInfo
	for attempt := 0; attempt < 3; attempt++ {
		adapters = make([]syscall.IpAdapterInfo, int(size)/int(unsafe.Sizeof(syscall.IpAdapterInfo{}))+1)
		err := syscall.GetAdaptersInfo(&adapters[0], &size)
		if err == nil {
			break
		}
		if err != syscall.ERROR_BUFFER_OVERFLOW {
			return nil
		}
		adapters = nil
	}
	if adapters == nil {
		return nil
	}
	var out []string
	for adapter := &adapters[0]; adapter != nil; adapter = adapter.Next {
		if adapter.Type != windowsIfTypePropVirtual && adapter.Type != windowsIfTypeTunnel {
			continue
		}
		for address := &adapter.IpAddressList; address != nil; address = address.Next {
			text := strings.TrimRight(string(address.IpAddress.String[:]), "\x00")
			if text != "" && text != "0.0.0.0" {
				out = append(out, text)
			}
		}
	}
	return out
}
