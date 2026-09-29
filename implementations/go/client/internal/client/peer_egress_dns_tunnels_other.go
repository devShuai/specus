//go:build !windows

package client

import (
	"net"
	"runtime"
)

// egressTunnelInterfaceAddresses lists the IPv4 addresses of this device's tunnel-type interfaces,
// leaving out own, this client's TUN. A system DNS server on one of them is another VPN's resolver,
// and taking the system over from it is the rollback trap: point-to-point interfaces on Linux, and
// on macOS the ones named utun, ipsec or ppp.
func egressTunnelInterfaceAddresses(own string) []string {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	var out []string
	for _, iface := range interfaces {
		if iface.Name == own {
			continue
		}
		tunnel := false
		switch runtime.GOOS {
		case "linux":
			tunnel = iface.Flags&net.FlagPointToPoint != 0
		case "darwin":
			tunnel = egressTunnelTypeName(iface.Name)
		}
		if tunnel {
			out = append(out, interfaceIPv4Addresses(iface)...)
		}
	}
	return out
}
