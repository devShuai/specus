package client

// Giving the TUN the device's derived IPv6 address (protocol/spec/peer-egress.md, IPv6 数据面, 消费端).
//
// The address is the mesh IPv4 inside fd53:7065:6375:7300::/96, as a /128: no on-link route comes
// with it, so nothing reaches the TUN by IPv6 but what a rule's route sends there, and the system
// picks it as the source for exactly that traffic. Without it an application's packet would leave
// with some other source, which the data plane refuses as ipv6-source-not-mesh.
//
// No build tag: the command builders are the part worth testing everywhere, and only the device
// files that run them are platform-specific.

// peerDeviceAddress6 is the derived IPv6 address the TUN is given, or false when it is given none:
// the consumer is switched off, or this device has no IPv6 data plane (its platform, or a
// peerMeshMtu below 1280). Assigned only for the consumer -- an address on the TUN serves nothing
// else, and a device that never asked for IPv6 should not grow one.
func peerDeviceAddress6(config Config, virtualIPv4 string) (string, bool) {
	if !config.PeerEgressEnabled || !egressConsumerCarriesIPv6(config.PeerMeshMTU) {
		return "", false
	}
	address, ok := egressDeviceAddress6(virtualIPv4)
	if !ok {
		return "", false
	}
	return formatEgressAddress6(address), true
}

// linuxAssignAddress6Args is the spec's `ip -6 address add <address>/128 dev <tun>`. Argv entries,
// never seen by a shell. Add rather than replace: the interface was created a moment ago and dies
// with the descriptor, so an address already on it is not this run's.
func linuxAssignAddress6Args(device string, address string) []string {
	return []string{"ip", "-6", "address", "add", address + "/128", "dev", device}
}

// macosAssignAddress6Args is the spec's `ifconfig <utun> inet6 <address> prefixlen 128`, with the
// same whitelists as the route commands: an interface name that cannot read as an option, and an
// address in the form this feature writes.
func macosAssignAddress6Args(device string, address string) ([]string, error) {
	if _, ok := parseEgressAddress6(address); !ok || !validMacosInterfaceName(device) {
		return nil, errEgressRouteArgument
	}
	return []string{"ifconfig", device, "inet6", address, "prefixlen", "128"}, nil
}
