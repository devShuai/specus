//go:build !linux && !windows && !darwin

package client

import "log"

func newPlatformPeerVirtualDevice(config Config, _ PeerMeshConfig, _ *log.Logger) peerVirtualDevice {
	return newUnsupportedPeerVirtualDevice(config, "Go client Peer Mesh TUN data plane is not implemented on this platform; use peerMeshDevice=noop")
}
