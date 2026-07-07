package client

import (
	"fmt"
	"log"
	"net"
	"strings"
)

type peerVirtualDevice interface {
	Name() string
	Start(stopCh <-chan struct{}, outbound func([]byte)) error
	SyncPeerRoutes(peerVirtualIPs []string)
	WritePacket(packet []byte) error
	Close() error
	Status() string
	Error() string
}

func normalizePeerRouteIPs(peerVirtualIPs []string, selfVirtualIP string) map[string]struct{} {
	desired := make(map[string]struct{}, len(peerVirtualIPs))
	self := strings.TrimSpace(selfVirtualIP)
	for _, peerVirtualIP := range peerVirtualIPs {
		normalized := strings.TrimSpace(peerVirtualIP)
		if normalized == "" || normalized == self {
			continue
		}
		if ip := net.ParseIP(normalized); ip == nil || ip.To4() == nil || strings.Contains(normalized, ":") {
			continue
		}
		desired[normalized] = struct{}{}
	}
	return desired
}

type noopPeerVirtualDevice struct {
	name   string
	status string
	err    string
}

func newPeerVirtualDevice(config Config, runtime PeerMeshConfig, logger *log.Logger) peerVirtualDevice {
	mode := strings.ToLower(strings.TrimSpace(config.PeerMeshDevice))
	if mode == "" || mode == "noop" {
		return &noopPeerVirtualDevice{name: config.PeerMeshTunName, status: "NOOP"}
	}
	return newPlatformPeerVirtualDevice(config, runtime, logger)
}

func newUnsupportedPeerVirtualDevice(config Config, message string) peerVirtualDevice {
	return &noopPeerVirtualDevice{name: config.PeerMeshTunName, status: "ERROR", err: message}
}

func (device *noopPeerVirtualDevice) Name() string {
	return device.name
}

func (device *noopPeerVirtualDevice) Start(_ <-chan struct{}, _ func([]byte)) error {
	if device.err != "" {
		return fmt.Errorf("%s", device.err)
	}
	return nil
}

func (device *noopPeerVirtualDevice) SyncPeerRoutes(_ []string) {
}

func (device *noopPeerVirtualDevice) WritePacket(_ []byte) error {
	return nil
}

func (device *noopPeerVirtualDevice) Close() error {
	return nil
}

func (device *noopPeerVirtualDevice) Status() string {
	return device.status
}

func (device *noopPeerVirtualDevice) Error() string {
	return device.err
}
