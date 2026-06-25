package client

import (
	"fmt"
	"log"
	"strings"
)

type peerVirtualDevice interface {
	Name() string
	Start(stopCh <-chan struct{}, outbound func([]byte)) error
	WritePacket(packet []byte) error
	Close() error
	Status() string
	Error() string
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
