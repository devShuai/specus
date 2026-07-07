//go:build linux

package client

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"unsafe"
)

const (
	linuxTunSetIFF = 0x400454ca
	linuxIFFTUN    = 0x0001
	linuxIFFNOPI   = 0x1000
	linuxIFNAMSIZ  = 16
)

type linuxTunDevice struct {
	name    string
	virtual string
	cidr    string
	mtu     int
	logger  *log.Logger

	mu     sync.Mutex
	file   *os.File
	status string
	err    string

	routesMu         sync.Mutex
	syncedPeerRoutes map[string]struct{}
}

func newPlatformPeerVirtualDevice(config Config, runtime PeerMeshConfig, logger *log.Logger) peerVirtualDevice {
	return &linuxTunDevice{
		name:             firstNonEmpty(config.PeerMeshTunName, DefaultPeerMeshTunName),
		virtual:          runtime.VirtualIP,
		cidr:             runtime.CIDR,
		mtu:              config.PeerMeshMTU,
		logger:           logger,
		status:           "INIT",
		syncedPeerRoutes: make(map[string]struct{}),
	}
}

func (device *linuxTunDevice) Name() string {
	return device.name
}

func (device *linuxTunDevice) Start(stopCh <-chan struct{}, outbound func([]byte)) error {
	if strings.TrimSpace(device.virtual) == "" || strings.TrimSpace(device.cidr) == "" {
		device.setStatus("ERROR", "missing peer mesh virtual IP or CIDR")
		return errors.New(device.err)
	}
	file, err := os.OpenFile("/dev/net/tun", os.O_RDWR, 0)
	if err != nil {
		device.setStatus("ERROR", fmt.Sprintf("open /dev/net/tun failed: %v", err))
		return err
	}
	var ifr [linuxIFNAMSIZ + 64]byte
	copy(ifr[:linuxIFNAMSIZ], []byte(device.name))
	binary.LittleEndian.PutUint16(ifr[linuxIFNAMSIZ:], linuxIFFTUN|linuxIFFNOPI)
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, file.Fd(), uintptr(linuxTunSetIFF), uintptr(unsafe.Pointer(&ifr[0])))
	if errno != 0 {
		_ = file.Close()
		err := errno
		device.setStatus("ERROR", fmt.Sprintf("create TUN device failed: %v", err))
		return err
	}
	actualName := strings.TrimRight(string(ifr[:linuxIFNAMSIZ]), "\x00")
	if actualName != "" {
		device.name = actualName
	}
	if err := device.configure(); err != nil {
		_ = file.Close()
		device.setStatus("ERROR", err.Error())
		return err
	}
	device.mu.Lock()
	device.file = file
	device.status = "UP"
	device.err = ""
	device.mu.Unlock()
	go device.readLoop(stopCh, outbound)
	return nil
}

func (device *linuxTunDevice) SyncPeerRoutes(peerVirtualIPs []string) {
	device.routesMu.Lock()
	defer device.routesMu.Unlock()
	desired := normalizePeerRouteIPs(peerVirtualIPs, device.virtual)
	for routeIP := range device.syncedPeerRoutes {
		if _, ok := desired[routeIP]; !ok {
			device.deletePeerRouteLocked(routeIP)
		}
	}
	for routeIP := range desired {
		if _, ok := device.syncedPeerRoutes[routeIP]; !ok {
			device.addPeerRouteLocked(routeIP)
		}
	}
}

func (device *linuxTunDevice) addPeerRouteLocked(peerVirtualIP string) {
	route := peerVirtualIP + "/32"
	if err := runCommand("ip", "route", "replace", route, "dev", device.name); err != nil {
		if device.logger != nil {
			device.logger.Printf("Peer Mesh Linux TUN add peer route failed: route=%s err=%v", route, err)
		}
		return
	}
	device.syncedPeerRoutes[peerVirtualIP] = struct{}{}
}

func (device *linuxTunDevice) deletePeerRouteLocked(peerVirtualIP string) {
	device.runCommandQuiet("ip", "route", "del", peerVirtualIP+"/32", "dev", device.name)
	delete(device.syncedPeerRoutes, peerVirtualIP)
}

func (device *linuxTunDevice) runCommandQuiet(args ...string) {
	if err := runCommand(args...); err != nil && device.logger != nil {
		device.logger.Printf("Peer Mesh Linux TUN ignored command failure: %v", err)
	}
}

func (device *linuxTunDevice) WritePacket(packet []byte) error {
	device.mu.Lock()
	file := device.file
	device.mu.Unlock()
	if file == nil {
		return io.ErrClosedPipe
	}
	for len(packet) > 0 {
		written, err := file.Write(packet)
		if err != nil {
			return err
		}
		if written == 0 {
			return io.ErrShortWrite
		}
		packet = packet[written:]
	}
	return nil
}

func (device *linuxTunDevice) Close() error {
	device.SyncPeerRoutes(nil)
	device.mu.Lock()
	file := device.file
	device.file = nil
	device.mu.Unlock()
	if file != nil {
		return file.Close()
	}
	return nil
}

func (device *linuxTunDevice) Status() string {
	device.mu.Lock()
	defer device.mu.Unlock()
	return device.status
}

func (device *linuxTunDevice) Error() string {
	device.mu.Lock()
	defer device.mu.Unlock()
	return device.err
}

func (device *linuxTunDevice) readLoop(stopCh <-chan struct{}, outbound func([]byte)) {
	buffer := make([]byte, 65535)
	for {
		device.mu.Lock()
		file := device.file
		device.mu.Unlock()
		if file == nil {
			return
		}
		n, err := file.Read(buffer)
		if n > 0 {
			outbound(append([]byte(nil), buffer[:n]...))
		}
		if err != nil {
			select {
			case <-stopCh:
				return
			default:
			}
			device.setStatus("ERROR", fmt.Sprintf("read TUN packet failed: %v", err))
			if device.logger != nil {
				device.logger.Printf("Peer Mesh TUN read failed: %v", err)
			}
			return
		}
	}
}

func (device *linuxTunDevice) configure() error {
	if device.mtu <= 0 {
		device.mtu = DefaultPeerMeshMTU
	}
	commands := [][]string{
		{"ip", "addr", "replace", device.virtual + "/32", "dev", device.name},
		{"ip", "link", "set", "dev", device.name, "mtu", fmt.Sprintf("%d", device.mtu), "up"},
	}
	for _, args := range commands {
		if err := runCommand(args...); err != nil {
			return err
		}
	}
	if strings.TrimSpace(device.cidr) != "" {
		device.runCommandQuiet("ip", "route", "del", device.cidr, "dev", device.name)
	}
	return nil
}

func (device *linuxTunDevice) setStatus(status, errText string) {
	device.mu.Lock()
	device.status = status
	device.err = errText
	device.mu.Unlock()
}

func runCommand(args ...string) error {
	if len(args) == 0 {
		return nil
	}
	cmd := exec.Command(args[0], args[1:]...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s failed: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(string(output)))
	}
	return nil
}
