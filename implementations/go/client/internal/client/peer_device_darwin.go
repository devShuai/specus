//go:build darwin

package client

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"unsafe"
)

const (
	darwinAFSystem          = 32
	darwinAFSysControl      = 2
	darwinSysprotoControl   = 2
	darwinCtlIOCGInfo       = 0xc0644e03
	darwinUtunOptIfname     = 2
	darwinCtlNameSize       = 96
	darwinSockaddrCtlSize   = 32
	darwinPacketInfoBytes   = 4
	darwinUtunControlName   = "com.apple.net.utun_control"
	darwinUtunDefaultPrefix = "utun"
)

type darwinUtunDevice struct {
	name    string
	virtual string
	cidr    string
	mtu     int
	logger  *log.Logger

	mu     sync.Mutex
	fd     int
	status string
	err    string

	routesMu         sync.Mutex
	syncedPeerRoutes map[string]struct{}
}

type darwinCtlInfo struct {
	ID   uint32
	Name [darwinCtlNameSize]byte
}

type darwinSockaddrCtl struct {
	Len      uint8
	Family   uint8
	Sysaddr  uint16
	ID       uint32
	Unit     uint32
	Reserved [5]uint32
}

func newPlatformPeerVirtualDevice(config Config, runtime PeerMeshConfig, logger *log.Logger) peerVirtualDevice {
	mode := strings.ToLower(strings.TrimSpace(config.PeerMeshDevice))
	if mode != "auto" && mode != "utun" && mode != "mac-utun" && mode != "macos-utun" && mode != "darwin-utun" {
		return newUnsupportedPeerVirtualDevice(config, fmt.Sprintf("unsupported peerMeshDevice on macOS: %s", config.PeerMeshDevice))
	}
	return &darwinUtunDevice{
		name:             firstNonEmpty(config.PeerMeshTunName, darwinUtunDefaultPrefix),
		virtual:          runtime.VirtualIP,
		cidr:             runtime.CIDR,
		mtu:              config.PeerMeshMTU,
		logger:           logger,
		fd:               -1,
		status:           "INIT",
		syncedPeerRoutes: make(map[string]struct{}),
	}
}

func (device *darwinUtunDevice) Name() string {
	device.mu.Lock()
	defer device.mu.Unlock()
	return device.name
}

func (device *darwinUtunDevice) Start(stopCh <-chan struct{}, outbound func([]byte)) error {
	if strings.TrimSpace(device.virtual) == "" || strings.TrimSpace(device.cidr) == "" {
		device.setStatus("ERROR", "missing peer mesh virtual IP or CIDR")
		return errors.New(device.err)
	}
	fd, err := syscall.Socket(darwinAFSystem, syscall.SOCK_DGRAM, darwinSysprotoControl)
	if err != nil {
		device.setStatus("ERROR", fmt.Sprintf("open utun socket failed: %v", err))
		return err
	}
	if err := connectDarwinUtun(fd, device.requestedUnit()); err != nil {
		_ = syscall.Close(fd)
		device.setStatus("ERROR", err.Error())
		return err
	}
	if actualName, err := darwinUtunName(fd); err == nil && actualName != "" {
		device.name = actualName
	}
	if err := device.configure(); err != nil {
		_ = syscall.Close(fd)
		device.setStatus("ERROR", err.Error())
		return err
	}
	device.mu.Lock()
	device.fd = fd
	device.status = "UP"
	device.err = ""
	device.mu.Unlock()
	go device.readLoop(stopCh, outbound)
	return nil
}

func (device *darwinUtunDevice) SyncPeerRoutes(peerVirtualIPs []string) {
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

func (device *darwinUtunDevice) addPeerRouteLocked(peerVirtualIP string) {
	device.runCommandQuiet("route", "-n", "delete", "-host", peerVirtualIP)
	if err := runDarwinCommand("route", "-n", "add", "-host", peerVirtualIP, "-interface", device.Name()); err != nil {
		if device.logger != nil {
			device.logger.Printf("Peer Mesh utun add peer route failed: route=%s/32 err=%v", peerVirtualIP, err)
		}
		return
	}
	device.syncedPeerRoutes[peerVirtualIP] = struct{}{}
}

func (device *darwinUtunDevice) deletePeerRouteLocked(peerVirtualIP string) {
	device.runCommandQuiet("route", "-n", "delete", "-host", peerVirtualIP)
	delete(device.syncedPeerRoutes, peerVirtualIP)
}

func (device *darwinUtunDevice) runCommandQuiet(args ...string) {
	if err := runDarwinCommand(args...); err != nil && device.logger != nil {
		device.logger.Printf("Peer Mesh utun ignored command failure: %v", err)
	}
}

func (device *darwinUtunDevice) WritePacket(packet []byte) error {
	device.mu.Lock()
	fd := device.fd
	device.mu.Unlock()
	if fd < 0 {
		return io.ErrClosedPipe
	}
	if len(packet) == 0 {
		return nil
	}
	frame := make([]byte, darwinPacketInfoBytes+len(packet))
	if packet[0]>>4 == 6 {
		binary.BigEndian.PutUint32(frame[:darwinPacketInfoBytes], syscall.AF_INET6)
	} else {
		binary.BigEndian.PutUint32(frame[:darwinPacketInfoBytes], syscall.AF_INET)
	}
	copy(frame[darwinPacketInfoBytes:], packet)
	for len(frame) > 0 {
		n, err := syscall.Write(fd, frame)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		frame = frame[n:]
	}
	return nil
}

func (device *darwinUtunDevice) Close() error {
	device.SyncPeerRoutes(nil)
	device.mu.Lock()
	fd := device.fd
	device.fd = -1
	device.mu.Unlock()
	if fd >= 0 {
		return syscall.Close(fd)
	}
	return nil
}

func (device *darwinUtunDevice) Status() string {
	device.mu.Lock()
	defer device.mu.Unlock()
	return device.status
}

func (device *darwinUtunDevice) Error() string {
	device.mu.Lock()
	defer device.mu.Unlock()
	return device.err
}

func (device *darwinUtunDevice) readLoop(stopCh <-chan struct{}, outbound func([]byte)) {
	buffer := make([]byte, 65535)
	for {
		select {
		case <-stopCh:
			return
		default:
		}
		device.mu.Lock()
		fd := device.fd
		device.mu.Unlock()
		if fd < 0 {
			return
		}
		n, err := syscall.Read(fd, buffer)
		if n > darwinPacketInfoBytes {
			outbound(append([]byte(nil), buffer[darwinPacketInfoBytes:n]...))
		}
		if err != nil {
			select {
			case <-stopCh:
				return
			default:
			}
			device.setStatus("ERROR", fmt.Sprintf("read utun packet failed: %v", err))
			if device.logger != nil {
				device.logger.Printf("Peer Mesh utun read failed: %v", err)
			}
			return
		}
	}
}

func (device *darwinUtunDevice) configure() error {
	if device.mtu <= 0 {
		device.mtu = DefaultPeerMeshMTU
	}
	if err := runDarwinCommand("ifconfig", device.name, "inet", device.virtual, device.virtual,
		"netmask", "255.255.255.255", "mtu", fmt.Sprintf("%d", device.mtu), "up"); err != nil {
		return err
	}
	if strings.TrimSpace(device.cidr) != "" {
		device.runCommandQuiet("route", "-n", "delete", "-net", device.cidr)
	}
	return nil
}

func (device *darwinUtunDevice) requestedUnit() uint32 {
	name := strings.ToLower(strings.TrimSpace(device.name))
	if !strings.HasPrefix(name, darwinUtunDefaultPrefix) {
		return 0
	}
	unitText := strings.TrimPrefix(name, darwinUtunDefaultPrefix)
	if unitText == "" {
		return 0
	}
	unit, err := strconv.Atoi(unitText)
	if err != nil || unit < 0 {
		return 0
	}
	return uint32(unit + 1)
}

func (device *darwinUtunDevice) setStatus(status, errText string) {
	device.mu.Lock()
	device.status = status
	device.err = errText
	device.mu.Unlock()
}

func connectDarwinUtun(fd int, unit uint32) error {
	var info darwinCtlInfo
	copy(info.Name[:], []byte(darwinUtunControlName))
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), uintptr(darwinCtlIOCGInfo), uintptr(unsafe.Pointer(&info))); errno != 0 {
		return fmt.Errorf("utun CTLIOCGINFO failed: %w", errno)
	}
	addr := darwinSockaddrCtl{
		Len:     darwinSockaddrCtlSize,
		Family:  darwinAFSystem,
		Sysaddr: darwinAFSysControl,
		ID:      info.ID,
		Unit:    unit,
	}
	_, _, errno := syscall.RawSyscall(syscall.SYS_CONNECT, uintptr(fd), uintptr(unsafe.Pointer(&addr)), uintptr(unsafe.Sizeof(addr)))
	if errno != 0 {
		return fmt.Errorf("connect utun failed: %w", errno)
	}
	return nil
}

func darwinUtunName(fd int) (string, error) {
	var name [32]byte
	length := uint32(len(name))
	_, _, errno := syscall.Syscall6(
		syscall.SYS_GETSOCKOPT,
		uintptr(fd),
		uintptr(darwinSysprotoControl),
		uintptr(darwinUtunOptIfname),
		uintptr(unsafe.Pointer(&name[0])),
		uintptr(unsafe.Pointer(&length)),
		0)
	if errno != 0 {
		return "", errno
	}
	end := 0
	for end < int(length) && end < len(name) && name[end] != 0 {
		end++
	}
	return string(name[:end]), nil
}

func runDarwinCommand(args ...string) error {
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
