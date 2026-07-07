//go:build windows

package client

import (
	"embed"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

const windowsWintunRingCapacity = 0x400000

//go:embed native/windows/*/wintun.dll
var bundledWintunFS embed.FS

type windowsWintunDevice struct {
	name    string
	virtual string
	cidr    string
	mtu     int
	logger  *log.Logger

	mu      sync.Mutex
	dll     *syscall.LazyDLL
	api     *wintunAPI
	adapter uintptr
	session uintptr
	status  string
	err     string

	routesMu         sync.Mutex
	syncedPeerRoutes map[string]struct{}
}

type wintunAPI struct {
	openAdapter          *syscall.LazyProc
	createAdapter        *syscall.LazyProc
	closeAdapter         *syscall.LazyProc
	startSession         *syscall.LazyProc
	endSession           *syscall.LazyProc
	receivePacket        *syscall.LazyProc
	releaseReceivePacket *syscall.LazyProc
	allocateSendPacket   *syscall.LazyProc
	sendPacket           *syscall.LazyProc
}

func newPlatformPeerVirtualDevice(config Config, runtime PeerMeshConfig, logger *log.Logger) peerVirtualDevice {
	mode := strings.ToLower(strings.TrimSpace(config.PeerMeshDevice))
	if mode != "auto" && mode != "windows-wintun" && mode != "wintun" {
		return newUnsupportedPeerVirtualDevice(config, fmt.Sprintf("unsupported peerMeshDevice on Windows: %s", config.PeerMeshDevice))
	}
	return &windowsWintunDevice{
		name:             firstNonEmpty(config.PeerMeshTunName, DefaultPeerMeshTunName),
		virtual:          runtime.VirtualIP,
		cidr:             runtime.CIDR,
		mtu:              config.PeerMeshMTU,
		logger:           logger,
		status:           "INIT",
		syncedPeerRoutes: make(map[string]struct{}),
	}
}

func (device *windowsWintunDevice) Name() string {
	return device.name
}

func (device *windowsWintunDevice) Start(stopCh <-chan struct{}, outbound func([]byte)) error {
	if strings.TrimSpace(device.virtual) == "" || strings.TrimSpace(device.cidr) == "" {
		device.setStatus("ERROR", "missing peer mesh virtual IP or CIDR")
		return errors.New(device.err)
	}
	dll, api, err := loadWintunAPI()
	if err != nil {
		device.setStatus("ERROR", err.Error())
		return err
	}
	name, err := syscall.UTF16PtrFromString(device.name)
	if err != nil {
		device.setStatus("ERROR", err.Error())
		return err
	}
	adapter, _, _ := api.openAdapter.Call(uintptr(unsafe.Pointer(name)))
	if adapter == 0 {
		tunnelType, err := syscall.UTF16PtrFromString("shuai-tunnel")
		if err != nil {
			device.setStatus("ERROR", err.Error())
			return err
		}
		adapter, _, _ = api.createAdapter.Call(uintptr(unsafe.Pointer(name)), uintptr(unsafe.Pointer(tunnelType)), 0)
	}
	if adapter == 0 {
		err := errors.New("Wintun adapter create/open failed; run as administrator and ensure wintun.dll is available")
		device.setStatus("ERROR", err.Error())
		return err
	}
	session, _, _ := api.startSession.Call(adapter, uintptr(windowsWintunRingCapacity))
	if session == 0 {
		api.closeAdapter.Call(adapter)
		err := errors.New("Wintun session start failed")
		device.setStatus("ERROR", err.Error())
		return err
	}
	device.mu.Lock()
	device.dll = dll
	device.api = api
	device.adapter = adapter
	device.session = session
	device.mu.Unlock()
	if err := device.configure(); err != nil {
		_ = device.Close()
		device.setStatus("ERROR", err.Error())
		return err
	}
	device.setStatus("UP", "")
	go device.readLoop(stopCh, outbound)
	return nil
}

func (device *windowsWintunDevice) SyncPeerRoutes(peerVirtualIPs []string) {
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

func (device *windowsWintunDevice) addPeerRouteLocked(peerVirtualIP string) {
	route := peerVirtualIP + "/32"
	device.runCommandQuiet("netsh", "interface", "ipv4", "delete", "route", route, device.name, "store=active")
	if err := runWindowsCommand("netsh", "interface", "ipv4", "add", "route", route, device.name, "store=active"); err != nil {
		if device.logger != nil {
			device.logger.Printf("Peer Mesh Wintun add peer route failed: route=%s err=%v", route, err)
		}
		return
	}
	device.syncedPeerRoutes[peerVirtualIP] = struct{}{}
}

func (device *windowsWintunDevice) deletePeerRouteLocked(peerVirtualIP string) {
	device.runCommandQuiet("netsh", "interface", "ipv4", "delete", "route", peerVirtualIP+"/32", device.name, "store=active")
	delete(device.syncedPeerRoutes, peerVirtualIP)
}

func (device *windowsWintunDevice) runCommandQuiet(args ...string) {
	if err := runWindowsCommand(args...); err != nil && device.logger != nil {
		device.logger.Printf("Peer Mesh Wintun ignored command failure: %v", err)
	}
}

func (device *windowsWintunDevice) WritePacket(packet []byte) error {
	device.mu.Lock()
	api := device.api
	session := device.session
	device.mu.Unlock()
	if api == nil || session == 0 {
		return io.ErrClosedPipe
	}
	sendPacket, _, _ := api.allocateSendPacket.Call(session, uintptr(len(packet)))
	if sendPacket == 0 {
		return errors.New("Wintun send packet allocation failed")
	}
	buffer := unsafe.Slice((*byte)(unsafe.Pointer(sendPacket)), len(packet))
	copy(buffer, packet)
	api.sendPacket.Call(session, sendPacket)
	return nil
}

func (device *windowsWintunDevice) Close() error {
	device.SyncPeerRoutes(nil)
	device.mu.Lock()
	api := device.api
	session := device.session
	adapter := device.adapter
	device.api = nil
	device.session = 0
	device.adapter = 0
	device.dll = nil
	device.mu.Unlock()
	if api != nil && session != 0 {
		api.endSession.Call(session)
	}
	if api != nil && adapter != 0 {
		api.closeAdapter.Call(adapter)
	}
	return nil
}

func (device *windowsWintunDevice) Status() string {
	device.mu.Lock()
	defer device.mu.Unlock()
	return device.status
}

func (device *windowsWintunDevice) Error() string {
	device.mu.Lock()
	defer device.mu.Unlock()
	return device.err
}

func (device *windowsWintunDevice) readLoop(stopCh <-chan struct{}, outbound func([]byte)) {
	for {
		select {
		case <-stopCh:
			return
		default:
		}
		device.mu.Lock()
		api := device.api
		session := device.session
		device.mu.Unlock()
		if api == nil || session == 0 {
			return
		}
		var packetSize uint32
		packet, _, _ := api.receivePacket.Call(session, uintptr(unsafe.Pointer(&packetSize)))
		if packet == 0 {
			time.Sleep(5 * time.Millisecond)
			continue
		}
		if packetSize > 0 {
			data := unsafe.Slice((*byte)(unsafe.Pointer(packet)), int(packetSize))
			outbound(append([]byte(nil), data...))
		}
		api.releaseReceivePacket.Call(session, packet)
	}
}

func (device *windowsWintunDevice) configure() error {
	if device.mtu <= 0 {
		device.mtu = DefaultPeerMeshMTU
	}
	commands := [][]string{
		{"netsh", "interface", "ip", "set", "address", "name=" + device.name, "static", device.virtual, "255.255.255.255"},
		{"netsh", "interface", "ipv4", "set", "subinterface", device.name, fmt.Sprintf("mtu=%d", device.mtu), "store=active"},
	}
	for _, args := range commands {
		if err := runWindowsCommand(args...); err != nil {
			return err
		}
	}
	if strings.TrimSpace(device.cidr) != "" {
		device.runCommandQuiet("netsh", "interface", "ipv4", "delete", "route", device.cidr, device.name, "store=active")
	}
	return nil
}

func (device *windowsWintunDevice) setStatus(status, errText string) {
	device.mu.Lock()
	device.status = status
	device.err = errText
	device.mu.Unlock()
}

func loadWintunAPI() (*syscall.LazyDLL, *wintunAPI, error) {
	var loadErrors []string
	candidates, candidateErrors := wintunCandidates()
	for _, candidate := range candidates {
		dll := syscall.NewLazyDLL(candidate)
		if err := dll.Load(); err != nil {
			loadErrors = append(loadErrors, fmt.Sprintf("%s: %v", candidate, err))
			continue
		}
		api := &wintunAPI{
			openAdapter:          dll.NewProc("WintunOpenAdapter"),
			createAdapter:        dll.NewProc("WintunCreateAdapter"),
			closeAdapter:         dll.NewProc("WintunCloseAdapter"),
			startSession:         dll.NewProc("WintunStartSession"),
			endSession:           dll.NewProc("WintunEndSession"),
			receivePacket:        dll.NewProc("WintunReceivePacket"),
			releaseReceivePacket: dll.NewProc("WintunReleaseReceivePacket"),
			allocateSendPacket:   dll.NewProc("WintunAllocateSendPacket"),
			sendPacket:           dll.NewProc("WintunSendPacket"),
		}
		for _, proc := range []*syscall.LazyProc{
			api.openAdapter,
			api.createAdapter,
			api.closeAdapter,
			api.startSession,
			api.endSession,
			api.receivePacket,
			api.releaseReceivePacket,
			api.allocateSendPacket,
			api.sendPacket,
		} {
			if err := proc.Find(); err != nil {
				loadErrors = append(loadErrors, fmt.Sprintf("%s:%s: %v", candidate, proc.Name, err))
				dll = nil
				break
			}
		}
		if dll != nil {
			return dll, api, nil
		}
	}
	loadErrors = append(candidateErrors, loadErrors...)
	return nil, nil, fmt.Errorf("load wintun.dll failed; set SHUAI_PEER_MESH_WINTUN_DLL or use the bundled native/windows/*/wintun.dll: %s", strings.Join(loadErrors, "; "))
}

func wintunCandidates() ([]string, []string) {
	var candidates []string
	var errors []string
	if configured := strings.TrimSpace(os.Getenv("SHUAI_PEER_MESH_WINTUN_DLL")); configured != "" {
		candidates = append(candidates, configured)
	}
	if bundled, err := extractBundledWintun(); err != nil {
		errors = append(errors, err.Error())
	} else if bundled != "" {
		candidates = append(candidates, bundled)
	}
	if executable, err := os.Executable(); err == nil {
		base := filepath.Dir(executable)
		if arch := wintunArchDir(); arch != "" {
			candidates = append(candidates, filepath.Join(base, "native", "windows", arch, "wintun.dll"))
		}
		candidates = append(candidates, filepath.Join(base, "wintun.dll"))
	}
	candidates = append(candidates, "wintun.dll")
	return candidates, errors
}

func extractBundledWintun() (string, error) {
	arch := wintunArchDir()
	if arch == "" {
		return "", nil
	}
	resource := "native/windows/" + arch + "/wintun.dll"
	data, err := bundledWintunFS.ReadFile(resource)
	if err != nil {
		return "", fmt.Errorf("read bundled %s failed: %w", resource, err)
	}
	targetDir := filepath.Join(wintunNativeCacheDir(), "windows", arch)
	if err := os.MkdirAll(targetDir, 0o755); err != nil {
		return "", fmt.Errorf("create Wintun native cache failed: %w", err)
	}
	target := filepath.Join(targetDir, "wintun.dll")
	if err := os.WriteFile(target, data, 0o644); err != nil {
		return "", fmt.Errorf("write bundled Wintun to cache failed: %w", err)
	}
	return target, nil
}

func wintunNativeCacheDir() string {
	if configured := strings.TrimSpace(os.Getenv("SHUAI_PEER_MESH_NATIVE_CACHE_DIR")); configured != "" {
		return configured
	}
	if localAppData := strings.TrimSpace(os.Getenv("LOCALAPPDATA")); localAppData != "" {
		return filepath.Join(localAppData, "shuai-tunnel", "native")
	}
	if cacheDir, err := os.UserCacheDir(); err == nil && strings.TrimSpace(cacheDir) != "" {
		return filepath.Join(cacheDir, "shuai-tunnel", "native")
	}
	return filepath.Join(os.TempDir(), "shuai-tunnel", "native")
}

func wintunArchDir() string {
	switch runtime.GOARCH {
	case "amd64":
		return "x86_64"
	case "arm64":
		return "aarch64"
	case "386":
		return "x86"
	default:
		return ""
	}
}

func runWindowsCommand(args ...string) error {
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
