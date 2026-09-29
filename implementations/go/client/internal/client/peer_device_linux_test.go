//go:build linux

package client

import (
	"log"
	"net"
	"os/exec"
	"testing"
	"time"
)

// The Linux TUN device itself, reading real packets out of a real interface.
//
// Every other test of the data plane hands the mesh a fake device, so the one thing this device
// exists to do -- come up and deliver what the kernel writes into it -- had no coverage at all
// until a consumer and an egress were run against each other for real.
//
// This creates an interface and reads from it, so it runs under the same gate as the route
// commander tests: SPECUS_ROUTE_MUTATION_TEST=1, inside a namespace whose main table is empty.

// TestLinuxTunDeviceDeliversWhatTheKernelWritesIntoIt sends one packet into the device's own
// prefix and waits for it to come back out of the read loop.
//
// The load in the background is not decoration. The device is only broken when the runtime poller
// gets a chance to observe the descriptor's error state before the first read, which is every live
// client and was no test: without it, this passes against a device that fails in production.
func TestLinuxTunDeviceDeliversWhatTheKernelWritesIntoIt(t *testing.T) {
	linuxMutationNamespace(t)

	stopBackground := make(chan struct{})
	defer close(stopBackground)
	keepThePollerBusy(t, stopBackground)

	const virtual = "100.96.0.41"
	device := newPlatformPeerVirtualDevice(
		Config{PeerMeshTunName: "specustest0", PeerMeshMTU: 1280, PeerMeshDevice: "auto"},
		PeerMeshConfig{VirtualIP: virtual, CIDR: "100.96.0.0/11"},
		log.New(testLogWriter{t}, "", 0),
	)
	packets := make(chan []byte, 8)
	stop := make(chan struct{})
	if err := device.Start(stop, func(packet []byte) {
		select {
		case packets <- packet:
		default:
		}
	}); err != nil {
		t.Fatalf("start the device: %v", err)
	}
	defer func() {
		close(stop)
		_ = device.Close()
	}()

	// A destination inside the mesh prefix, routed into the device, so the kernel hands the packet
	// to the read loop instead of to a neighbour.
	const peer = "100.96.0.42"
	if out, err := exec.Command("ip", "route", "replace", peer+"/32", "dev", device.Name()).CombinedOutput(); err != nil {
		t.Fatalf("route %s into the device: %v: %s", peer, err, out)
	}
	go func() { _ = exec.Command("ping", "-c", "2", "-W", "2", peer).Run() }()

	// An interface that has just come up also emits IPv6 multicast of its own, so the ping is the
	// packet with the right destination rather than simply the first one to arrive.
	deadline := time.After(10 * time.Second)
	seen := 0
	for {
		select {
		case packet := <-packets:
			seen++
			if len(packet) < 20 || packet[0]>>4 != 4 {
				continue
			}
			if destination := net.IP(packet[16:20]).String(); destination != peer {
				continue
			}
			if status := device.Status(); status != "UP" {
				t.Errorf("device status = %s (%s), want UP", status, device.Error())
			}
			return
		case <-deadline:
			t.Fatalf("the ping to %s never came out of the device after %d other packets; status=%s err=%s",
				peer, seen, device.Status(), device.Error())
		}
	}
}

// keepThePollerBusy runs loopback traffic for the duration of a test, so the runtime's network
// poller is actually running rather than idle.
func keepThePollerBusy(t *testing.T, stop <-chan struct{}) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("no loopback listener in this namespace: %v", err)
	}
	go func() {
		<-stop
		_ = listener.Close()
	}()
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				buffer := make([]byte, 64)
				for {
					read, err := conn.Read(buffer)
					if err != nil {
						return
					}
					if _, err := conn.Write(buffer[:read]); err != nil {
						return
					}
				}
			}()
		}
	}()
	go func() {
		for {
			select {
			case <-stop:
				return
			default:
			}
			conn, err := net.Dial("tcp", listener.Addr().String())
			if err != nil {
				return
			}
			buffer := make([]byte, 64)
			for range 50 {
				if _, err := conn.Write([]byte("poll")); err != nil {
					break
				}
				if _, err := conn.Read(buffer); err != nil {
					break
				}
			}
			_ = conn.Close()
		}
	}()
}

type testLogWriter struct{ t *testing.T }

func (w testLogWriter) Write(p []byte) (int, error) {
	w.t.Log(string(p))
	return len(p), nil
}
