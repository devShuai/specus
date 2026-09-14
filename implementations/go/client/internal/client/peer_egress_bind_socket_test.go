//go:build windows || darwin

package client

import (
	"errors"
	"net"
	"testing"
	"time"
)

// The egress socket binding, against real sockets and the real routing table.
//
// No network is needed. 127.0.0.1 is reachable only through the loopback interface, and a socket
// the stack holds to any other interface cannot reach it -- which is what turns "the option was set"
// into "the option is doing something". Each test here would pass against a binder that set nothing
// except the last one, and that one is the reason the others can be trusted.

func egressBindLoopback(t *testing.T) net.Interface {
	t.Helper()
	interfaces, err := net.Interfaces()
	if err != nil {
		t.Fatalf("list interfaces: %v", err)
	}
	for _, iface := range interfaces {
		if iface.Flags&net.FlagLoopback != 0 && iface.Flags&net.FlagUp != 0 {
			return iface
		}
	}
	t.Fatal("no loopback interface")
	return net.Interface{}
}

// egressBindListeners starts a TCP and a UDP echo on 127.0.0.1 and returns their addresses.
func egressBindListeners(t *testing.T) (string, string) {
	t.Helper()
	stream, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen tcp: %v", err)
	}
	t.Cleanup(func() { _ = stream.Close() })
	go func() {
		for {
			conn, err := stream.Accept()
			if err != nil {
				return
			}
			_ = conn.Close()
		}
	}()
	packet, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	t.Cleanup(func() { _ = packet.Close() })
	return stream.Addr().String(), packet.LocalAddr().String()
}

// A dial to 127.0.0.1 is bound to the loopback interface, and the socket says so.
func TestEgressDialBindsTheSocketToTheInterfaceItChose(t *testing.T) {
	loopback := egressBindLoopback(t)
	tcpAddress, udpAddress := egressBindListeners(t)
	binder := newEgressSocketBinder(func() string { return "" })

	for _, target := range []struct{ protocol, address string }{{"tcp", tcpAddress}, {"udp", udpAddress}} {
		conn, err := binder.dial(target.protocol, target.address, 2*time.Second)
		if err != nil {
			t.Fatalf("%s dial: %v", target.protocol, err)
		}
		bound, err := egressBoundInterface(conn)
		_ = conn.Close()
		if err != nil {
			t.Fatalf("%s read back the binding: %v", target.protocol, err)
		}
		if bound != loopback.Index {
			t.Errorf("%s socket is bound to interface %d, want loopback %d", target.protocol, bound, loopback.Index)
		}
	}
}

// When the tunnel's routes are the only ones leading to a destination, the dial is refused rather
// than left unbound.
//
// The tunnel is named by the loopback interface's real name, so this also proves that the platform
// resolves a name to the key its table carries -- an index on Windows. The table itself is cut down to
// the loopback routes: in the real one the default route covers 127.0.0.1 too, and leaving loopback
// out would bind the socket to the physical interface instead, which the stack then refuses on its
// own (the last test in this file is about that).
func TestEgressDialIsRefusedWhenOnlyTheTunnelLeadsThere(t *testing.T) {
	loopback := egressBindLoopback(t)
	tcpAddress, udpAddress := egressBindListeners(t)
	binder := newEgressSocketBinder(func() string { return loopback.Name })
	key := binder.tunnelKey(loopback.Name)
	if key == "" {
		t.Fatalf("the loopback interface %q did not resolve to a table key", loopback.Name)
	}
	real, err := binder.routes()
	if err != nil {
		t.Fatalf("read the routing table: %v", err)
	}
	var loopbackRoutes []egressBindRoute
	for _, route := range real {
		if route.Interface == key {
			loopbackRoutes = append(loopbackRoutes, route)
		}
	}
	if chosen, ok := selectEgressBindInterface(loopbackRoutes, "", "127.0.0.1"); !ok || chosen != key {
		t.Fatalf("the real table's loopback routes do not lead to 127.0.0.1 through %s (got %q)", key, chosen)
	}
	binder.routes = func() ([]egressBindRoute, error) { return loopbackRoutes, nil }

	for _, target := range []struct{ protocol, address string }{{"tcp", tcpAddress}, {"udp", udpAddress}} {
		conn, err := binder.dial(target.protocol, target.address, 2*time.Second)
		if err == nil {
			_ = conn.Close()
			t.Fatalf("%s dial succeeded with the only route to it named as the tunnel", target.protocol)
		}
		if !errors.Is(err, errEgressNoPhysicalRoute) {
			t.Errorf("%s dial error = %v, want the no-physical-route refusal", target.protocol, err)
		}
	}
}

// The stack holds the socket to the interface it was bound to.
//
// The binder is handed a table claiming 127.0.0.0/8 is behind a physical interface. An unbound
// socket would reach 127.0.0.1 anyway, because the real table says otherwise; a bound one cannot.
// This is the test that fails if the option is never set.
//
// "Reach" is a connection for TCP and a delivered datagram for UDP. The two platforms refuse a
// misbound UDP socket at different points: Windows at connect, macOS not until the datagram is
// sent, because connecting a UDP socket there only records the peer. So the UDP half sends and
// listens rather than stopping at connect, and a correctly bound send is tried first so that
// silence cannot pass for enforcement.
func TestEgressSocketIsHeldToTheBoundInterface(t *testing.T) {
	loopback := egressBindLoopback(t)
	tcpAddress, _ := egressBindListeners(t)

	real := newEgressSocketBinder(func() string { return "" })
	routes, err := real.routes()
	if err != nil {
		t.Fatalf("read the routing table: %v", err)
	}
	loopbackKey := real.tunnelKey(loopback.Name)
	physical, ok := selectEgressBindInterface(routes, loopbackKey, "192.0.2.1")
	if !ok {
		t.Fatal("no default route outside loopback; this test needs a machine with working networking")
	}

	lying := newEgressSocketBinder(func() string { return "" })
	lying.routes = func() ([]egressBindRoute, error) {
		return []egressBindRoute{{Prefix: "127.0.0.0/8", Interface: physical, Usable: true}}, nil
	}

	conn, err := lying.dial("tcp", tcpAddress, 2*time.Second)
	if err == nil {
		bound, _ := egressBoundInterface(conn)
		_ = conn.Close()
		t.Fatalf("tcp reached 127.0.0.1 while bound to %s (read back %d): the binding is not enforced", physical, bound)
	}
	if errors.Is(err, errEgressNoPhysicalRoute) {
		t.Fatalf("tcp dial was refused before any socket existed, so nothing was tested: %v", err)
	}
	t.Logf("tcp bound to %s: %v", physical, err)

	packet, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	defer packet.Close()
	if delivered, detail := egressBindDelivers(t, real, packet, "control"); !delivered {
		t.Fatalf("udp bound to loopback did not deliver either (%s), so silence would prove nothing", detail)
	}
	delivered, detail := egressBindDelivers(t, lying, packet, "misbound")
	if delivered {
		t.Fatalf("udp reached 127.0.0.1 while bound to %s: the binding is not enforced", physical)
	}
	t.Logf("udp bound to %s: %s", physical, detail)
}

// egressBindDelivers dials packet's address through binder, sends one datagram, and reports whether
// it arrived, with what stopped it when it did not.
func egressBindDelivers(t *testing.T, binder *egressSocketBinder, packet net.PacketConn, label string) (bool, string) {
	t.Helper()
	conn, err := binder.dial("udp", packet.LocalAddr().String(), 2*time.Second)
	if err != nil {
		if errors.Is(err, errEgressNoPhysicalRoute) {
			t.Fatalf("udp %s dial was refused before any socket existed: %v", label, err)
		}
		return false, "connect: " + err.Error()
	}
	defer conn.Close()
	payload := []byte("specus-bind-" + label)
	if _, err := conn.Write(payload); err != nil {
		return false, "send: " + err.Error()
	}
	buffer := make([]byte, 64)
	deadline := time.Now().Add(time.Second)
	for {
		_ = packet.SetReadDeadline(deadline)
		n, _, err := packet.ReadFrom(buffer)
		if err != nil {
			return false, "sent without error, never arrived"
		}
		if string(buffer[:n]) == string(payload) {
			return true, "delivered"
		}
	}
}
