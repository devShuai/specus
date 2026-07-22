package server

import (
	"bufio"
	"context"
	"crypto/rand"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/devShuai/shuai-tunnel/implementations/go/server/internal/protocol"
)

// freeTCPPort grabs an ephemeral port by binding and immediately releasing it.
func freeTCPPort(t *testing.T) int {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("probe free port: %v", err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()
	return port
}

// natTestClient logs in, registers a tunnel on listenPort, and echoes any DATA it receives
// straight back to the server (acting as a loopback upstream). It runs until ctx is done.
func natTestClient(t *testing.T, ctx context.Context, app *App, port, listenPort int, registered chan<- bool) {
	t.Helper()
	controlConn, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		t.Errorf("control dial: %v", err)
		registered <- false
		return
	}
	go func() { <-ctx.Done(); controlConn.Close() }()

	session := issueClientSession(t, app, DemoClientName)
	controlLogin := protocol.LoginRequest{
		ClientName:      DemoClientName,
		ClientSessionID: session.ID,
		AccessToken:     session.AccessToken,
		ConnectionRole:  protocol.ConnectionRoleControl,
	}
	if err := protocol.WritePacket(controlConn, controlLogin); err != nil {
		t.Errorf("control login: %v", err)
		registered <- false
		return
	}
	controlReader := bufio.NewReader(controlConn)
	controlResponse, ok := readPacket(t, controlReader).(protocol.LoginResponse)
	if !ok || !controlResponse.Success {
		t.Errorf("control login rejected: %#v", controlResponse)
		registered <- false
		return
	}

	conn, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		t.Errorf("data dial: %v", err)
		registered <- false
		return
	}
	go func() { <-ctx.Done(); conn.Close() }()
	dataLogin := controlLogin
	dataLogin.ConnectionRole = protocol.ConnectionRoleData
	if err := protocol.WritePacket(conn, dataLogin); err != nil {
		t.Errorf("data login: %v", err)
		registered <- false
		return
	}

	reader := bufio.NewReader(conn)
	sentRegister := false
	for {
		command, body, err := protocol.ReadFrame(reader)
		if err != nil {
			return
		}
		packet, err := protocol.Decode(command, body)
		if err != nil {
			return
		}
		switch p := packet.(type) {
		case protocol.LoginResponse:
			if !p.Success {
				registered <- false
				return
			}
			if !sentRegister {
				sentRegister = true
				_ = protocol.WritePacket(conn, protocol.NatMessage{
					Type: protocol.NatRegister,
					Metadata: map[string]any{
						"port":          listenPort,
						"tunnelPort":    9,
						"tunnelAddress": "127.0.0.1",
						"clientName":    DemoClientName,
					},
				})
			}
		case protocol.NatMessage:
			switch p.Type {
			case protocol.NatRegisterResult:
				registered <- p.Metadata["success"] == true
			case protocol.NatData:
				// Loopback: echo the bytes on the same v2 stream and release the
				// server-to-client flow-control credit after consuming them.
				_ = protocol.WritePacket(conn, protocol.NatMessage{
					Type:     protocol.NatWindowUpdate,
					StreamID: p.StreamID,
					Value:    uint32(len(p.Data)),
				})
				_ = protocol.WritePacket(conn, protocol.NatMessage{
					Type:     protocol.NatData,
					StreamID: p.StreamID,
					Data:     p.Data,
				})
			}
		}
	}
}

func TestNatRoundTrip(t *testing.T) {
	app, port := startTestApp(t)
	listenPort := freeTCPPort(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	registered := make(chan bool, 1)
	go natTestClient(t, ctx, app, port, listenPort, registered)

	select {
	case ok := <-registered:
		if !ok {
			t.Fatal("tunnel registration failed")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for registration")
	}

	// Wait until the public port is actually bound.
	deadline := time.Now().Add(5 * time.Second)
	for !app.RemotePorts().HasBinding(listenPort) && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if !app.RemotePorts().HasBinding(listenPort) {
		t.Fatal("public port never bound")
	}

	// Small round-trip.
	external, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(listenPort)))
	if err != nil {
		t.Fatalf("dial external: %v", err)
	}
	defer external.Close()

	payload := []byte("hello-through-the-go-tunnel")
	if _, err := external.Write(payload); err != nil {
		t.Fatalf("write external: %v", err)
	}
	got := make([]byte, len(payload))
	_ = external.SetReadDeadline(time.Now().Add(10 * time.Second))
	if _, err := readFull(external, got); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if string(got) != string(payload) {
		t.Fatalf("echo mismatch: got %q want %q", got, payload)
	}

	// 1 MiB burst to exercise sustained forwarding and backpressure.
	burst := make([]byte, 1024*1024)
	_, _ = rand.Read(burst)
	burstConn, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(listenPort)))
	if err != nil {
		t.Fatalf("dial burst: %v", err)
	}
	defer burstConn.Close()

	writeErr := make(chan error, 1)
	go func() {
		_, err := burstConn.Write(burst)
		writeErr <- err
	}()
	echoed := make([]byte, len(burst))
	_ = burstConn.SetReadDeadline(time.Now().Add(30 * time.Second))
	if read, err := readFull(burstConn, echoed); err != nil {
		t.Fatalf("read burst echo after %d/%d bytes: %v", read, len(echoed), err)
	}
	if err := <-writeErr; err != nil {
		t.Fatalf("write burst: %v", err)
	}
	for i := range burst {
		if burst[i] != echoed[i] {
			t.Fatalf("burst mismatch at byte %d", i)
		}
	}

	// Traffic counters should reflect both directions after a flush.
	app.Traffic().Flush(context.Background())
	flushCtx, fcancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer fcancel()
	up, down, err := app.DB().SumTraffic(flushCtx, DemoClientName)
	if err != nil {
		t.Fatalf("read traffic: %v", err)
	}
	if up <= 0 || down <= 0 {
		t.Fatalf("expected non-zero traffic, up=%d down=%d", up, down)
	}
}

func readFull(conn net.Conn, buf []byte) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := conn.Read(buf[total:])
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}
