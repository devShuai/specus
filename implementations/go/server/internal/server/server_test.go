package server

import (
	"bufio"
	"context"
	"io"
	"log/slog"
	"net"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/devShuai/shuai-tunnel/implementations/go/server/internal/auth"
	"github.com/devShuai/shuai-tunnel/implementations/go/server/internal/config"
	"github.com/devShuai/shuai-tunnel/implementations/go/server/internal/protocol"
)

// startTestApp boots an App on an ephemeral control port + a temp SQLite file and returns it
// along with the bound control port. The app stops when the test ends.
func startTestApp(t *testing.T) (*App, int) {
	t.Helper()
	cfg := config.Default()
	return startTestAppWithConfig(t, cfg)
}

func startTestAppWithConfig(t *testing.T, cfg config.Config) (*App, int) {
	t.Helper()
	cfg.Netty.Port = 0
	cfg.ManagementAddr = "127.0.0.1:0"
	cfg.ConnectionString = filepath.Join(t.TempDir(), "test.db")

	app, err := New(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("new app: %v", err)
	}
	t.Cleanup(func() { app.Close() })

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = app.Run(ctx) }()

	deadline := time.Now().Add(5 * time.Second)
	for app.ControlPort() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	port := app.ControlPort()
	if port == 0 {
		t.Fatal("control channel never bound")
	}
	return app, port
}

func issueClientSession(t *testing.T, app *App, clientName string) auth.Session {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	account, err := app.DB().FindClientByName(ctx, clientName)
	if err != nil {
		t.Fatalf("find client: %v", err)
	}
	if account == nil {
		t.Fatalf("client %q not found", clientName)
	}
	return app.clientAuth.Create(*account, time.Hour)
}

func dialAndLogin(t *testing.T, app *App, port int, clientName string) (net.Conn, *bufio.Reader) {
	t.Helper()
	conn, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { conn.Close() })

	session := issueClientSession(t, app, clientName)
	login := protocol.LoginRequest{
		ClientName:      clientName,
		ClientSessionID: session.ID,
		AccessToken:     session.AccessToken,
		ConnectionRole:  protocol.ConnectionRoleControl,
	}
	if err := protocol.WritePacket(conn, login); err != nil {
		t.Fatalf("write login: %v", err)
	}
	return conn, bufio.NewReader(conn)
}

func readPacket(t *testing.T, reader *bufio.Reader) protocol.Packet {
	t.Helper()
	command, body, err := protocol.ReadFrame(reader)
	if err != nil {
		t.Fatalf("read frame: %v", err)
	}
	packet, err := protocol.Decode(command, body)
	if err != nil {
		t.Fatalf("decode frame: %v", err)
	}
	return packet
}

func TestLoginSuccessAndHeartbeat(t *testing.T) {
	app, port := startTestApp(t)
	conn, reader := dialAndLogin(t, app, port, DemoClientName)

	resp, ok := readPacket(t, reader).(protocol.LoginResponse)
	if !ok {
		t.Fatalf("expected LoginResponse, got %T", resp)
	}
	if !resp.Success || resp.ClientName != DemoClientName {
		t.Fatalf("login failed: %+v", resp)
	}

	// Heartbeat round-trip.
	if err := protocol.WritePacket(conn, protocol.HeartbeatRequest{}); err != nil {
		t.Fatalf("write heartbeat: %v", err)
	}
	heartbeatReceived := false
	for range 8 {
		if _, ok := readPacket(t, reader).(protocol.HeartbeatResponse); ok {
			heartbeatReceived = true
			break
		}
	}
	if !heartbeatReceived {
		t.Fatal("expected HeartbeatResponse after asynchronous login pushes")
	}

	// A successful connection record should exist.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	count, err := app.DB().CountConnections(ctx, DemoClientName, true)
	if err != nil {
		t.Fatalf("count connections: %v", err)
	}
	if count < 1 {
		t.Fatalf("expected >=1 successful connection record, got %d", count)
	}
}

func TestLoginRejectsBadAccessToken(t *testing.T) {
	_, port := startTestApp(t)
	conn, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	login := protocol.LoginRequest{
		ClientName:      DemoClientName,
		ClientSessionID: 12345,
		AccessToken:     "invalid",
		ConnectionRole:  protocol.ConnectionRoleControl,
	}
	if err := protocol.WritePacket(conn, login); err != nil {
		t.Fatalf("write login: %v", err)
	}
	reader := bufio.NewReader(conn)

	resp, ok := readPacket(t, reader).(protocol.LoginResponse)
	if !ok {
		t.Fatalf("expected LoginResponse, got %T", resp)
	}
	if resp.Success {
		t.Fatal("login should have failed with a bad access token")
	}
	if resp.Reason == nil || *resp.Reason != "客户端访问令牌无效" {
		t.Fatalf("unexpected reason: %v", resp.Reason)
	}
	_ = conn
}

func TestUnauthenticatedPacketClosesConnection(t *testing.T) {
	_, port := startTestApp(t)
	conn, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	// Send a heartbeat before logging in -> server should drop the connection.
	if err := protocol.WritePacket(conn, protocol.HeartbeatRequest{}); err != nil {
		t.Fatalf("write: %v", err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	reader := bufio.NewReader(conn)
	if _, _, err := protocol.ReadFrame(reader); err == nil {
		t.Fatal("expected connection to be closed, but read succeeded")
	}
}
