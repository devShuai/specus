package server

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"io"
	"log/slog"
	"net"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/devShuai/shuai-tunnel/tunnel-server-go/internal/config"
	"github.com/devShuai/shuai-tunnel/tunnel-server-go/internal/protocol"
)

// startTestApp boots an App on an ephemeral control port + a temp SQLite file and returns it
// along with the bound control port. The app stops when the test ends.
func startTestApp(t *testing.T) (*App, int) {
	t.Helper()
	cfg := config.Default()
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

func dialAndLogin(t *testing.T, port int, clientName, password string) (net.Conn, *bufio.Reader) {
	t.Helper()
	conn, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { conn.Close() })

	timestamp := strconv.FormatInt(time.Now().UnixMilli(), 10)
	var nonceRaw [8]byte
	_, _ = rand.Read(nonceRaw[:])
	nonce := hex.EncodeToString(nonceRaw[:])
	login := protocol.LoginRequest{
		ClientName: clientName,
		Timestamp:  timestamp,
		Nonce:      nonce,
		CheckSign:  protocol.SignLogin(clientName, password, timestamp, nonce),
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
	conn, reader := dialAndLogin(t, port, DemoClientName, DemoClientPassword)

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
	if _, ok := readPacket(t, reader).(protocol.HeartbeatResponse); !ok {
		t.Fatal("expected HeartbeatResponse")
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

func TestLoginRejectsBadSignature(t *testing.T) {
	_, port := startTestApp(t)
	conn, reader := dialAndLogin(t, port, DemoClientName, "wrong-password")

	resp, ok := readPacket(t, reader).(protocol.LoginResponse)
	if !ok {
		t.Fatalf("expected LoginResponse, got %T", resp)
	}
	if resp.Success {
		t.Fatal("login should have failed with a bad password")
	}
	if resp.Reason == nil || *resp.Reason != "签名无效或已过期" {
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
