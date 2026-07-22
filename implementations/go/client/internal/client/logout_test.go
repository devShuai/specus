package client

import (
	"io"
	"log"
	"net"
	"testing"
	"time"

	"github.com/devShuai/shuai-tunnel/implementations/go/client/internal/protocol"
)

func TestHandleLogoutRequestClosesControlConnection(t *testing.T) {
	local, remote := net.Pipe()
	defer remote.Close()

	tunnelClient := New(Config{}, log.New(io.Discard, "", 0))
	if err := tunnelClient.handlePacket(local, protocol.Packet{Command: protocol.CommandLogoutRequest},
		protocol.ConnectionRoleControl); err != nil {
		t.Fatalf("handlePacket(LOGOUT_REQUEST) error = %v", err)
	}

	done := make(chan error, 1)
	go func() {
		var one [1]byte
		_, err := remote.Read(one[:])
		done <- err
	}()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("remote read unexpectedly succeeded after logout close")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("remote read did not unblock after logout close")
	}
}
