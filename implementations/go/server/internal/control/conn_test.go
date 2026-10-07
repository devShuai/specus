package control

import (
	"bufio"
	"context"
	"net"
	"testing"
	"time"

	"github.com/devShuai/specus/implementations/go/server/internal/protocol"
)

// A frame sent because of what commit published must not overtake the packet CommitAndSend
// writes, the way an OPEN on a just-registered data connection must follow its login response.
func TestCommitAndSendKeepsFramesItPublishesBehindThePacket(t *testing.T) {
	serverSide, clientSide := net.Pipe()
	t.Cleanup(func() { clientSide.Close() })
	conn := newConn(serverSide, 1024*1024, 16*1024, 32*1024, 64*1024, context.Background())
	t.Cleanup(func() { conn.Close("") })

	follower := make(chan error, 1)
	sent := make(chan error, 1)
	go func() {
		sent <- conn.CommitAndSend(func() {
			go func() { follower <- conn.Send(protocol.HeartbeatRequest{}) }()
			if conn.writeMu.TryLock() {
				conn.writeMu.Unlock()
				t.Error("commit ran without the write lock, so another writer could go first")
			}
		}, protocol.LoginResponse{ClientName: "demo", Success: true})
	}()

	_ = clientSide.SetReadDeadline(time.Now().Add(5 * time.Second))
	reader := bufio.NewReader(clientSide)
	for index, want := range []int8{protocol.CommandLoginResponse, protocol.CommandHeartbeatRequest} {
		command, _, err := protocol.ReadFrame(reader)
		if err != nil {
			t.Fatalf("read frame %d: %v", index, err)
		}
		if command != want {
			t.Fatalf("frame %d command = %d, want %d", index, command, want)
		}
	}
	if err := <-sent; err != nil {
		t.Fatalf("CommitAndSend: %v", err)
	}
	if err := <-follower; err != nil {
		t.Fatalf("follower Send: %v", err)
	}
}
