package control

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/devShuai/specus/implementations/go/server/internal/protocol"
	"github.com/devShuai/specus/implementations/go/server/internal/store"
)

// cutConn is a connection whose first write puts half of what it is given on the wire and then
// fails, as a write cut short by a reset or a write timeout does. Whatever is written after it is
// recorded too.
type cutConn struct {
	mu     sync.Mutex
	wire   bytes.Buffer
	writes int
	closed bool
}

func (c *cutConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.writes++
	if c.writes == 1 {
		half := len(p) / 2
		c.wire.Write(p[:half])
		return half, errors.New("connection reset after half a frame")
	}
	return c.wire.Write(p)
}

func (c *cutConn) Read([]byte) (int, error) { return 0, io.EOF }

func (c *cutConn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closed = true
	return nil
}

func (c *cutConn) state() (wire int, closed bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.wire.Len(), c.closed
}

func (c *cutConn) LocalAddr() net.Addr              { return nil }
func (c *cutConn) RemoteAddr() net.Addr             { return nil }
func (c *cutConn) SetDeadline(time.Time) error      { return nil }
func (c *cutConn) SetReadDeadline(time.Time) error  { return nil }
func (c *cutConn) SetWriteDeadline(time.Time) error { return nil }

// A write that fails partway through a frame closes the connection, and nothing is written after
// the cut frame: the client would read anything that followed out of step ("帧写入失败" in
// protocol/spec/control-protocol.md). Before, the error only went back to the caller and the
// connection stayed open for the next frame.
func TestWriteCutShortClosesTheConnection(t *testing.T) {
	netConn := &cutConn{}
	conn := newConn(netConn, 1<<20, 16<<10, 32<<10, 64<<10, context.Background())

	push := protocol.MessageResponse{
		ClientName:   "server",
		ToClientName: "client",
		MessageType:  1,
		Message:      strings.Repeat("x", 8<<10),
	}
	if err := conn.Send(push); err == nil {
		t.Fatal("Send reported a frame cut short as written")
	}
	cut, closed := netConn.state()
	if cut == 0 {
		t.Fatal("the cut frame put nothing on the wire; the test does not cut a frame short")
	}
	if !closed {
		t.Fatal("the connection was left open after a frame was cut short")
	}
	select {
	case <-conn.Context().Done():
	default:
		t.Fatal("the connection's context was not cancelled after a frame was cut short")
	}
	if reason := conn.Reason(); reason != store.ReasonIOError {
		t.Fatalf("disconnect reason = %q, want %q", reason, store.ReasonIOError)
	}

	if err := conn.Send(protocol.HeartbeatResponse{}); err == nil {
		t.Fatal("a frame was reported written after the cut frame")
	}
	// As the priority writer would, had it taken a queued frame just as the connection closed.
	frame, err := protocol.EncodeFrameLimit(protocol.HeartbeatResponse{}, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	if err := conn.writeFrame(frame, store.ReasonIOError); err == nil {
		t.Fatal("a queued frame was reported written after the cut frame")
	}
	if wire, _ := netConn.state(); wire != cut {
		t.Fatalf("%d byte(s) followed the cut frame", wire-cut)
	}
}

// A packet that cannot be encoded writes nothing, so the connection stays usable.
func TestFrameTooLargeToEncodeKeepsTheConnection(t *testing.T) {
	netConn := &cutConn{writes: 1}
	conn := newConn(netConn, 1<<10, 1<<10, 32<<10, 64<<10, context.Background())
	if err := conn.Send(protocol.MessageResponse{Message: strings.Repeat("x", 4<<10)}); err == nil {
		t.Fatal("a frame past maxFrameSize was sent")
	}
	if _, closed := netConn.state(); closed || conn.Context().Err() != nil {
		t.Fatal("a frame that was never written closed the connection")
	}
	if err := conn.Send(protocol.HeartbeatResponse{}); err != nil {
		t.Fatalf("the connection is no longer usable: %v", err)
	}
	if wire, _ := netConn.state(); wire == 0 {
		t.Fatal("the heartbeat after the refused frame was not written")
	}
}

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
