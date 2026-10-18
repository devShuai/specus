package control

import (
	"bufio"
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/devShuai/specus/implementations/go/server/internal/protocol"
	"github.com/devShuai/specus/implementations/go/server/internal/store"
)

func TestOriginalRuntimeReferenceIsImmutableAndReturnedByValue(t *testing.T) {
	conn, _, _ := contextConnFixture(t)
	if _, ok := conn.RuntimeReference(); ok {
		t.Fatal("unauthenticated transport has runtime authority")
	}
	original := store.RuntimeClientReference{ClientID: 71, SessionID: 81, CredentialID: 91, IdentityID: 101, TenantID: "default", ClientName: "original", TokenHash: "fixture-hash", ChannelID: "untrusted-input", ExpiresAt: time.Now().Add(time.Hour)}
	if !conn.BindRuntimeReference(original) {
		t.Fatal("original runtime not captured")
	}
	original.ChannelID = conn.ChannelID()
	copy, ok := conn.RuntimeReference()
	if !ok || copy != original {
		t.Fatal("runtime reference not bound to the physical channel")
	}
	copy.ClientID = 72
	if conn.BindRuntimeReference(copy) {
		t.Fatal("second binding replaced original transport identity")
	}
	current, _ := conn.RuntimeReference()
	if current != original {
		t.Fatal("returned value mutated live runtime identity")
	}
}

type observedContextConn struct {
	net.Conn
	entered  chan struct{}
	once     sync.Once
	mu       sync.Mutex
	deadline time.Time
	writes   int
}

func (c *observedContextConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	c.writes++
	c.mu.Unlock()
	c.once.Do(func() { close(c.entered) })
	return c.Conn.Write(p)
}
func (c *observedContextConn) SetWriteDeadline(deadline time.Time) error {
	c.mu.Lock()
	c.deadline = deadline
	c.mu.Unlock()
	return c.Conn.SetWriteDeadline(deadline)
}
func contextConnFixture(t *testing.T) (*Conn, *observedContextConn, net.Conn) {
	t.Helper()
	left, right := net.Pipe()
	observed := &observedContextConn{Conn: left, entered: make(chan struct{})}
	conn := newConn(observed, 1<<20, 16<<10, 32<<10, 64<<10, context.Background())
	t.Cleanup(func() { conn.Close(""); _ = right.Close() })
	return conn, observed, right
}
func awaitContextSend(t *testing.T, done <-chan error) error {
	t.Helper()
	select {
	case err := <-done:
		return err
	case <-time.After(time.Second):
		t.Fatal("bounded socket operation did not finish")
		return nil
	}
}

func TestSendContextInterruptsActualBlockedSocketWrite(t *testing.T) {
	conn, observed, _ := contextConnFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- conn.SendContext(ctx, protocol.HeartbeatResponse{}) }()
	select {
	case <-observed.entered:
	case <-time.After(time.Second):
		t.Fatal("actual socket write was not reached")
	}
	cancel()
	if err := awaitContextSend(t, done); !errors.Is(err, context.Canceled) {
		t.Fatalf("blocked physical write not cancelled: %v", err)
	}
	if conn.Reason() != store.ReasonIOError {
		t.Fatalf("incomplete frame not closed as ordinary IO failure: %s", conn.Reason())
	}
	if conn.WriteBackpressure.IsBackpressured() {
		t.Fatal("cancelled write leaked pending backpressure")
	}
	pending := conn.WriteBackpressure.PendingBytes()
	if pending != 0 {
		t.Fatal("cancelled write leaked pending byte accounting")
	}
}

func TestSendContextCancelsWriteLockWaitWithoutTouchingConnection(t *testing.T) {
	conn, observed, peer := contextConnFixture(t)
	conn.writeMu.Lock()
	conn.WriteBackpressure = NewWriteBackpressureGate(0, 1)
	queued := make(chan struct{})
	var queuedOnce sync.Once
	conn.WriteBackpressure.AddListener(func(active bool) {
		if active {
			queuedOnce.Do(func() { close(queued) })
		}
	})
	locked := true
	defer func() {
		if locked {
			conn.writeMu.Unlock()
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	done := make(chan error, 1)
	go func() { done <- conn.SendContext(ctx, protocol.HeartbeatResponse{}) }()
	select {
	case <-queued:
	case <-time.After(time.Second):
		t.Fatal("bounded sender did not queue behind held write lock")
	}
	cancel()
	if err := awaitContextSend(t, done); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	observed.mu.Lock()
	writes, deadline := observed.writes, observed.deadline
	observed.mu.Unlock()
	if writes != 0 || !deadline.IsZero() || conn.Reason() != "" {
		t.Fatal("waiting cancellation wrote bytes/set deadline/closed healthy transport")
	}
	if conn.WriteBackpressure.PendingBytes() != 0 {
		t.Fatal("cancelled lock wait leaked pending bytes")
	}
	conn.writeMu.Unlock()
	locked = false
	read := make(chan error, 1)
	go func() { _, _, err := protocol.ReadFrame(bufio.NewReader(peer)); read <- err }()
	if err := conn.Send(protocol.HeartbeatResponse{}); err != nil {
		t.Fatal(err)
	}
	if err := awaitContextSend(t, read); err != nil {
		t.Fatal(err)
	}
}

func TestSendContextStopsCancellationAndClearsDeadlineBeforeNextWrite(t *testing.T) {
	conn, observed, peer := contextConnFixture(t)
	read := make(chan error, 1)
	go func() {
		reader := bufio.NewReader(peer)
		for range 2 {
			if _, _, err := protocol.ReadFrame(reader); err != nil {
				read <- err
				return
			}
		}
		read <- nil
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	if err := conn.SendContext(ctx, protocol.HeartbeatResponse{}); err != nil {
		t.Fatal(err)
	}
	cancel()
	observed.mu.Lock()
	deadline := observed.deadline
	observed.mu.Unlock()
	if !deadline.IsZero() {
		t.Fatal("successful bounded send leaked its deadline/cancellation callback")
	}
	if err := conn.Send(protocol.HeartbeatResponse{}); err != nil {
		t.Fatal(err)
	}
	if err := awaitContextSend(t, read); err != nil {
		t.Fatal(err)
	}
	if conn.Reason() != "" {
		t.Fatal("successful bounded write forced a reconnect")
	}
}

func TestSendContextRejectsUnboundedContextWithoutWriting(t *testing.T) {
	conn, observed, _ := contextConnFixture(t)
	if err := conn.SendContext(context.Background(), protocol.HeartbeatResponse{}); err == nil {
		t.Fatal("unbounded background delivery accepted")
	}
	observed.mu.Lock()
	writes := observed.writes
	observed.mu.Unlock()
	if writes != 0 || conn.Reason() != "" {
		t.Fatal("invalid context changed transport")
	}
}
