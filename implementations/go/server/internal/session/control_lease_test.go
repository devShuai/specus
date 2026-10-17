package session

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestControlLeaseCancellationDoesNotConsumeOrLeakStripe(t *testing.T) {
	registry := NewRegistry()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	release, err := registry.AcquireControlLease(ctx, "publisher")
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	// Registry lookup and a different stripe remain usable while lifecycle work is held.
	registry.Find("publisher")
	other, err := registry.AcquireControlLease(ctx, "independent-publisher")
	if err != nil {
		t.Fatal(err)
	}
	other()
	deadline, cancelDeadline := context.WithTimeout(ctx, 20*time.Millisecond)
	if _, err := registry.AcquireControlLease(deadline, "publisher"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("blocked stripe ignored deadline: %v", err)
	}
	cancelDeadline()
	blocked, stop := context.WithCancel(ctx)
	stop()
	if _, err := registry.AcquireControlLease(blocked, "publisher"); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled waiter: %v", err)
	}
	release()
	release()
	again, err := registry.AcquireControlLease(ctx, "publisher")
	if err != nil {
		t.Fatal(err)
	}
	again()
	if _, err := registry.AcquireControlLease(blocked, "publisher"); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled free stripe: %v", err)
	}
	final, err := registry.AcquireControlLease(ctx, "publisher")
	if err != nil {
		t.Fatal(err)
	}
	final()
}
