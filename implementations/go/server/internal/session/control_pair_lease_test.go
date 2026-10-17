package session

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestControlPairLeaseDeduplicatesNamesAndCollidingStripes(t *testing.T) {
	registry := NewRegistry()
	seen := map[int]string{}
	var first, second string
	for i := 0; ; i++ {
		name := fmt.Sprintf("pair-collision-%d", i)
		index := controlLeaseIndex(name)
		if previous, ok := seen[index]; ok {
			first, second = previous, name
			break
		}
		seen[index] = name
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	release, err := registry.AcquireControlLeases(ctx, first, second, first, second)
	if err != nil {
		t.Fatalf("same stripe was acquired recursively: %v", err)
	}
	registry.Find(first) // The short registry mutex remains independent of lifecycle work.
	release()
	release()
	for _, name := range []string{first, second} {
		release, err := registry.AcquireControlLease(ctx, name)
		if err != nil {
			t.Fatal(err)
		}
		release()
	}
}

func TestControlPairLeasePartialCancellationReleasesOnlyAcquiredStripes(t *testing.T) {
	registry := NewRegistry()
	low, high := "pair-low", "pair-high"
	if controlLeaseIndex(low) > controlLeaseIndex(high) {
		low, high = high, low
	}
	if controlLeaseIndex(low) == controlLeaseIndex(high) {
		t.Fatal("fixture requires distinct stripes")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	hold, err := registry.AcquireControlLease(ctx, high)
	if err != nil {
		t.Fatal(err)
	}
	defer hold()
	blocked, stop := context.WithTimeout(ctx, 30*time.Millisecond)
	defer stop()
	if _, err := registry.AcquireControlLeases(blocked, high, low); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("pair ignored blocked stripe/deadline: %v", err)
	}
	free, err := registry.AcquireControlLease(ctx, low)
	if err != nil {
		t.Fatalf("partial acquisition leaked lower stripe: %v", err)
	}
	free()
	stillHeld, cancelHeld := context.WithTimeout(ctx, 20*time.Millisecond)
	defer cancelHeld()
	if release, err := registry.AcquireControlLease(stillHeld, high); err == nil {
		release()
		t.Fatal("cancellation released another caller's higher stripe")
	}
	hold()
	all, err := registry.AcquireControlLeases(ctx, low, high)
	if err != nil {
		t.Fatal(err)
	}
	all()
}

func TestControlPairLeaseOppositeOrderCompletesWithoutOverlap(t *testing.T) {
	registry := NewRegistry()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	var active atomic.Int32
	var workers sync.WaitGroup
	start := make(chan struct{})
	errors := make(chan error, 2)
	for _, names := range [][]string{{"pair-left", "pair-right"}, {"pair-right", "pair-left"}} {
		workers.Add(1)
		go func() {
			defer workers.Done()
			<-start
			for range 500 {
				release, err := registry.AcquireControlLeases(ctx, names...)
				if err != nil {
					errors <- err
					return
				}
				if count := active.Add(1); count != 1 {
					errors <- fmt.Errorf("overlapping pair owners: %d", count)
					active.Add(-1)
					release()
					return
				}
				active.Add(-1)
				release()
			}
		}()
	}
	close(start)
	workers.Wait()
	close(errors)
	for err := range errors {
		t.Error(err)
	}
}
