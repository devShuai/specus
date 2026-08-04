package control

import (
	"context"
	"testing"
	"time"
)

func TestLoginExecutorConsumesCoreMaxAndQueueConfiguration(t *testing.T) {
	executor := NewLoginExecutor(1, 2, 1)
	ctx, cancel := context.WithCancel(context.Background())
	executor.Start(ctx)
	release := make(chan struct{})
	started := make(chan int, 2)
	blockingTask := func(id int) func() {
		return func() {
			started <- id
			<-release
		}
	}

	if !executor.TryEnqueue(blockingTask(1)) {
		t.Fatal("core worker task was rejected")
	}
	waitExecutorTask(t, started, 1)
	if !executor.TryEnqueue(func() {}) {
		t.Fatal("configured queue slot was rejected")
	}
	if !executor.TryEnqueue(blockingTask(3)) {
		t.Fatal("executor did not grow from core to max when the queue filled")
	}
	waitExecutorTask(t, started, 3)
	if executor.TryEnqueue(func() {}) {
		t.Fatal("executor accepted work beyond max workers and queue capacity")
	}

	close(release)
	cancel()
	executor.Wait()
}

func waitExecutorTask(t *testing.T, started <-chan int, want int) {
	t.Helper()
	select {
	case got := <-started:
		if got != want {
			t.Fatalf("started task = %d, want %d", got, want)
		}
	case <-time.After(time.Second):
		t.Fatalf("task %d did not start", want)
	}
}
