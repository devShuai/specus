package control

import (
	"context"
	"sync"
)

// LoginExecutor is a bounded worker pool for offloading login work off the read loop.
// TryEnqueue is non-blocking and returns false when the queue is full (the caller then
// answers with SERVER_BUSY), mirroring the C# bounded login executor.
type LoginExecutor struct {
	queue chan func()
	wg    sync.WaitGroup
	once  sync.Once
}

// NewLoginExecutor builds an executor with the given worker count and queue capacity.
func NewLoginExecutor(workers, capacity int) *LoginExecutor {
	if workers < 1 {
		workers = 1
	}
	if capacity < 1 {
		capacity = 1
	}
	return &LoginExecutor{queue: make(chan func(), capacity)}
}

// Start launches the worker goroutines; they drain until ctx is cancelled.
func (e *LoginExecutor) Start(ctx context.Context, workers int) {
	if workers < 1 {
		workers = 1
	}
	for range workers {
		e.wg.Add(1)
		go func() {
			defer e.wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case task := <-e.queue:
					task()
				}
			}
		}()
	}
}

// TryEnqueue submits a task without blocking; returns false if the queue is full.
func (e *LoginExecutor) TryEnqueue(task func()) bool {
	select {
	case e.queue <- task:
		return true
	default:
		return false
	}
}

// Wait blocks until all workers have exited (after their context is cancelled).
func (e *LoginExecutor) Wait() { e.wg.Wait() }
