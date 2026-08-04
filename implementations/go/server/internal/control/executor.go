package control

import (
	"context"
	"sync"
	"sync/atomic"
)

// LoginExecutor is a bounded worker pool for offloading login work off the read loop.
// TryEnqueue is non-blocking and returns false when the queue is full (the caller then
// answers with SERVER_BUSY), mirroring the C# bounded login executor.
type LoginExecutor struct {
	queue  chan func()
	core   int
	max    int
	ctx    context.Context
	active atomic.Int32
	wg     sync.WaitGroup
	once   sync.Once
}

// NewLoginExecutor builds an executor with the given worker count and queue capacity.
func NewLoginExecutor(core, max, capacity int) *LoginExecutor {
	if core < 1 {
		core = 1
	}
	if max < core {
		max = core
	}
	if capacity < 1 {
		capacity = 1
	}
	return &LoginExecutor{queue: make(chan func(), capacity), core: core, max: max}
}

// Start launches the configured Java-equivalent core workers. When the bounded queue fills,
// TryEnqueue may grow the pool up to max before rejecting with SERVER_BUSY.
func (e *LoginExecutor) Start(ctx context.Context) {
	e.once.Do(func() {
		e.ctx = ctx
		for range e.core {
			e.startWorker(nil)
		}
	})
}

func (e *LoginExecutor) startWorker(initial func()) {
	e.active.Add(1)
	e.startReservedWorker(initial)
}

func (e *LoginExecutor) startReservedWorker(initial func()) {
	e.wg.Add(1)
	go func() {
		defer e.wg.Done()
		defer e.active.Add(-1)
		if initial != nil {
			initial()
		}
		for {
			select {
			case <-e.ctx.Done():
				return
			case task := <-e.queue:
				task()
			}
		}
	}()
}

// TryEnqueue submits a task without blocking; returns false if the queue is full.
func (e *LoginExecutor) TryEnqueue(task func()) bool {
	select {
	case e.queue <- task:
		return true
	default:
		for {
			current := e.active.Load()
			if current >= int32(e.max) || e.ctx == nil {
				return false
			}
			if e.active.CompareAndSwap(current, current+1) {
				e.startReservedWorker(task)
				return true
			}
		}
	}
}

// Wait blocks until all workers have exited (after their context is cancelled).
func (e *LoginExecutor) Wait() { e.wg.Wait() }
