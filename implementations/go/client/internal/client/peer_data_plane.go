package client

import (
	"net"
	"runtime"
	"sync"
	"sync/atomic"
)

const (
	// A full queue drops frames instead of stalling the receive loop, so the capacity only needs to
	// absorb a burst while the virtual device catches up. Mirrors the Java client.
	peerDataPlaneQueueCapacity = 2048
	minPeerDataPlaneWorkers    = 2
	maxPeerDataPlaneWorkers    = 8
)

type peerDataFrameTask struct {
	payload   []byte
	remote    *net.UDPAddr
	relayFrom string
}

// peerDataPlane moves peer data frames off the single UDP receive loop.
//
// Decrypting a frame ends in a write to the virtual device, which can block for as long as the OS
// wants. Handling frames inline meant one slow TUN write — or a flood of data frames — stalled the
// receive loop that also carries STUN binding responses, TURN refreshes, keepalive replies and the
// probe results that drive path switching: the mesh went blind exactly when it was busiest.
//
// Frames are sharded by session id so each session keeps its ordering (the replay window depends on
// it), and every shard has a bounded queue. When a shard is saturated the frame is dropped rather
// than queued without limit, matching the Java worker's abort policy: UDP is lossy by contract and
// the peer will retransmit, whereas unbounded buffering would trade liveness for memory.
type peerDataPlane struct {
	queues    []chan peerDataFrameTask
	handle    func(payload []byte, remote *net.UDPAddr, relayFrom string)
	stopCh    chan struct{}
	stopOnce  sync.Once
	wg        sync.WaitGroup
	rejected  atomic.Int64
	accepted  atomic.Int64
	highWater atomic.Int64
}

func newPeerDataPlane(workers, capacity int,
	handle func(payload []byte, remote *net.UDPAddr, relayFrom string)) *peerDataPlane {
	if handle == nil {
		return nil
	}
	workers = boundPeerDataPlaneWorkers(workers)
	if capacity <= 0 {
		capacity = peerDataPlaneQueueCapacity
	}
	plane := &peerDataPlane{
		queues: make([]chan peerDataFrameTask, workers),
		handle: handle,
		stopCh: make(chan struct{}),
	}
	for index := range plane.queues {
		plane.queues[index] = make(chan peerDataFrameTask, capacity)
		plane.wg.Add(1)
		go plane.work(plane.queues[index])
	}
	return plane
}

// defaultPeerDataPlaneWorkers sizes the pool from the CPU count, clamped like the Java client.
func defaultPeerDataPlaneWorkers() int {
	return boundPeerDataPlaneWorkers(runtime.NumCPU())
}

func boundPeerDataPlaneWorkers(workers int) int {
	if workers < minPeerDataPlaneWorkers {
		return minPeerDataPlaneWorkers
	}
	if workers > maxPeerDataPlaneWorkers {
		return maxPeerDataPlaneWorkers
	}
	return workers
}

func (plane *peerDataPlane) work(queue chan peerDataFrameTask) {
	defer plane.wg.Done()
	for {
		select {
		case <-plane.stopCh:
			return
		case task := <-queue:
			plane.handle(task.payload, task.remote, task.relayFrom)
		}
	}
}

// submit hands the frame to the shard owning sessionID. It never blocks: false means the shard was
// saturated and the caller should drop the frame.
func (plane *peerDataPlane) submit(sessionID int64, task peerDataFrameTask) bool {
	if plane == nil || len(plane.queues) == 0 {
		return false
	}
	select {
	case <-plane.stopCh:
		return false
	default:
	}
	queue := plane.queues[peerDataPlaneShard(sessionID, len(plane.queues))]
	select {
	case queue <- task:
		plane.accepted.Add(1)
		if depth := int64(len(queue)); depth > plane.highWater.Load() {
			plane.highWater.Store(depth)
		}
		return true
	default:
		plane.rejected.Add(1)
		return false
	}
}

func peerDataPlaneShard(sessionID int64, shards int) int {
	if shards <= 1 {
		return 0
	}
	shard := sessionID % int64(shards)
	if shard < 0 {
		shard += int64(shards)
	}
	return int(shard)
}

// close stops the workers. It returns without waiting for in-flight frames so a caller holding the
// mesh lock can never deadlock against a worker that needs the same lock.
func (plane *peerDataPlane) close() {
	if plane == nil {
		return
	}
	plane.stopOnce.Do(func() { close(plane.stopCh) })
}

func (plane *peerDataPlane) wait() {
	if plane == nil {
		return
	}
	plane.wg.Wait()
}

type peerDataPlaneStats struct {
	Workers   int
	Accepted  int64
	Rejected  int64
	Depth     int
	HighWater int64
}

func (plane *peerDataPlane) stats() peerDataPlaneStats {
	if plane == nil {
		return peerDataPlaneStats{}
	}
	depth := 0
	for _, queue := range plane.queues {
		depth += len(queue)
	}
	return peerDataPlaneStats{
		Workers:   len(plane.queues),
		Accepted:  plane.accepted.Load(),
		Rejected:  plane.rejected.Load(),
		Depth:     depth,
		HighWater: plane.highWater.Load(),
	}
}
