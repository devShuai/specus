package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

var latencyBounds = []time.Duration{
	50 * time.Microsecond, 100 * time.Microsecond, 200 * time.Microsecond,
	500 * time.Microsecond, time.Millisecond, 2 * time.Millisecond, 5 * time.Millisecond,
	10 * time.Millisecond, 20 * time.Millisecond, 50 * time.Millisecond,
	100 * time.Millisecond, 200 * time.Millisecond, 500 * time.Millisecond,
	time.Second, 2 * time.Second, 5 * time.Second, 10 * time.Second, 30 * time.Second,
}

type latencyHistogram struct {
	buckets []atomic.Uint64
}

func newLatencyHistogram() *latencyHistogram {
	return &latencyHistogram{buckets: make([]atomic.Uint64, len(latencyBounds)+1)}
}

func (h *latencyHistogram) observe(value time.Duration) {
	index := sort.Search(len(latencyBounds), func(index int) bool {
		return value <= latencyBounds[index]
	})
	h.buckets[index].Add(1)
}

func (h *latencyHistogram) quantile(percentile float64) time.Duration {
	var total uint64
	for index := range h.buckets {
		total += h.buckets[index].Load()
	}
	if total == 0 {
		return 0
	}
	target := uint64(float64(total-1)*percentile) + 1
	var current uint64
	for index := range h.buckets {
		current += h.buckets[index].Load()
		if current >= target {
			if index == len(latencyBounds) {
				return latencyBounds[len(latencyBounds)-1]
			}
			return latencyBounds[index]
		}
	}
	return latencyBounds[len(latencyBounds)-1]
}

type levelCounters struct {
	connectionsOpened atomic.Uint64
	connectErrors     atomic.Uint64
	operations        atomic.Uint64
	operationErrors   atomic.Uint64
	transferredBytes  atomic.Uint64
	latency           *latencyHistogram
}

type levelReport struct {
	Concurrency       int     `json:"concurrency"`
	DurationSeconds   float64 `json:"durationSeconds"`
	ConnectionsOpened uint64  `json:"connectionsOpened"`
	ConnectErrors     uint64  `json:"connectErrors"`
	Operations        uint64  `json:"operations"`
	OperationErrors   uint64  `json:"operationErrors"`
	ErrorRate         float64 `json:"errorRate"`
	TransferredBytes  uint64  `json:"transferredBytes"`
	MegabitsPerSecond float64 `json:"megabitsPerSecond"`
	P50               string  `json:"p50"`
	P95               string  `json:"p95"`
	P99               string  `json:"p99"`
}

type capacityReport struct {
	GeneratedAt string        `json:"generatedAt"`
	Target      string        `json:"target"`
	Runtime     string        `json:"runtime"`
	Payload     int           `json:"payloadBytes"`
	SlowRead    string        `json:"slowReadDelay"`
	Levels      []levelReport `json:"levels"`
}

func main() {
	target := flag.String("addr", "127.0.0.1:19000", "TCP echo endpoint, normally a public specus port")
	levelsValue := flag.String("levels", "1,10,100,1000", "comma-separated concurrent stream levels")
	duration := flag.Duration("duration", 30*time.Second, "measurement duration per level")
	payloadBytes := flag.Int("payload", 16*1024, "echo payload bytes per operation")
	slowRead := flag.Duration("slow-read", 0, "delay before each response read")
	dialTimeout := flag.Duration("dial-timeout", 5*time.Second, "TCP connect timeout")
	operationTimeout := flag.Duration("operation-timeout", 10*time.Second, "write plus echo read timeout")
	pause := flag.Duration("pause", 3*time.Second, "pause between levels")
	output := flag.String("output", "", "optional JSON report path")
	flag.Parse()

	levels, err := parseLevels(*levelsValue)
	if err != nil {
		fatal(err)
	}
	if *duration <= 0 || *payloadBytes <= 0 || *payloadBytes > 1024*1024 ||
		*dialTimeout <= 0 || *operationTimeout <= 0 || *slowRead < 0 {
		fatal(fmt.Errorf("duration/timeouts and payload must be positive; payload is limited to 1 MiB"))
	}
	payload := make([]byte, *payloadBytes)
	for index := range payload {
		payload[index] = byte(index * 31)
	}

	report := capacityReport{
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		Target:      *target,
		Runtime:     runtime.Version() + "/" + runtime.GOOS + "/" + runtime.GOARCH,
		Payload:     *payloadBytes,
		SlowRead:    slowRead.String(),
		Levels:      make([]levelReport, 0, len(levels)),
	}
	for index, concurrency := range levels {
		fmt.Fprintf(os.Stderr, "running concurrency=%d duration=%s target=%s\n",
			concurrency, duration.String(), *target)
		result := runLevel(*target, concurrency, *duration, payload, *slowRead,
			*dialTimeout, *operationTimeout)
		report.Levels = append(report.Levels, result)
		fmt.Fprintf(os.Stderr,
			"complete concurrency=%d ops=%d errors=%d throughput=%.2f Mbit/s p99=%s\n",
			result.Concurrency, result.Operations,
			result.ConnectErrors+result.OperationErrors, result.MegabitsPerSecond, result.P99)
		if index+1 < len(levels) && *pause > 0 {
			time.Sleep(*pause)
		}
	}

	encoded, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		fatal(err)
	}
	encoded = append(encoded, '\n')
	if *output != "" {
		if err := os.WriteFile(*output, encoded, 0o600); err != nil {
			fatal(err)
		}
	}
	_, _ = os.Stdout.Write(encoded)
}

func runLevel(target string, concurrency int, duration time.Duration, payload []byte,
	slowRead, dialTimeout, operationTimeout time.Duration) levelReport {
	ctx, cancel := context.WithTimeout(context.Background(), duration)
	defer cancel()
	counters := &levelCounters{latency: newLatencyHistogram()}
	started := time.Now()
	var workers sync.WaitGroup
	workers.Add(concurrency)
	for worker := 0; worker < concurrency; worker++ {
		go func() {
			defer workers.Done()
			runWorker(ctx, target, payload, slowRead, dialTimeout, operationTimeout, counters)
		}()
	}
	workers.Wait()
	elapsed := time.Since(started)
	operations := counters.operations.Load()
	errors := counters.connectErrors.Load() + counters.operationErrors.Load()
	attempts := operations + errors
	errorRate := 0.0
	if attempts > 0 {
		errorRate = float64(errors) / float64(attempts)
	}
	transferred := counters.transferredBytes.Load()
	return levelReport{
		Concurrency:       concurrency,
		DurationSeconds:   elapsed.Seconds(),
		ConnectionsOpened: counters.connectionsOpened.Load(),
		ConnectErrors:     counters.connectErrors.Load(),
		Operations:        operations,
		OperationErrors:   counters.operationErrors.Load(),
		ErrorRate:         errorRate,
		TransferredBytes:  transferred,
		MegabitsPerSecond: float64(transferred*8) / elapsed.Seconds() / 1_000_000,
		P50:               counters.latency.quantile(0.50).String(),
		P95:               counters.latency.quantile(0.95).String(),
		P99:               counters.latency.quantile(0.99).String(),
	}
}

func runWorker(ctx context.Context, target string, payload []byte, slowRead, dialTimeout,
	operationTimeout time.Duration, counters *levelCounters) {
	dialer := net.Dialer{Timeout: dialTimeout, KeepAlive: 30 * time.Second}
	response := make([]byte, len(payload))
	for ctx.Err() == nil {
		conn, err := dialer.DialContext(ctx, "tcp", target)
		if err != nil {
			if ctx.Err() == nil {
				counters.connectErrors.Add(1)
				waitForRetry(ctx)
			}
			continue
		}
		counters.connectionsOpened.Add(1)
		runConnection(ctx, conn, payload, response, slowRead, operationTimeout, counters)
		_ = conn.Close()
	}
}

func runConnection(ctx context.Context, conn net.Conn, payload, response []byte, slowRead,
	operationTimeout time.Duration, counters *levelCounters) {
	for ctx.Err() == nil {
		deadline := time.Now().Add(operationTimeout)
		if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
			deadline = contextDeadline
		}
		_ = conn.SetDeadline(deadline)
		started := time.Now()
		if err := writeAll(conn, payload); err != nil {
			if ctx.Err() == nil {
				counters.operationErrors.Add(1)
			}
			return
		}
		if slowRead > 0 {
			select {
			case <-ctx.Done():
				return
			case <-time.After(slowRead):
			}
		}
		if _, err := io.ReadFull(conn, response); err != nil || !bytes.Equal(payload, response) {
			if ctx.Err() == nil {
				counters.operationErrors.Add(1)
			}
			return
		}
		counters.operations.Add(1)
		counters.transferredBytes.Add(uint64(len(payload) * 2))
		counters.latency.observe(time.Since(started))
	}
}

func writeAll(writer io.Writer, payload []byte) error {
	for len(payload) > 0 {
		written, err := writer.Write(payload)
		if err != nil {
			return err
		}
		if written <= 0 {
			return io.ErrUnexpectedEOF
		}
		payload = payload[written:]
	}
	return nil
}

func parseLevels(value string) ([]int, error) {
	seen := make(map[int]struct{})
	levels := make([]int, 0)
	for _, item := range strings.Split(value, ",") {
		parsed, err := strconv.Atoi(strings.TrimSpace(item))
		if err != nil || parsed <= 0 || parsed > 100_000 {
			return nil, fmt.Errorf("invalid concurrency level %q", item)
		}
		if _, exists := seen[parsed]; exists {
			continue
		}
		seen[parsed] = struct{}{}
		levels = append(levels, parsed)
	}
	if len(levels) == 0 {
		return nil, fmt.Errorf("at least one concurrency level is required")
	}
	return levels, nil
}

func waitForRetry(ctx context.Context) {
	select {
	case <-ctx.Done():
	case <-time.After(100 * time.Millisecond):
	}
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(2)
}
