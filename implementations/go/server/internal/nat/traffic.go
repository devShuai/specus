package nat

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/devShuai/shuai-tunnel/tunnel-server-go/internal/store"
)

type trafficCounter struct {
	upload   int64
	download int64
}

// TrafficService accumulates per-client upload/download byte counts in memory and flushes
// them to tunnel_traffic_usage on a fixed interval. Mirrors the C# TrafficUsageService.
type TrafficService struct {
	db       *store.DB
	logger   *slog.Logger
	interval time.Duration

	mu       sync.Mutex
	counters map[string]*trafficCounter
}

// NewTrafficService builds the traffic accumulator with the given flush interval.
func NewTrafficService(db *store.DB, interval time.Duration, logger *slog.Logger) *TrafficService {
	if interval < 100*time.Millisecond {
		interval = 100 * time.Millisecond
	}
	return &TrafficService{db: db, logger: logger, interval: interval, counters: make(map[string]*trafficCounter)}
}

// RecordUpload adds bytes sent from a client to its upstream service.
func (s *TrafficService) RecordUpload(clientName string, bytes int64) {
	if clientName == "" || bytes <= 0 {
		return
	}
	s.mu.Lock()
	s.counterFor(clientName).upload += bytes
	s.mu.Unlock()
}

// RecordDownload adds bytes received from an external connection toward a client.
func (s *TrafficService) RecordDownload(clientName string, bytes int64) {
	if clientName == "" || bytes <= 0 {
		return
	}
	s.mu.Lock()
	s.counterFor(clientName).download += bytes
	s.mu.Unlock()
}

func (s *TrafficService) counterFor(clientName string) *trafficCounter {
	counter, ok := s.counters[clientName]
	if !ok {
		counter = &trafficCounter{}
		s.counters[clientName] = counter
	}
	return counter
}

// Run flushes on a fixed interval until ctx is cancelled, then performs a final flush.
func (s *TrafficService) Run(ctx context.Context) {
	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			s.Flush(context.Background())
			return
		case <-ticker.C:
			s.Flush(ctx)
		}
	}
}

// Flush persists and resets the accumulated counters. Failed clients are re-credited so no
// bytes are lost.
func (s *TrafficService) Flush(ctx context.Context) {
	s.mu.Lock()
	snapshot := s.counters
	s.counters = make(map[string]*trafficCounter)
	s.mu.Unlock()

	usageDate := time.Now().UTC().Format("2006-01-02")
	for clientName, counter := range snapshot {
		if counter.upload == 0 && counter.download == 0 {
			continue
		}
		if err := s.flushOne(ctx, clientName, usageDate, counter); err != nil {
			s.logger.Error("traffic flush failed", "client", clientName, "err", err)
			s.mu.Lock()
			c := s.counterFor(clientName)
			c.upload += counter.upload
			c.download += counter.download
			s.mu.Unlock()
		}
	}
}

func (s *TrafficService) flushOne(ctx context.Context, clientName, usageDate string, counter *trafficCounter) error {
	account, err := s.db.FindClientByName(ctx, clientName)
	if err != nil {
		return err
	}
	if account == nil {
		return nil // client deleted; drop the counters
	}
	return s.db.AddTraffic(ctx, account.ID, clientName, usageDate, counter.upload, counter.download)
}
