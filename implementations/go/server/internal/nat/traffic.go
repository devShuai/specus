package nat

import (
	"context"
	"log/slog"
	"strconv"
	"sync"
	"time"

	"github.com/devShuai/shuai-tunnel/tunnel-server-go/internal/store"
)

type trafficCounter struct {
	upload   int64
	download int64
}

type resourceCounterKey struct {
	clientName   string
	resourceType string
	resourceKey  string
}

const (
	ResourceTypeTCPTunnel = "TCP_TUNNEL"
	ResourceTypeHTTPRoute = "HTTP_ROUTE"
)

// TrafficService accumulates per-client upload/download byte counts in memory and flushes
// them to tunnel_traffic_usage on a fixed interval. Mirrors the C# TrafficUsageService.
type TrafficService struct {
	db       *store.DB
	logger   *slog.Logger
	interval time.Duration

	mu               sync.Mutex
	counters         map[string]*trafficCounter
	resourceCounters map[resourceCounterKey]*trafficCounter
}

// NewTrafficService builds the traffic accumulator with the given flush interval.
func NewTrafficService(db *store.DB, interval time.Duration, logger *slog.Logger) *TrafficService {
	if interval < 100*time.Millisecond {
		interval = 100 * time.Millisecond
	}
	return &TrafficService{
		db:               db,
		logger:           logger,
		interval:         interval,
		counters:         make(map[string]*trafficCounter),
		resourceCounters: make(map[resourceCounterKey]*trafficCounter),
	}
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

func (s *TrafficService) RecordTCPUpload(clientName string, listenPort int, bytes int64) {
	s.RecordUpload(clientName, bytes)
	if listenPort > 0 {
		s.recordResourceUpload(clientName, ResourceTypeTCPTunnel, tcpResourceKey(listenPort), bytes)
	}
}

func (s *TrafficService) RecordTCPDownload(clientName string, listenPort int, bytes int64) {
	s.RecordDownload(clientName, bytes)
	if listenPort > 0 {
		s.recordResourceDownload(clientName, ResourceTypeTCPTunnel, tcpResourceKey(listenPort), bytes)
	}
}

func (s *TrafficService) RecordHTTPUpload(clientName, route string, bytes int64) {
	s.RecordUpload(clientName, bytes)
	s.recordResourceUpload(clientName, ResourceTypeHTTPRoute, httpResourceKey(route), bytes)
}

func (s *TrafficService) RecordHTTPDownload(clientName, route string, bytes int64) {
	s.RecordDownload(clientName, bytes)
	s.recordResourceDownload(clientName, ResourceTypeHTTPRoute, httpResourceKey(route), bytes)
}

func (s *TrafficService) counterFor(clientName string) *trafficCounter {
	counter, ok := s.counters[clientName]
	if !ok {
		counter = &trafficCounter{}
		s.counters[clientName] = counter
	}
	return counter
}

func (s *TrafficService) recordResourceUpload(clientName, resourceType, resourceKey string, bytes int64) {
	if clientName == "" || bytes <= 0 {
		return
	}
	s.mu.Lock()
	s.resourceCounterFor(resourceCounterKey{clientName: clientName, resourceType: resourceType, resourceKey: resourceKey}).upload += bytes
	s.mu.Unlock()
}

func (s *TrafficService) recordResourceDownload(clientName, resourceType, resourceKey string, bytes int64) {
	if clientName == "" || bytes <= 0 {
		return
	}
	s.mu.Lock()
	s.resourceCounterFor(resourceCounterKey{clientName: clientName, resourceType: resourceType, resourceKey: resourceKey}).download += bytes
	s.mu.Unlock()
}

func (s *TrafficService) resourceCounterFor(key resourceCounterKey) *trafficCounter {
	counter, ok := s.resourceCounters[key]
	if !ok {
		counter = &trafficCounter{}
		s.resourceCounters[key] = counter
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
	resourceSnapshot := s.resourceCounters
	s.resourceCounters = make(map[resourceCounterKey]*trafficCounter)
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
	for key, counter := range resourceSnapshot {
		if counter.upload == 0 && counter.download == 0 {
			continue
		}
		if err := s.flushResourceOne(ctx, key, usageDate, counter); err != nil {
			s.logger.Error("resource traffic flush failed", "client", key.clientName, "type", key.resourceType,
				"resource", key.resourceKey, "err", err)
			s.mu.Lock()
			c := s.resourceCounterFor(key)
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
	return s.db.AddTraffic(ctx, *account, usageDate, counter.upload, counter.download)
}

func (s *TrafficService) flushResourceOne(ctx context.Context, key resourceCounterKey, usageDate string, counter *trafficCounter) error {
	account, err := s.db.FindClientByName(ctx, key.clientName)
	if err != nil {
		return err
	}
	if account == nil {
		return nil
	}
	return s.db.AddResourceTraffic(ctx, *account, key.resourceType, key.resourceKey, usageDate, counter.upload, counter.download)
}

func tcpResourceKey(listenPort int) string {
	return "tcp:" + strconv.Itoa(listenPort)
}

func httpResourceKey(route string) string {
	return "http:" + route
}
