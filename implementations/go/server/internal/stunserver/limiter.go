package stunserver

import (
	"net"
	"sync"
	"time"
)

type LimitDecision string

const (
	LimitAllowed        LimitDecision = "allowed"
	LimitGlobalRate     LimitDecision = "global_rate_limit"
	LimitSourceRate     LimitDecision = "source_rate_limit"
	LimitSourceTable    LimitDecision = "source_table_full"
	limiterCleanupEvery               = 1024
)

type RequestLimiter struct {
	mu      sync.Mutex
	config  ProtectionConfig
	global  tokenBucket
	sources map[string]*sourceBucket
	count   uint64
}

type sourceBucket struct {
	tokens   tokenBucket
	lastSeen time.Time
}

type tokenBucket struct {
	tokens  float64
	updated time.Time
}

func NewRequestLimiter(config ProtectionConfig) *RequestLimiter {
	now := time.Now()
	return &RequestLimiter{
		config:  config,
		global:  tokenBucket{tokens: float64(config.GlobalBurst), updated: now},
		sources: make(map[string]*sourceBucket),
	}
}

func (l *RequestLimiter) Allow(source net.IP) LimitDecision {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	l.count++
	if !l.global.consume(now, l.config.GlobalRatePerSecond, l.config.GlobalBurst) {
		return LimitGlobalRate
	}
	if l.count%limiterCleanupEvery == 0 {
		l.removeIdle(now)
	}
	key := source.String()
	bucket := l.sources[key]
	if bucket == nil {
		if len(l.sources) >= l.config.MaxTrackedSources {
			l.removeIdle(now)
		}
		if len(l.sources) >= l.config.MaxTrackedSources {
			return LimitSourceTable
		}
		bucket = &sourceBucket{
			tokens: tokenBucket{
				tokens:  float64(l.config.SourceBurst),
				updated: now,
			},
			lastSeen: now,
		}
		l.sources[key] = bucket
	}
	bucket.lastSeen = now
	if !bucket.tokens.consume(now, l.config.SourceRatePerSecond, l.config.SourceBurst) {
		return LimitSourceRate
	}
	return LimitAllowed
}

func (l *RequestLimiter) TrackedSources() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.removeIdle(time.Now())
	return len(l.sources)
}

func (l *RequestLimiter) removeIdle(now time.Time) {
	idle := time.Duration(l.config.SourceIdleSeconds) * time.Second
	for key, bucket := range l.sources {
		if now.Sub(bucket.lastSeen) >= idle {
			delete(l.sources, key)
		}
	}
}

func (b *tokenBucket) consume(now time.Time, rate, burst int) bool {
	elapsed := now.Sub(b.updated).Seconds()
	if elapsed > 0 {
		b.tokens = min(float64(burst), b.tokens+elapsed*float64(rate))
		b.updated = now
	}
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}
