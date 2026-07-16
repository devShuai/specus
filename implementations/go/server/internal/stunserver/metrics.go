package stunserver

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type Metrics struct {
	started          time.Time
	packetsReceived  atomic.Uint64
	requestsAccepted atomic.Uint64
	bytesReceived    atomic.Uint64
	bytesSent        atomic.Uint64
	mu               sync.Mutex
	drops            map[string]uint64
	responses        map[string]uint64
	features         map[string]uint64
}

func NewMetrics() *Metrics {
	return &Metrics{
		started:   time.Now(),
		drops:     make(map[string]uint64),
		responses: make(map[string]uint64),
		features:  make(map[string]uint64),
	}
}

func (m *Metrics) RecordPacket(bytes int) {
	m.packetsReceived.Add(1)
	m.bytesReceived.Add(uint64(max(0, bytes)))
}

func (m *Metrics) RecordAcceptedRequest() {
	m.requestsAccepted.Add(1)
}

func (m *Metrics) RecordDrop(reason string) {
	m.increment(m.drops, reason)
}

func (m *Metrics) RecordResponse(code, bytes int) {
	m.increment(m.responses, fmt.Sprintf("%d", code))
	m.bytesSent.Add(uint64(max(0, bytes)))
}

func (m *Metrics) RecordFeature(feature string) {
	m.increment(m.features, feature)
}

func (m *Metrics) Render(trackedSources int) string {
	var result strings.Builder
	appendMetric(&result, "stun_packets_received_total", "UDP datagrams received by the STUN service.", "counter", m.packetsReceived.Load())
	appendMetric(&result, "stun_requests_accepted_total", "Valid Binding requests accepted for processing.", "counter", m.requestsAccepted.Load())
	appendMetric(&result, "stun_bytes_received_total", "UDP payload bytes received by the STUN service.", "counter", m.bytesReceived.Load())
	appendMetric(&result, "stun_bytes_sent_total", "STUN response payload bytes sent by the service.", "counter", m.bytesSent.Load())
	m.mu.Lock()
	appendLabelMetrics(&result, "stun_packets_dropped_total", "UDP datagrams dropped before a response was sent.", "reason", m.drops)
	appendLabelMetrics(&result, "stun_responses_total", "STUN Binding responses sent by response code.", "code", m.responses)
	appendLabelMetrics(&result, "stun_feature_requests_total", "Accepted Binding requests using RFC 5780 features.", "feature", m.features)
	m.mu.Unlock()
	result.WriteString("# HELP stun_tracked_sources Current source IP token buckets.\n")
	result.WriteString("# TYPE stun_tracked_sources gauge\n")
	fmt.Fprintf(&result, "stun_tracked_sources %d\n", max(0, trackedSources))
	result.WriteString("# HELP stun_uptime_seconds STUN process uptime in seconds.\n")
	result.WriteString("# TYPE stun_uptime_seconds gauge\n")
	fmt.Fprintf(&result, "stun_uptime_seconds %d\n", int64(time.Since(m.started).Seconds()))
	return result.String()
}

func (m *Metrics) increment(values map[string]uint64, key string) {
	m.mu.Lock()
	values[key]++
	m.mu.Unlock()
}

func appendMetric(result *strings.Builder, name, help, metricType string, value uint64) {
	fmt.Fprintf(result, "# HELP %s %s\n# TYPE %s %s\n%s %d\n", name, help, name, metricType, name, value)
}

func appendLabelMetrics(result *strings.Builder, name, help, label string, values map[string]uint64) {
	fmt.Fprintf(result, "# HELP %s %s\n# TYPE %s counter\n", name, help, name)
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		fmt.Fprintf(result, "%s{%s=\"%s\"} %d\n", name, label, escapeMetricLabel(key), values[key])
	}
}

func escapeMetricLabel(value string) string {
	return strings.ReplaceAll(strings.ReplaceAll(value, `\`, `\\`), `"`, `\"`)
}
