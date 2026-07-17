package com.theshuai.stunserver;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.LongAdder;
import java.util.function.IntSupplier;

final class StunServerMetrics {
    private final long startedNanos = System.nanoTime();
    private final LongAdder packetsReceived = new LongAdder();
    private final LongAdder requestsAccepted = new LongAdder();
    private final LongAdder bytesReceived = new LongAdder();
    private final LongAdder bytesSent = new LongAdder();
    private final Map<String, LongAdder> drops = new ConcurrentHashMap<>();
    private final Map<String, LongAdder> responses = new ConcurrentHashMap<>();
    private final Map<String, LongAdder> features = new ConcurrentHashMap<>();
    private final Map<String, LongAdder> distributed = new ConcurrentHashMap<>();

    void recordPacket(int bytes) {
        packetsReceived.increment();
        bytesReceived.add(Math.max(0, bytes));
    }

    void recordAcceptedRequest() {
        requestsAccepted.increment();
    }

    void recordDrop(String reason) {
        increment(drops, reason);
    }

    void recordResponse(int code, int bytes) {
        increment(responses, Integer.toString(code));
        bytesSent.add(Math.max(0, bytes));
    }

    void recordFeature(String feature) {
        increment(features, feature);
    }

    void recordDistributed(String event) {
        increment(distributed, event);
    }

    String render(IntSupplier trackedSources) {
        StringBuilder result = new StringBuilder(2_048);
        appendCounter(result, "stun_packets_received_total",
                "UDP datagrams received by the STUN service.", packetsReceived.sum());
        appendCounter(result, "stun_requests_accepted_total",
                "Valid Binding requests accepted for processing.", requestsAccepted.sum());
        appendCounter(result, "stun_bytes_received_total",
                "UDP payload bytes received by the STUN service.", bytesReceived.sum());
        appendCounter(result, "stun_bytes_sent_total",
                "STUN response payload bytes sent by the service.", bytesSent.sum());
        appendLabelCounters(result, "stun_packets_dropped_total",
                "UDP datagrams dropped before a response was sent.", "reason", drops);
        appendLabelCounters(result, "stun_responses_total",
                "STUN Binding responses sent by response code.", "code", responses);
        appendLabelCounters(result, "stun_feature_requests_total",
                "Accepted Binding requests using RFC 5780 features.", "feature", features);
        appendLabelCounters(result, "stun_distributed_forward_total",
                "Authenticated inter-node STUN forwarding events.", "event", distributed);
        result.append("# HELP stun_tracked_sources Current source IP token buckets.\n")
                .append("# TYPE stun_tracked_sources gauge\n")
                .append("stun_tracked_sources ")
                .append(Math.max(0, trackedSources.getAsInt()))
                .append('\n');
        result.append("# HELP stun_uptime_seconds STUN process uptime in seconds.\n")
                .append("# TYPE stun_uptime_seconds gauge\n")
                .append("stun_uptime_seconds ")
                .append(Math.max(0, (System.nanoTime() - startedNanos) / 1_000_000_000L))
                .append('\n');
        return result.toString();
    }

    private static void increment(Map<String, LongAdder> counters, String label) {
        counters.computeIfAbsent(label == null ? "unknown" : label, ignored -> new LongAdder())
                .increment();
    }

    private static void appendCounter(
            StringBuilder result,
            String name,
            String help,
            long value) {
        result.append("# HELP ").append(name).append(' ').append(help).append('\n')
                .append("# TYPE ").append(name).append(" counter\n")
                .append(name).append(' ').append(value).append('\n');
    }

    private static void appendLabelCounters(
            StringBuilder result,
            String name,
            String help,
            String labelName,
            Map<String, LongAdder> counters) {
        result.append("# HELP ").append(name).append(' ').append(help).append('\n')
                .append("# TYPE ").append(name).append(" counter\n");
        counters.entrySet().stream()
                .sorted(Map.Entry.comparingByKey())
                .forEach(entry -> result.append(name)
                        .append('{')
                        .append(labelName)
                        .append("=\"")
                        .append(escape(entry.getKey()))
                        .append("\"} ")
                        .append(entry.getValue().sum())
                        .append('\n'));
    }

    private static String escape(String value) {
        return value.replace("\\", "\\\\").replace("\"", "\\\"");
    }
}
