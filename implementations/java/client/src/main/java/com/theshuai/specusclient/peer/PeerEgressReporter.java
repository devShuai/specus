package com.theshuai.specusclient.peer;

import com.theshuai.common.peeregress.PeerEgressReportMessage;
import java.util.Map;
import java.util.TreeMap;

/**
 * When this node, serving as an egress, tells the server what it is doing, and what it says.
 *
 * <p>The server keeps only the latest {@code egress-report} of each egress and shows it on the
 * admin activity page. So a report carries the running totals of the local status rather than
 * counts for an interval, and is sent only when there is something new to show: once per control
 * session, and whenever a number moved. A check runs every {@link #INTERVAL_MS}; see
 * {@code protocol/spec/peer-egress.md} ({@code egress-report}) and the shared vector
 * {@code protocol/test-vectors/peer-egress-report-v1.json}.
 *
 * <p>Pure: time arrives as an argument and the numbers as the status snapshot, so the vector can
 * drive it without a clock or a network. One per egress process; safe to call from the check's
 * thread and the control connection's at once.
 */
final class PeerEgressReporter {

    /** How often the egress checks whether to report; the vector's {@code intervalSeconds}. */
    static final long INTERVAL_MS = 60_000L;

    /** The numbers a report is compared by, as the status gave them. */
    private record Counters(long flows, long totalFlows, Map<String, Long> refused, long bytesIn, long bytesOut) {
    }

    /**
     * The last revision sent. Never reset: the server ignores a report below the one it holds, and
     * that one may come from an earlier session or an earlier process.
     */
    private long revision;

    /** What the last report of this control session said, while the egress ran; null for none. */
    private Counters lastSent;

    /**
     * A new control session. The server behind it may have restarted or lost the row, so the next
     * check reports whether or not anything changed.
     */
    synchronized void newSession() {
        lastSent = null;
    }

    /**
     * One check: the report to send now, or null.
     *
     * <p>Nothing while the egress is switched off, and the first check after it is switched on
     * again reports. Otherwise a report goes when none went in this session yet or when any number
     * differs from the last one sent, so an idle egress sends one and then stays quiet.
     *
     * @param wallMs  the wall clock in milliseconds. The revision is this, or one above the last
     *                when the clock stands still or stepped back: counting from 1 instead would
     *                put a restarted egress below what the server holds, and it would drop every
     *                report as stale
     * @param runtime the egress section's source, the same snapshot the local status reads; null
     *                while this node never received an egress-config
     */
    synchronized PeerEgressReportMessage check(long wallMs, PeerEgressStatus.RuntimeSnapshot runtime) {
        if (runtime == null || !runtime.enabled()) {
            lastSent = null;
            return null;
        }
        Map<String, Long> refused = runtime.refused() == null ? Map.of() : new TreeMap<>(runtime.refused());
        Counters now = new Counters(runtime.flows(), runtime.stats().totalFlows(), refused,
                runtime.stats().bytesIn(), runtime.stats().bytesOut());
        if (now.equals(lastSent)) {
            return null;
        }
        revision = Math.max(revision + 1, wallMs);
        lastSent = now;
        return new PeerEgressReportMessage(revision, now.flows(), now.totalFlows(), now.refused(),
                now.bytesIn(), now.bytesOut());
    }
}
