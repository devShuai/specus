package com.theshuai.specusclient.peer;

import static org.junit.jupiter.api.Assertions.assertTrue;

import com.theshuai.specusclient.peer.PeerEgressSegment.Segment;
import java.io.ByteArrayOutputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.PriorityQueue;
import java.util.Random;
import java.util.TreeMap;
import org.junit.jupiter.api.Test;

/**
 * Drives the egress's TCP state machine through a lossy link against a minimal receiver, the way the
 * lab's 2% loss step does, but deterministically: a seed that stalls stalls every time.
 *
 * <p>The lab once saw a 512 KiB download stop 688 bytes short of the end, the last partial segment,
 * and wait out curl's 60 seconds. Nothing in the logs said why; this is where a stall can be found.
 */
class PeerEgressLossSimulationTests {

    private static final int CONSUMER_IP = 0x64600002;
    private static final int TARGET_IP = 0xCB00710A;
    private static final int LATENCY_MS = 5;
    private static final int TICK_MS = 10;

    private record Packet(long at, long order, boolean toEgress, byte[] bytes) {
    }

    /** The consumer's kernel, as far as receiving goes: in-order delivery, an ACK per segment. */
    private static final class Receiver {
        int rcvNxt;
        final TreeMap<Integer, byte[]> outOfOrder = new TreeMap<>();
        final ByteArrayOutputStream received = new ByteArrayOutputStream();
        Integer finAt;
        boolean finished;
    }

    private static final List<Long> DURATIONS = new ArrayList<>();

    private static String simulate(long seed, int bytes, double loss) {
        Random random = new Random(seed);
        PriorityQueue<Packet> link = new PriorityQueue<>((a, b) -> a.at != b.at ? Long.compare(a.at, b.at) : Long.compare(a.order, b.order));
        long[] order = {0};
        long now = 0;
        int consumerIss = 1000;
        Segment syn = new Segment(CONSUMER_IP, TARGET_IP, 40000, 80, consumerIss, 0,
                PeerEgressSegment.FLAG_SYN, 65535, 1360, new byte[0]);
        PeerEgressTcpConnection.Output first = new PeerEgressTcpConnection.Output();
        PeerEgressTcpConnection egress = PeerEgressTcpConnection.accept(syn, 7777, 1400, 60_000, now, first);
        Receiver receiver = new Receiver();
        receiver.rcvNxt = -1;
        byte[] data = new byte[bytes];
        random.nextBytes(data);
        int read = 0;
        boolean closed = false;

        List<byte[]> pendingOut = new ArrayList<>(first.segments);
        long nextTick = TICK_MS;
        while (now < 120_000) {
            for (byte[] packet : pendingOut) {
                if (random.nextDouble() >= loss) {
                    link.add(new Packet(now + LATENCY_MS, order[0]++, false, packet));
                }
            }
            pendingOut.clear();
            // The reader reads whenever there is credit, as the socket reader does.
            if (egress.state() == PeerEgressTcpConnection.State.ESTABLISHED || egress.state() == PeerEgressTcpConnection.State.CLOSE_WAIT) {
                int credit = egress.appReadCredit();
                if (read < bytes && credit > 0) {
                    int n = Math.min(credit, Math.min(16384, bytes - read));
                    pendingOut.addAll(egress.onAppData(Arrays.copyOfRange(data, read, read + n), now).segments);
                    read += n;
                    continue;
                }
                if (read == bytes && !closed) {
                    closed = true;
                    pendingOut.addAll(egress.onAppClose(now).segments);
                    continue;
                }
            }
            if (receiver.finished) {
                if (!Arrays.equals(receiver.received.toByteArray(), data)) {
                    return "finished with " + receiver.received.size() + " bytes that differ from what was sent";
                }
                DURATIONS.add(now);
                return null;
            }
            Packet next = link.peek();
            if (next == null || next.at > nextTick) {
                now = nextTick;
                nextTick += TICK_MS;
                pendingOut.addAll(egress.onTick(now).segments);
                if (egress.done()) {
                    return receiver.finished ? null : "egress closed after " + receiver.received.size() + " bytes";
                }
                continue;
            }
            link.poll();
            now = next.at;
            if (next.toEgress) {
                PeerEgressTcpConnection.Output output = egress.onSegment(PeerEgressSegment.parse(next.bytes), now);
                pendingOut.addAll(output.segments);
                continue;
            }
            Segment segment = PeerEgressSegment.parse(next.bytes);
            if (segment.has(PeerEgressSegment.FLAG_RST)) {
                return "reset after " + receiver.received.size() + " bytes";
            }
            if (segment.has(PeerEgressSegment.FLAG_SYN)) {
                receiver.rcvNxt = segment.seq() + 1;
            } else if (receiver.rcvNxt >= 0) {
                int seq = segment.seq();
                byte[] payload = segment.payload();
                if (payload.length > 0 && PeerEgressSegment.seqLessEqual(seq + payload.length, receiver.rcvNxt)) {
                    // A duplicate: nothing new.
                } else if (payload.length > 0) {
                    receiver.outOfOrder.put(seq, payload);
                }
                if (segment.has(PeerEgressSegment.FLAG_FIN)) {
                    receiver.finAt = seq + payload.length;
                }
                boolean advanced = true;
                while (advanced) {
                    advanced = false;
                    for (var candidate : new ArrayList<>(receiver.outOfOrder.entrySet())) {
                        int start = candidate.getKey();
                        byte[] bytesAt = candidate.getValue();
                        int end = start + bytesAt.length;
                        if (PeerEgressSegment.seqLessEqual(start, receiver.rcvNxt) && PeerEgressSegment.seqLess(receiver.rcvNxt, end)) {
                            int skip = receiver.rcvNxt - start;
                            receiver.received.write(bytesAt, skip, bytesAt.length - skip);
                            receiver.rcvNxt = end;
                            receiver.outOfOrder.remove(start);
                            advanced = true;
                        } else if (PeerEgressSegment.seqLessEqual(end, receiver.rcvNxt)) {
                            receiver.outOfOrder.remove(start);
                        }
                    }
                }
                if (receiver.finAt != null && receiver.finAt == receiver.rcvNxt) {
                    receiver.rcvNxt++;
                    receiver.finished = true;
                }
            }
            // An ACK for every segment, the way a receiver answers loss.
            byte[] ack = PeerEgressSegment.build(new Segment(CONSUMER_IP, TARGET_IP, 40000, 80,
                    consumerIss + 1, receiver.rcvNxt, PeerEgressSegment.FLAG_ACK, 65535, 0, new byte[0]));
            if (random.nextDouble() >= loss) {
                link.add(new Packet(now + LATENCY_MS, order[0]++, true, ack));
            }
        }
        return "stalled at " + receiver.received.size() + " of " + bytes + " bytes, egress " + egress.state()
                + ", read " + read + ", closed " + closed;
    }

    @Test
    void aDownloadCompletesThroughTwoPercentLossEachWay() {
        List<String> stalls = new ArrayList<>();
        for (long seed = 0; seed < 300; seed++) {
            String outcome = simulate(seed, 512 * 1024, 0.02);
            if (outcome != null) {
                stalls.add("seed " + seed + ": " + outcome);
            }
        }
        List<Long> sorted = new ArrayList<>(DURATIONS);
        java.util.Collections.sort(sorted);
        System.out.println("SIM completed=" + sorted.size() + " median_ms=" + (sorted.isEmpty() ? -1 : sorted.get(sorted.size() / 2))
                + " max_ms=" + (sorted.isEmpty() ? -1 : sorted.get(sorted.size() - 1)));
        assertTrue(stalls.isEmpty(), String.join("\n", stalls));
    }
}
