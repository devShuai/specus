package com.theshuai.specusclient.peer;

import static org.junit.jupiter.api.Assertions.assertTrue;

import com.theshuai.specusclient.peer.PeerEgressSegment.Segment;
import java.io.ByteArrayOutputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.PriorityQueue;
import java.util.Random;
import java.util.Set;
import java.util.TreeMap;
import org.junit.jupiter.api.Test;

/**
 * Drives the egress's TCP state machine through a lossy link against a minimal receiver, the way the
 * lab's 2% loss step does, but deterministically: a seed that stalls stalls every time.
 *
 * <p>The lab once saw a 512 KiB download stop 688 bytes short of the end, the last partial segment,
 * and wait out curl's 60 seconds. Nothing in the logs said why; this is where a stall can be found.
 * A later snapshot caught one in progress: the egress's send buffer full, the consumer holding
 * everything after one hole, and nothing resent for 3.5 s. The timer was firing; the timeout it
 * fired on had grown with every recovery, which {@link #aRunOfLossesDoesNotStretchTheRetransmissionTimeout}
 * replays.
 */
class PeerEgressLossSimulationTests {

    private static final int CONSUMER_IP = 0x64600002;
    private static final int TARGET_IP = 0xCB00710A;
    private static final int LATENCY_MS = 5;
    private static final int TICK_MS = 10;
    /** What the egress plane's timer loop runs at, so retransmissions land on its ticks. */
    private static final int PLANE_TICK_MS = 100;

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

    private record Replay(boolean intact, long durationMs, long longestSilenceMs) {
    }

    /**
     * One 512 KiB response through the egress with chosen segments lost once on their way to the
     * consumer, and nothing else random: the upstream hands over everything the send buffer has
     * room for at once and then its end of stream, the consumer acknowledges only in-order data
     * (a duplicate ACK for anything after a hole), and time advances on the plane's 100 ms tick.
     * Reports whether the response arrived intact, when, and the longest the consumer heard nothing.
     */
    private static Replay replayScriptedLoss(int... lostSegments) {
        int responseBytes = 524_445; // the lab's 512 KiB body and its headers
        int consumerIss = 1000;
        long now = 0;
        Segment syn = new Segment(CONSUMER_IP, TARGET_IP, 40000, 80, consumerIss, 0,
                PeerEgressSegment.FLAG_SYN, 65535, 1240, new byte[0]);
        PeerEgressTcpConnection.Output first = new PeerEgressTcpConnection.Output();
        PeerEgressTcpConnection egress = PeerEgressTcpConnection.accept(syn, 7777, 1272, 60_000, now, first);
        int dataStart = PeerEgressSegment.parse(first.segments.get(0)).seq() + 1;
        egress.onSegment(new Segment(CONSUMER_IP, TARGET_IP, 40000, 80, consumerIss + 1, dataStart,
                PeerEgressSegment.FLAG_ACK, 65535, 0, new byte[0]), now);

        byte[] response = new byte[responseBytes];
        new Random(responseBytes).nextBytes(response);
        Set<Integer> toLose = new HashSet<>();
        for (int index : lostSegments) {
            toLose.add(index);
        }
        PriorityQueue<Packet> link = new PriorityQueue<>((a, b) -> a.at != b.at ? Long.compare(a.at, b.at) : Long.compare(a.order, b.order));
        long order = 0;
        int read = 0;
        boolean endOfStream = false;
        Receiver receiver = new Receiver();
        receiver.rcvNxt = dataStart;
        long lastHeard = now;
        long longestSilence = 0;
        long nextTick = PLANE_TICK_MS;
        List<byte[]> pendingOut = new ArrayList<>();
        while (now < 120_000 && !receiver.finished) {
            for (byte[] packet : pendingOut) {
                Segment segment = PeerEgressSegment.parse(packet);
                int index = (segment.seq() - dataStart) / egress.sendMss();
                if (segment.payload().length > 0 && toLose.remove(index)) {
                    continue;
                }
                link.add(new Packet(now + 1, order++, false, packet));
            }
            pendingOut.clear();
            if (egress.appReadCredit() > 0 && read < responseBytes) {
                int n = Math.min(egress.appReadCredit(), Math.min(32 * 1024, responseBytes - read));
                pendingOut.addAll(egress.onAppData(Arrays.copyOfRange(response, read, read + n), now).segments);
                read += n;
                continue;
            }
            if (read == responseBytes && !endOfStream) {
                endOfStream = true;
                pendingOut.addAll(egress.onAppClose(now).segments);
                continue;
            }
            Packet next = link.peek();
            if (next == null || next.at > nextTick) {
                now = nextTick;
                nextTick += PLANE_TICK_MS;
                pendingOut.addAll(egress.onTick(now).segments);
                if (egress.done()) {
                    break;
                }
                continue;
            }
            link.poll();
            now = next.at;
            if (next.toEgress) {
                pendingOut.addAll(egress.onSegment(PeerEgressSegment.parse(next.bytes), now).segments);
                continue;
            }
            longestSilence = Math.max(longestSilence, now - lastHeard);
            lastHeard = now;
            Segment segment = PeerEgressSegment.parse(next.bytes);
            if (segment.payload().length > 0 && PeerEgressSegment.seqLess(receiver.rcvNxt, segment.seq() + segment.payload().length)) {
                receiver.outOfOrder.put(segment.seq(), segment.payload());
            }
            if (segment.has(PeerEgressSegment.FLAG_FIN)) {
                receiver.finAt = segment.seq() + segment.payload().length;
            }
            while (true) {
                var head = receiver.outOfOrder.floorEntry(receiver.rcvNxt);
                if (head == null) {
                    break;
                }
                receiver.outOfOrder.remove(head.getKey());
                int end = head.getKey() + head.getValue().length;
                if (PeerEgressSegment.seqLess(receiver.rcvNxt, end)) {
                    int skip = receiver.rcvNxt - head.getKey();
                    receiver.received.write(head.getValue(), skip, head.getValue().length - skip);
                    receiver.rcvNxt = end;
                }
            }
            if (receiver.finAt != null && receiver.finAt == receiver.rcvNxt) {
                receiver.rcvNxt++;
                receiver.finished = true;
            }
            link.add(new Packet(now + 1, order++, true, PeerEgressSegment.build(new Segment(
                    CONSUMER_IP, TARGET_IP, 40000, 80, consumerIss + 1, receiver.rcvNxt,
                    PeerEgressSegment.FLAG_ACK, 65535, 0, new byte[0]))));
        }
        boolean intact = receiver.finished && Arrays.equals(receiver.received.toByteArray(), response);
        return new Replay(intact, now, longestSilence);
    }

    /**
     * The lab's stall, without randomness. Six segments lost a few apart, about 1.4% of the
     * response, used to leave the consumer holding the segments after a hole while the egress, its
     * 64 KiB send buffer full and the upstream read paused, did not resend the hole for seconds:
     * every recovery's ACK also acknowledged the segments sent beside the lost one, the egress took
     * their wait for a round trip, and each timeout came out longer than the last. Mid-stream that
     * was an 11.6 s silence and 21.3 s for the response; at the tail, with the upstream already at
     * end of stream and the last, partial segment among the lost, 9.6 s and 17.7 s. Now the longest
     * silence is about 0.3 s and the response takes under 2 s.
     */
    @Test
    void aRunOfLossesDoesNotStretchTheRetransmissionTimeout() {
        List<String> slow = new ArrayList<>();
        for (int[] lost : new int[][] {{100, 106, 112, 118, 124, 130}, {395, 401, 407, 413, 419, 425}}) {
            Replay replay = replayScriptedLoss(lost);
            System.out.println("REPLAY losing segments " + Arrays.toString(lost) + ": " + replay);
            // The lab's gate allows 10 s for the whole response; a hole should be resent within a
            // tick or two of the 200 ms floor, not after a second of silence.
            if (!replay.intact() || replay.longestSilenceMs() > 1_000 || replay.durationMs() > 10_000) {
                slow.add("losing segments " + Arrays.toString(lost) + ": " + replay);
            }
        }
        assertTrue(slow.isEmpty(), String.join("\n", slow));
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
