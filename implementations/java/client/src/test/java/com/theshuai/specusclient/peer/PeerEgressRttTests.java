package com.theshuai.specusclient.peer;

import static org.junit.jupiter.api.Assertions.*;
import org.junit.jupiter.api.Test;

class PeerEgressRttTests {
    private PeerEgressSegment.Segment ack(int next) {
        return new PeerEgressSegment.Segment(0x64600001, 0xcb00710a, 40000, 443,
                1001, next, PeerEgressSegment.FLAG_ACK, 65535, 0, new byte[0]);
    }

    private PeerEgressTcpConnection afterRetransmittedAck() {
        var syn = new PeerEgressSegment.Segment(0x64600001, 0xcb00710a, 40000, 443,
                1000, 0, PeerEgressSegment.FLAG_SYN, 65535, 1240, new byte[0]);
        var connection = PeerEgressTcpConnection.accept(syn, 5000, 1280, 60000, 0,
                new PeerEgressTcpConnection.Output());
        connection.onSegment(ack(5001), 10); // unambiguous 10 ms sample => 200 ms RTO
        connection.onAppData(new byte[]{1}, 10);
        assertEquals(1, connection.onTick(210).segments.size());
        connection.onSegment(ack(5002), 210); // Karn: not a fresh RTT sample
        return connection;
    }

    @Test void retransmittedAckDoesNotCollapseBackoff() {
        var connection = afterRetransmittedAck();
        connection.onAppData(new byte[]{2}, 210);
        assertTrue(connection.onTick(410).segments.isEmpty(), "ambiguous ACK collapsed backoff");
        assertEquals(1, connection.onTick(610).segments.size());
    }

    /**
     * The segments sent alongside a lost one are acknowledged only when its retransmission fills
     * the hole, so their send-to-ACK time is the retransmission timeout, not the path. Taking them as
     * round-trip samples made every recovery stretch the next timeout (here 419 ms instead of the
     * 200 ms floor after one recovery and one clean ACK), and in the lab a flow with 64 KiB queued
     * went seconds without retransmitting the hole its consumer was waiting for.
     */
    @Test void theAckThatFillsAHoleIsNotARoundTripSample() {
        var syn = new PeerEgressSegment.Segment(0x64600001, 0xcb00710a, 40000, 443,
                1000, 0, PeerEgressSegment.FLAG_SYN, 65535, 1240, new byte[0]);
        var connection = PeerEgressTcpConnection.accept(syn, 5000, 1280, 60000, 0,
                new PeerEgressTcpConnection.Output());
        connection.onSegment(ack(5001), 10); // unambiguous 10 ms sample => 200 ms RTO

        // Four segments in flight; the first is lost and the consumer holds the other three.
        assertEquals(4, connection.onAppData(new byte[4 * 1240], 10).segments.size());
        for (int duplicate = 0; duplicate < 3; duplicate++) {
            assertTrue(connection.onSegment(ack(5001), 11).segments.isEmpty());
        }
        assertEquals(1, connection.onTick(210).segments.size(), "the hole was not resent");
        connection.onSegment(ack(5001 + 4 * 1240), 211); // fills the hole: covers all four

        // One clean round trip, then the next loss.
        assertEquals(1, connection.onAppData(new byte[1240], 211).segments.size());
        connection.onSegment(ack(5001 + 5 * 1240), 212);
        assertEquals(1, connection.onAppData(new byte[1240], 300).segments.size());
        assertTrue(connection.onTick(499).segments.isEmpty(), "retransmitted before the RTO");
        assertEquals(1, connection.onTick(500).segments.size(),
                "the recovery's ACK was taken as a round-trip sample and stretched the timeout");
    }

    @Test void sameMillisecondCleanAckCollapsesBackoff() {
        var connection = afterRetransmittedAck();
        connection.onAppData(new byte[]{2}, 210);
        connection.onSegment(ack(5003), 210); // same millisecond as this clean segment's send
        connection.onAppData(new byte[]{3}, 410);
        assertTrue(connection.onTick(609).segments.isEmpty());
        assertEquals(1, connection.onTick(610).segments.size(), "sub-ms RTT was discarded, leaving stale backoff");
    }
}
