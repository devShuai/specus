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

    @Test void sameMillisecondCleanAckCollapsesBackoff() {
        var connection = afterRetransmittedAck();
        connection.onAppData(new byte[]{2}, 210);
        connection.onSegment(ack(5003), 210); // same millisecond as this clean segment's send
        connection.onAppData(new byte[]{3}, 410);
        assertTrue(connection.onTick(609).segments.isEmpty());
        assertEquals(1, connection.onTick(610).segments.size(), "sub-ms RTT was discarded, leaving stale backoff");
    }
}
