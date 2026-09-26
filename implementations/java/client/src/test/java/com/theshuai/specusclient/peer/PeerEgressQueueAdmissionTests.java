package com.theshuai.specusclient.peer;

import static org.junit.jupiter.api.Assertions.*;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;

class PeerEgressQueueAdmissionTests {
    private PeerEgressTcpConnection connection() {
        var syn = new PeerEgressSegment.Segment(0x64600001, 0xcb00710a, 40000, 443,
                1000, 0, PeerEgressSegment.FLAG_SYN, 65535, 1240, new byte[0]);
        var connection = PeerEgressTcpConnection.accept(syn, 5000, 1280, 60000, 0,
                new PeerEgressTcpConnection.Output());
        connection.onSegment(new PeerEgressSegment.Segment(syn.sourceIp(), syn.destinationIp(),
                40000, 443, 1001, 5001, PeerEgressSegment.FLAG_ACK, 65535, 0, new byte[0]), 0);
        return connection;
    }

    @Test void rejectedDataAndFinAreRetainedUntilQueueRecovery() {
        var connection = connection();
        connection.tryTransmit = packet -> false;
        connection.onAppData(new byte[]{1, 2, 3}, 0);
        connection.onAppClose(0);
        for (int i = 1; i <= 10; i++) {
            connection.onTick(i * 1000);
            assertEquals(PeerEgressTcpConnection.State.ESTABLISHED, connection.state());
        }
        List<PeerEgressSegment.Segment> sent = new ArrayList<>();
        connection.tryTransmit = packet -> { sent.add(PeerEgressSegment.parse(packet)); return true; };
        connection.onTick(10000);
        assertEquals(2, sent.size());
        assertEquals(5001, sent.get(0).seq());
        assertArrayEquals(new byte[]{1, 2, 3}, sent.get(0).payload());
        assertEquals(5004, sent.get(1).seq());
        assertTrue(sent.get(1).has(PeerEgressSegment.FLAG_FIN));
    }

    @Test void rejectedRetransmissionsDoNotConsumeRetryBudget() {
        var connection = connection();
        connection.onAppData(new byte[]{1, 2, 3}, 0);
        connection.tryTransmit = packet -> false;
        for (int i = 1; i <= 10; i++) { connection.onTick(i * 1000); }
        List<PeerEgressSegment.Segment> sent = new ArrayList<>();
        connection.tryTransmit = packet -> { sent.add(PeerEgressSegment.parse(packet)); return true; };
        connection.onTick(10000);
        assertEquals(PeerEgressTcpConnection.State.ESTABLISHED, connection.state());
        assertEquals(1, sent.size());
        assertEquals(5001, sent.get(0).seq());
        // The zero-time handshake supplies no RTT sample: first accepted retry backs 1 s off to 2 s.
        sent.clear();
        connection.onTick(12000);
        assertEquals(1, sent.size());
    }
}
