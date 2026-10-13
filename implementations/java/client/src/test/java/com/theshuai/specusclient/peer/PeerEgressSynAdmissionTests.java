package com.theshuai.specusclient.peer;

import static org.junit.jupiter.api.Assertions.*;
import com.theshuai.common.peeregress.Ipv4Cidr;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;

class PeerEgressSynAdmissionTests {
    @Test
    void admissionPreservesSequenceMssAndHandshake() {
        var syn = new PeerEgressSegment.Segment(Ipv4Cidr.parseAddress("100.96.0.1"),
                Ipv4Cidr.parseAddress("203.0.113.10"), 40000, 443, 1000, 0,
                PeerEgressSegment.FLAG_SYN, 65535, 1360, new byte[0]);
        int iss = -1;
        var admit = new AtomicBoolean();
        var attempts = new AtomicInteger();
        List<PeerEgressSegment.Segment> sent = new ArrayList<>();
        var output = new PeerEgressTcpConnection.Output();
        var conn = PeerEgressTcpConnection.accept(syn, iss, 1280, 60_000, 0, output, packet -> {
            attempts.incrementAndGet();
            if (!admit.get()) return false;
            var segment = PeerEgressSegment.parse(packet);
            assertNotNull(segment);
            sent.add(segment);
            return true;
        });
        assertTrue(output.segments.isEmpty());
        assertTrue(conn.sendBlocked);
        conn.onAppData(new byte[]{1, 2, 3}, 0);
        var forged = new PeerEgressSegment.Segment(syn.sourceIp(), syn.destinationIp(),
                syn.sourcePort(), syn.destinationPort(), syn.seq() + 1, iss,
                PeerEgressSegment.FLAG_ACK, 65535, 0, new byte[0]);
        conn.onSegment(forged, 0);
        for (int tick = 1; tick <= 10; tick++) conn.onTick(tick);
        assertEquals(PeerEgressTcpConnection.State.SYN_RECEIVED, conn.state());
        assertEquals(11, attempts.get());
        assertTrue(sent.isEmpty());
        admit.set(true);
        conn.onTick(2000);
        assertEquals(1, sent.size());
        var synAck = sent.getFirst();
        assertEquals(iss, synAck.seq());
        assertEquals(1240, synAck.mss());
        assertEquals(PeerEgressSegment.FLAG_SYN | PeerEgressSegment.FLAG_ACK, synAck.flags());
        conn.onTick(2999);
        assertEquals(1, sent.size(), "RTO must start at admission, not construction");
        var ack = new PeerEgressSegment.Segment(syn.sourceIp(), syn.destinationIp(),
                syn.sourcePort(), syn.destinationPort(), syn.seq() + 1, iss + 1,
                PeerEgressSegment.FLAG_ACK, 65535, 0, new byte[0]);
        conn.onSegment(ack, 3000);
        assertEquals(PeerEgressTcpConnection.State.ESTABLISHED, conn.state());
        assertEquals(2, sent.size());
        assertEquals(0, sent.get(1).seq(), "valid wrap of TCP sequence space");
        assertArrayEquals(new byte[]{1, 2, 3}, sent.get(1).payload());
    }
}
