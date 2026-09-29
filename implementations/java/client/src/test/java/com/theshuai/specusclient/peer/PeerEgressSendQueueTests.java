package com.theshuai.specusclient.peer;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class PeerEgressSendQueueTests {

    @Test
    void segmentsAreTakenAcrossTheChunksTheyArrivedIn() {
        var queue = new PeerEgressTcpConnection.SendQueue();
        queue.add(new byte[] {1, 2, 3});
        queue.add(new byte[0]);
        queue.add(new byte[] {4, 5});
        queue.add(new byte[] {6, 7, 8, 9});
        assertThat(queue.size()).isEqualTo(9);

        // A peek leaves everything in place, so a refused segment is sent again unchanged.
        assertThat(queue.peek(4)).containsExactly(1, 2, 3, 4);
        assertThat(queue.peek(4)).containsExactly(1, 2, 3, 4);

        queue.skip(2);
        assertThat(queue.size()).isEqualTo(7);
        assertThat(queue.peek(5)).containsExactly(3, 4, 5, 6, 7);

        queue.skip(3);
        assertThat(queue.peek(1)).containsExactly(6);
        queue.skip(4);
        assertThat(queue.size()).isZero();

        queue.add(new byte[] {10});
        assertThat(queue.peek(1)).containsExactly(10);
        queue.clear();
        assertThat(queue.size()).isZero();
    }
}
