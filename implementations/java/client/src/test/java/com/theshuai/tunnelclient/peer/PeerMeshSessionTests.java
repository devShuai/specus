package com.theshuai.tunnelclient.peer;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class PeerMeshSessionTests {

    @Test
    void replayWindowRejectsDuplicatesAndZeroSequence() {
        PeerMeshClient.PeerSession session =
                new PeerMeshClient.PeerSession(100L, 2L, "token", "", new byte[32]);

        assertThat(session.acceptInboundSequence(7L)).isTrue();
        assertThat(session.acceptInboundSequence(7L)).isFalse();
        assertThat(session.acceptInboundSequence(8L)).isTrue();
        assertThat(session.acceptInboundSequence(0L)).isFalse();
    }

    @Test
    void sameSessionCopyKeepsReplayHistoryWithoutSharingFutureUpdates() {
        PeerMeshClient.PeerSession source =
                new PeerMeshClient.PeerSession(100L, 2L, "token", "", new byte[32]);
        PeerMeshClient.PeerSession target =
                new PeerMeshClient.PeerSession(100L, 2L, "token", "", new byte[32]);
        assertThat(source.acceptInboundSequence(7L)).isTrue();

        source.copyInboundStateTo(target);

        assertThat(target.acceptInboundSequence(7L)).isFalse();
        assertThat(target.acceptInboundSequence(8L)).isTrue();
        assertThat(source.acceptInboundSequence(8L)).isTrue();
    }
}
