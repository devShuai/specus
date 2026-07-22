package com.theshuai.tunnelserver.peer;

import com.theshuai.tunnelserver.config.PeerMeshProperties;
import com.theshuai.tunnelserver.management.service.PeerMeshService;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.junit.jupiter.api.Test;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

class StunTurnServerMetricsTests {

    @Test
    void recordsRelayQueueDropsAndHighWaterMark() throws Exception {
        PeerMeshProperties properties = new PeerMeshProperties();
        properties.setRelayWorkerThreads(1);
        properties.setRelayWorkerQueueCapacity(1);
        SimpleMeterRegistry meterRegistry = new SimpleMeterRegistry();
        StunTurnServer server = new StunTurnServer(
                properties,
                mock(PeerMeshService.class),
                mock(TurnCredentialService.class),
                meterRegistry);
        ThreadPoolExecutor executor = server.createRelayExecutor();
        CountDownLatch started = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);

        try {
            executor.execute(() -> {
                started.countDown();
                try {
                    release.await();
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            });
            assertThat(started.await(5, TimeUnit.SECONDS)).isTrue();

            executor.execute(() -> { });
            executor.execute(() -> { });

            assertThat(meterRegistry.counter("tunnel.peer_mesh.turn.relay.queue.dropped").count())
                    .isEqualTo(1.0);
            assertThat(meterRegistry.get("tunnel.peer_mesh.turn.relay.queue.high.water").gauge().value())
                    .isEqualTo(1.0);
        } finally {
            release.countDown();
            executor.shutdownNow();
        }
    }
}
