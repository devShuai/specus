package com.theshuai.tunnelserver.peer;

import com.theshuai.tunnelserver.config.PeerMeshProperties;
import com.theshuai.tunnelserver.management.service.PeerMeshService;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.junit.jupiter.api.Test;

import java.net.InetSocketAddress;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

class StunTurnServerMetricsTests {

    @Test
    void generalRelayDestinationPolicyRejectsNonPublicTargets() {
        // 通用中继（公开互传）的目的地址完全由浏览器指定，必须挡住指向服务端内网的目标，
        // 否则中继会变成打向内网的跳板。
        StunTurnServer server = new StunTurnServer(
                new PeerMeshProperties(),
                mock(PeerMeshService.class),
                mock(TurnCredentialService.class),
                new SimpleMeterRegistry());

        assertThat(server.isRelayableDestination(endpoint("203.0.113.10", 50000))).isTrue();
        assertThat(server.isRelayableDestination(endpoint("2001:db8::10", 50000))).isTrue();

        assertThat(server.isRelayableDestination(endpoint("127.0.0.1", 50000))).isFalse();
        assertThat(server.isRelayableDestination(endpoint("0.0.0.0", 50000))).isFalse();
        assertThat(server.isRelayableDestination(endpoint("192.168.1.10", 50000))).isFalse();
        assertThat(server.isRelayableDestination(endpoint("169.254.1.10", 50000))).isFalse();
        assertThat(server.isRelayableDestination(endpoint("239.1.1.1", 50000))).isFalse();
        // 100.64.0.0/10：CGNAT，Peer Mesh 虚拟网段也落在其中
        assertThat(server.isRelayableDestination(endpoint("100.96.0.2", 50000))).isFalse();
        assertThat(server.isRelayableDestination(endpoint("fd00::1", 50000))).isFalse();
        assertThat(server.isRelayableDestination(endpoint("203.0.113.10", 0))).isFalse();
    }

    @Test
    void generalRelayTokenBucketEnforcesConfiguredRate() {
        StunTurnServer.TokenBucket bucket = new StunTurnServer.TokenBucket();

        // 首次调用把桶充满到 1 秒额度
        assertThat(bucket.tryConsume(600, 1_000)).isTrue();
        assertThat(bucket.tryConsume(400, 1_000)).isTrue();
        // 额度已用尽，补充速度远慢于连续调用
        assertThat(bucket.tryConsume(400, 1_000)).isFalse();
        // 速率 <= 0 表示不限速
        assertThat(bucket.tryConsume(Integer.MAX_VALUE, 0)).isTrue();
    }

    private static InetSocketAddress endpoint(String host, int port) {
        try {
            // 全部是 IP 字面量，getByName 不会触发 DNS 解析
            return new InetSocketAddress(java.net.InetAddress.getByName(host), port);
        } catch (java.net.UnknownHostException e) {
            throw new IllegalArgumentException("invalid literal address: " + host, e);
        }
    }

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
