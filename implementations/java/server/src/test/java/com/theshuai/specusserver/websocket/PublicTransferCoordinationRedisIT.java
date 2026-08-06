package com.theshuai.specusserver.websocket;

import com.theshuai.specusserver.config.PublicTransferProperties;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;

class PublicTransferCoordinationRedisIT {

    @Test
    void twoInstancesSharePresenceEventsNamesAndRateLimits() throws Exception {
        String redisUri = System.getenv("SPECUS_TEST_REDIS_URI");
        Assumptions.assumeTrue(redisUri != null && !redisUri.isBlank(),
                "SPECUS_TEST_REDIS_URI is not configured");
        PublicTransferProperties properties = properties(redisUri);
        try (PublicTransferCoordinationService first = new PublicTransferCoordinationService(properties);
             PublicTransferCoordinationService second = new PublicTransferCoordinationService(properties)) {
            first.start();
            second.start();
            PublicTransferCoordinationService.Participant alpha = participant(
                    "lease-a", "peer-a", "Device Alpha", "room", "key", "203.0.113.1",
                    "2026-07-22T00:00:00Z");
            PublicTransferCoordinationService.Participant beta = participant(
                    "lease-b", "peer-b", "Device Beta", "room", "key", "203.0.113.1",
                    "2026-07-22T00:00:01Z");

            assertThat(first.register(alpha, 2).accepted()).isTrue();
            assertThat(second.register(beta, 2).accepted()).isTrue();
            PublicTransferCoordinationService.Roster roster = first.roster(alpha);
            assertThat(roster.revision()).isGreaterThanOrEqualTo(2);
            assertThat(roster.participants()).extracting(
                    PublicTransferCoordinationService.Participant::peerId)
                    .containsExactly("peer-a", "peer-b");

            assertThat(second.register(participant("lease-c", "peer-c", "device alpha",
                    "other", "key", "203.0.113.1", "2026-07-22T00:00:02Z"), 2).error())
                    .isEqualTo("client name is already in use");
            assertThat(second.register(participant("lease-d", "peer-d", "Device Delta",
                    "room", "key", "203.0.113.1", "2026-07-22T00:00:03Z"), 2).error())
                    .isEqualTo("room is full");

            assertThat(first.allowRate("integration", "same-source", 1, 60)).isTrue();
            assertThat(second.allowRate("integration", "same-source", 1, 60)).isFalse();

            CountDownLatch delivered = new CountDownLatch(1);
            second.addListener(event -> {
                if (event.kind() == PublicTransferClusterFrame.KIND_TEXT
                        && event.groupId().equals(alpha.groupId())
                        && new String(event.payload(), StandardCharsets.UTF_8).equals("cross-instance")) {
                    delivered.countDown();
                }
            });
            first.publishText(alpha.groupId(), "peer-b", alpha.leaseId(), false,
                    "cross-instance".getBytes(StandardCharsets.UTF_8));
            assertThat(delivered.await(5, TimeUnit.SECONDS)).isTrue();

            CountDownLatch managementDelivered = new CountDownLatch(1);
            byte[] managementPayload = "{\"tenantId\":\"default\",\"type\":\"created\"}"
                    .getBytes(StandardCharsets.UTF_8);
            second.addListener(event -> {
                if (event.kind() == PublicTransferClusterFrame.KIND_MANAGEMENT
                        && event.groupId().equals(
                        PublicTransferCoordinationService.managementGroupId("default"))
                        && java.util.Arrays.equals(event.payload(), managementPayload)) {
                    managementDelivered.countDown();
                }
            });
            first.publishManagement("default", managementPayload);
            assertThat(managementDelivered.await(5, TimeUnit.SECONDS)).isTrue();

            assertThat(first.unregister(alpha)).isGreaterThan(0);
            assertThat(second.unregister(beta)).isGreaterThan(0);
        }
    }

    @Test
    void rosterMergesSameNetAcrossGroupsAndKeepsRevisionMonotonic() throws Exception {
        String redisUri = System.getenv("SPECUS_TEST_REDIS_URI");
        Assumptions.assumeTrue(redisUri != null && !redisUri.isBlank(),
                "SPECUS_TEST_REDIS_URI is not configured");
        PublicTransferProperties properties = properties(redisUri);
        try (PublicTransferCoordinationService first = new PublicTransferCoordinationService(properties);
             PublicTransferCoordinationService second = new PublicTransferCoordinationService(properties)) {
            first.start();
            second.start();
            PublicTransferCoordinationService.Participant alpha = participant(
                    "lease-a", "peer-a", "Device Alpha", "room", "room:1", "203.0.113.1",
                    "2026-07-22T00:00:00Z");
            // 同网跨 group:合并 roster 内互相可见。
            PublicTransferCoordinationService.Participant beta = participant(
                    "lease-b", "peer-b", "Device Beta", "room", "room:2", "203.0.113.1",
                    "2026-07-22T00:00:01Z");
            // 同 group 异网:原有房间可见性保留。
            PublicTransferCoordinationService.Participant gamma = participant(
                    "lease-c", "peer-c", "Device Gamma", "room", "room:1", "198.51.100.2",
                    "2026-07-22T00:00:02Z");
            // 异 roomId 但同网:net 维度不再含 roomId,互相可见。
            PublicTransferCoordinationService.Participant delta = participant(
                    "lease-d", "peer-d", "Device Delta", "other-room", "room:1", "203.0.113.1",
                    "2026-07-22T00:00:03Z");
            // 异 roomId 且异网:与 delta 同 group,但合并读取时被内存复核排除。
            PublicTransferCoordinationService.Participant zeta = participant(
                    "lease-z", "peer-z", "Device Zeta", "other-room", "room:1", "192.0.2.9",
                    "2026-07-22T00:00:04Z");

            assertThat(first.register(alpha, 10).accepted()).isTrue();
            assertThat(second.register(beta, 10).accepted()).isTrue();
            assertThat(second.register(gamma, 10).accepted()).isTrue();
            assertThat(second.register(delta, 10).accepted()).isTrue();
            assertThat(second.register(zeta, 10).accepted()).isTrue();

            PublicTransferCoordinationService.Roster merged = first.roster(alpha);
            assertThat(merged.participants()).extracting(
                    PublicTransferCoordinationService.Participant::peerId)
                    .containsExactly("peer-a", "peer-b", "peer-c", "peer-d");
            // 同 net 内 peerId 查重(跨 group)。
            assertThat(second.register(participant("lease-e", "peer-b", "Device Echo",
                    "room", "room:9", "203.0.113.1", "2026-07-22T00:00:05Z"), 10).error())
                    .isEqualTo("peer id is already connected");
            // 定向路由解析:同网跨 group/跨 roomId 目标按其所在 group 返回;异网目标不可见。
            assertThat(first.findPeer(alpha, "peer-b").groupId()).isEqualTo(beta.groupId());
            assertThat(first.findPeer(alpha, "peer-d").groupId()).isEqualTo(delta.groupId());
            assertThat(first.findPeer(alpha, "peer-z")).isNull();

            long revisionBefore = merged.revision();
            assertThat(second.unregister(beta)).isGreaterThan(0);
            PublicTransferCoordinationService.Roster afterUnregister = first.roster(alpha);
            assertThat(afterUnregister.revision()).isGreaterThan(revisionBefore);
            assertThat(afterUnregister.participants()).extracting(
                    PublicTransferCoordinationService.Participant::peerId)
                    .containsExactly("peer-a", "peer-c", "peer-d");

            assertThat(first.unregister(alpha)).isGreaterThan(0);
            assertThat(second.unregister(gamma)).isGreaterThan(0);
            assertThat(second.unregister(delta)).isGreaterThan(0);
            assertThat(second.unregister(zeta)).isGreaterThan(0);
        }
    }

    private static PublicTransferProperties properties(String redisUri) {
        PublicTransferProperties properties = new PublicTransferProperties();
        properties.setClusterEnabled(true);
        properties.setRedisUri(redisUri);
        properties.setRedisKeyPrefix("specus:test:" + UUID.randomUUID());
        properties.setPresenceLeaseSeconds(30);
        properties.setPresenceRefreshIntervalMs(10_000);
        properties.setRedisCommandTimeoutMs(2_000);
        return properties;
    }

    private static PublicTransferCoordinationService.Participant participant(
            String leaseId, String peerId, String displayName, String roomId, String roomKey,
            String publicAddress, String connectedAt) {
        return new PublicTransferCoordinationService.Participant(leaseId, peerId, displayName,
                roomId, publicAddress, roomKey, "EDITOR", true, connectedAt);
    }
}
