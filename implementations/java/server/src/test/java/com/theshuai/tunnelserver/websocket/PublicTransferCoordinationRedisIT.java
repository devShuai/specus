package com.theshuai.tunnelserver.websocket;

import com.theshuai.tunnelserver.config.PublicTransferProperties;
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
        String redisUri = System.getenv("TUNNEL_TEST_REDIS_URI");
        Assumptions.assumeTrue(redisUri != null && !redisUri.isBlank(),
                "TUNNEL_TEST_REDIS_URI is not configured");
        PublicTransferProperties properties = properties(redisUri);
        try (PublicTransferCoordinationService first = new PublicTransferCoordinationService(properties);
             PublicTransferCoordinationService second = new PublicTransferCoordinationService(properties)) {
            first.start();
            second.start();
            PublicTransferCoordinationService.Participant alpha = participant(
                    "lease-a", "peer-a", "Device Alpha", "room", "key", "2026-07-22T00:00:00Z");
            PublicTransferCoordinationService.Participant beta = participant(
                    "lease-b", "peer-b", "Device Beta", "room", "key", "2026-07-22T00:00:01Z");

            assertThat(first.register(alpha, 2).accepted()).isTrue();
            assertThat(second.register(beta, 2).accepted()).isTrue();
            PublicTransferCoordinationService.Roster roster = first.roster(alpha.groupId());
            assertThat(roster.revision()).isGreaterThanOrEqualTo(2);
            assertThat(roster.participants()).extracting(
                    PublicTransferCoordinationService.Participant::peerId)
                    .containsExactly("peer-a", "peer-b");

            assertThat(second.register(participant("lease-c", "peer-c", "device alpha",
                    "other", "key", "2026-07-22T00:00:02Z"), 2).error())
                    .isEqualTo("client name is already in use");
            assertThat(second.register(participant("lease-d", "peer-d", "Device Delta",
                    "room", "key", "2026-07-22T00:00:03Z"), 2).error())
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

    private static PublicTransferProperties properties(String redisUri) {
        PublicTransferProperties properties = new PublicTransferProperties();
        properties.setClusterEnabled(true);
        properties.setRedisUri(redisUri);
        properties.setRedisKeyPrefix("shuai-tunnel:test:" + UUID.randomUUID());
        properties.setPresenceLeaseSeconds(30);
        properties.setPresenceRefreshIntervalMs(10_000);
        properties.setRedisCommandTimeoutMs(2_000);
        return properties;
    }

    private static PublicTransferCoordinationService.Participant participant(
            String leaseId, String peerId, String displayName, String roomId, String roomKey,
            String connectedAt) {
        return new PublicTransferCoordinationService.Participant(leaseId, peerId, displayName,
                roomId, "203.0.113.1", roomKey, "EDITOR", true, connectedAt);
    }
}
