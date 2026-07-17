package com.theshuai.stunserver;

import com.theshuai.common.stun.StunEndpointTopology;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class StandaloneStunServerConfigTests {
    @Test
    void createsFourEndpointRfc5780Topology() {
        StandaloneStunServerConfig config = StandaloneStunServerConfig.fromEnvironment(Map.of(
                "STUN_PRIMARY_BIND_ADDRESS", "10.0.0.10",
                "STUN_PRIMARY_PUBLIC_ADDRESS", "203.0.113.10",
                "STUN_ALTERNATE_BIND_ADDRESS", "10.0.0.11",
                "STUN_ALTERNATE_PUBLIC_ADDRESS", "203.0.113.11",
                "STUN_PRIMARY_PORT", "3478",
                "STUN_ALTERNATE_PORT", "3479"));

        assertTrue(config.topology().supportsRfc5780());
        assertEquals(4, config.topology().endpoints().size());
        assertEquals(
                "203.0.113.11",
                config.topology()
                        .endpoint(StunEndpointTopology.ALTERNATE)
                        .advertisedAddress()
                        .getAddress()
                        .getHostAddress());
    }

    @Test
    void createsStandardsCompliantBasicTopologyWithoutOtherAddress() {
        StandaloneStunServerConfig config = StandaloneStunServerConfig.fromEnvironment(Map.of(
                "STUN_PRIMARY_BIND_ADDRESS", "127.0.0.1",
                "STUN_ALTERNATE_PORT", "0"));

        assertFalse(config.topology().supportsRfc5780());
        assertEquals(1, config.topology().endpoints().size());
        assertFalse(config.legacySingleIpOtherAddress());
    }

    @Test
    void requiresPublicAddressForWildcardBind() {
        IllegalArgumentException error = assertThrows(
                IllegalArgumentException.class,
                () -> StandaloneStunServerConfig.fromEnvironment(Map.of()));

        assertTrue(error.getMessage().contains("STUN_PRIMARY_PUBLIC_ADDRESS"));
    }

    @Test
    void rejectsPartialAlternateAddressConfiguration() {
        IllegalArgumentException error = assertThrows(
                IllegalArgumentException.class,
                () -> StandaloneStunServerConfig.fromEnvironment(Map.of(
                        "STUN_PRIMARY_BIND_ADDRESS", "10.0.0.10",
                        "STUN_PRIMARY_PUBLIC_ADDRESS", "203.0.113.10",
                        "STUN_ALTERNATE_BIND_ADDRESS", "10.0.0.11")));

        assertTrue(error.getMessage().contains("configured together"));
    }

    @Test
    void readsProtectionAndMetricsConfiguration() {
        StandaloneStunServerConfig config = StandaloneStunServerConfig.fromEnvironment(
                Map.ofEntries(
                        Map.entry("STUN_PRIMARY_BIND_ADDRESS", "127.0.0.1"),
                        Map.entry("STUN_ALTERNATE_PORT", "0"),
                        Map.entry("STUN_RATE_LIMIT_PER_SECOND", "25"),
                        Map.entry("STUN_RATE_LIMIT_BURST", "40"),
                        Map.entry("STUN_GLOBAL_RATE_LIMIT_PER_SECOND", "1000"),
                        Map.entry("STUN_GLOBAL_RATE_LIMIT_BURST", "2000"),
                        Map.entry("STUN_MAX_TRACKED_SOURCES", "1234"),
                        Map.entry("STUN_SOURCE_IDLE_SECONDS", "30"),
                        Map.entry("STUN_MAX_PACKET_BYTES", "4096"),
                        Map.entry("STUN_MAX_PADDING_RESPONSE_BYTES", "1200"),
                        Map.entry("STUN_METRICS_BIND_ADDRESS", "127.0.0.2"),
                        Map.entry("STUN_METRICS_PORT", "9191")));

        assertEquals(25, config.protection().sourceRatePerSecond());
        assertEquals(40, config.protection().sourceBurst());
        assertEquals(4_096, config.protection().maxPacketBytes());
        assertEquals(1_200, config.protection().maxPaddingResponseBytes());
        assertEquals(9_191, config.metrics().port());
        assertEquals("127.0.0.2", config.metrics().bindAddress().getHostAddress());
    }

    @Test
    void createsDistributedRfc5780TopologyWithOnlyTheLocalAddressSlotBound() {
        String secret = Base64.getEncoder().encodeToString(
                "0123456789abcdef0123456789abcdef".getBytes(StandardCharsets.US_ASCII));
        StandaloneStunServerConfig config = StandaloneStunServerConfig.fromEnvironment(
                Map.ofEntries(
                        Map.entry("STUN_DISTRIBUTED_ENABLED", "true"),
                        Map.entry("STUN_DISTRIBUTED_LOCAL_ADDRESS_SLOT", "alternate"),
                        Map.entry("STUN_DISTRIBUTED_STUN_BIND_ADDRESS", "0.0.0.0"),
                        Map.entry("STUN_DISTRIBUTED_CONTROL_BIND_ADDRESS", "10.0.1.10"),
                        Map.entry("STUN_DISTRIBUTED_PEER_CONTROL_ADDRESS", "10.0.0.10"),
                        Map.entry("STUN_DISTRIBUTED_SHARED_SECRET", secret),
                        Map.entry("STUN_PRIMARY_PUBLIC_ADDRESS", "203.0.113.10"),
                        Map.entry("STUN_ALTERNATE_PUBLIC_ADDRESS", "203.0.113.11"),
                        Map.entry("STUN_PRIMARY_PORT", "3478"),
                        Map.entry("STUN_ALTERNATE_PORT", "3479")));

        assertTrue(config.topology().supportsRfc5780());
        assertTrue(config.distribution().enabled());
        assertEquals(StunEndpointTopology.AddressSlot.ALTERNATE,
                config.distribution().localAddressSlot());
        assertEquals(
                java.util.List.of(
                        StunEndpointTopology.ALTERNATE_PRIMARY_PORT,
                        StunEndpointTopology.ALTERNATE),
                config.localEndpoints().stream()
                        .map(StunEndpointTopology.Endpoint::id)
                        .toList());
    }

    @Test
    void rejectsShortDistributedSharedSecret() {
        String secret = Base64.getEncoder().encodeToString(new byte[16]);
        IllegalArgumentException error = assertThrows(
                IllegalArgumentException.class,
                () -> StandaloneStunServerConfig.fromEnvironment(
                        Map.ofEntries(
                                Map.entry("STUN_DISTRIBUTED_ENABLED", "true"),
                                Map.entry("STUN_DISTRIBUTED_LOCAL_ADDRESS_SLOT", "primary"),
                                Map.entry("STUN_DISTRIBUTED_CONTROL_BIND_ADDRESS", "10.0.0.10"),
                                Map.entry("STUN_DISTRIBUTED_PEER_CONTROL_ADDRESS", "10.0.1.10"),
                                Map.entry("STUN_DISTRIBUTED_SHARED_SECRET", secret),
                                Map.entry("STUN_PRIMARY_PUBLIC_ADDRESS", "203.0.113.10"),
                                Map.entry("STUN_ALTERNATE_PUBLIC_ADDRESS", "203.0.113.11"))));

        assertTrue(error.getMessage().contains("32"));
    }

    @Test
    void rejectsDistributedControlPortCollision() {
        String secret = Base64.getEncoder().encodeToString(
                "0123456789abcdef0123456789abcdef".getBytes(StandardCharsets.US_ASCII));
        IllegalArgumentException error = assertThrows(
                IllegalArgumentException.class,
                () -> StandaloneStunServerConfig.fromEnvironment(
                        Map.ofEntries(
                                Map.entry("STUN_DISTRIBUTED_ENABLED", "true"),
                                Map.entry("STUN_DISTRIBUTED_LOCAL_ADDRESS_SLOT", "primary"),
                                Map.entry("STUN_DISTRIBUTED_CONTROL_BIND_ADDRESS", "10.0.0.10"),
                                Map.entry("STUN_DISTRIBUTED_CONTROL_PORT", "3478"),
                                Map.entry("STUN_DISTRIBUTED_PEER_CONTROL_ADDRESS", "10.0.1.10"),
                                Map.entry("STUN_DISTRIBUTED_PEER_CONTROL_PORT", "3478"),
                                Map.entry("STUN_DISTRIBUTED_SHARED_SECRET", secret),
                                Map.entry("STUN_PRIMARY_PUBLIC_ADDRESS", "203.0.113.10"),
                                Map.entry("STUN_ALTERNATE_PUBLIC_ADDRESS", "203.0.113.11"))));

        assertTrue(error.getMessage().contains("must differ"));
    }

    @Test
    void rejectsIdenticalDistributedControlEndpoints() {
        String secret = Base64.getEncoder().encodeToString(
                "0123456789abcdef0123456789abcdef".getBytes(StandardCharsets.US_ASCII));
        IllegalArgumentException error = assertThrows(
                IllegalArgumentException.class,
                () -> StandaloneStunServerConfig.fromEnvironment(
                        Map.ofEntries(
                                Map.entry("STUN_DISTRIBUTED_ENABLED", "true"),
                                Map.entry("STUN_DISTRIBUTED_LOCAL_ADDRESS_SLOT", "primary"),
                                Map.entry("STUN_DISTRIBUTED_CONTROL_BIND_ADDRESS", "10.0.0.10"),
                                Map.entry("STUN_DISTRIBUTED_PEER_CONTROL_ADDRESS", "10.0.0.10"),
                                Map.entry("STUN_DISTRIBUTED_SHARED_SECRET", secret),
                                Map.entry("STUN_PRIMARY_PUBLIC_ADDRESS", "203.0.113.10"),
                                Map.entry("STUN_ALTERNATE_PUBLIC_ADDRESS", "203.0.113.11"))));

        assertTrue(error.getMessage().contains("distinct"));
    }
}
