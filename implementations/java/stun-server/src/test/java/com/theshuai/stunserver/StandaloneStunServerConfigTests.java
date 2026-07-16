package com.theshuai.stunserver;

import com.theshuai.common.stun.StunEndpointTopology;
import org.junit.jupiter.api.Test;

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
}
