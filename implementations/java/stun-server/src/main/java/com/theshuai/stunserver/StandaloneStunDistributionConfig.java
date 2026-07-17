package com.theshuai.stunserver;

import com.theshuai.common.stun.StunEndpointTopology;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.util.Arrays;
import java.util.Objects;

public record StandaloneStunDistributionConfig(
        boolean enabled,
        StunEndpointTopology.AddressSlot localAddressSlot,
        InetSocketAddress controlBindAddress,
        InetSocketAddress peerControlAddress,
        byte[] sharedSecret,
        int maxClockSkewSeconds,
        int replayCacheSize,
        int maxForwardPacketBytes,
        int forwardRatePerSecond,
        int forwardBurst) {
    private static final int MIN_SECRET_BYTES = 32;

    public StandaloneStunDistributionConfig {
        if (!enabled) {
            localAddressSlot = null;
            controlBindAddress = null;
            peerControlAddress = null;
            sharedSecret = new byte[0];
            maxClockSkewSeconds = 30;
            replayCacheSize = 65_536;
            maxForwardPacketBytes = 4_096;
            forwardRatePerSecond = 10_000;
            forwardBurst = 20_000;
        } else {
            Objects.requireNonNull(localAddressSlot, "localAddressSlot");
            validateControlAddress(controlBindAddress, "controlBindAddress");
            validateControlAddress(peerControlAddress, "peerControlAddress");
            if (controlBindAddress.getAddress().getAddress().length
                    != peerControlAddress.getAddress().getAddress().length) {
                throw new IllegalArgumentException(
                        "distributed control addresses must use the same address family");
            }
            if (controlBindAddress.equals(peerControlAddress)) {
                throw new IllegalArgumentException(
                        "distributed control endpoints must be distinct");
            }
            sharedSecret = sharedSecret == null
                    ? new byte[0]
                    : Arrays.copyOf(sharedSecret, sharedSecret.length);
            if (sharedSecret.length < MIN_SECRET_BYTES || sharedSecret.length > 256) {
                throw new IllegalArgumentException(
                        "distributed shared secret must contain between 32 and 256 bytes");
            }
            positive(maxClockSkewSeconds, "maxClockSkewSeconds");
            positive(replayCacheSize, "replayCacheSize");
            if (maxForwardPacketBytes < 512 || maxForwardPacketBytes > 65_507) {
                throw new IllegalArgumentException(
                        "maxForwardPacketBytes must be between 512 and 65507");
            }
            positive(forwardRatePerSecond, "forwardRatePerSecond");
            positive(forwardBurst, "forwardBurst");
        }
    }

    public static StandaloneStunDistributionConfig disabled() {
        return new StandaloneStunDistributionConfig(
                false,
                null,
                null,
                null,
                null,
                30,
                65_536,
                4_096,
                10_000,
                20_000);
    }

    @Override
    public byte[] sharedSecret() {
        return Arrays.copyOf(sharedSecret, sharedSecret.length);
    }

    public boolean isLocal(StunEndpointTopology.EndpointId endpointId) {
        return !enabled || (endpointId != null
                && endpointId.addressSlot() == localAddressSlot);
    }

    public String describe() {
        if (!enabled) {
            return "disabled";
        }
        return "localSlot=" + localAddressSlot.name().toLowerCase()
                + ", controlBind=" + controlBindAddress
                + ", peerControl=" + peerControlAddress
                + ", clockSkew=" + maxClockSkewSeconds + "s"
                + ", replayCache=" + replayCacheSize
                + ", maxPacket=" + maxForwardPacketBytes
                + ", rate=" + forwardRatePerSecond + "/s burst=" + forwardBurst;
    }

    private static void validateControlAddress(InetSocketAddress address, String name) {
        Objects.requireNonNull(address, name);
        InetAddress inetAddress = address.getAddress();
        if (inetAddress == null || address.isUnresolved()) {
            throw new IllegalArgumentException(name + " must be resolved");
        }
        if (address.getPort() <= 0) {
            throw new IllegalArgumentException(name + " port must be positive");
        }
        if (inetAddress.isAnyLocalAddress() || inetAddress.isMulticastAddress()) {
            throw new IllegalArgumentException(name + " must be an explicit unicast address");
        }
    }

    private static void positive(int value, String name) {
        if (value <= 0) {
            throw new IllegalArgumentException(name + " must be positive");
        }
    }
}
