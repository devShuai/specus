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
        ForwardKey currentKey,
        ForwardKey previousKey,
        int maxClockSkewSeconds,
        int replayWindowSize,
        int maxForwardPacketBytes,
        int forwardRatePerSecond,
        int forwardBurst) {
    private static final int MIN_SECRET_BYTES = 32;

    public StandaloneStunDistributionConfig {
        if (!enabled) {
            localAddressSlot = null;
            controlBindAddress = null;
            peerControlAddress = null;
            currentKey = null;
            previousKey = null;
            maxClockSkewSeconds = 30;
            replayWindowSize = 4_096;
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
            Objects.requireNonNull(currentKey, "currentKey");
            currentKey = new ForwardKey(currentKey.keyId(), currentKey.secret());
            if (previousKey != null) {
                previousKey = new ForwardKey(previousKey.keyId(), previousKey.secret());
                if (previousKey.keyId() == currentKey.keyId()) {
                    throw new IllegalArgumentException("distributed forward key IDs must differ");
                }
            }
            positive(maxClockSkewSeconds, "maxClockSkewSeconds");
            if (replayWindowSize < 64 || replayWindowSize > 1_048_576) {
                throw new IllegalArgumentException("replayWindowSize must be between 64 and 1048576");
            }
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
                null,
                30,
                4_096,
                4_096,
                10_000,
                20_000);
    }

    public ForwardKey key(int keyId) {
        if (currentKey != null && currentKey.keyId() == keyId) {
            return currentKey;
        }
        return previousKey != null && previousKey.keyId() == keyId ? previousKey : null;
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
                + ", currentKeyId=" + currentKey.keyId()
                + (previousKey == null ? "" : ", previousKeyId=" + previousKey.keyId())
                + ", replayWindow=" + replayWindowSize
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

    public record ForwardKey(int keyId, byte[] secret) {
        public ForwardKey {
            if (keyId <= 0) {
                throw new IllegalArgumentException("distributed forward key ID must be positive");
            }
            secret = secret == null ? new byte[0] : Arrays.copyOf(secret, secret.length);
            if (secret.length < MIN_SECRET_BYTES || secret.length > 256) {
                throw new IllegalArgumentException(
                        "distributed forward secret must contain between 32 and 256 bytes");
            }
        }

        @Override
        public byte[] secret() {
            return Arrays.copyOf(secret, secret.length);
        }
    }
}
