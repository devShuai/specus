package com.theshuai.stunserver;

public record StandaloneStunProtectionConfig(
        int sourceRatePerSecond,
        int sourceBurst,
        int globalRatePerSecond,
        int globalBurst,
        int maxTrackedSources,
        int sourceIdleSeconds,
        int maxPacketBytes,
        int maxPaddingResponseBytes) {
    public StandaloneStunProtectionConfig {
        positive(sourceRatePerSecond, "sourceRatePerSecond");
        positive(sourceBurst, "sourceBurst");
        positive(globalRatePerSecond, "globalRatePerSecond");
        positive(globalBurst, "globalBurst");
        positive(maxTrackedSources, "maxTrackedSources");
        positive(sourceIdleSeconds, "sourceIdleSeconds");
        if (maxPacketBytes < 20 || maxPacketBytes > 65_507) {
            throw new IllegalArgumentException("maxPacketBytes must be between 20 and 65507");
        }
        if (maxPaddingResponseBytes < 0 || maxPaddingResponseBytes > 65_503) {
            throw new IllegalArgumentException(
                    "maxPaddingResponseBytes must be between 0 and 65503");
        }
    }

    public static StandaloneStunProtectionConfig defaults() {
        return new StandaloneStunProtectionConfig(
                100,
                200,
                10_000,
                20_000,
                65_536,
                300,
                65_507,
                1_472);
    }

    public String describe() {
        return "source=" + sourceRatePerSecond + "/s burst=" + sourceBurst
                + ", global=" + globalRatePerSecond + "/s burst=" + globalBurst
                + ", trackedSources=" + maxTrackedSources
                + ", maxPacket=" + maxPacketBytes
                + ", maxPadding=" + maxPaddingResponseBytes;
    }

    private static void positive(int value, String name) {
        if (value <= 0) {
            throw new IllegalArgumentException(name + " must be positive");
        }
    }
}
