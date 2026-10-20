package com.theshuai.specusclient.peer;

import java.util.Collection;

public interface PeerVirtualDevice extends AutoCloseable {
    String name();

    void start(PacketHandler outboundHandler);

    default void syncPeerRoutes(Collection<String> peerVirtualIps) {
        // no-op for devices that do not manage OS routes
    }

    void writePacket(byte[] packet);

    /**
     * Whether the device carries IPv6 ({@code protocol/spec/peer-egress.md}, IPv6 数据面): up with its
     * derived IPv6 address assigned, and why not when it is not. A device whose address could not be
     * assigned has no IPv6 data plane, and its IPv4 one is unaffected. A device that does not answer
     * -- the noop device -- carries no IPv6.
     */
    default Ipv6Readiness ipv6Readiness() {
        return Ipv6Readiness.no("the virtual device carries no IPv6");
    }

    @Override
    void close();

    @FunctionalInterface
    interface PacketHandler {
        void handle(byte[] packet, int offset, int length);
    }

    /** Whether a device carries IPv6, and the reason when it does not. */
    record Ipv6Readiness(boolean ready, String reason) {
        public static Ipv6Readiness yes() {
            return new Ipv6Readiness(true, "");
        }

        public static Ipv6Readiness no(String reason) {
            return new Ipv6Readiness(false, reason);
        }
    }
}
