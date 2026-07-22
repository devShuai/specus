package com.theshuai.tunnelclient.peer;

import java.util.Collection;

public interface PeerVirtualDevice extends AutoCloseable {
    String name();

    void start(PacketHandler outboundHandler);

    default void syncPeerRoutes(Collection<String> peerVirtualIps) {
        // no-op for devices that do not manage OS routes
    }

    void writePacket(byte[] packet);

    @Override
    void close();

    @FunctionalInterface
    interface PacketHandler {
        void handle(byte[] packet, int offset, int length);
    }
}
