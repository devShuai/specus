package com.theshuai.tunnelclient.peer;

public interface PeerVirtualDevice extends AutoCloseable {
    String name();

    void start(PacketHandler outboundHandler);

    void writePacket(byte[] packet);

    @Override
    void close();

    @FunctionalInterface
    interface PacketHandler {
        void handle(byte[] packet);
    }
}
