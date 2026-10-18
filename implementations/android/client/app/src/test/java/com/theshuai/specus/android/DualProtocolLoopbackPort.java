package com.theshuai.specus.android;

import java.io.IOException;
import java.net.BindException;
import java.net.DatagramSocket;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.util.concurrent.ThreadLocalRandom;
import java.util.function.IntSupplier;

/** Owns one port in both protocols until each listener is ready to take it over. */
final class DualProtocolLoopbackPort implements AutoCloseable {
    static final int MAX_CANDIDATES = 32;
    private final ServerSocket tcp;
    private final DatagramSocket udp;
    private final int port;

    private DualProtocolLoopbackPort(ServerSocket tcp, DatagramSocket udp) {
        this.tcp = tcp;
        this.udp = udp;
        this.port = tcp.getLocalPort();
    }

    static DualProtocolLoopbackPort reserve() throws IOException {
        return reserve(DualProtocolLoopbackPort::nextCandidate);
    }

    static int nextCandidate() {
        // A TCP port-0 allocator may walk a whole UDP-excluded range on Windows.
        // Spread candidates, but accept one only while both real sockets are bound.
        return ThreadLocalRandom.current().nextInt(1024, 65536);
    }

    static DualProtocolLoopbackPort reserve(IntSupplier candidate) throws IOException {
        BindException conflict = null;
        // A port chosen for one protocol is not necessarily free for the other. Allocate before the
        // scenario starts: no operation under test, UDP request or assertion is retried here.
        for (int attempt = 0; attempt < MAX_CANDIDATES; attempt++) {
            ServerSocket tcp = new ServerSocket();
            DatagramSocket udp = null;
            boolean handedOff = false;
            try {
                udp = new DatagramSocket(null);
                tcp.bind(new InetSocketAddress("127.0.0.1", candidate.getAsInt()));
                udp.bind(new InetSocketAddress("127.0.0.1", tcp.getLocalPort()));
                DualProtocolLoopbackPort reserved = new DualProtocolLoopbackPort(tcp, udp);
                handedOff = true;
                return reserved;
            } catch (BindException unavailableInEitherProtocol) {
                conflict = unavailableInEitherProtocol;
            } finally {
                if (!handedOff) {
                    try { tcp.close(); } finally { if (udp != null) udp.close(); }
                }
            }
        }
        throw new IOException("Cannot reserve one loopback port for TCP and UDP", conflict);
    }

    int port() { return port; }

    void releaseTcp() throws IOException { tcp.close(); }

    void releaseUdp() { udp.close(); }

    @Override
    public void close() throws IOException {
        try { tcp.close(); } finally { udp.close(); }
    }
}
