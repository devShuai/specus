package com.theshuai.specus.android;

import org.junit.Test;

import java.io.IOException;
import java.net.DatagramSocket;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.SocketException;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

public class DualProtocolLoopbackPortTest {
    @Test
    public void reservationsRemainOwnedUntilEachProtocolIsHandedOff() throws Exception {
        try (DualProtocolLoopbackPort reservation = DualProtocolLoopbackPort.reserve()) {
            int port = reservation.port();
            assertTrue(port >= 1024 && port <= 65535);
            assertThrows(IOException.class, () -> { try (ServerSocket unexpected = tcpAt(port)) { } });
            assertThrows(SocketException.class, () -> { try (DatagramSocket unexpected = udpAt(port)) { } });
            reservation.releaseTcp();
            try (ServerSocket tcp = tcpAt(port)) {
                assertEquals(port, tcp.getLocalPort());
                assertThrows(SocketException.class, () -> { try (DatagramSocket unexpected = udpAt(port)) { } });
            }
            reservation.releaseUdp();
            try (DatagramSocket udp = udpAt(port)) {
                assertEquals(port, udp.getLocalPort());
            }
        }
    }

    @Test
    public void rejectedUdpCandidateDoesNotLeakItsTcpReservation() throws Exception {
        try (DualProtocolLoopbackPort occupiedUdp = DualProtocolLoopbackPort.reserve()) {
            int unavailable = occupiedUdp.port();
            occupiedUdp.releaseTcp();
            AtomicInteger attempts = new AtomicInteger();
            try (DualProtocolLoopbackPort available = DualProtocolLoopbackPort.reserve(
                    () -> attempts.getAndIncrement() == 0 ? unavailable : DualProtocolLoopbackPort.nextCandidate())) {
                assertTrue(attempts.get() >= 2);
                assertNotEquals(unavailable, available.port());
                try (ServerSocket released = tcpAt(unavailable)) {
                    assertEquals(unavailable, released.getLocalPort());
                }
            }
        }
    }

    @Test
    public void candidateAllocationIsBoundedAndClosesAllRejectedResources() throws Exception {
        try (DualProtocolLoopbackPort occupiedUdp = DualProtocolLoopbackPort.reserve()) {
            int unavailable = occupiedUdp.port();
            occupiedUdp.releaseTcp();
            AtomicInteger attempts = new AtomicInteger();
            assertThrows(IOException.class, () -> DualProtocolLoopbackPort.reserve(() -> {
                attempts.incrementAndGet();
                return unavailable;
            }));
            assertEquals(DualProtocolLoopbackPort.MAX_CANDIDATES, attempts.get());
            try (ServerSocket released = tcpAt(unavailable)) {
                assertEquals(unavailable, released.getLocalPort());
            }
        }
    }

    private static ServerSocket tcpAt(int port) throws IOException {
        ServerSocket socket = new ServerSocket();
        try {
            socket.bind(new InetSocketAddress("127.0.0.1", port));
            return socket;
        } catch (IOException failure) { socket.close(); throw failure; }
    }

    private static DatagramSocket udpAt(int port) throws SocketException {
        DatagramSocket socket = new DatagramSocket(null);
        try {
            socket.bind(new InetSocketAddress("127.0.0.1", port));
            return socket;
        } catch (SocketException failure) { socket.close(); throw failure; }
    }
}
