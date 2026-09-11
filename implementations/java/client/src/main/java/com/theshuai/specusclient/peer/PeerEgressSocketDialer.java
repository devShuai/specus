package com.theshuai.specusclient.peer;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetSocketAddress;
import java.net.Socket;

/**
 * The real outbound socket.
 *
 * <p>This is the one place the egress touches the network directly, and the only part of the plane
 * that is not driven by the shared vectors: what it produces is a connection, not a value.
 *
 * <h2>Keeping forwarded traffic off the tunnel</h2>
 *
 * <p>The egress sends a consumer's traffic to the real internet. If the outbound socket picked up
 * this node's own tunnel route, that traffic would go back into the mesh instead of out, and on a
 * node that is both an egress and a consumer of another egress it would loop.
 *
 * <p>The Go client marks the socket with {@code SO_MARK} so a policy routing rule can steer it to
 * the physical interface regardless of what the tunnel did to the main table. <strong>Java has no
 * equivalent.</strong> The JDK exposes neither the socket's file descriptor nor a {@code SO_MARK}
 * option, so a Java egress on Linux cannot mark its sockets without native access.
 *
 * <p>What protects a Java egress instead is the forced-deny list: this node's own tunnel and
 * virtual interface networks are refused before any connect, so a consumer cannot ask it to reach
 * back into the overlay. That covers the loop, not the routing: on a node whose tunnel has claimed
 * the default route, a Java egress will send forwarded traffic into the tunnel rather than out of
 * the physical interface. Phase one does not take the default route, so the case does not arise
 * from this feature's own rules, but an operator who took it by other means would see it.
 *
 * <p>Recorded in {@code protocol/spec/peer-egress.md} under current limitations.
 */
final class PeerEgressSocketDialer implements PeerEgressRuntime.Dialer {

    @Override
    public PeerEgressRuntime.Socket dial(String protocol, String host, int port, long timeoutMs)
            throws IOException {
        InetSocketAddress target = new InetSocketAddress(host, port);
        if (target.isUnresolved()) {
            // Addresses arrive as literals from the flow key, so this means the host was not one.
            throw new IOException("cannot resolve " + host);
        }
        if ("udp".equalsIgnoreCase(protocol)) {
            return new Datagram(target, timeoutMs);
        }
        return new Stream(target, timeoutMs);
    }

    /** One TCP connection. */
    private static final class Stream implements PeerEgressRuntime.Socket {
        private final Socket socket;
        private final InputStream in;
        private final OutputStream out;

        Stream(InetSocketAddress target, long timeoutMs) throws IOException {
            socket = new Socket();
            try {
                socket.connect(target, (int) Math.min(timeoutMs, Integer.MAX_VALUE));
                socket.setTcpNoDelay(true);
                in = socket.getInputStream();
                out = socket.getOutputStream();
            } catch (IOException failure) {
                closeQuietly();
                throw failure;
            }
        }

        @Override
        public int read(byte[] buffer) throws IOException {
            return in.read(buffer);
        }

        @Override
        public void write(byte[] data) throws IOException {
            out.write(data);
            out.flush();
        }

        @Override
        public void closeWrite() {
            try {
                socket.shutdownOutput();
            } catch (IOException alreadyGone) {
                // The consumer's half-close outliving the socket is ordinary.
            }
        }

        @Override
        public void close() {
            closeQuietly();
        }

        private void closeQuietly() {
            try {
                socket.close();
            } catch (IOException ignored) {
                // Teardown races are ordinary; the flow table has already dropped the entry.
            }
        }
    }

    /**
     * One UDP session, connected to the target so a reply from anywhere else is not delivered.
     *
     * <p>Connecting rather than binding is what makes the reply path safe: an unconnected socket
     * would accept a datagram from any source, and the plane would relay it to the consumer as
     * though it came from the address they asked for.
     */
    private static final class Datagram implements PeerEgressRuntime.Socket {
        private final DatagramSocket socket;

        Datagram(InetSocketAddress target, long timeoutMs) throws IOException {
            socket = new DatagramSocket();
            try {
                socket.connect(target);
                socket.setSoTimeout(0);
            } catch (RuntimeException failure) {
                socket.close();
                throw new IOException("connect " + target, failure);
            }
        }

        @Override
        public int read(byte[] buffer) throws IOException {
            DatagramPacket packet = new DatagramPacket(buffer, buffer.length);
            socket.receive(packet);
            return packet.getLength();
        }

        @Override
        public void write(byte[] data) throws IOException {
            socket.send(new DatagramPacket(data, data.length));
        }

        @Override
        public void close() {
            socket.close();
        }
    }
}
