package com.theshuai.specusclient.peer;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.StandardProtocolFamily;
import java.nio.ByteBuffer;
import java.nio.channels.DatagramChannel;
import java.nio.channels.SocketChannel;

/**
 * The real outbound socket.
 *
 * <p>This is the one place the egress touches the network directly, and the only part of the plane
 * that is not driven by the shared vectors: what it produces is a connection, not a value.
 *
 * <p>Each socket is bound, before it connects, to the interface the operating system would have
 * used had this node's own tunnel routes not been there; see {@link PeerEgressSocketBinding}. The
 * sockets are NIO channels rather than {@code java.net.Socket} because a channel's handle can be
 * reached to bind it, and they are opened as IPv4 so the IPv4 option applies to them.
 *
 * <p>On Linux nothing is bound. Each socket is marked instead, before it connects, for a policy
 * routing rule to steer to the physical interface, as the Go and .NET egresses mark theirs. That
 * one is best-effort; see {@link PeerEgressSocketBinder.Linux}.
 */
final class PeerEgressSocketDialer implements PeerEgressRuntime.Dialer {

    private final PeerEgressSocketBinder binder;

    PeerEgressSocketDialer(PeerEgressSocketBinder binder) {
        this.binder = binder;
    }

    @Override
    public PeerEgressRuntime.Socket dial(String protocol, String host, int port, long timeoutMs)
            throws IOException {
        InetSocketAddress target = new InetSocketAddress(host, port);
        if (target.isUnresolved()) {
            // Addresses arrive as literals from the flow key, so this means the host was not one.
            throw new IOException("cannot resolve " + host);
        }
        if ("udp".equalsIgnoreCase(protocol)) {
            return new Datagram(target, binder);
        }
        return new Stream(target, timeoutMs, binder);
    }

    /** The socket family for a target: IPv6 for an IPv6 target, which the egress now dials. */
    private static StandardProtocolFamily familyOf(InetSocketAddress target) {
        return target.getAddress() instanceof java.net.Inet6Address
                ? StandardProtocolFamily.INET6
                : StandardProtocolFamily.INET;
    }

    /** One TCP connection. */
    private static final class Stream implements PeerEgressRuntime.Socket {
        private final SocketChannel channel;

        Stream(InetSocketAddress target, long timeoutMs, PeerEgressSocketBinder binder) throws IOException {
            channel = SocketChannel.open(familyOf(target));
            try {
                binder.bind(channel, target);
                channel.socket().connect(target, (int) Math.min(timeoutMs, Integer.MAX_VALUE));
                channel.socket().setTcpNoDelay(true);
            } catch (IOException | RuntimeException failure) {
                closeQuietly();
                throw failure;
            }
        }

        @Override
        public int read(byte[] buffer) throws IOException {
            return channel.read(ByteBuffer.wrap(buffer));
        }

        @Override
        public int read(byte[] buffer, int length) throws IOException {
            return channel.read(ByteBuffer.wrap(buffer, 0, Math.min(length, buffer.length)));
        }

        @Override
        public void write(byte[] data) throws IOException {
            ByteBuffer remaining = ByteBuffer.wrap(data);
            while (remaining.hasRemaining()) {
                channel.write(remaining);
            }
        }

        @Override
        public void closeWrite() {
            try {
                channel.shutdownOutput();
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
                channel.close();
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
        private final DatagramChannel channel;

        Datagram(InetSocketAddress target, PeerEgressSocketBinder binder) throws IOException {
            channel = DatagramChannel.open(familyOf(target));
            try {
                binder.bind(channel, target);
                channel.connect(target);
            } catch (IOException | RuntimeException failure) {
                close();
                throw failure instanceof IOException io ? io : new IOException("connect " + target, failure);
            }
        }

        @Override
        public int read(byte[] buffer) throws IOException {
            return channel.read(ByteBuffer.wrap(buffer));
        }

        @Override
        public int read(byte[] buffer, int length) throws IOException {
            return channel.read(ByteBuffer.wrap(buffer, 0, Math.min(length, buffer.length)));
        }

        @Override
        public void write(byte[] data) throws IOException {
            channel.write(ByteBuffer.wrap(data));
        }

        @Override
        public void close() {
            try {
                channel.close();
            } catch (IOException ignored) {
                // Same as the stream.
            }
        }
    }
}
