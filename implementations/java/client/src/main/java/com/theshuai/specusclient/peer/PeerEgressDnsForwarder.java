package com.theshuai.specusclient.peer;

import com.theshuai.common.peeregress.Ipv4Cidr;
import java.io.DataInputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.util.Arrays;
import java.util.List;

/**
 * Sends a query the responder does not answer itself to the original upstreams, and brings back
 * the first reply (protocol/spec/peer-egress-dns.md, section three, "forwarding").
 *
 * <p>The query goes byte for byte and the reply comes back byte for byte, TC bit included: nothing
 * is rewritten or cached. Upstreams are tried in order, each given two seconds -- for UDP to
 * answer, for TCP to connect and answer -- and an unreachable one is passed over at once. A UDP
 * reply is taken only from the upstream it was sent to and only with the query's ID; anything
 * else is ignored while the wait goes on. Nothing is resolved here: resolving would be one more way
 * out of the machine besides the rules.
 *
 * <p>The sockets are ordinary ones and follow the system's routes. An upstream an egress rule
 * covers is therefore reached through that egress, which is what the rule asks for.
 */
final class PeerEgressDnsForwarder implements PeerEgressDnsResponder.Forwarder {

    /** How long one upstream is given. */
    static final long UPSTREAM_TIMEOUT_MS = 2_000L;
    static final int DNS_PORT = 53;
    private static final int MAX_MESSAGE = 65_535;

    private final long timeoutMs;

    PeerEgressDnsForwarder() {
        this(UPSTREAM_TIMEOUT_MS);
    }

    /** With a shorter wait, so a test of the fallback does not spend two seconds per upstream. */
    PeerEgressDnsForwarder(long timeoutMs) {
        this.timeoutMs = timeoutMs;
    }

    @Override
    public byte[] forward(byte[] query, boolean tcp, List<InetSocketAddress> upstreams) {
        int id = PeerEgressDnsMessage.id(query);
        for (InetSocketAddress upstream : upstreams) {
            try {
                byte[] reply = tcp ? overTcp(query, id, upstream) : overUdp(query, id, upstream);
                if (reply != null) {
                    return reply;
                }
            } catch (IOException | RuntimeException unavailable) {
                // Timed out, unreachable or refused: the next upstream is asked.
            }
        }
        return null;
    }

    private byte[] overUdp(byte[] query, int id, InetSocketAddress upstream) throws IOException {
        long deadline = System.nanoTime() + timeoutMs * 1_000_000L;
        try (DatagramSocket socket = new DatagramSocket()) {
            // Connected, so the kernel delivers only what comes from the upstream's address and
            // port, and reports it unreachable instead of leaving the wait to time out.
            socket.connect(upstream);
            socket.send(new DatagramPacket(query, query.length));
            byte[] buffer = new byte[MAX_MESSAGE];
            while (true) {
                long remaining = (deadline - System.nanoTime()) / 1_000_000L;
                if (remaining <= 0) {
                    return null;
                }
                socket.setSoTimeout((int) Math.max(1, remaining));
                DatagramPacket packet = new DatagramPacket(buffer, buffer.length);
                try {
                    socket.receive(packet);
                } catch (SocketTimeoutException timedOut) {
                    return null;
                }
                byte[] reply = Arrays.copyOf(packet.getData(), packet.getLength());
                if (PeerEgressDnsMessage.id(reply) == id) {
                    return reply;
                }
            }
        }
    }

    private byte[] overTcp(byte[] query, int id, InetSocketAddress upstream) throws IOException {
        long deadline = System.nanoTime() + timeoutMs * 1_000_000L;
        try (Socket socket = new Socket()) {
            socket.connect(upstream, (int) Math.max(1, timeoutMs));
            long remaining = (deadline - System.nanoTime()) / 1_000_000L;
            if (remaining <= 0) {
                return null;
            }
            socket.setSoTimeout((int) remaining);
            OutputStream out = socket.getOutputStream();
            byte[] framed = new byte[2 + query.length];
            framed[0] = (byte) (query.length >>> 8);
            framed[1] = (byte) query.length;
            System.arraycopy(query, 0, framed, 2, query.length);
            out.write(framed);
            out.flush();
            DataInputStream in = new DataInputStream(socket.getInputStream());
            int length = in.readUnsignedShort();
            byte[] reply = new byte[length];
            // The whole reply within the same two seconds: the timeout re-arms on each read, so the
            // deadline is checked between them.
            int read = 0;
            while (read < length) {
                remaining = (deadline - System.nanoTime()) / 1_000_000L;
                if (remaining <= 0) {
                    return null;
                }
                socket.setSoTimeout((int) remaining);
                int count = in.read(reply, read, length - read);
                if (count < 0) {
                    return null;
                }
                read += count;
            }
            return PeerEgressDnsMessage.id(reply) == id ? reply : null;
        }
    }

    /**
     * An upstream as the caller names it: an IPv4 address with an optional port ({@code 192.0.2.53},
     * {@code 127.0.0.1:5353}), or an IPv6 address, bracketed when it carries a port. Only literal
     * addresses: a name would have to be resolved, which is what forwarding exists not to do.
     * Null when the text is none of these.
     */
    static InetSocketAddress parseUpstream(String text) {
        String value = text == null ? "" : text.trim();
        if (value.isEmpty()) {
            return null;
        }
        try {
            if (value.startsWith("[")) {
                int close = value.indexOf(']');
                if (close < 0) {
                    return null;
                }
                String host = value.substring(1, close);
                String rest = value.substring(close + 1);
                int port = rest.isEmpty() ? DNS_PORT : rest.startsWith(":") ? port(rest.substring(1)) : -1;
                byte[] address = PeerEgressDnsTakeoverParse.parseIpv6(host);
                return port < 0 || address == null ? null
                        : new InetSocketAddress(InetAddress.getByAddress(address), port);
            }
            int colon = value.indexOf(':');
            if (colon >= 0 && value.indexOf(':', colon + 1) >= 0) {
                // Bare IPv6, parsed here: InetAddress.getByName would hand malformed text to the
                // resolver, and forwarding must never cause a lookup of its own.
                byte[] address = PeerEgressDnsTakeoverParse.parseIpv6(value);
                return address == null ? null : new InetSocketAddress(InetAddress.getByAddress(address), DNS_PORT);
            }
            String host = colon < 0 ? value : value.substring(0, colon);
            int port = colon < 0 ? DNS_PORT : port(value.substring(colon + 1));
            Integer address = Ipv4Cidr.parseAddress(host);
            if (address == null || port < 0) {
                return null;
            }
            return new InetSocketAddress(InetAddress.getByAddress(new byte[] {
                    (byte) (address >>> 24), (byte) (address >>> 16), (byte) (address >>> 8), (byte) (int) address}),
                    port);
        } catch (IOException | IllegalArgumentException unusable) {
            return null;
        }
    }

    private static int port(String text) {
        if (text.isEmpty() || text.length() > 5 || !text.chars().allMatch(c -> c >= '0' && c <= '9')) {
            return -1;
        }
        int port = Integer.parseInt(text);
        return port >= 1 && port <= 65_535 ? port : -1;
    }
}
