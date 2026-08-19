package com.theshuai.common.peermesh;

import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * Minimal DNS-SD browse for local HTTP/SSH/UDP services. Only loopback and local-interface
 * targets survive {@link PeerServiceDiscovery#requireTargetHost(String)}.
 */
public final class PeerMdnsBrowser {
    private static final String[] QUERIES = {
            "_http._tcp.local",
            "_https._tcp.local",
            "_ssh._tcp.local",
            "_udp.local"
    };

    private PeerMdnsBrowser() {
    }

    public static List<PeerMdnsCandidate> browse(Duration timeout) {
        List<byte[]> packets = new ArrayList<>();
        try (DatagramSocket socket = new DatagramSocket()) {
            socket.setSoTimeout((int) Math.max(50, timeout.toMillis() / Math.max(1, QUERIES.length)));
            socket.setBroadcast(true);
            InetAddress mdns = InetAddress.getByName("224.0.0.251");
            for (String name : QUERIES) {
                byte[] query = encodePtrQuery(name);
                socket.send(new DatagramPacket(query, query.length, mdns, 5353));
            }
            long deadline = System.currentTimeMillis() + Math.max(200, timeout.toMillis());
            byte[] buffer = new byte[1500];
            while (System.currentTimeMillis() < deadline) {
                DatagramPacket packet = new DatagramPacket(buffer, buffer.length);
                try {
                    socket.receive(packet);
                    packets.add(java.util.Arrays.copyOf(packet.getData(), packet.getLength()));
                } catch (Exception ignored) {
                    break;
                }
            }
        } catch (Exception ignored) {
            return List.of();
        }
        return parseResponses(packets);
    }

    static List<PeerMdnsCandidate> parseResponses(List<byte[]> packets) {
        Map<String, PeerMdnsCandidate> found = new LinkedHashMap<>();
        Map<String, String> ptr = new LinkedHashMap<>();
        Map<String, Srv> srv = new LinkedHashMap<>();
        Map<String, String> addr = new LinkedHashMap<>();
        for (byte[] packet : packets) {
            parsePacket(packet, ptr, srv, addr);
        }
        for (Map.Entry<String, String> entry : ptr.entrySet()) {
            Srv record = srv.get(entry.getValue().toLowerCase(Locale.ROOT));
            if (record == null) {
                continue;
            }
            String host = addr.getOrDefault(record.target.toLowerCase(Locale.ROOT), record.target);
            try {
                host = PeerServiceDiscovery.requireTargetHost(host);
            } catch (RuntimeException ignored) {
                continue;
            }
            String application = applicationFor(entry.getKey());
            String transport = PeerServiceDiscovery.APPLICATION_UDP.equals(application)
                    ? PeerServiceDiscovery.TRANSPORT_UDP : PeerServiceDiscovery.TRANSPORT_TCP;
            PeerMdnsCandidate candidate = new PeerMdnsCandidate();
            candidate.setName(instanceName(entry.getValue(), application));
            candidate.setTransport(transport);
            candidate.setApplication(application);
            candidate.setTargetHost(host);
            candidate.setTargetPort(record.port);
            found.put(candidate.getName() + ":" + host + ":" + record.port, candidate);
        }
        return List.copyOf(found.values());
    }

    private static void parsePacket(byte[] packet,
                                    Map<String, String> ptr,
                                    Map<String, Srv> srv,
                                    Map<String, String> addr) {
        if (packet == null || packet.length < 12) {
            return;
        }
        ByteBuffer buffer = ByteBuffer.wrap(packet);
        buffer.position(4);
        int questions = Short.toUnsignedInt(buffer.getShort());
        int answers = Short.toUnsignedInt(buffer.getShort());
        int authority = Short.toUnsignedInt(buffer.getShort());
        int additional = Short.toUnsignedInt(buffer.getShort());
        for (int i = 0; i < questions && buffer.hasRemaining(); i++) {
            skipName(buffer);
            if (buffer.remaining() < 4) {
                return;
            }
            buffer.getShort();
            buffer.getShort();
        }
        int records = answers + authority + additional;
        for (int i = 0; i < records && buffer.remaining() >= 10; i++) {
            int nameAt = buffer.position();
            String name = readName(buffer, packet);
            if (buffer.remaining() < 10) {
                return;
            }
            int type = Short.toUnsignedInt(buffer.getShort());
            buffer.getShort();
            buffer.getInt();
            int rdlength = Short.toUnsignedInt(buffer.getShort());
            if (buffer.remaining() < rdlength) {
                return;
            }
            int dataAt = buffer.position();
            if (type == 12) {
                String target = readName(buffer, packet);
                ptr.put(name.toLowerCase(Locale.ROOT), target);
            } else if (type == 33 && rdlength >= 6) {
                buffer.getShort();
                buffer.getShort();
                int port = Short.toUnsignedInt(buffer.getShort());
                String target = readName(buffer, packet);
                srv.put(name.toLowerCase(Locale.ROOT), new Srv(target, port));
            } else if (type == 1 && rdlength == 4) {
                int b1 = Byte.toUnsignedInt(buffer.get());
                int b2 = Byte.toUnsignedInt(buffer.get());
                int b3 = Byte.toUnsignedInt(buffer.get());
                int b4 = Byte.toUnsignedInt(buffer.get());
                addr.put(name.toLowerCase(Locale.ROOT), b1 + "." + b2 + "." + b3 + "." + b4);
            }
            buffer.position(dataAt + rdlength);
            if (nameAt == buffer.position()) {
                return;
            }
        }
    }

    private static String readName(ByteBuffer buffer, byte[] packet) {
        StringBuilder name = new StringBuilder();
        int hops = 0;
        int end = -1;
        while (hops++ < 16 && buffer.hasRemaining()) {
            int len = Byte.toUnsignedInt(buffer.get());
            if (len == 0) {
                break;
            }
            if ((len & 0xC0) == 0xC0) {
                if (!buffer.hasRemaining()) {
                    break;
                }
                int offset = ((len & 0x3F) << 8) | Byte.toUnsignedInt(buffer.get());
                if (end < 0) {
                    end = buffer.position();
                }
                if (offset < 0 || offset >= packet.length) {
                    break;
                }
                buffer.position(offset);
                continue;
            }
            if (buffer.remaining() < len) {
                break;
            }
            if (name.length() > 0) {
                name.append('.');
            }
            byte[] label = new byte[len];
            buffer.get(label);
            name.append(new String(label, StandardCharsets.UTF_8));
        }
        if (end >= 0) {
            buffer.position(end);
        }
        return name.toString();
    }

    private static void skipName(ByteBuffer buffer) {
        while (buffer.hasRemaining()) {
            int len = Byte.toUnsignedInt(buffer.get());
            if (len == 0) {
                return;
            }
            if ((len & 0xC0) == 0xC0) {
                if (buffer.hasRemaining()) {
                    buffer.get();
                }
                return;
            }
            if (buffer.remaining() < len) {
                buffer.position(buffer.limit());
                return;
            }
            buffer.position(buffer.position() + len);
        }
    }

    private static byte[] encodePtrQuery(String name) {
        ByteBuffer buffer = ByteBuffer.allocate(512);
        buffer.putShort((short) 0);
        buffer.putShort((short) 0);
        buffer.putShort((short) 1);
        buffer.putShort((short) 0);
        buffer.putShort((short) 0);
        buffer.putShort((short) 0);
        for (String label : name.split("\\.")) {
            byte[] bytes = label.getBytes(StandardCharsets.UTF_8);
            buffer.put((byte) bytes.length);
            buffer.put(bytes);
        }
        buffer.put((byte) 0);
        buffer.putShort((short) 12);
        buffer.putShort((short) 1);
        byte[] query = new byte[buffer.position()];
        buffer.flip();
        buffer.get(query);
        return query;
    }

    private static String applicationFor(String ptr) {
        String value = ptr == null ? "" : ptr.toLowerCase(Locale.ROOT);
        if (value.contains("_https._tcp")) {
            return PeerServiceDiscovery.APPLICATION_HTTPS;
        }
        if (value.contains("_http._tcp")) {
            return PeerServiceDiscovery.APPLICATION_HTTP;
        }
        if (value.contains("_ssh._tcp")) {
            return PeerServiceDiscovery.APPLICATION_SSH;
        }
        return PeerServiceDiscovery.APPLICATION_UDP;
    }

    private static String instanceName(String srvName, String application) {
        String value = srvName == null ? application : srvName;
        int dot = value.indexOf('.');
        if (dot > 0) {
            value = value.substring(0, dot);
        }
        if (value.length() > PeerServiceDiscovery.MAX_NAME_LENGTH) {
            value = value.substring(0, PeerServiceDiscovery.MAX_NAME_LENGTH);
        }
        return value.isBlank() ? application : value;
    }

    private record Srv(String target, int port) {
    }
}
