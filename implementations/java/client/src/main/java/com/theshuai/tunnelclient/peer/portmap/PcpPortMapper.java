package com.theshuai.tunnelclient.peer.portmap;

import lombok.extern.slf4j.Slf4j;

import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketTimeoutException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Set;

/**
 * PCP（Port Control Protocol，RFC 6887）实现。PCP 是 NAT-PMP 的官方后继协议，
 * 同样用 UDP 5351 端口（和 NAT-PMP 共用），但报文版本号是 2，结构稍大但功能更全。
 *
 * <p>PCP server 按规范应当**同时**回应 NAT-PMP v0 请求；这里把两个 mapper 分开写
 * 是为了语义清晰，调用方按需各试一次。
 *
 * <p>Request 报文（共 60 字节，MAP opcode）：
 *
 * <pre>
 *  Common Header (24 bytes)
 *    +---------+---------+---------+---------+
 *    | vers=2  | R=0,op=1|     reserved=0    |
 *    +---------+---------+---------+---------+
 *    |       requested lifetime (4B)         |
 *    +---------+---------+---------+---------+
 *    |     client IP address (16B)           |
 *    |     (IPv4-mapped v6: ::ffff:a.b.c.d)  |
 *    +---------+---------+---------+---------+
 *
 *  MAP opcode-specific data (36 bytes)
 *    +---------+---------+---------+---------+
 *    |          mapping nonce (12B)          |
 *    +---------+---------+---------+---------+
 *    |proto=17 |     reserved=0 (3B)         |
 *    +---------+---------+---------+---------+
 *    | internal port     | suggested ext port|
 *    +---------+---------+---------+---------+
 *    |     suggested external IP (16B)       |
 *    +---------+---------+---------+---------+
 * </pre>
 *
 * <p>Response（同样 60 字节）头部 result code 在 byte[3]。Mapping Nonce 必须和请求一致——
 * 这是 PCP 用来防止其它客户端伪造"代你删除映射"的机制。
 */
@Slf4j
final class PcpPortMapper implements NatPortMapper {

    private static final int PCP_PORT = 5351;
    private static final int TIMEOUT_MS = 1_500;
    private static final int MAX_ATTEMPTS = 2;

    private static final byte VERSION = 2;
    private static final byte OPCODE_MAP = 1;
    private static final byte RESPONSE_MAP_OPCODE = (byte) (OPCODE_MAP | 0x80);
    private static final byte PROTOCOL_UDP = 17;

    private static final int REQUEST_SIZE = 60;
    private static final int RESPONSE_SIZE = 60;

    /**
     * Nonce 在一个客户端生命周期内复用：续期时复用同一 nonce 才能确保路由器把它当成
     * 「同一个 owner 在 refresh」，而不是 「新 owner 在新建」。
     */
    private final byte[] nonce = new byte[12];

    PcpPortMapper() {
        new SecureRandom().nextBytes(nonce);
    }

    @Override
    public PortMappingProtocol protocol() {
        return PortMappingProtocol.PCP;
    }

    @Override
    public NatPortMapping addMapping(int internalPort,
                                     int preferredExternal,
                                     int leaseSeconds,
                                     String description) throws PortMappingException {
        Set<InetAddress> gateways = DefaultGatewayDiscovery.candidates();
        if (gateways.isEmpty()) {
            throw new PortMappingException("no default gateway candidates found");
        }
        PortMappingException last = null;
        for (InetAddress gateway : gateways) {
            try {
                return mapOnGateway(gateway, internalPort, preferredExternal, leaseSeconds);
            } catch (PortMappingException e) {
                last = e;
                log.debug("PCP attempt to {} failed: {}", gateway.getHostAddress(), e.getMessage());
            }
        }
        throw last != null ? last : new PortMappingException("PCP failed against all gateway candidates");
    }

    private NatPortMapping mapOnGateway(InetAddress gateway,
                                        int internalPort,
                                        int preferredExternal,
                                        int leaseSeconds) throws PortMappingException {
        // 推导本机出口 IP（在 IPv4-mapped IPv6 里）。RFC 6887 要求 client IP 字段填的是
        // 这台机器**面向网关那一侧**的 IP，路由器据此校验是否同源；填错会被 ADDRESS_MISMATCH 拒。
        byte[] clientIp16 = clientIpMappedIpv6(gateway);

        ByteBuffer req = ByteBuffer.allocate(REQUEST_SIZE).order(ByteOrder.BIG_ENDIAN);
        // Common header
        req.put(VERSION);
        req.put(OPCODE_MAP); // R=0, opcode=1
        req.putShort((short) 0); // reserved
        req.putInt(leaseSeconds);
        req.put(clientIp16);
        // MAP opcode-specific
        req.put(nonce);
        req.put(PROTOCOL_UDP);
        req.put((byte) 0); // reserved
        req.put((byte) 0);
        req.put((byte) 0);
        req.putShort((short) internalPort);
        req.putShort((short) preferredExternal);
        // suggested external IP = all zeros = 「让路由器决定」
        req.put(new byte[16]);

        byte[] response = sendAndRecv(gateway, req.array());
        ByteBuffer rsp = ByteBuffer.wrap(response).order(ByteOrder.BIG_ENDIAN);
        byte respVersion = rsp.get();
        byte respOpcode = rsp.get();
        rsp.get(); // reserved
        int resultCode = Byte.toUnsignedInt(rsp.get());
        if (respVersion != VERSION) {
            throw new PortMappingException("PCP response version mismatch: got " + respVersion);
        }
        if (respOpcode != RESPONSE_MAP_OPCODE) {
            throw new PortMappingException("PCP response opcode mismatch: got 0x" + Integer.toHexString(respOpcode & 0xff));
        }
        if (resultCode != 0) {
            throw new PortMappingException("PCP MAP rejected: " + describeResult(resultCode));
        }
        int grantedLifetime = rsp.getInt();
        rsp.getInt(); // epoch (ignored)
        // skip 12 bytes reserved
        rsp.position(rsp.position() + 12);
        // MAP opcode response data
        byte[] respNonce = new byte[12];
        rsp.get(respNonce);
        if (!java.util.Arrays.equals(respNonce, nonce)) {
            throw new PortMappingException("PCP MAP response nonce mismatch (replay attack?)");
        }
        byte respProto = rsp.get();
        if (respProto != PROTOCOL_UDP) {
            throw new PortMappingException("PCP MAP response protocol mismatch: " + respProto);
        }
        rsp.get();
        rsp.get();
        rsp.get(); // reserved
        int reflectedInternalPort = Short.toUnsignedInt(rsp.getShort());
        int assignedExternalPort = Short.toUnsignedInt(rsp.getShort());
        byte[] externalIp16 = new byte[16];
        rsp.get(externalIp16);
        String externalAddr = extractIpv4(externalIp16);
        if (reflectedInternalPort != internalPort) {
            log.warn("PCP gateway reflected internal port mismatch: requested {}, got {}",
                    internalPort, reflectedInternalPort);
        }
        log.info("PCP mapping established: {}:{} -> internal {} (lifetime={}s, gateway={})",
                externalAddr, assignedExternalPort, internalPort, grantedLifetime, gateway.getHostAddress());
        return new NatPortMapping(
                protocol(),
                externalAddr,
                assignedExternalPort,
                internalPort,
                Math.max(60, grantedLifetime),
                Instant.now());
    }

    @Override
    public void deleteMapping(NatPortMapping mapping) {
        // RFC 6887 §15: lifetime=0 + nonce matching 表示删除该映射
        try {
            addMapping(mapping.internalPort(), 0, 0, null);
        } catch (PortMappingException e) {
            log.debug("PCP delete failed (best-effort): {}", e.getMessage());
        }
    }

    /**
     * 推导本机面向网关那一侧的 IPv4 地址，转成 IPv4-mapped IPv6（::ffff:a.b.c.d）。
     */
    private static byte[] clientIpMappedIpv6(InetAddress gateway) throws PortMappingException {
        try (DatagramSocket socket = new DatagramSocket()) {
            socket.connect(new InetSocketAddress(gateway, PCP_PORT));
            InetAddress local = socket.getLocalAddress();
            if (local instanceof Inet4Address) {
                byte[] mapped = new byte[16];
                // ::ffff:a.b.c.d   →  bytes 10..11 = 0xff 0xff, bytes 12..15 = the v4
                mapped[10] = (byte) 0xff;
                mapped[11] = (byte) 0xff;
                System.arraycopy(local.getAddress(), 0, mapped, 12, 4);
                return mapped;
            } else if (local instanceof Inet6Address) {
                return local.getAddress();
            }
            throw new PortMappingException("PCP cannot determine local IP facing gateway " + gateway.getHostAddress());
        } catch (Exception e) {
            throw new PortMappingException("PCP local IP discovery failed", e);
        }
    }

    private static String extractIpv4(byte[] ipv6Bytes) {
        // 检查 IPv4-mapped IPv6 前缀 ::ffff:0:0/96
        boolean prefixZero = true;
        for (int i = 0; i < 10; i++) {
            if (ipv6Bytes[i] != 0) {
                prefixZero = false;
                break;
            }
        }
        if (prefixZero && ipv6Bytes[10] == (byte) 0xff && ipv6Bytes[11] == (byte) 0xff) {
            try {
                byte[] v4 = new byte[4];
                System.arraycopy(ipv6Bytes, 12, v4, 0, 4);
                return InetAddress.getByAddress(v4).getHostAddress();
            } catch (Exception ignored) {
            }
        }
        try {
            return InetAddress.getByAddress(ipv6Bytes).getHostAddress();
        } catch (Exception e) {
            return "?";
        }
    }

    private byte[] sendAndRecv(InetAddress gateway, byte[] request) throws PortMappingException {
        for (int attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {
            try (DatagramSocket socket = new DatagramSocket()) {
                socket.setSoTimeout(TIMEOUT_MS);
                socket.send(new DatagramPacket(request, request.length, new InetSocketAddress(gateway, PCP_PORT)));

                byte[] buffer = new byte[1100];
                DatagramPacket packet = new DatagramPacket(buffer, buffer.length);
                socket.receive(packet);
                if (packet.getLength() < RESPONSE_SIZE) {
                    throw new PortMappingException("PCP response truncated: " + packet.getLength() + " bytes");
                }
                if (!packet.getAddress().equals(gateway)) {
                    continue;
                }
                byte[] out = new byte[packet.getLength()];
                System.arraycopy(packet.getData(), packet.getOffset(), out, 0, packet.getLength());
                return out;
            } catch (SocketTimeoutException timeout) {
                log.trace("PCP timeout on attempt {} to {}", attempt, gateway.getHostAddress());
            } catch (PortMappingException e) {
                throw e;
            } catch (Exception e) {
                throw new PortMappingException("PCP I/O failed", e);
            }
        }
        throw new PortMappingException("PCP no response from " + gateway.getHostAddress());
    }

    private static String describeResult(int code) {
        return switch (code) {
            case 1 -> "UNSUPP_VERSION";
            case 2 -> "NOT_AUTHORIZED";
            case 3 -> "MALFORMED_REQUEST";
            case 4 -> "UNSUPP_OPCODE";
            case 5 -> "UNSUPP_OPTION";
            case 6 -> "MALFORMED_OPTION";
            case 7 -> "NETWORK_FAILURE";
            case 8 -> "NO_RESOURCES";
            case 9 -> "UNSUPP_PROTOCOL";
            case 10 -> "USER_EX_QUOTA";
            case 11 -> "CANNOT_PROVIDE_EXTERNAL";
            case 12 -> "ADDRESS_MISMATCH";
            case 13 -> "EXCESSIVE_REMOTE_PEERS";
            default -> "result=" + code;
        };
    }
}
