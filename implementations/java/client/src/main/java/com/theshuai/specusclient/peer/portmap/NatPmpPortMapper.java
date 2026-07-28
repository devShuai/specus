package com.theshuai.specusclient.peer.portmap;

import lombok.extern.slf4j.Slf4j;

import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketTimeoutException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.time.Instant;
import java.util.Set;

/**
 * NAT-PMP（RFC 6886）实现。协议非常简单：所有报文都是定长二进制 UDP，发到网关的 5351 端口。
 *
 * <p>报文结构（big-endian）：
 *
 * <pre>
 *  External Address Request (2B)
 *    +--------+--------+
 *    | vers=0 | op=0   |
 *    +--------+--------+
 *
 *  External Address Response (12B)
 *    +--------+--------+--------+--------+
 *    | vers=0 | op=128 |   result code   |
 *    +--------+--------+--------+--------+
 *    |   seconds since start of epoch    |
 *    +--------+--------+--------+--------+
 *    |        external IPv4 (4 bytes)    |
 *    +--------+--------+--------+--------+
 *
 *  Map Request (12B)
 *    +--------+--------+--------+--------+
 *    | vers=0 | op=1   |   reserved=0    |
 *    +--------+--------+--------+--------+
 *    |  internal port  | suggested ext   |
 *    +--------+--------+--------+--------+
 *    |    requested lifetime (seconds)   |
 *    +--------+--------+--------+--------+
 *
 *  Map Response (16B)
 *    +--------+--------+--------+--------+
 *    | vers=0 | op=129 |  result code    |
 *    +--------+--------+--------+--------+
 *    |   seconds since start of epoch    |
 *    +--------+--------+--------+--------+
 *    |  internal port  | mapped ext port |
 *    +--------+--------+--------+--------+
 *    |     granted lifetime (seconds)    |
 *    +--------+--------+--------+--------+
 * </pre>
 *
 * <p>对端口操作 op：UDP=1, TCP=2，响应的 op 是请求 op + 128。
 *
 * <p>NAT-PMP 没有 "delete" 专用操作；要释放时只需要再发一次 Map Request，lifetime=0，
 * 路由器就会移除映射并返回成功。
 */
@Slf4j
final class NatPmpPortMapper implements NatPortMapper {

    private static final int NAT_PMP_PORT = 5351;
    private static final int TIMEOUT_MS = 1_500;
    private static final int MAX_ATTEMPTS = 2;

    private static final byte VERSION = 0;
    private static final byte OP_EXTERNAL_ADDRESS = 0;
    private static final byte OP_MAP_UDP = 1;
    private static final byte OP_MAP_UDP_RESPONSE = (byte) (OP_MAP_UDP | 0x80);

    /**
     * RFC 6886 §3.3 定义的 result code。
     */
    private static final int RESULT_SUCCESS = 0;
    private static final String[] RESULT_TEXT = {
            "success",
            "unsupported version",
            "not authorized / refused",
            "network failure",
            "out of resources",
            "unsupported opcode",
    };

    @Override
    public PortMappingProtocol protocol() {
        return PortMappingProtocol.NAT_PMP;
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
                log.debug("NAT-PMP attempt to {} failed: {}", gateway.getHostAddress(), e.getMessage());
            }
        }
        throw last != null ? last : new PortMappingException("NAT-PMP failed against all gateway candidates");
    }

    private NatPortMapping mapOnGateway(InetAddress gateway,
                                        int internalPort,
                                        int preferredExternal,
                                        int leaseSeconds) throws PortMappingException {
        // 先发 external-address，确认对端真的是 NAT-PMP 路由器，顺带拿到公网 IP
        String externalIp = requestExternalAddress(gateway);

        ByteBuffer mapReq = ByteBuffer.allocate(12).order(ByteOrder.BIG_ENDIAN);
        mapReq.put(VERSION);
        mapReq.put(OP_MAP_UDP);
        mapReq.putShort((short) 0); // reserved
        mapReq.putShort((short) internalPort);
        mapReq.putShort((short) preferredExternal);
        mapReq.putInt(leaseSeconds);

        byte[] response = sendAndRecv(gateway, mapReq.array(), 16);
        ByteBuffer rsp = ByteBuffer.wrap(response).order(ByteOrder.BIG_ENDIAN);
        byte respVersion = rsp.get();
        byte respOp = rsp.get();
        int resultCode = Short.toUnsignedInt(rsp.getShort());
        if (respVersion != VERSION || respOp != OP_MAP_UDP_RESPONSE) {
            throw new PortMappingException("NAT-PMP map response shape unexpected: version="
                    + respVersion + ", op=" + (respOp & 0xff));
        }
        if (resultCode != RESULT_SUCCESS) {
            throw new PortMappingException("NAT-PMP map rejected: " + describeResult(resultCode));
        }
        rsp.getInt(); // seconds since epoch (ignored)
        int reflectedInternalPort = Short.toUnsignedInt(rsp.getShort());
        int mappedExternalPort = Short.toUnsignedInt(rsp.getShort());
        int grantedLifetime = rsp.getInt();
        if (reflectedInternalPort != internalPort) {
            log.warn("NAT-PMP gateway reflected internal port mismatch: requested {}, got {}",
                    internalPort, reflectedInternalPort);
        }
        log.info("NAT-PMP mapping established: {}:{} -> internal {} (lifetime={}s, gateway={})",
                externalIp, mappedExternalPort, internalPort, grantedLifetime, gateway.getHostAddress());
        return new NatPortMapping(
                protocol(),
                externalIp,
                mappedExternalPort,
                internalPort,
                Math.max(60, grantedLifetime),
                Instant.now());
    }

    @Override
    public void deleteMapping(NatPortMapping mapping) {
        // RFC 6886 §3.4：lifetime=0 + suggested external=0 表示删除。
        Set<InetAddress> gateways = DefaultGatewayDiscovery.candidates();
        for (InetAddress gateway : gateways) {
            try {
                ByteBuffer buf = ByteBuffer.allocate(12).order(ByteOrder.BIG_ENDIAN);
                buf.put(VERSION);
                buf.put(OP_MAP_UDP);
                buf.putShort((short) 0); // reserved
                buf.putShort((short) mapping.internalPort());
                buf.putShort((short) 0); // suggested external = 0 → delete
                buf.putInt(0);           // lifetime = 0 → delete
                sendAndRecv(gateway, buf.array(), 16);
                log.debug("NAT-PMP delete sent to {} for internal port {}", gateway.getHostAddress(), mapping.internalPort());
                return;
            } catch (PortMappingException e) {
                log.debug("NAT-PMP delete on {} failed: {}", gateway.getHostAddress(), e.getMessage());
            }
        }
    }

    private String requestExternalAddress(InetAddress gateway) throws PortMappingException {
        byte[] request = new byte[]{VERSION, OP_EXTERNAL_ADDRESS};
        byte[] response = sendAndRecv(gateway, request, 12);
        ByteBuffer rsp = ByteBuffer.wrap(response).order(ByteOrder.BIG_ENDIAN);
        byte respVersion = rsp.get();
        byte respOp = rsp.get();
        int resultCode = Short.toUnsignedInt(rsp.getShort());
        if (respVersion != VERSION || (respOp & 0x7F) != OP_EXTERNAL_ADDRESS) {
            throw new PortMappingException("NAT-PMP external-address response shape unexpected");
        }
        if (resultCode != RESULT_SUCCESS) {
            throw new PortMappingException("NAT-PMP external-address rejected: " + describeResult(resultCode));
        }
        rsp.getInt(); // seconds since epoch (ignored)
        byte[] ip = new byte[4];
        rsp.get(ip);
        try {
            return InetAddress.getByAddress(ip).getHostAddress();
        } catch (Exception e) {
            throw new PortMappingException("NAT-PMP external-address parse failed", e);
        }
    }

    /**
     * 发一个请求并读响应。带指数退避重试（RFC 6886 §3.1 推荐 250ms / 500ms / 1s / 2s 的退避，
     * 我们简化成 1.5 秒固定超时 × 2 次）。
     */
    private byte[] sendAndRecv(InetAddress gateway, byte[] request, int expectedResponseSize) throws PortMappingException {
        for (int attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {
            try (DatagramSocket socket = new DatagramSocket()) {
                socket.setSoTimeout(TIMEOUT_MS);
                socket.send(new DatagramPacket(request, request.length, new InetSocketAddress(gateway, NAT_PMP_PORT)));

                byte[] buffer = new byte[Math.max(expectedResponseSize, 64)];
                DatagramPacket packet = new DatagramPacket(buffer, buffer.length);
                socket.receive(packet);

                if (packet.getLength() < expectedResponseSize) {
                    throw new PortMappingException("NAT-PMP response truncated: " + packet.getLength() + " bytes");
                }
                if (!packet.getAddress().equals(gateway)) {
                    // 收到非网关回包，忽略，继续重试
                    continue;
                }
                byte[] out = new byte[packet.getLength()];
                System.arraycopy(packet.getData(), packet.getOffset(), out, 0, packet.getLength());
                return out;
            } catch (SocketTimeoutException timeout) {
                log.trace("NAT-PMP timeout on attempt {} to {}", attempt, gateway.getHostAddress());
            } catch (PortMappingException e) {
                throw e;
            } catch (Exception e) {
                throw new PortMappingException("NAT-PMP I/O failed", e);
            }
        }
        throw new PortMappingException("NAT-PMP no response from " + gateway.getHostAddress());
    }

    private static String describeResult(int code) {
        if (code >= 0 && code < RESULT_TEXT.length) {
            return "code=" + code + "(" + RESULT_TEXT[code] + ")";
        }
        return "code=" + code;
    }
}
