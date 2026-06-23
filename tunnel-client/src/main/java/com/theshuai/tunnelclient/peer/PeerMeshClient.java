package com.theshuai.tunnelclient.peer;

import com.fasterxml.jackson.databind.JsonNode;
import com.theshuai.common.peermesh.PeerCandidate;
import com.theshuai.common.peermesh.PeerControlMessage;
import com.theshuai.common.peermesh.PeerCrypto;
import com.theshuai.common.peermesh.PeerUdpProbe;
import com.theshuai.common.clientauth.ClientAuthLoginResponse;
import com.theshuai.common.util.JsonUtil;
import lombok.extern.slf4j.Slf4j;
import org.springframework.util.StringUtils;

import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

@Slf4j
public class PeerMeshClient implements AutoCloseable {
    private final Map<Long, PeerInfo> peers = new ConcurrentHashMap<>();
    private final Map<Long, PeerSession> sessions = new ConcurrentHashMap<>();
    private final Map<String, PendingProbe> pendingProbes = new ConcurrentHashMap<>();
    private final SecureRandom secureRandom = new SecureRandom();
    private final ControlSender controlSender;
    private final PeerKeyStore.KeyMaterial keyMaterial;
    private final PeerVirtualDevice virtualDevice;
    private volatile ClientAuthLoginResponse.PeerMeshConfig config;
    private volatile boolean running;
    private volatile DatagramSocket udpSocket;
    private volatile Thread receiverThread;

    public PeerMeshClient(ClientAuthLoginResponse.PeerMeshConfig config, ControlSender controlSender) {
        this.controlSender = controlSender;
        this.keyMaterial = PeerKeyStore.keyMaterial();
        this.virtualDevice = new NoopPeerVirtualDevice();
        startOrUpdate(config);
    }

    public synchronized void startOrUpdate(ClientAuthLoginResponse.PeerMeshConfig nextConfig) {
        this.config = nextConfig;
        if (nextConfig == null || !nextConfig.isEnabled()) {
            if (running) {
                log.info("Peer mesh 已关闭");
            }
            running = false;
            peers.clear();
            sessions.clear();
            pendingProbes.clear();
            stopUdpSocket();
            virtualDevice.close();
            return;
        }
        running = true;
        startUdpSocket();
        virtualDevice.start(this::sendVirtualPacket);
        log.info("Peer mesh 已启用: client={}, virtualIp={}, cidr={}, stun={}:{}, turn={}:{}",
                nextConfig.getClientName(),
                nextConfig.getVirtualIp(),
                nextConfig.getCidr(),
                nextConfig.getStunHost(),
                nextConfig.getStunPort(),
                nextConfig.getTurnHost(),
                nextConfig.getTurnPort());
        log.info("Peer mesh UDP 探测端口: {}，加密 frame 数据面已就绪，等待 TUN/Wintun 适配接入",
                udpSocket == null ? "-" : udpSocket.getLocalPort());
        announceCandidatesToOnlinePeers();
    }

    public void handleControlMessage(String message) {
        if (!running || !StringUtils.hasText(message)) {
            return;
        }
        JsonNode root = JsonUtil.readString(message);
        if (root == null) {
            log.warn("Peer mesh 信令不是有效 JSON");
            return;
        }
        String type = root.path("type").asText("");
        if (PeerControlMessage.TYPE_ROSTER.equals(type)) {
            updateRoster(root.path("peers"));
            return;
        }
        PeerControlMessage control = JsonUtil.stringToObject(message, PeerControlMessage.class);
        if (control == null) {
            log.warn("Peer mesh 信令解析失败");
            return;
        }
        switch (type) {
            case PeerControlMessage.TYPE_SESSION_GRANT -> rememberSession(control);
            case PeerControlMessage.TYPE_CANDIDATES -> handleCandidates(control);
            case PeerControlMessage.TYPE_CLOSE -> closeSession(control);
            default -> log.debug("收到 peer mesh 信令: type={}, source={}, target={}",
                    type,
                    root.path("sourceClientName").asText("-"),
                    root.path("targetClientName").asText("-"));
        }
    }

    private void updateRoster(JsonNode peerNodes) {
        peers.clear();
        if (peerNodes != null && peerNodes.isArray()) {
            for (JsonNode node : peerNodes) {
                long clientId = node.path("clientId").asLong(0);
                if (clientId <= 0) {
                    continue;
                }
                peers.put(clientId, new PeerInfo(
                        clientId,
                        node.path("clientName").asText(""),
                        node.path("virtualIp").asText(""),
                        node.path("publicKey").asText(""),
                        node.path("online").asBoolean(false),
                        List.of()
                ));
            }
        }
        log.info("Peer mesh 可互联客户端刷新: {} 个", peers.size());
        refreshSessionKeys();
        announceCandidatesToOnlinePeers();
    }

    @Override
    public void close() {
        running = false;
        peers.clear();
        sessions.clear();
        pendingProbes.clear();
        stopUdpSocket();
        virtualDevice.close();
    }

    private void handleCandidates(PeerControlMessage control) {
        rememberSession(control);
        PeerInfo peer = peerFromSignal(control);
        if (peer == null || control.getCandidates() == null || control.getCandidates().isEmpty()) {
            return;
        }
        peers.compute(peer.clientId(), (id, current) -> {
            PeerInfo base = current == null ? peer : current;
            return new PeerInfo(
                    base.clientId(),
                    StringUtils.hasText(base.clientName()) ? base.clientName() : peer.clientName(),
                    base.virtualIp(),
                    base.publicKey(),
                    true,
                    List.copyOf(control.getCandidates())
            );
        });
        sendConnectivityChecks(control);
    }

    private void rememberSession(PeerControlMessage control) {
        if (control.getSessionId() == null || control.getSessionId() <= 0 || !StringUtils.hasText(control.getToken())) {
            return;
        }
        long peerId = peerId(control);
        if (peerId <= 0) {
            return;
        }
        PeerInfo peer = peers.get(peerId);
        String peerPublicKey = peer == null ? "" : peer.publicKey();
        PeerSession next = new PeerSession(
                control.getSessionId(),
                peerId,
                control.getToken(),
                control.getExpiresAt(),
                deriveSessionKey(control, peerId, peerPublicKey)
        );
        PeerSession previous = sessions.put(peerId, next);
        if (previous != null) {
            next.remoteEndpoint = previous.remoteEndpoint;
            next.lastInboundSequence = previous.lastInboundSequence;
        }
        log.debug("Peer mesh session 已授权: session={}, peer={}", control.getSessionId(), peerId);
    }

    private void refreshSessionKeys() {
        for (Map.Entry<Long, PeerSession> entry : sessions.entrySet()) {
            PeerSession session = entry.getValue();
            if (session.aesKey() != null) {
                continue;
            }
            PeerInfo peer = peers.get(entry.getKey());
            if (peer == null || !StringUtils.hasText(peer.publicKey())) {
                continue;
            }
            PeerControlMessage control = new PeerControlMessage();
            control.setSessionId(session.sessionId());
            control.setToken(session.token());
            byte[] aesKey = deriveSessionKey(control, session.peerId(), peer.publicKey());
            if (aesKey != null) {
                PeerSession next = session.withAesKey(aesKey);
                next.remoteEndpoint = session.remoteEndpoint;
                next.lastInboundSequence = session.lastInboundSequence;
                sessions.put(entry.getKey(), next);
            }
        }
    }

    private void closeSession(PeerControlMessage control) {
        long peerId = peerId(control);
        if (peerId > 0) {
            sessions.remove(peerId);
        }
    }

    private void announceCandidatesToOnlinePeers() {
        if (!running || config == null || controlSender == null) {
            return;
        }
        List<PeerCandidate> candidates = gatherHostCandidates();
        if (candidates.isEmpty()) {
            log.debug("Peer mesh 没有可上报的 host candidate");
            return;
        }
        for (PeerInfo peer : peers.values()) {
            if (!peer.online() || !StringUtils.hasText(peer.clientName())) {
                continue;
            }
            PeerControlMessage message = new PeerControlMessage();
            message.setType(PeerControlMessage.TYPE_CANDIDATES);
            message.setSourceClientId(config.getClientId());
            message.setSourceClientName(config.getClientName());
            message.setTargetClientId(peer.clientId());
            message.setTargetClientName(peer.clientName());
            message.setCreatedAtMillis(System.currentTimeMillis());
            message.setCandidates(candidates);
            controlSender.send(peer.clientName(), JsonUtil.objectToString(message));
        }
    }

    private List<PeerCandidate> gatherHostCandidates() {
        DatagramSocket socket = udpSocket;
        if (socket == null || socket.isClosed()) {
            return List.of();
        }
        List<PeerCandidate> candidates = new ArrayList<>();
        int port = socket.getLocalPort();
        try {
            Enumeration<NetworkInterface> interfaces = NetworkInterface.getNetworkInterfaces();
            while (interfaces != null && interfaces.hasMoreElements()) {
                NetworkInterface networkInterface = interfaces.nextElement();
                if (!networkInterface.isUp() || networkInterface.isVirtual()) {
                    continue;
                }
                Enumeration<InetAddress> addresses = networkInterface.getInetAddresses();
                while (addresses.hasMoreElements()) {
                    InetAddress address = addresses.nextElement();
                    if (!(address instanceof Inet4Address)
                            || address.isAnyLocalAddress()
                            || address.isMulticastAddress()
                            || address.isLinkLocalAddress()) {
                        continue;
                    }
                    PeerCandidate candidate = new PeerCandidate();
                    candidate.setType("host");
                    candidate.setTransport("udp");
                    candidate.setAddress(address.getHostAddress());
                    candidate.setPort(port);
                    candidate.setPriority(address.isLoopbackAddress() ? 100 : 1000);
                    candidate.setFoundation(networkInterface.getName());
                    candidates.add(candidate);
                }
            }
        } catch (SocketException e) {
            log.warn("Peer mesh host candidate 枚举失败: {}", e.getMessage());
        }
        return candidates;
    }

    private void sendConnectivityChecks(PeerControlMessage control) {
        PeerSession session = sessions.get(peerId(control));
        if (session == null) {
            return;
        }
        for (PeerCandidate candidate : control.getCandidates()) {
            if (!"udp".equalsIgnoreCase(candidate.getTransport())
                    || !StringUtils.hasText(candidate.getAddress())
                    || candidate.getPort() <= 0) {
                continue;
            }
            sendUdpProbe(session, candidate);
        }
    }

    private void sendUdpProbe(PeerSession session, PeerCandidate candidate) {
        DatagramSocket socket = udpSocket;
        if (socket == null || socket.isClosed()) {
            return;
        }
        String nonce = newNonce();
        PeerUdpProbe probe = new PeerUdpProbe();
        probe.setType(PeerUdpProbe.TYPE_CHECK);
        probe.setSessionId(session.sessionId());
        probe.setFromClientId(config.getClientId());
        probe.setToClientId(session.peerId());
        probe.setNonce(nonce);
        probe.setToken(session.token());
        probe.setSentAtMillis(System.currentTimeMillis());
        byte[] bytes = JsonUtil.objectToString(probe).getBytes(StandardCharsets.UTF_8);
        InetSocketAddress remote = new InetSocketAddress(candidate.getAddress(), candidate.getPort());
        pendingProbes.put(nonce, new PendingProbe(session.sessionId(), session.peerId(), System.currentTimeMillis(), remote));
        try {
            socket.send(new DatagramPacket(bytes, bytes.length, remote));
            log.debug("Peer mesh UDP check 已发送: session={}, remote={}", session.sessionId(), remote);
        } catch (Exception e) {
            pendingProbes.remove(nonce);
            log.debug("Peer mesh UDP check 发送失败: remote={}, reason={}", remote, e.getMessage());
        }
    }

    private void startUdpSocket() {
        DatagramSocket current = udpSocket;
        if (current != null && !current.isClosed()) {
            return;
        }
        try {
            DatagramSocket next = new DatagramSocket(0);
            next.setReuseAddress(true);
            udpSocket = next;
            Thread thread = new Thread(this::receiveLoop, "peer-mesh-udp");
            thread.setDaemon(true);
            receiverThread = thread;
            thread.start();
        } catch (Exception e) {
            log.warn("Peer mesh UDP socket 启动失败: {}", e.getMessage());
        }
    }

    private void stopUdpSocket() {
        DatagramSocket socket = udpSocket;
        udpSocket = null;
        if (socket != null) {
            socket.close();
        }
        Thread thread = receiverThread;
        receiverThread = null;
        if (thread != null) {
            thread.interrupt();
        }
    }

    private void receiveLoop() {
        byte[] buffer = new byte[2048];
        while (running) {
            DatagramSocket socket = udpSocket;
            if (socket == null || socket.isClosed()) {
                return;
            }
            DatagramPacket packet = new DatagramPacket(buffer, buffer.length);
            try {
                socket.receive(packet);
                handleUdpPacket(packet);
            } catch (SocketException e) {
                return;
            } catch (Exception e) {
                log.debug("Peer mesh UDP packet 处理失败: {}", e.getMessage());
            }
        }
    }

    private void handleUdpPacket(DatagramPacket packet) {
        if (PeerDataFrameCodec.looksLikeDataFrame(packet.getData(), packet.getOffset(), packet.getLength())) {
            handleDataFrame(packet);
            return;
        }
        String raw = new String(packet.getData(), packet.getOffset(), packet.getLength(), StandardCharsets.UTF_8);
        PeerUdpProbe probe = JsonUtil.stringToObject(raw, PeerUdpProbe.class);
        if (probe == null
                || !PeerUdpProbe.MAGIC.equals(probe.getMagic())
                || config == null
                || probe.getToClientId() == null
                || !probe.getToClientId().equals(config.getClientId())) {
            return;
        }
        if (PeerUdpProbe.TYPE_CHECK.equals(probe.getType())) {
            replyUdpProbe(probe, packet);
        } else if (PeerUdpProbe.TYPE_CHECK_RESPONSE.equals(probe.getType())) {
            completeUdpProbe(probe, packet);
        }
    }

    private void handleDataFrame(DatagramPacket packet) {
        byte[] raw = Arrays.copyOfRange(packet.getData(), packet.getOffset(), packet.getOffset() + packet.getLength());
        for (PeerSession session : sessions.values()) {
            if (session.aesKey() == null) {
                continue;
            }
            PeerDataFrame frame = PeerDataFrameCodec.decode(
                    session.aesKey(),
                    raw,
                    session.sessionId(),
                    config.getClientId()
            );
            if (frame == null || !session.acceptInboundSequence(frame.sequence())) {
                continue;
            }
            session.remoteEndpoint = new InetSocketAddress(packet.getAddress(), packet.getPort());
            log.debug("Peer mesh encrypted frame 收到: session={}, from={}, bytes={}",
                    frame.sessionId(), frame.fromClientId(), frame.plaintext().length);
            handlePlainPacket(frame);
            return;
        }
        log.debug("Peer mesh encrypted frame 无法解密或未匹配 session: remote={}", packet.getSocketAddress());
    }

    private void handlePlainPacket(PeerDataFrame frame) {
        virtualDevice.writePacket(frame.plaintext());
    }

    private void replyUdpProbe(PeerUdpProbe probe, DatagramPacket packet) {
        DatagramSocket socket = udpSocket;
        if (socket == null || socket.isClosed()) {
            return;
        }
        PeerSession session = sessions.get(probe.getFromClientId());
        if (session == null || !session.token().equals(probe.getToken())) {
            return;
        }
        PeerUdpProbe response = new PeerUdpProbe();
        response.setType(PeerUdpProbe.TYPE_CHECK_RESPONSE);
        response.setSessionId(probe.getSessionId());
        response.setFromClientId(config.getClientId());
        response.setToClientId(probe.getFromClientId());
        response.setNonce(probe.getNonce());
        response.setToken(probe.getToken());
        response.setSentAtMillis(probe.getSentAtMillis());
        byte[] bytes = JsonUtil.objectToString(response).getBytes(StandardCharsets.UTF_8);
        try {
            socket.send(new DatagramPacket(bytes, bytes.length, packet.getSocketAddress()));
        } catch (Exception e) {
            log.debug("Peer mesh UDP check-response 发送失败: {}", e.getMessage());
        }
    }

    private void completeUdpProbe(PeerUdpProbe probe, DatagramPacket packet) {
        PendingProbe pending = pendingProbes.remove(probe.getNonce());
        if (pending == null || !pending.sessionId().equals(probe.getSessionId())) {
            return;
        }
        PeerSession session = sessions.get(pending.peerId());
        if (session == null || !session.token().equals(probe.getToken())) {
            return;
        }
        long rttMillis = Math.max(0, System.currentTimeMillis() - pending.sentAtMillis());
        String remote = packet.getAddress().getHostAddress() + ":" + packet.getPort();
        String local = localEndpoint();
        session.remoteEndpoint = new InetSocketAddress(packet.getAddress(), packet.getPort());
        log.info("Peer mesh direct UDP path active: session={}, peer={}, remote={}, rtt={}ms",
                session.sessionId(), session.peerId(), remote, rttMillis);
        reportPath(session, local, remote, rttMillis);
    }

    private void reportPath(PeerSession session, String localEndpoint, String remoteEndpoint, long rttMillis) {
        if (controlSender == null) {
            return;
        }
        PeerControlMessage report = new PeerControlMessage();
        report.setType(PeerControlMessage.TYPE_PATH_REPORT);
        report.setSessionId(session.sessionId());
        report.setSourceClientId(config.getClientId());
        report.setSourceClientName(config.getClientName());
        report.setTargetClientId(session.peerId());
        PeerInfo peer = peers.get(session.peerId());
        report.setTargetClientName(peer == null ? "" : peer.clientName());
        report.setPathType("DIRECT");
        report.setStatus("ACTIVE");
        report.setLocalEndpoint(localEndpoint);
        report.setRemoteEndpoint(remoteEndpoint);
        report.setRttMillis(rttMillis);
        report.setCreatedAtMillis(System.currentTimeMillis());
        controlSender.send("", JsonUtil.objectToString(report));
    }

    public boolean sendEncryptedPayload(String targetVirtualIp, byte[] payload) {
        if (!running || !StringUtils.hasText(targetVirtualIp) || payload == null) {
            return false;
        }
        PeerInfo peer = peers.values().stream()
                .filter(item -> targetVirtualIp.equals(item.virtualIp()))
                .findFirst()
                .orElse(null);
        if (peer == null) {
            return false;
        }
        PeerSession session = sessions.get(peer.clientId());
        if (session == null || !session.canSend()) {
            return false;
        }
        DatagramSocket socket = udpSocket;
        if (socket == null || socket.isClosed()) {
            return false;
        }
        long sequence = session.nextOutboundSequence();
        byte[] frame = PeerDataFrameCodec.encode(
                session.aesKey(),
                session.sessionId(),
                config.getClientId(),
                peer.clientId(),
                sequence,
                payload
        );
        try {
            socket.send(new DatagramPacket(frame, frame.length, session.remoteEndpoint));
            return true;
        } catch (Exception e) {
            log.debug("Peer mesh encrypted frame 发送失败: peer={}, reason={}", peer.clientName(), e.getMessage());
            return false;
        }
    }

    public boolean sendVirtualPacket(byte[] ipv4Packet) {
        String targetVirtualIp = PeerIpPacket.destinationIpv4(ipv4Packet);
        if (!StringUtils.hasText(targetVirtualIp)) {
            log.trace("Peer mesh 忽略非 IPv4 或无效 IP 包");
            return false;
        }
        return sendEncryptedPayload(targetVirtualIp, ipv4Packet);
    }

    private String localEndpoint() {
        DatagramSocket socket = udpSocket;
        if (socket == null || socket.isClosed()) {
            return "";
        }
        return "0.0.0.0:" + socket.getLocalPort();
    }

    private PeerInfo peerFromSignal(PeerControlMessage control) {
        Long sourceId = control.getSourceClientId();
        Long targetId = control.getTargetClientId();
        if (config == null) {
            return null;
        }
        if (sourceId != null && !sourceId.equals(config.getClientId())) {
            return new PeerInfo(
                    sourceId,
                    control.getSourceClientName(),
                    "",
                    "",
                    true,
                    List.of()
            );
        }
        if (targetId != null && !targetId.equals(config.getClientId())) {
            return new PeerInfo(
                    targetId,
                    control.getTargetClientName(),
                    "",
                    "",
                    true,
                    List.of()
            );
        }
        return null;
    }

    private long peerId(PeerControlMessage control) {
        if (config == null) {
            return 0;
        }
        if (control.getSourceClientId() != null && !control.getSourceClientId().equals(config.getClientId())) {
            return control.getSourceClientId();
        }
        if (control.getTargetClientId() != null && !control.getTargetClientId().equals(config.getClientId())) {
            return control.getTargetClientId();
        }
        return 0;
    }

    private String newNonce() {
        byte[] bytes = new byte[12];
        secureRandom.nextBytes(bytes);
        return HexFormat.of().formatHex(bytes);
    }

    private byte[] deriveSessionKey(PeerControlMessage control, long peerId, String peerPublicKey) {
        if (!StringUtils.hasText(keyMaterial.privateKeyBase64()) || !StringUtils.hasText(peerPublicKey)) {
            log.debug("Peer mesh session={} 暂无法派生密钥: peer public key missing", control.getSessionId());
            return null;
        }
        try {
            return PeerCrypto.deriveAes256Key(
                    keyMaterial.privateKeyBase64(),
                    peerPublicKey,
                    control.getSessionId(),
                    control.getToken(),
                    config.getClientId(),
                    peerId
            );
        } catch (Exception e) {
            log.warn("Peer mesh session={} 派生密钥失败: {}", control.getSessionId(), e.getMessage());
            return null;
        }
    }

    @FunctionalInterface
    public interface ControlSender {
        void send(String toClientName, String message);
    }

    private record PeerInfo(long clientId,
                            String clientName,
                            String virtualIp,
                            String publicKey,
                            boolean online,
                            List<PeerCandidate> candidates) {
    }

    private static final class PeerSession {
        private final Long sessionId;
        private final long peerId;
        private final String token;
        private final String expiresAt;
        private final byte[] aesKey;
        private final AtomicLong outboundSequence = new AtomicLong();
        private volatile long lastInboundSequence = -1;
        private volatile InetSocketAddress remoteEndpoint;

        private PeerSession(Long sessionId, long peerId, String token, String expiresAt, byte[] aesKey) {
            this.sessionId = sessionId;
            this.peerId = peerId;
            this.token = token;
            this.expiresAt = expiresAt;
            this.aesKey = aesKey;
        }

        PeerSession withAesKey(byte[] nextKey) {
            PeerSession next = new PeerSession(sessionId, peerId, token, expiresAt, nextKey);
            next.outboundSequence.set(outboundSequence.get());
            return next;
        }

        Long sessionId() {
            return sessionId;
        }

        long peerId() {
            return peerId;
        }

        String token() {
            return token;
        }

        byte[] aesKey() {
            return aesKey;
        }

        boolean canSend() {
            return aesKey != null && remoteEndpoint != null;
        }

        long nextOutboundSequence() {
            return outboundSequence.incrementAndGet();
        }

        boolean acceptInboundSequence(long sequence) {
            if (sequence <= lastInboundSequence) {
                return false;
            }
            lastInboundSequence = sequence;
            return true;
        }
    }

    private record PendingProbe(Long sessionId,
                                long peerId,
                                long sentAtMillis,
                                InetSocketAddress remote) {
    }
}
