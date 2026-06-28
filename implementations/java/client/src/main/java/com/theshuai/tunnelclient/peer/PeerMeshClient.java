package com.theshuai.tunnelclient.peer;

import com.fasterxml.jackson.databind.JsonNode;
import com.theshuai.common.peermesh.PeerCandidate;
import com.theshuai.common.peermesh.PeerControlMessage;
import com.theshuai.common.peermesh.PeerCrypto;
import com.theshuai.common.peermesh.PeerRelayBinaryFrame;
import com.theshuai.common.peermesh.PeerRelayMessage;
import com.theshuai.common.peermesh.PeerUdpProbe;
import com.theshuai.common.clientauth.ClientAuthLoginResponse;
import com.theshuai.common.util.JsonUtil;
import com.theshuai.tunnelclient.peer.portmap.NatPortMapping;
import com.theshuai.tunnelclient.peer.portmap.NatPortMappingService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.util.StringUtils;

import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Enumeration;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;

@Slf4j
public class PeerMeshClient implements AutoCloseable {
    private final Map<Long, PeerInfo> peers = new ConcurrentHashMap<>();
    private final Map<Long, PeerSession> sessions = new ConcurrentHashMap<>();
    private final Map<String, PendingProbe> pendingProbes = new ConcurrentHashMap<>();
    private final Map<String, NatProbeObservation> natProbeObservations = new ConcurrentHashMap<>();
    private final Map<String, Long> payloadDropLogMillis = new ConcurrentHashMap<>();
    private final Map<String, Long> packetTraceLogMillis = new ConcurrentHashMap<>();
    private final Map<Long, List<PendingVirtualPacket>> pendingVirtualPackets = new ConcurrentHashMap<>();
    private final Map<Long, Long> pathPrepareMillis = new ConcurrentHashMap<>();
    private final AtomicBoolean directSuppressedLogged = new AtomicBoolean(false);
    private final SecureRandom secureRandom = new SecureRandom();
    private final ControlSender controlSender;
    private final PeerKeyStore.KeyMaterial keyMaterial;
    private final PeerVirtualDeviceOptions virtualDeviceOptions;
    private volatile ClientAuthLoginResponse.PeerMeshConfig config;
    private volatile boolean running;
    private volatile DatagramSocket udpSocket;
    private volatile Thread receiverThread;
    private volatile PeerVirtualDevice virtualDevice = new NoopPeerVirtualDevice();
    private volatile String virtualDeviceKey = "noop";
    private volatile PeerCandidate serverReflexiveCandidate;
    private volatile PeerCandidate relayCandidate;
    private volatile PeerCandidate portMapCandidate;
    private volatile NatPortMapping portMapping;
    private volatile long lastPortMapAttemptMillis;
    private final NatPortMappingService natPortMappingService = new NatPortMappingService();
    private volatile String natType = "";
    private volatile String lastEndpoint = "";
    private volatile String relayAllocationId;
    private volatile long relayAllocationExpiresAtMillis;
    private volatile long lastRelayCandidateRequestMillis;
    private volatile long lastAlternateNatProbeRequestMillis;
    private volatile ScheduledExecutorService maintenanceExecutor;
    private static final long MAX_SESSION_REFRESH_WINDOW_MILLIS = 120_000;
    private static final long MIN_SESSION_REFRESH_WINDOW_MILLIS = 10_000;
    private static final long DIRECT_STALE_MILLIS = 45_000;
    private static final long PENDING_PROBE_TTL_MILLIS = 15_000;
    private static final long PENDING_PACKET_TTL_MILLIS = 30_000;
    private static final int MAX_PENDING_PACKETS_PER_PEER = 32;
    private static final long ON_DEMAND_PREPARE_INTERVAL_MILLIS = 2_000;
    private static final long NAT_PROBE_STALE_MILLIS = 120_000;
    private static final long ALTERNATE_NAT_PROBE_MIN_INTERVAL_MILLIS = 15_000;
    /**
     * 端口映射重试节流：上次尝试失败后，最少等多久再试一次。失败的网关通常持续失败，
     * 30 秒退避足够避免狂刷 log 也保证用户在路由器 reboot 后能尽快重新映射。
     */
    private static final long PORT_MAPPING_RETRY_INTERVAL_MILLIS = 30_000;
    /** 端口映射 lease 请求长度（秒）。多数路由器会钳到 7200 或自家默认值。 */
    private static final int PORT_MAPPING_LEASE_SECONDS = 7_200;

    public PeerMeshClient(ClientAuthLoginResponse.PeerMeshConfig config, ControlSender controlSender) {
        this(config, controlSender, new PeerVirtualDeviceOptions(
                "noop", "shuai0", PeerVirtualDeviceOptions.DEFAULT_MTU));
    }

    public PeerMeshClient(ClientAuthLoginResponse.PeerMeshConfig config,
                          ControlSender controlSender,
                          PeerVirtualDeviceOptions virtualDeviceOptions) {
        this.controlSender = controlSender;
        this.keyMaterial = PeerKeyStore.keyMaterial();
        this.virtualDeviceOptions = virtualDeviceOptions == null
                ? new PeerVirtualDeviceOptions("noop", "shuai0", PeerVirtualDeviceOptions.DEFAULT_MTU)
                : virtualDeviceOptions;
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
            natProbeObservations.clear();
            payloadDropLogMillis.clear();
            packetTraceLogMillis.clear();
            pendingVirtualPackets.clear();
            pathPrepareMillis.clear();
            serverReflexiveCandidate = null;
            relayCandidate = null;
            releasePortMapping();
            natType = "";
            lastEndpoint = "";
            directSuppressedLogged.set(false);
            relayAllocationId = null;
            relayAllocationExpiresAtMillis = 0;
            lastRelayCandidateRequestMillis = 0;
            lastAlternateNatProbeRequestMillis = 0;
            stopMaintenance();
            stopUdpSocket();
            closeVirtualDevice();
            return;
        }
        running = true;
        startUdpSocket();
        tryAcquirePortMappingAsync();
        startMaintenance();
        requestPeerServerCandidates();
        PeerVirtualDevice activeDevice = startVirtualDevice(nextConfig);
        log.info("Peer mesh 已启用: client={}, virtualIp={}, cidr={}, stun={}:{}, turn={}:{}",
                nextConfig.getClientName(),
                nextConfig.getVirtualIp(),
                nextConfig.getCidr(),
                nextConfig.getStunHost(),
                nextConfig.getStunPort(),
                nextConfig.getTurnHost(),
                nextConfig.getTurnPort());
        log.info("Peer mesh UDP 探测端口: {}，虚拟网卡适配: {}",
                udpSocket == null ? "-" : udpSocket.getLocalPort(),
                activeDevice.name());
        announceCandidatesToOnlinePeers();
    }

    public void handleControlMessage(String message) {
        if (!StringUtils.hasText(message)) {
            return;
        }
        JsonNode root = JsonUtil.readString(message);
        if (root == null) {
            log.warn("Peer mesh 信令不是有效 JSON");
            return;
        }
        String type = root.path("type").asText("");
        if (PeerControlMessage.TYPE_CONFIG.equals(type)) {
            PeerControlMessage control = JsonUtil.stringToObject(message, PeerControlMessage.class);
            if (control == null || control.getPeerMesh() == null) {
                log.warn("Peer mesh 配置刷新消息无效");
                return;
            }
            startOrUpdate(control.getPeerMesh());
            return;
        }
        if (!running) {
            return;
        }
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
            case PeerControlMessage.TYPE_SESSION_GRANT -> {
                mergePeerFromSignal(control, null);
                rememberSession(control);
            }
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
        natProbeObservations.clear();
        payloadDropLogMillis.clear();
        packetTraceLogMillis.clear();
        pendingVirtualPackets.clear();
        pathPrepareMillis.clear();
        // 先释放 port mapping（best-effort 通知路由器撤销），再停 socket。
        // 即使释放失败，路由器侧的 lease 也会自动过期。
        releasePortMapping();
        stopMaintenance();
        stopUdpSocket();
        closeVirtualDevice();
    }

    // ─── NAT Port Mapping (UPnP / NAT-PMP / PCP) ────────────────────────────────

    /**
     * 异步触发一次端口映射协商。UPnP SSDP 多播 + 3 个 mapper 并发，最多 4 秒返回。
     * 单独起线程，不阻塞 startOrUpdate 的同步段。失败兜底交给 STUN/打洞。
     *
     * <p>节流：上一次（成功或失败）{@link #PORT_MAPPING_RETRY_INTERVAL_MILLIS} 毫秒内不重试，
     * 避免坏路由器场景里反复打满 log。
     */
    private void tryAcquirePortMappingAsync() {
        DatagramSocket socket = udpSocket;
        if (socket == null || socket.isClosed()) {
            return;
        }
        long now = System.currentTimeMillis();
        if (now - lastPortMapAttemptMillis < PORT_MAPPING_RETRY_INTERVAL_MILLIS && portMapping == null) {
            return;
        }
        lastPortMapAttemptMillis = now;
        int internalPort = socket.getLocalPort();
        if (internalPort <= 0) {
            return;
        }
        Thread thread = new Thread(() -> attemptPortMapping(internalPort), "peer-mesh-port-mapper");
        thread.setDaemon(true);
        thread.start();
    }

    private void attemptPortMapping(int internalPort) {
        if (!running) {
            return;
        }
        NatPortMapping mapping;
        try {
            mapping = natPortMappingService.tryAcquireMapping(
                    internalPort,
                    internalPort,
                    PORT_MAPPING_LEASE_SECONDS,
                    "shuai-tunnel peer mesh");
        } catch (Exception e) {
            log.debug("Peer mesh NAT 端口映射尝试异常: {}", e.getMessage());
            return;
        }
        if (!running || mapping == null) {
            return;
        }
        // 把映射结果转成一个 candidate，对端来连这个 (externalAddress, externalPort) 就能直达。
        // type=srflx 让现有协议路径（连通性检查、Path 选择）零修改就能用上。
        PeerCandidate candidate = new PeerCandidate();
        candidate.setType("srflx");
        candidate.setTransport("udp");
        candidate.setAddress(mapping.externalAddress());
        candidate.setPort(mapping.externalPort());
        // 比 STUN srflx (800) 高，因为这是路由器**显式承诺**的映射，比通过 STUN 推断的更可靠。
        candidate.setPriority(900);
        candidate.setFoundation("port-map-" + mapping.protocol().name().toLowerCase());
        portMapCandidate = candidate;
        portMapping = mapping;
        log.info("Peer mesh NAT 端口映射成功: protocol={}, external={}:{}, internal={}, lease={}s",
                mapping.protocol(),
                mapping.externalAddress(),
                mapping.externalPort(),
                mapping.internalPort(),
                mapping.leaseSeconds());
        announceCandidatesToOnlinePeers();
    }

    private void renewPortMappingIfNeeded() {
        NatPortMapping current = portMapping;
        if (current == null) {
            // 没有现存映射，看看是不是节流窗口外了，可以重新尝试。
            tryAcquirePortMappingAsync();
            return;
        }
        if (!current.shouldRenew(Instant.now())) {
            return;
        }
        DatagramSocket socket = udpSocket;
        if (socket == null || socket.isClosed()) {
            return;
        }
        NatPortMapping renewed = natPortMappingService.renewMapping(
                current,
                PORT_MAPPING_LEASE_SECONDS,
                "shuai-tunnel peer mesh");
        if (renewed != null) {
            portMapping = renewed;
            log.debug("Peer mesh NAT 端口映射续期: protocol={}, external={}:{}, lease={}s",
                    renewed.protocol(), renewed.externalAddress(), renewed.externalPort(), renewed.leaseSeconds());
        } else {
            // 续期失败，丢掉当前映射，让 maintenance 下一轮重新发起 acquire
            log.info("Peer mesh NAT 端口映射续期失败，下次 maintenance 重新协商");
            portMapping = null;
            portMapCandidate = null;
            lastPortMapAttemptMillis = 0;  // 立刻允许重试
        }
    }

    private void releasePortMapping() {
        NatPortMapping current = portMapping;
        portMapping = null;
        portMapCandidate = null;
        lastPortMapAttemptMillis = 0;
        if (current != null) {
            try {
                natPortMappingService.releaseMapping(current);
            } catch (Exception e) {
                log.debug("Peer mesh NAT 端口映射释放失败（best-effort，路由器侧 lease 会自动过期）: {}",
                        e.getMessage());
            }
        }
    }

    private void handleCandidates(PeerControlMessage control) {
        PeerInfo peer = peerFromSignal(control);
        if (peer == null || control.getCandidates() == null || control.getCandidates().isEmpty()) {
            return;
        }
        mergePeer(peer, control.getCandidates());
        rememberSession(control);
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
            boolean sameSession = previous.sessionId().equals(next.sessionId());
            if (sameSession) {
                next.outboundSequence.set(previous.outboundSequence.get());
                next.inboundReplayWindow = previous.inboundReplayWindow.copy();
            }
            next.remoteEndpoint = previous.remoteEndpoint;
            next.relayTargetAllocationId = previous.relayTargetAllocationId;
            next.directBytesSinceReport.addAndGet(previous.drainDirectBytes());
            next.lastDirectSuccessMillis = previous.lastDirectSuccessMillis;
            next.lastRelaySuccessMillis = previous.lastRelaySuccessMillis;
            next.lastDirectKeepaliveMillis = previous.lastDirectKeepaliveMillis;
            next.lastPathLogMillis = previous.lastPathLogMillis;
            next.lastPathReportMillis = previous.lastPathReportMillis;
            next.lastKeyMissingLogMillis = previous.lastKeyMissingLogMillis;
            next.lastPathRemoteText = previous.lastPathRemoteText;
            next.currentPathType = previous.currentPathType;
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
            if (session.isExpired(System.currentTimeMillis())) {
                sessions.remove(entry.getKey(), session);
                continue;
            }
            PeerControlMessage control = new PeerControlMessage();
            control.setSessionId(session.sessionId());
            control.setToken(session.token());
            byte[] aesKey = deriveSessionKey(control, session.peerId(), peer.publicKey());
            if (aesKey != null) {
                PeerSession next = session.withAesKey(aesKey);
                sessions.put(entry.getKey(), next);
            }
        }
    }

    private void closeSession(PeerControlMessage control) {
        long peerId = peerId(control);
        if (peerId > 0) {
            sessions.remove(peerId);
            PeerInfo peer = peers.get(peerId);
            if (peer != null && peer.online()) {
                pathPrepareMillis.remove(peerId);
                preparePathForPeer(peer, null);
            }
        }
    }

    private void announceCandidatesToOnlinePeers() {
        if (!running || config == null || controlSender == null) {
            return;
        }
        requestPeerServerCandidates();
        List<PeerCandidate> candidates = gatherHostCandidates();
        if (candidates.isEmpty()) {
            log.debug("Peer mesh 没有可上报的 host candidate");
            return;
        }
        for (PeerInfo peer : peers.values()) {
            if (!peer.online() || !StringUtils.hasText(peer.clientName())) {
                continue;
            }
            PeerSession session = reusableSession(peer.clientId());
            sendCandidatesToPeer(peer, session, candidates);
        }
    }

    private void sendCandidatesToPeer(PeerInfo peer, PeerSession session, List<PeerCandidate> candidates) {
        if (!running || config == null || controlSender == null || peer == null
                || !peer.online() || !StringUtils.hasText(peer.clientName())) {
            return;
        }
        List<PeerCandidate> outboundCandidates = candidates == null ? gatherHostCandidates() : candidates;
        if (outboundCandidates.isEmpty()) {
            requestPeerServerCandidates();
            outboundCandidates = gatherHostCandidates();
        }
        if (outboundCandidates.isEmpty()) {
            return;
        }
        PeerControlMessage message = new PeerControlMessage();
        message.setType(PeerControlMessage.TYPE_CANDIDATES);
        message.setSourceClientId(config.getClientId());
        message.setSourceClientName(config.getClientName());
        message.setSourceVirtualIp(config.getVirtualIp());
        message.setSourcePublicKey(keyMaterial.publicKeyBase64());
        message.setTargetClientId(peer.clientId());
        message.setTargetClientName(peer.clientName());
        message.setTargetVirtualIp(peer.virtualIp());
        message.setTargetPublicKey(peer.publicKey());
        if (session != null) {
            message.setSessionId(session.sessionId());
            message.setToken(session.token());
            message.setExpiresAt(session.expiresAt());
        }
        message.setCreatedAtMillis(System.currentTimeMillis());
        message.setCandidates(outboundCandidates);
        controlSender.send(peer.clientName(), JsonUtil.objectToString(message));
    }

    private PeerSession reusableSession(long peerId) {
        PeerSession session = sessions.get(peerId);
        if (session == null) {
            return null;
        }
        long now = System.currentTimeMillis();
        if (session.isExpired(now)) {
            sessions.remove(peerId, session);
            return null;
        }
        if (session.shouldRefresh(now)) {
            return null;
        }
        return session;
    }

    private void requestPeerServerCandidates() {
        if (!running || config == null) {
            return;
        }
        InetSocketAddress relayEndpoint = relayEndpoint();
        if (relayEndpoint == null) {
            return;
        }
        long now = System.currentTimeMillis();
        boolean allocationExpiring = relayAllocationId == null || relayAllocationExpiresAtMillis - now <= 60_000;
        if (!allocationExpiring && now - lastRelayCandidateRequestMillis < 60_000) {
            return;
        }
        if (allocationExpiring && now - lastRelayCandidateRequestMillis < 15_000) {
            return;
        }
        lastRelayCandidateRequestMillis = now;
        PeerRelayMessage binding = new PeerRelayMessage();
        binding.setType(PeerRelayMessage.TYPE_BINDING);
        binding.setProbeRole(PeerRelayMessage.PROBE_PRIMARY);
        binding.setTransactionId(UUID.randomUUID().toString());
        sendRelayControl(binding, relayEndpoint);

        if (relayAllocationId != null && relayAllocationExpiresAtMillis - now > 60_000) {
            PeerRelayMessage refresh = new PeerRelayMessage();
            refresh.setType(PeerRelayMessage.TYPE_REFRESH);
            refresh.setTransactionId(UUID.randomUUID().toString());
            refresh.setAllocationId(relayAllocationId);
            sendRelayControl(refresh, relayEndpoint);
            return;
        }
        PeerRelayMessage allocate = new PeerRelayMessage();
        allocate.setType(PeerRelayMessage.TYPE_ALLOCATE);
        allocate.setTransactionId(UUID.randomUUID().toString());
        sendRelayControl(allocate, relayEndpoint);
    }

    private void sendRelayControl(PeerRelayMessage message, InetSocketAddress relayEndpoint) {
        DatagramSocket socket = udpSocket;
        if (socket == null || socket.isClosed() || relayEndpoint == null) {
            return;
        }
        try {
            byte[] bytes = JsonUtil.objectToString(message).getBytes(StandardCharsets.UTF_8);
            socket.send(new DatagramPacket(bytes, bytes.length, relayEndpoint));
        } catch (Exception e) {
            log.debug("Peer mesh relay control 发送失败: type={}, reason={}", message.getType(), e.getMessage());
        }
    }

    private List<PeerCandidate> gatherHostCandidates() {
        DatagramSocket socket = udpSocket;
        if (socket == null || socket.isClosed()) {
            return List.of();
        }
        List<PeerCandidate> candidates = new ArrayList<>();
        int port = socket.getLocalPort();
        boolean directDisabled = shouldAvoidDirectPath();
        if (directDisabled) {
            logDirectSuppressed("gather-candidates");
        } else {
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
                        // 公共过滤：未定地址 / multicast / link-local（fe80::/10、169.254/16）
                        // 都不是对端能直接 reach 的有效端点；mesh 自身分配的虚拟 IP 也跳过避免回环。
                        if (address.isAnyLocalAddress()
                                || address.isMulticastAddress()
                                || address.isLinkLocalAddress()
                                || isMeshAddress(address.getHostAddress())) {
                            continue;
                        }
                        // IPv6 额外过滤：跳过 ULA (fc00::/7)、IPv4-compatible (::a.b.c.d)、
                        // IPv4-mapped (::ffff:a.b.c.d) ——这些都是同 LAN 或回环语义，对端 reach 不到。
                        // 全局 IPv6 (2000::/3) 通常是公网直连无 NAT，是最优 host candidate。
                        if (address instanceof java.net.Inet6Address ipv6) {
                            byte first = ipv6.getAddress()[0];
                            if ((first & 0xfe) == 0xfc) {
                                continue; // ULA
                            }
                            if (ipv6.isIPv4CompatibleAddress()) {
                                continue;
                            }
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
        }
        PeerCandidate srflx = serverReflexiveCandidate;
        if (srflx != null && !directDisabled) {
            candidates.add(srflx);
        }
        // 端口映射 candidate 不受 NAT 类型限制——UPnP/NAT-PMP/PCP 在路由器上建立了显式映射，
        // 对端 UDP 包能直接被路由器转发到我们，跳过整套 NAT 行为约束。即使本地是 Symmetric
        // NAT，对端往这个端点发包也能命中。
        PeerCandidate portMap = portMapCandidate;
        if (portMap != null) {
            candidates.add(portMap);
        }
        PeerCandidate relay = relayCandidate;
        if (relay != null) {
            candidates.add(relay);
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
                    || candidate.getPort() <= 0
                    || isRecursiveDirectCandidate(candidate)
                    || shouldSkipDirectCandidate(candidate)) {
                continue;
            }
            sendUdpProbe(session, candidate);
        }
    }

    /**
     * S0.3 探测 burst 配置：对每个 direct candidate 发送多个相同 nonce 的 STUN binding，
     * 间隔短于 NAT conntrack 的 race window。提高 first-RTT 成功率，对 NAT 设备做 conntrack
     * jitter 处理时尤其管用。
     *
     * <p>三个常量做 PROBE_BURST_COUNT × PROBE_BURST_INTERVAL_MILLIS = 总窗口（默认 90 ms）。
     * Relay candidate 不做 burst——relay 已经是 reliable 转发，多发只是浪费流量。
     */
    private static final int PROBE_BURST_COUNT = 3;
    private static final long PROBE_BURST_INTERVAL_MILLIS = 30;

    /**
     * S0.4 Direct keepalive 间隔。每个 ACTIVE DIRECT 会话至少 {@code KEEPALIVE_INTERVAL_MILLIS}
     * 毫秒发一次小包探测，用来在中国宽带 NAT 30~60 秒 mapping TTL 内保活。
     *
     * <p>注意这是「最小间隔」而不是「精确周期」——调度器以 5 秒 tick 跑，根据 session
     * 各自的 lastDirectKeepaliveMillis 决定是否需要发。25 秒打底确保即使最短 NAT TTL
     * 也来得及刷新。
     */
    private static final long DIRECT_KEEPALIVE_INTERVAL_MILLIS = 25_000;

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
        boolean relay = "relay".equalsIgnoreCase(candidate.getType());
        pendingProbes.put(nonce, new PendingProbe(
                session.sessionId(),
                session.peerId(),
                System.currentTimeMillis(),
                remote,
                relay,
                candidate.getRelayId()));
        try {
            if (relay) {
                if (!sendRelayPayload(candidate.getRelayId(), bytes)) {
                    pendingProbes.remove(nonce);
                    return;
                }
                log.debug("Peer mesh UDP check 已发送 (relay): session={}, remote={}", session.sessionId(), remote);
            } else {
                // direct candidate: 发 burst 提高 conntrack race 下的命中率
                socket.send(new DatagramPacket(bytes, bytes.length, remote));
                scheduleProbeBurst(socket, bytes, remote, nonce, session.sessionId());
                log.debug("Peer mesh UDP check 已发送 (burst x{}): session={}, remote={}",
                        PROBE_BURST_COUNT, session.sessionId(), remote);
            }
        } catch (Exception e) {
            pendingProbes.remove(nonce);
            log.debug("Peer mesh UDP check 发送失败: remote={}, reason={}", remote, e.getMessage());
        }
    }

    /**
     * 调度 burst 的后续重发。所有重发使用同一 nonce，对端去重；若第一发已被处理，
     * 后续发送也无害——pendingProbes 的 entry 还在，{@link #completeUdpProbe} 是幂等的。
     */
    private void scheduleProbeBurst(DatagramSocket socket, byte[] bytes, InetSocketAddress remote,
                                    String nonce, Long sessionId) {
        ScheduledExecutorService executor = maintenanceExecutor;
        if (executor == null || executor.isShutdown()) {
            return;
        }
        for (int i = 1; i < PROBE_BURST_COUNT; i++) {
            long delay = PROBE_BURST_INTERVAL_MILLIS * i;
            executor.schedule(() -> {
                if (!running || socket.isClosed()) {
                    return;
                }
                // 如果 probe 已经被对方响应（pendingProbes 里没了），就不再发后续 burst 包。
                if (!pendingProbes.containsKey(nonce)) {
                    return;
                }
                try {
                    socket.send(new DatagramPacket(bytes, bytes.length, remote));
                } catch (Exception e) {
                    log.trace("Peer mesh UDP burst retx 失败: session={}, remote={}, reason={}",
                            sessionId, remote, e.getMessage());
                }
            }, delay, TimeUnit.MILLISECONDS);
        }
    }

    /**
     * S0.4：遍历所有 session，对当前正走 DIRECT 通路、且距上次 keepalive ≥
     * {@link #DIRECT_KEEPALIVE_INTERVAL_MILLIS} 的，发一发小包刷新 NAT 映射。
     *
     * <p>跑在 maintenance 调度器的 5 秒 tick 上，每个 session 实际发送频率受 lastDirectKeepaliveMillis
     * 节流。relay 路径不做 keepalive——server 端有自己的连接保活，且 relay 包穿透 NAT 不靠对端映射。
     */
    private void keepaliveDirectPaths() {
        DatagramSocket socket = udpSocket;
        if (socket == null || socket.isClosed()) {
            return;
        }
        long now = System.currentTimeMillis();
        for (PeerSession session : sessions.values()) {
            if (!session.hasHealthyDirect(now)) {
                continue;
            }
            long sinceLast = now - session.lastDirectKeepaliveMillis;
            if (sinceLast < DIRECT_KEEPALIVE_INTERVAL_MILLIS) {
                continue;
            }
            InetSocketAddress endpoint = session.remoteEndpoint;
            if (endpoint == null || isMeshAddress(endpoint.getAddress().getHostAddress())) {
                continue;
            }
            sendDirectKeepalive(session, endpoint);
            session.lastDirectKeepaliveMillis = now;
        }
    }

    /**
     * 给一个 session 的已确认 DIRECT endpoint 发一发轻量 keepalive probe。
     * 和正常 connectivity check 用同一种 PeerUdpProbe.TYPE_CHECK 报文格式，对端透明地回 ACK，
     * 借此更新本端 lastDirectSuccessMillis 把 path 一直标为「健康」。不做 burst：
     * 已建路径不再有 NAT race 风险，单包足够。
     */
    private void sendDirectKeepalive(PeerSession session, InetSocketAddress endpoint) {
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
        pendingProbes.put(nonce, new PendingProbe(
                session.sessionId(),
                session.peerId(),
                System.currentTimeMillis(),
                endpoint,
                false,    // direct, not relay
                null));
        try {
            socket.send(new DatagramPacket(bytes, bytes.length, endpoint));
            log.trace("Peer mesh keepalive sent: session={}, remote={}", session.sessionId(), endpoint);
        } catch (Exception e) {
            pendingProbes.remove(nonce);
            log.debug("Peer mesh keepalive 发送失败: session={}, remote={}, reason={}",
                    session.sessionId(), endpoint, e.getMessage());
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

    private synchronized void startMaintenance() {
        ScheduledExecutorService current = maintenanceExecutor;
        if (current != null && !current.isShutdown()) {
            return;
        }
        ScheduledExecutorService next = Executors.newSingleThreadScheduledExecutor(task -> {
            Thread thread = new Thread(task, "peer-mesh-maintenance");
            thread.setDaemon(true);
            return thread;
        });
        maintenanceExecutor = next;
        next.scheduleWithFixedDelay(() -> {
            try {
                if (running) {
                    reportTrafficDeltas();
                    removeExpiredSessions();
                    cleanupPendingProbes();
                    cleanupPendingVirtualPackets();
                    requestPeerServerCandidates();
                    renewPortMappingIfNeeded();
                    announceCandidatesToOnlinePeers();
                    probeKnownCandidates();
                }
            } catch (Exception e) {
                log.debug("Peer mesh maintenance failed: {}", e.getMessage());
            }
        }, 30, 30, TimeUnit.SECONDS);
        // S0.4 独立 keepalive：每 5 秒检查一次，每个 ACTIVE DIRECT 会话每 25 秒发一次轻量 probe
        // 用以保活 NAT 映射。30s maintenance cycle 对 30-60s 的 NAT TTL 偏迟，单独跑细粒度任务。
        next.scheduleAtFixedRate(() -> {
            try {
                if (running) {
                    keepaliveDirectPaths();
                }
            } catch (Exception e) {
                log.debug("Peer mesh keepalive failed: {}", e.getMessage());
            }
        }, 5, 5, TimeUnit.SECONDS);
    }

    private synchronized void stopMaintenance() {
        ScheduledExecutorService current = maintenanceExecutor;
        maintenanceExecutor = null;
        if (current != null) {
            current.shutdownNow();
        }
    }

    private synchronized PeerVirtualDevice ensureVirtualDevice(ClientAuthLoginResponse.PeerMeshConfig nextConfig) {
        String desiredKey = PeerVirtualDevices.key(virtualDeviceOptions, nextConfig);
        if (virtualDevice != null && desiredKey.equals(virtualDeviceKey)) {
            return virtualDevice;
        }
        closeVirtualDevice();
        try {
            PeerVirtualDevice next = PeerVirtualDevices.create(virtualDeviceOptions, nextConfig);
            virtualDevice = next;
            virtualDeviceKey = desiredKey;
            return next;
        } catch (Exception e) {
            log.warn("Peer mesh 虚拟网卡初始化失败，回退 noop: {}", e.getMessage());
            PeerVirtualDevice fallback = new NoopPeerVirtualDevice();
            virtualDevice = fallback;
            virtualDeviceKey = "fallback|" + desiredKey;
            return fallback;
        }
    }

    private synchronized PeerVirtualDevice startVirtualDevice(ClientAuthLoginResponse.PeerMeshConfig nextConfig) {
        String desiredKey = PeerVirtualDevices.key(virtualDeviceOptions, nextConfig);
        PeerVirtualDevice next = ensureVirtualDevice(nextConfig);
        try {
            next.start(this::sendVirtualPacket);
            reportVirtualDevice(next, deviceStatus(next), null);
            return next;
        } catch (Exception e) {
            log.warn("Peer mesh 虚拟网卡启动失败，回退 noop: {}", e.getMessage());
            closeVirtualDevice();
            PeerVirtualDevice fallback = new NoopPeerVirtualDevice();
            virtualDevice = fallback;
            virtualDeviceKey = "fallback|" + desiredKey;
            fallback.start(this::sendVirtualPacket);
            reportVirtualDevice(fallback, "FAILED_FALLBACK_NOOP", e.getMessage());
            return fallback;
        }
    }

    private void reportVirtualDevice(PeerVirtualDevice device, String status, String error) {
        if (!running || controlSender == null) {
            return;
        }
        PeerControlMessage report = new PeerControlMessage();
        report.setType(PeerControlMessage.TYPE_DEVICE_REPORT);
        report.setVirtualDeviceMode(virtualDeviceOptions.mode());
        report.setVirtualDeviceName(device == null ? "" : device.name());
        report.setVirtualDeviceStatus(status);
        report.setVirtualDeviceError(limit(error, 512));
        report.setNatType(natType);
        report.setLastEndpoint(lastEndpoint);
        report.setCreatedAtMillis(System.currentTimeMillis());
        try {
            controlSender.send(null, JsonUtil.objectToString(report));
        } catch (Exception e) {
            log.debug("Peer mesh 虚拟网卡状态上报失败: {}", e.getMessage());
        }
    }

    private void recordNatObservation(PeerRelayMessage message, InetSocketAddress observedRemote) {
        if (message == null || !StringUtils.hasText(message.getMappedAddress()) || message.getMappedPort() <= 0) {
            return;
        }
        String role = normalizeProbeRole(message.getProbeRole());
        NatProbeObservation observation = new NatProbeObservation(
                role,
                message.getMappedAddress(),
                message.getMappedPort(),
                observedRemote == null || observedRemote.getAddress() == null
                        ? ""
                        : observedRemote.getAddress().getHostAddress() + ":" + observedRemote.getPort(),
                System.currentTimeMillis()
        );
        natProbeObservations.put(role, observation);
        NatProbeResult result = classifyNat();
        reportNatObservation(result.natType(), result.endpoint());
    }

    private void reportNatObservation(String observedNatType, String endpoint) {
        if (!StringUtils.hasText(observedNatType) || !StringUtils.hasText(endpoint)) {
            return;
        }
        if (observedNatType.equals(natType) && endpoint.equals(lastEndpoint)) {
            return;
        }
        natType = observedNatType;
        lastEndpoint = endpoint;
        if (!shouldAvoidDirectPath()) {
            directSuppressedLogged.set(false);
        }
        log.info("Peer mesh NAT 探测结果: type={}, mapped={}", observedNatType, endpoint);
        if (!running || controlSender == null) {
            return;
        }
        PeerControlMessage report = new PeerControlMessage();
        report.setType(PeerControlMessage.TYPE_DEVICE_REPORT);
        report.setNatType(observedNatType);
        report.setLastEndpoint(endpoint);
        report.setCreatedAtMillis(System.currentTimeMillis());
        try {
            controlSender.send(null, JsonUtil.objectToString(report));
        } catch (Exception e) {
            log.debug("Peer mesh NAT 状态上报失败: {}", e.getMessage());
        }
    }

    private NatProbeResult classifyNat() {
        long now = System.currentTimeMillis();
        NatProbeObservation primary = freshObservation(PeerRelayMessage.PROBE_PRIMARY, now);
        NatProbeObservation alternate = freshObservation(PeerRelayMessage.PROBE_ALTERNATE, now);
        NatProbeObservation changedPort = freshObservation(PeerRelayMessage.PROBE_CHANGED_PORT, now);
        NatProbeObservation base = primary == null
                ? (alternate == null ? changedPort : alternate)
                : primary;
        if (base == null) {
            return new NatProbeResult("", "");
        }
        if (isNoNat(base)) {
            return new NatProbeResult("NO_NAT", base.mappedEndpoint());
        }
        if (primary != null && alternate != null) {
            if (!primary.sameMappedEndpoint(alternate)) {
                return new NatProbeResult("SYMMETRIC_NAT", primary.mappedEndpoint());
            }
            if (changedPort != null) {
                return new NatProbeResult("FULL_CONE_OR_RESTRICTED_NAT", primary.mappedEndpoint());
            }
            return new NatProbeResult("PORT_RESTRICTED_NAT", primary.mappedEndpoint());
        }
        if (primary != null && changedPort != null) {
            return new NatProbeResult("FULL_CONE_OR_RESTRICTED_NAT", primary.mappedEndpoint());
        }
        return new NatProbeResult(isPortPreserved(base) ? "PORT_PRESERVED_NAT" : "NAT", base.mappedEndpoint());
    }

    private NatProbeObservation freshObservation(String role, long now) {
        NatProbeObservation observation = natProbeObservations.get(role);
        if (observation == null || now - observation.observedAtMillis() > NAT_PROBE_STALE_MILLIS) {
            return null;
        }
        return observation;
    }

    private boolean isNoNat(NatProbeObservation observation) {
        return isPortPreserved(observation) && isLocalAddress(observation.mappedAddress());
    }

    private boolean isPortPreserved(NatProbeObservation observation) {
        DatagramSocket socket = udpSocket;
        int localPort = socket == null || socket.isClosed() ? -1 : socket.getLocalPort();
        return localPort > 0 && observation.mappedPort() == localPort;
    }

    private String normalizeProbeRole(String role) {
        if (PeerRelayMessage.PROBE_ALTERNATE.equals(role)
                || PeerRelayMessage.PROBE_CHANGED_PORT.equals(role)) {
            return role;
        }
        return PeerRelayMessage.PROBE_PRIMARY;
    }

    private boolean isLocalAddress(String mappedAddress) {
        if (!StringUtils.hasText(mappedAddress)) {
            return false;
        }
        try {
            InetAddress mapped = InetAddress.getByName(mappedAddress);
            Enumeration<NetworkInterface> interfaces = NetworkInterface.getNetworkInterfaces();
            while (interfaces != null && interfaces.hasMoreElements()) {
                NetworkInterface networkInterface = interfaces.nextElement();
                if (!networkInterface.isUp()) {
                    continue;
                }
                Enumeration<InetAddress> addresses = networkInterface.getInetAddresses();
                while (addresses.hasMoreElements()) {
                    if (mapped.equals(addresses.nextElement())) {
                        return true;
                    }
                }
            }
        } catch (Exception e) {
            log.debug("Peer mesh NAT 本地地址匹配失败: {}", e.getMessage());
        }
        return false;
    }

    private String deviceStatus(PeerVirtualDevice device) {
        if (device instanceof NoopPeerVirtualDevice) {
            return "NOOP";
        }
        return "ACTIVE";
    }

    private String limit(String value, int max) {
        if (!StringUtils.hasText(value)) {
            return "";
        }
        return value.length() <= max ? value : value.substring(0, max);
    }

    private synchronized void closeVirtualDevice() {
        PeerVirtualDevice current = virtualDevice;
        virtualDevice = null;
        virtualDeviceKey = "";
        if (current != null) {
            try {
                current.close();
            } catch (Exception e) {
                log.debug("Peer mesh 虚拟网卡关闭失败: {}", e.getMessage());
            }
        }
    }

    private void receiveLoop() {
        byte[] buffer = new byte[65_507];
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
        byte[] payload = Arrays.copyOfRange(packet.getData(), packet.getOffset(), packet.getOffset() + packet.getLength());
        InetSocketAddress observedRemote = new InetSocketAddress(packet.getAddress(), packet.getPort());
        PeerRelayBinaryFrame binaryFrame = PeerRelayBinaryFrame.parse(payload);
        if (binaryFrame != null && binaryFrame.type() == PeerRelayBinaryFrame.TYPE_DATA) {
            handleUdpPayload(binaryFrame.payload(), observedRemote, binaryFrame.fromAllocationId());
            return;
        }
        String raw = new String(payload, StandardCharsets.UTF_8);
        if (raw.startsWith("{") && raw.contains(PeerRelayMessage.MAGIC)) {
            PeerRelayMessage relayMessage = JsonUtil.stringToObject(raw, PeerRelayMessage.class);
            if (relayMessage != null && PeerRelayMessage.MAGIC.equals(relayMessage.getMagic())) {
                handleRelayMessage(relayMessage, observedRemote);
                return;
            }
        }
        handleUdpPayload(payload, observedRemote, null);
    }

    private void handleRelayMessage(PeerRelayMessage message, InetSocketAddress observedRemote) {
        switch (message.getType()) {
            case PeerRelayMessage.TYPE_BINDING_RESPONSE -> {
                if (StringUtils.hasText(message.getMappedAddress()) && message.getMappedPort() > 0) {
                    recordNatObservation(message, observedRemote);
                    requestAlternateNatProbe(message, observedRemote);
                    PeerCandidate candidate = new PeerCandidate();
                    candidate.setType("srflx");
                    candidate.setTransport("udp");
                    candidate.setAddress(message.getMappedAddress());
                    candidate.setPort(message.getMappedPort());
                    candidate.setPriority(800);
                    candidate.setFoundation("server-reflexive");
                    serverReflexiveCandidate = candidate;
                    announceCandidatesToOnlinePeers();
                }
            }
            case PeerRelayMessage.TYPE_ALLOCATED -> {
                if (StringUtils.hasText(message.getAllocationId())) {
                    relayAllocationId = message.getAllocationId();
                    relayAllocationExpiresAtMillis = System.currentTimeMillis()
                            + Math.max(30, message.getTtlSeconds()) * 1000;
                    PeerCandidate candidate = new PeerCandidate();
                    candidate.setType("relay");
                    candidate.setTransport("udp");
                    candidate.setAddress(observedRemote.getAddress().getHostAddress());
                    candidate.setPort(observedRemote.getPort());
                    candidate.setPriority(100);
                    candidate.setFoundation("turn-lite");
                    candidate.setRelayId(relayAllocationId);
                    relayCandidate = candidate;
                    announceCandidatesToOnlinePeers();
                }
            }
            case PeerRelayMessage.TYPE_DATA -> {
                if (StringUtils.hasText(message.getPayloadBase64())) {
                    byte[] inner = Base64.getDecoder().decode(message.getPayloadBase64());
                    handleUdpPayload(inner, observedRemote, message.getFromAllocationId());
                }
            }
            case PeerRelayMessage.TYPE_ERROR -> log.debug("Peer mesh relay error: {}", message.getError());
            default -> log.trace("Peer mesh relay message ignored: type={}", message.getType());
        }
    }

    private void requestAlternateNatProbe(PeerRelayMessage response, InetSocketAddress observedRemote) {
        if (!PeerRelayMessage.PROBE_PRIMARY.equals(normalizeProbeRole(response.getProbeRole()))
                || response.getAlternatePort() <= 0
                || observedRemote == null
                || observedRemote.getAddress() == null) {
            return;
        }
        long now = System.currentTimeMillis();
        if (now - lastAlternateNatProbeRequestMillis < ALTERNATE_NAT_PROBE_MIN_INTERVAL_MILLIS) {
            return;
        }
        String alternateAddress = response.getAlternateAddress();
        if (!StringUtils.hasText(alternateAddress) || isUnspecifiedAddress(alternateAddress)) {
            alternateAddress = observedRemote.getAddress().getHostAddress();
        }
        if (!StringUtils.hasText(alternateAddress) || response.getAlternatePort() == observedRemote.getPort()) {
            return;
        }
        lastAlternateNatProbeRequestMillis = now;
        PeerRelayMessage binding = new PeerRelayMessage();
        binding.setType(PeerRelayMessage.TYPE_BINDING);
        binding.setProbeRole(PeerRelayMessage.PROBE_ALTERNATE);
        binding.setTransactionId(UUID.randomUUID().toString());
        sendRelayControl(binding, new InetSocketAddress(alternateAddress, response.getAlternatePort()));
    }

    private boolean isUnspecifiedAddress(String address) {
        return "0.0.0.0".equals(address)
                || "::".equals(address)
                || "0:0:0:0:0:0:0:0".equals(address);
    }

    private void handleUdpPayload(byte[] payload, InetSocketAddress observedRemote, String relayFromAllocationId) {
        if (PeerDataFrameCodec.looksLikeDataFrame(payload, 0, payload.length)) {
            handleDataFrame(payload, observedRemote, relayFromAllocationId);
            return;
        }
        String raw = new String(payload, StandardCharsets.UTF_8);
        PeerUdpProbe probe = JsonUtil.stringToObject(raw, PeerUdpProbe.class);
        if (probe == null
                || !PeerUdpProbe.MAGIC.equals(probe.getMagic())
                || config == null
                || probe.getToClientId() == null
                || !probe.getToClientId().equals(config.getClientId())) {
            return;
        }
        if (!StringUtils.hasText(relayFromAllocationId) && shouldAvoidDirectPath()) {
            logDirectSuppressed("ignore-direct-check");
            return;
        }
        if (PeerUdpProbe.TYPE_CHECK.equals(probe.getType())) {
            replyUdpProbe(probe, observedRemote, relayFromAllocationId);
        } else if (PeerUdpProbe.TYPE_CHECK_RESPONSE.equals(probe.getType())) {
            completeUdpProbe(probe, observedRemote, relayFromAllocationId);
        }
    }

    private void handleDataFrame(byte[] raw, InetSocketAddress observedRemote, String relayFromAllocationId) {
        if (!StringUtils.hasText(relayFromAllocationId) && isMeshAddress(observedRemote)) {
            log.debug("Peer mesh 忽略来自虚拟网段的加密 frame，避免 overlay 递归: remote={}", observedRemote);
            return;
        }
        for (PeerSession session : sessions.values()) {
            if (session.aesKey() == null) {
                continue;
            }
            if (session.isExpired(System.currentTimeMillis())) {
                sessions.remove(session.peerId(), session);
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
            if (StringUtils.hasText(relayFromAllocationId)) {
                session.remoteEndpoint = relayEndpoint();
                session.relayTargetAllocationId = relayFromAllocationId;
            } else {
                if (shouldAvoidDirectPath()) {
                    logDirectSuppressed("drop-direct-data-frame");
                    return;
                }
                session.remoteEndpoint = observedRemote;
                session.relayTargetAllocationId = null;
                session.addDirectBytes(raw.length);
            }
            log.debug("Peer mesh encrypted frame 收到: session={}, from={}, bytes={}",
                    frame.sessionId(), frame.fromClientId(), frame.plaintext().length);
            handlePlainPacket(frame);
            return;
        }
        log.debug("Peer mesh encrypted frame 无法解密或未匹配 session: remote={}", observedRemote);
    }

    private void handlePlainPacket(PeerDataFrame frame) {
        PeerVirtualDevice device = virtualDevice;
        if (device != null && !(device instanceof NoopPeerVirtualDevice)) {
            try {
                tracePacket("inbound-to-tun", frame.plaintext());
                device.writePacket(frame.plaintext());
            } catch (Exception e) {
                log.warn("Peer mesh 写入虚拟网卡失败: session={}, packet={}, reason={}",
                        frame.sessionId(), PeerIpPacket.describe(frame.plaintext()), e.getMessage());
            }
            return;
        }
        byte[] icmpReply = PeerIpPacket.icmpEchoReplyFor(frame.plaintext(), config == null ? "" : config.getVirtualIp());
        if (icmpReply != null) {
            String targetVirtualIp = PeerIpPacket.destinationIpv4(icmpReply);
            if (sendEncryptedPayload(targetVirtualIp, icmpReply)) {
                log.debug("Peer mesh ICMP echo 已应用层响应(noop): session={}, target={}",
                        frame.sessionId(), targetVirtualIp);
            }
            return;
        }
        if (device != null) {
            device.writePacket(frame.plaintext());
        }
    }

    private void replyUdpProbe(PeerUdpProbe probe, InetSocketAddress observedRemote, String relayFromAllocationId) {
        DatagramSocket socket = udpSocket;
        if (socket == null || socket.isClosed()) {
            return;
        }
        PeerSession session = sessions.get(probe.getFromClientId());
        if (session == null || !session.token().equals(probe.getToken())) {
            return;
        }
        markPathFromInboundCheck(session, observedRemote, relayFromAllocationId);
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
            if (StringUtils.hasText(relayFromAllocationId)) {
                sendRelayPayload(relayFromAllocationId, bytes);
            } else {
                socket.send(new DatagramPacket(bytes, bytes.length, observedRemote));
            }
        } catch (Exception e) {
            log.debug("Peer mesh UDP check-response 发送失败: {}", e.getMessage());
        }
    }

    private void markPathFromInboundCheck(PeerSession session, InetSocketAddress observedRemote, String relayFromAllocationId) {
        if (session == null || session.aesKey() == null || session.isExpired(System.currentTimeMillis())) {
            return;
        }
        long now = System.currentTimeMillis();
        if (StringUtils.hasText(relayFromAllocationId)) {
            session.remoteEndpoint = relayEndpoint();
            session.relayTargetAllocationId = relayFromAllocationId;
            session.markPath("RELAY", now);
            flushPendingPackets(session);
            return;
        }
        if (isMeshAddress(observedRemote)) {
            return;
        }
        if (shouldAvoidDirectPath()) {
            logDirectSuppressed("ignore-direct-inbound-check");
            return;
        }
        session.remoteEndpoint = observedRemote;
        session.relayTargetAllocationId = null;
        session.markPath("DIRECT", now);
        flushPendingPackets(session);
    }

    private void removeExpiredSessions() {
        long now = System.currentTimeMillis();
        sessions.entrySet().removeIf(entry -> entry.getValue().isExpired(now));
    }

    private void cleanupPendingProbes() {
        long now = System.currentTimeMillis();
        pendingProbes.entrySet().removeIf(entry -> now - entry.getValue().sentAtMillis() > PENDING_PROBE_TTL_MILLIS);
    }

    private void probeKnownCandidates() {
        if (!running || config == null) {
            return;
        }
        long now = System.currentTimeMillis();
        for (PeerInfo peer : peers.values()) {
            if (!peer.online() || peer.candidates().isEmpty()) {
                continue;
            }
            PeerSession session = sessions.get(peer.clientId());
            if (session == null || session.isExpired(now)) {
                continue;
            }
            PeerControlMessage control = new PeerControlMessage();
            control.setSourceClientId(config.getClientId());
            control.setSourceClientName(config.getClientName());
            control.setTargetClientId(peer.clientId());
            control.setTargetClientName(peer.clientName());
            control.setSessionId(session.sessionId());
            control.setToken(session.token());
            control.setCandidates(peer.candidates());
            sendConnectivityChecks(control);
        }
    }

    private void completeUdpProbe(PeerUdpProbe probe, InetSocketAddress observedRemote, String relayFromAllocationId) {
        PendingProbe pending = pendingProbes.remove(probe.getNonce());
        if (pending == null || !pending.sessionId().equals(probe.getSessionId())) {
            return;
        }
        PeerSession session = sessions.get(pending.peerId());
        if (session == null || !session.token().equals(probe.getToken())) {
            return;
        }
        if (session.aesKey() == null) {
            refreshSessionKeys();
            session = sessions.get(pending.peerId());
            if (session == null || session.aesKey() == null) {
                long now = System.currentTimeMillis();
                if (session != null && now - session.lastKeyMissingLogMillis >= 30_000) {
                    log.warn("Peer mesh UDP 探测已通但数据面密钥未就绪，暂不标记路径 active: session={}, peer={}",
                            session.sessionId(), session.peerId());
                    session.lastKeyMissingLogMillis = now;
                }
                return;
            }
        }
        long now = System.currentTimeMillis();
        if (pending.relay() && session.hasHealthyDirect(now) && !shouldAvoidDirectPath()) {
            log.debug("Peer mesh relay UDP path ignored because direct path is healthy: session={}, peer={}",
                    session.sessionId(), session.peerId());
            return;
        }
        if (!pending.relay() && shouldAvoidDirectPath()) {
            logDirectSuppressed("ignore-direct-check-response");
            return;
        }
        if (!pending.relay() && isMeshAddress(observedRemote)) {
            log.debug("Peer mesh 忽略虚拟网段 direct path，避免 overlay 递归: session={}, peer={}, remote={}",
                    session.sessionId(), session.peerId(), observedRemote);
            return;
        }
        long rttMillis = Math.max(0, now - pending.sentAtMillis());
        String remote = pending.relay()
                ? "relay:" + (StringUtils.hasText(relayFromAllocationId) ? relayFromAllocationId : pending.relayId())
                : observedRemote.getAddress().getHostAddress() + ":" + observedRemote.getPort();
        String local = localEndpoint();
        String previousPath = session.currentPathType;
        String previousRemote = session.lastPathRemoteText;
        session.remoteEndpoint = pending.relay() ? relayEndpoint() : observedRemote;
        session.relayTargetAllocationId = pending.relay() ? pending.relayId() : null;
        String pathType = pending.relay() ? "RELAY" : "DIRECT";
        session.markPath(pathType, now);
        boolean changed = !pathType.equals(previousPath) || !remote.equals(previousRemote);
        session.lastPathRemoteText = remote;
        if (changed || now - session.lastPathLogMillis >= 60_000) {
            log.info("Peer mesh {} UDP path active: session={}, peer={}, remote={}, rtt={}ms",
                    pathType.toLowerCase(), session.sessionId(), session.peerId(), remote, rttMillis);
            session.lastPathLogMillis = now;
        } else {
            log.debug("Peer mesh {} UDP path still active: session={}, peer={}, remote={}, rtt={}ms",
                    pathType.toLowerCase(), session.sessionId(), session.peerId(), remote, rttMillis);
        }
        if (changed || now - session.lastPathReportMillis >= 60_000) {
            reportPath(session, pathType, local, remote, rttMillis);
            session.lastPathReportMillis = now;
        }
        flushPendingPackets(session);
    }

    private void reportPath(PeerSession session, String pathType, String localEndpoint, String remoteEndpoint, long rttMillis) {
        if (controlSender == null) {
            return;
        }
        PeerControlMessage report = new PeerControlMessage();
        report.setType(PeerControlMessage.TYPE_PATH_REPORT);
        report.setSessionId(session.sessionId());
        report.setSourceClientId(config.getClientId());
        report.setSourceClientName(config.getClientName());
        report.setSourceVirtualIp(config.getVirtualIp());
        report.setSourcePublicKey(keyMaterial.publicKeyBase64());
        report.setTargetClientId(session.peerId());
        PeerInfo peer = peers.get(session.peerId());
        report.setTargetClientName(peer == null ? "" : peer.clientName());
        report.setTargetVirtualIp(peer == null ? "" : peer.virtualIp());
        report.setTargetPublicKey(peer == null ? "" : peer.publicKey());
        report.setPathType(pathType);
        report.setStatus("ACTIVE");
        report.setLocalEndpoint(localEndpoint);
        report.setRemoteEndpoint(remoteEndpoint);
        report.setRttMillis(rttMillis);
        report.setCreatedAtMillis(System.currentTimeMillis());
        controlSender.send("", JsonUtil.objectToString(report));
    }

    private void reportTrafficDeltas() {
        if (controlSender == null || config == null) {
            return;
        }
        for (PeerSession session : sessions.values()) {
            long directBytes = session.drainDirectBytes();
            if (directBytes <= 0) {
                continue;
            }
            PeerControlMessage report = new PeerControlMessage();
            report.setType(PeerControlMessage.TYPE_TRAFFIC_REPORT);
            report.setSessionId(session.sessionId());
            report.setSourceClientId(config.getClientId());
            report.setSourceClientName(config.getClientName());
            report.setSourceVirtualIp(config.getVirtualIp());
            report.setSourcePublicKey(keyMaterial.publicKeyBase64());
            report.setTargetClientId(session.peerId());
            PeerInfo peer = peers.get(session.peerId());
            report.setTargetClientName(peer == null ? "" : peer.clientName());
            report.setTargetVirtualIp(peer == null ? "" : peer.virtualIp());
            report.setTargetPublicKey(peer == null ? "" : peer.publicKey());
            report.setDirectBytes(directBytes);
            report.setCreatedAtMillis(System.currentTimeMillis());
            controlSender.send("", JsonUtil.objectToString(report));
        }
    }

    public boolean sendEncryptedPayload(String targetVirtualIp, byte[] payload) {
        return sendEncryptedPayload(targetVirtualIp, payload, true);
    }

    private boolean sendEncryptedPayload(String targetVirtualIp, byte[] payload, boolean allowPendingQueue) {
        if (!running || !StringUtils.hasText(targetVirtualIp) || payload == null) {
            return false;
        }
        PeerInfo peer = peers.values().stream()
                .filter(item -> targetVirtualIp.equals(item.virtualIp()))
                .findFirst()
                .orElse(null);
        if (peer == null) {
            logPayloadDrop(targetVirtualIp, "peer-not-found");
            return false;
        }
        PeerSession session = sessions.get(peer.clientId());
        if (session == null || !session.canSend()) {
            if (allowPendingQueue) {
                queuePendingPacket(peer, payload);
                preparePathForPeer(peer, session);
            }
            logPayloadDrop(targetVirtualIp, session == null ? "session-not-found" : session.blockedReason());
            return false;
        }
        DatagramSocket socket = udpSocket;
        if (socket == null || socket.isClosed()) {
            logPayloadDrop(targetVirtualIp, "udp-socket-not-ready");
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
            if (StringUtils.hasText(session.relayTargetAllocationId)) {
                return sendRelayPayload(session.relayTargetAllocationId, frame);
            }
            if (shouldAvoidDirectPath()) {
                if (allowPendingQueue) {
                    queuePendingPacket(peer, payload);
                    preparePathForPeer(peer, session);
                }
                logDirectSuppressed("send-direct-data-frame");
                logPayloadDrop(targetVirtualIp, "direct-disabled-waiting-relay");
                return false;
            }
            if (isMeshAddress(session.remoteEndpoint)) {
                log.debug("Peer mesh 拒绝向虚拟网段 remoteEndpoint 发送加密 frame，避免 overlay 递归: peer={}, remote={}",
                        peer.clientName(), session.remoteEndpoint);
                session.remoteEndpoint = null;
                logPayloadDrop(targetVirtualIp, "recursive-remote-endpoint");
                return false;
            }
            socket.send(new DatagramPacket(frame, frame.length, session.remoteEndpoint));
            session.addDirectBytes(frame.length);
            return true;
        } catch (Exception e) {
            log.debug("Peer mesh encrypted frame 发送失败: peer={}, reason={}", peer.clientName(), e.getMessage());
            logPayloadDrop(targetVirtualIp, "send-error:" + e.getClass().getSimpleName());
            return false;
        }
    }

    public boolean sendVirtualPacket(byte[] ipv4Packet) {
        String targetVirtualIp = PeerIpPacket.destinationIpv4(ipv4Packet);
        if (!StringUtils.hasText(targetVirtualIp)) {
            log.trace("Peer mesh 忽略非 IPv4 或无效 IP 包");
            return false;
        }
        tracePacket("outbound-from-tun", ipv4Packet);
        return sendEncryptedPayload(targetVirtualIp, ipv4Packet);
    }

    private void queuePendingPacket(PeerInfo peer, byte[] payload) {
        if (peer == null || payload == null || payload.length == 0) {
            return;
        }
        long now = System.currentTimeMillis();
        List<PendingVirtualPacket> queue = pendingVirtualPackets.computeIfAbsent(peer.clientId(), ignored -> new ArrayList<>());
        synchronized (queue) {
            queue.removeIf(item -> now - item.createdAtMillis() > PENDING_PACKET_TTL_MILLIS);
            while (queue.size() >= MAX_PENDING_PACKETS_PER_PEER) {
                queue.remove(0);
            }
            queue.add(new PendingVirtualPacket(Arrays.copyOf(payload, payload.length), now));
        }
    }

    private void preparePathForPeer(PeerInfo peer, PeerSession session) {
        if (config == null || peer == null || !peer.online()) {
            return;
        }
        long now = System.currentTimeMillis();
        Long previous = pathPrepareMillis.get(peer.clientId());
        if (previous != null && now - previous < ON_DEMAND_PREPARE_INTERVAL_MILLIS) {
            return;
        }
        pathPrepareMillis.put(peer.clientId(), now);
        requestPeerServerCandidates();
        PeerSession reusable = reusableSession(peer.clientId());
        sendCandidatesToPeer(peer, reusable != null ? reusable : session, null);
        PeerSession activeSession = sessions.get(peer.clientId());
        if (activeSession != null && !activeSession.isExpired(now) && !peer.candidates().isEmpty()) {
            PeerControlMessage control = new PeerControlMessage();
            control.setSourceClientId(config.getClientId());
            control.setSourceClientName(config.getClientName());
            control.setTargetClientId(peer.clientId());
            control.setTargetClientName(peer.clientName());
            control.setSessionId(activeSession.sessionId());
            control.setToken(activeSession.token());
            control.setCandidates(peer.candidates());
            sendConnectivityChecks(control);
        }
    }

    private void flushPendingPackets(PeerSession session) {
        if (session == null || !session.canSend()) {
            return;
        }
        List<PendingVirtualPacket> queue = pendingVirtualPackets.remove(session.peerId());
        if (queue == null || queue.isEmpty()) {
            return;
        }
        long now = System.currentTimeMillis();
        int flushed = 0;
        synchronized (queue) {
            for (PendingVirtualPacket item : queue) {
                if (now - item.createdAtMillis() > PENDING_PACKET_TTL_MILLIS) {
                    continue;
                }
                String targetVirtualIp = PeerIpPacket.destinationIpv4(item.packet());
                if (sendEncryptedPayload(targetVirtualIp, item.packet(), false)) {
                    flushed++;
                }
            }
        }
        if (flushed > 0) {
            log.info("Peer mesh pending virtual packet flushed: peer={}, count={}", session.peerId(), flushed);
        }
    }

    private void cleanupPendingVirtualPackets() {
        long now = System.currentTimeMillis();
        pendingVirtualPackets.entrySet().removeIf(entry -> {
            List<PendingVirtualPacket> queue = entry.getValue();
            synchronized (queue) {
                queue.removeIf(item -> now - item.createdAtMillis() > PENDING_PACKET_TTL_MILLIS);
                return queue.isEmpty();
            }
        });
    }

    private void tracePacket(String direction, byte[] packet) {
        int protocol = PeerIpPacket.protocol(packet);
        if (protocol != 6 && protocol != 17) {
            return;
        }
        long now = System.currentTimeMillis();
        String key = direction + "|" + PeerIpPacket.flowKey(packet);
        Long previous = packetTraceLogMillis.get(key);
        if (previous != null && now - previous < 10_000) {
            return;
        }
        packetTraceLogMillis.put(key, now);
        log.info("Peer mesh packet {}: {} bytes={}",
                direction, PeerIpPacket.describe(packet), packet == null ? 0 : packet.length);
    }

    private void logPayloadDrop(String targetVirtualIp, String reason) {
        long now = System.currentTimeMillis();
        String key = targetVirtualIp + "|" + reason;
        Long previous = payloadDropLogMillis.get(key);
        if (previous != null && now - previous < 10_000) {
            return;
        }
        payloadDropLogMillis.put(key, now);
        log.warn("Peer mesh 虚拟包未发送: target={}, reason={}, peers={}, sessions={}",
                targetVirtualIp, reason, peers.size(), sessions.size());
    }

    private String localEndpoint() {
        DatagramSocket socket = udpSocket;
        if (socket == null || socket.isClosed()) {
            return "";
        }
        return "0.0.0.0:" + socket.getLocalPort();
    }

    private boolean isRecursiveDirectCandidate(PeerCandidate candidate) {
        return !"relay".equalsIgnoreCase(candidate.getType()) && isMeshAddress(candidate.getAddress());
    }

    private boolean shouldSkipDirectCandidate(PeerCandidate candidate) {
        if (candidate == null || "relay".equalsIgnoreCase(candidate.getType())) {
            return false;
        }
        if (!shouldAvoidDirectPath()) {
            return false;
        }
        logDirectSuppressed("skip-direct-candidate");
        return true;
    }

    /**
     * 历史上：当本机 NAT 是 Symmetric 时，本方法返回 true，导致 12 个调用点把 direct 全部禁掉、
     * 只走 relay。这种"准入开关"过于保守——Symmetric × Cone 这种组合在实际网络里占 30%+，
     * 让 Symmetric 端往对端 Cone NAT 的 srflx 发包，Cone 端的 NAT 会建立 mapping，
     * 反向回包就能命中，依然可以直连。
     *
     * <p>S0.1 改造：永远返回 false。direct 在所有 NAT 组合下都被尝试；不通的情况下
     * 已有的 relay 回退路径会自动接管。NAT 类型仍然通过控制面上报，仅用于运营观察和
     * 路径优先级的"软调度"（参见 S4.1 RTT-aware 路径选择）。
     */
    private boolean shouldAvoidDirectPath() {
        return false;
    }

    private void logDirectSuppressed(String reason) {
        if (directSuppressedLogged.compareAndSet(false, true)) {
            log.warn("Peer mesh direct UDP disabled: natType={}, reason={}, fallback=relay", natType, reason);
            return;
        }
        log.debug("Peer mesh direct UDP suppressed: natType={}, reason={}", natType, reason);
    }

    private boolean isMeshAddress(InetSocketAddress endpoint) {
        if (endpoint == null || endpoint.getAddress() == null) {
            return false;
        }
        return isMeshAddress(endpoint.getAddress().getHostAddress());
    }

    private boolean isMeshAddress(String address) {
        ClientAuthLoginResponse.PeerMeshConfig current = config;
        if (current == null || !StringUtils.hasText(current.getCidr()) || !StringUtils.hasText(address)) {
            return false;
        }
        String[] parts = current.getCidr().split("/", 2);
        if (parts.length != 2) {
            return false;
        }
        Long ip = ipv4ToLong(address.trim());
        Long base = ipv4ToLong(parts[0].trim());
        if (ip == null || base == null) {
            return false;
        }
        int prefix;
        try {
            prefix = Integer.parseInt(parts[1].trim());
        } catch (NumberFormatException e) {
            return false;
        }
        if (prefix < 0 || prefix > 32) {
            return false;
        }
        long mask = prefix == 0 ? 0 : (0xFFFF_FFFFL << (32 - prefix)) & 0xFFFF_FFFFL;
        return (ip & mask) == (base & mask);
    }

    private Long ipv4ToLong(String value) {
        if (!StringUtils.hasText(value)) {
            return null;
        }
        String[] parts = value.split("\\.", -1);
        if (parts.length != 4) {
            return null;
        }
        long result = 0;
        for (String part : parts) {
            int octet;
            try {
                octet = Integer.parseInt(part);
            } catch (NumberFormatException e) {
                return null;
            }
            if (octet < 0 || octet > 255) {
                return null;
            }
            result = (result << 8) | octet;
        }
        return result;
    }

    private boolean sendRelayPayload(String targetAllocationId, byte[] payload) {
        if (!StringUtils.hasText(relayAllocationId) || !StringUtils.hasText(targetAllocationId) || payload == null) {
            return false;
        }
        InetSocketAddress endpoint = relayEndpoint();
        if (endpoint == null) {
            return false;
        }
        DatagramSocket socket = udpSocket;
        if (socket == null || socket.isClosed()) {
            return false;
        }
        try {
            byte[] bytes = PeerRelayBinaryFrame.send(relayAllocationId, targetAllocationId, payload).toBytes();
            socket.send(new DatagramPacket(bytes, bytes.length, endpoint));
            return true;
        } catch (Exception e) {
            log.debug("Peer mesh relay payload 发送失败: reason={}", e.getMessage());
            return false;
        }
    }

    private InetSocketAddress relayEndpoint() {
        if (config == null || !StringUtils.hasText(config.getTurnHost()) || config.getTurnPort() <= 0) {
            return null;
        }
        return new InetSocketAddress(config.getTurnHost(), config.getTurnPort());
    }

    private void mergePeerFromSignal(PeerControlMessage control, List<PeerCandidate> candidates) {
        PeerInfo peer = peerFromSignal(control);
        if (peer != null) {
            mergePeer(peer, candidates);
        }
    }

    private void mergePeer(PeerInfo peer, List<PeerCandidate> candidates) {
        if (peer == null || peer.clientId() <= 0) {
            return;
        }
        peers.compute(peer.clientId(), (id, current) -> {
            List<PeerCandidate> nextCandidates = candidates == null
                    ? (current == null ? peer.candidates() : current.candidates())
                    : List.copyOf(candidates);
            return new PeerInfo(
                    peer.clientId(),
                    firstText(peer.clientName(), current == null ? "" : current.clientName()),
                    firstText(peer.virtualIp(), current == null ? "" : current.virtualIp()),
                    firstText(peer.publicKey(), current == null ? "" : current.publicKey()),
                    peer.online() || (current != null && current.online()),
                    nextCandidates
            );
        });
    }

    private String firstText(String first, String fallback) {
        return StringUtils.hasText(first) ? first : (fallback == null ? "" : fallback);
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
                    control.getSourceVirtualIp(),
                    control.getSourcePublicKey(),
                    true,
                    List.of()
            );
        }
        if (targetId != null && !targetId.equals(config.getClientId())) {
            return new PeerInfo(
                    targetId,
                    control.getTargetClientName(),
                    control.getTargetVirtualIp(),
                    control.getTargetPublicKey(),
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
        private final long createdAtMillis;
        private final AtomicLong outboundSequence = new AtomicLong();
        private final AtomicLong directBytesSinceReport = new AtomicLong();
        private volatile PeerReplayWindow inboundReplayWindow = new PeerReplayWindow();
        private volatile long lastDirectSuccessMillis;
        private volatile long lastRelaySuccessMillis;
        private volatile long lastDirectKeepaliveMillis;
        private volatile long lastPathLogMillis;
        private volatile long lastPathReportMillis;
        private volatile long lastKeyMissingLogMillis;
        private volatile String lastPathRemoteText = "";
        private volatile String currentPathType = "";
        private volatile InetSocketAddress remoteEndpoint;
        private volatile String relayTargetAllocationId;

        private PeerSession(Long sessionId, long peerId, String token, String expiresAt, byte[] aesKey) {
            this(sessionId, peerId, token, expiresAt, aesKey, System.currentTimeMillis());
        }

        private PeerSession(Long sessionId, long peerId, String token, String expiresAt, byte[] aesKey, long createdAtMillis) {
            this.sessionId = sessionId;
            this.peerId = peerId;
            this.token = token;
            this.expiresAt = expiresAt;
            this.aesKey = aesKey;
            this.createdAtMillis = createdAtMillis;
        }

        PeerSession withAesKey(byte[] nextKey) {
            PeerSession next = new PeerSession(sessionId, peerId, token, expiresAt, nextKey, createdAtMillis);
            next.outboundSequence.set(outboundSequence.get());
            next.directBytesSinceReport.set(directBytesSinceReport.get());
            next.remoteEndpoint = remoteEndpoint;
            next.inboundReplayWindow = inboundReplayWindow.copy();
            next.relayTargetAllocationId = relayTargetAllocationId;
            next.lastDirectSuccessMillis = lastDirectSuccessMillis;
            next.lastRelaySuccessMillis = lastRelaySuccessMillis;
            next.lastDirectKeepaliveMillis = lastDirectKeepaliveMillis;
            next.lastPathLogMillis = lastPathLogMillis;
            next.lastPathReportMillis = lastPathReportMillis;
            next.lastKeyMissingLogMillis = lastKeyMissingLogMillis;
            next.lastPathRemoteText = lastPathRemoteText;
            next.currentPathType = currentPathType;
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

        String expiresAt() {
            return expiresAt;
        }

        byte[] aesKey() {
            return aesKey;
        }

        boolean canSend() {
            return aesKey != null && remoteEndpoint != null && !isExpired(System.currentTimeMillis());
        }

        String blockedReason() {
            if (aesKey == null) {
                return "key-not-ready";
            }
            if (remoteEndpoint == null) {
                return "path-not-ready";
            }
            if (isExpired(System.currentTimeMillis())) {
                return "session-expired";
            }
            return "not-ready";
        }

        long nextOutboundSequence() {
            return outboundSequence.incrementAndGet();
        }

        boolean acceptInboundSequence(long sequence) {
            return inboundReplayWindow.accept(sequence);
        }

        void addDirectBytes(long bytes) {
            if (bytes > 0) {
                directBytesSinceReport.addAndGet(bytes);
            }
        }

        long drainDirectBytes() {
            return directBytesSinceReport.getAndSet(0);
        }

        void markPath(String pathType, long nowMillis) {
            if ("DIRECT".equals(pathType)) {
                lastDirectSuccessMillis = nowMillis;
            } else if ("RELAY".equals(pathType)) {
                lastRelaySuccessMillis = nowMillis;
            }
            currentPathType = pathType;
        }

        boolean hasHealthyDirect(long nowMillis) {
            return "DIRECT".equals(currentPathType)
                    && lastDirectSuccessMillis > 0
                    && nowMillis - lastDirectSuccessMillis <= DIRECT_STALE_MILLIS;
        }

        boolean isExpired(long nowMillis) {
            long expiresAtMillis = expiresAtMillis();
            return expiresAtMillis != Long.MAX_VALUE && expiresAtMillis <= nowMillis;
        }

        boolean shouldRefresh(long nowMillis) {
            long expiresAtMillis = expiresAtMillis();
            return expiresAtMillis != Long.MAX_VALUE && expiresAtMillis - nowMillis <= refreshWindowMillis(expiresAtMillis);
        }

        long refreshWindowMillis(long expiresAtMillis) {
            if (expiresAtMillis == Long.MAX_VALUE) {
                return 0;
            }
            long lifetimeMillis = Math.max(0, expiresAtMillis - createdAtMillis);
            long proportionalWindow = lifetimeMillis / 4;
            long boundedWindow = Math.max(MIN_SESSION_REFRESH_WINDOW_MILLIS, proportionalWindow);
            return Math.min(MAX_SESSION_REFRESH_WINDOW_MILLIS, boundedWindow);
        }

        private long expiresAtMillis() {
            if (!StringUtils.hasText(expiresAt)) {
                return Long.MAX_VALUE;
            }
            try {
                return Instant.parse(expiresAt).toEpochMilli();
            } catch (Exception ignored) {
                return Long.MAX_VALUE;
            }
        }
    }

    private record PendingProbe(Long sessionId,
                                long peerId,
                                long sentAtMillis,
                                InetSocketAddress remote,
                                boolean relay,
                                String relayId) {
    }

    private record PendingVirtualPacket(byte[] packet,
                                        long createdAtMillis) {
    }

    private record NatProbeObservation(String role,
                                       String mappedAddress,
                                       int mappedPort,
                                       String serverEndpoint,
                                       long observedAtMillis) {
        String mappedEndpoint() {
            return mappedAddress + ":" + mappedPort;
        }

        boolean sameMappedEndpoint(NatProbeObservation other) {
            return other != null
                    && mappedPort == other.mappedPort
                    && Objects.equals(mappedAddress, other.mappedAddress);
        }
    }

    private record NatProbeResult(String natType, String endpoint) {
    }
}
