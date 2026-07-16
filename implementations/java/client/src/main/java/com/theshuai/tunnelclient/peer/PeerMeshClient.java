package com.theshuai.tunnelclient.peer;

import com.fasterxml.jackson.databind.JsonNode;
import com.theshuai.common.peermesh.PeerCandidate;
import com.theshuai.common.peermesh.PeerControlMessage;
import com.theshuai.common.peermesh.PeerCrypto;
import com.theshuai.common.peermesh.PeerRelayMessage;
import com.theshuai.common.peermesh.PeerUdpProbe;
import com.theshuai.common.clientauth.ClientAuthLoginResponse;
import com.theshuai.common.stun.StunMessage;
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
import java.util.Enumeration;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
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
    private final Map<Long, PeerSession> sessionsById = new ConcurrentHashMap<>();
    private final Map<String, PendingProbe> pendingProbes = new ConcurrentHashMap<>();
    private final Map<String, NatProbeObservation> natProbeObservations = new ConcurrentHashMap<>();
    private final Map<String, Long> payloadDropLogMillis = new ConcurrentHashMap<>();
    private final Map<String, Long> packetTraceLogMillis = new ConcurrentHashMap<>();
    private final Map<Long, List<PendingVirtualPacket>> pendingVirtualPackets = new ConcurrentHashMap<>();
    private final Map<Long, Long> pathPrepareMillis = new ConcurrentHashMap<>();
    private final Map<String, PendingStunBinding> pendingStunBindings = new ConcurrentHashMap<>();
    private final Map<String, PendingTurnRequest> pendingTurnRequests = new ConcurrentHashMap<>();
    private final Map<String, Long> turnPermissions = new ConcurrentHashMap<>();
    private final Map<String, SrflxObservation> srflxObservations = new ConcurrentHashMap<>();
    private final AtomicBoolean directSuppressedLogged = new AtomicBoolean(false);
    private final SecureRandom secureRandom = new SecureRandom();
    private final TurnLongTermAuthenticator turnAuthenticator = new TurnLongTermAuthenticator();
    private final NatBehaviorDiscovery natBehaviorDiscovery = new NatBehaviorDiscovery();
    private final ControlSender controlSender;
    private final PeerKeyStore.KeyMaterial keyMaterial;
    private final PeerVirtualDeviceOptions virtualDeviceOptions;
    private volatile ClientAuthLoginResponse.PeerMeshConfig config;
    private volatile boolean running;
    private volatile DatagramSocket udpSocket;
    private volatile Thread receiverThread;
    private volatile PeerVirtualDevice virtualDevice = new NoopPeerVirtualDevice();
    private volatile String virtualDeviceKey = "noop";
    private volatile String runtimeConfigKey = "";
    private volatile PeerCandidate serverReflexiveCandidate;
    private final Map<String, PeerCandidate> serverReflexiveCandidates = new ConcurrentHashMap<>();
    private volatile PeerCandidate relayCandidate;
    private volatile PeerCandidate portMapCandidate;
    private volatile NatPortMapping portMapping;
    private volatile long lastPortMapAttemptMillis;
    private final NatPortMappingService natPortMappingService = new NatPortMappingService();
    private volatile String natType = "";
    private volatile String natMappingBehavior = "";
    private volatile String natFilteringBehavior = "";
    private volatile String natBehaviorDiscoveryMode = "";
    private volatile String lastEndpoint = "";
    private volatile String relayAllocationId;
    private volatile long relayAllocationExpiresAtMillis;
    private volatile long lastStunCandidateRequestMillis;
    private volatile long lastRelayCandidateRequestMillis;
    private volatile long lastAlternateNatProbeRequestMillis;
    private volatile long lastBehaviorDiscoveryStartedMillis;
    private volatile ScheduledExecutorService maintenanceExecutor;
    private static final long MAX_SESSION_REFRESH_WINDOW_MILLIS = 120_000;
    private static final long MIN_SESSION_REFRESH_WINDOW_MILLIS = 10_000;
    private static final long DIRECT_STALE_MILLIS = 45_000;
    private static final long PENDING_PROBE_TTL_MILLIS = 15_000;
    /** S4.1 RTT 滞回阈值：避免 direct/relay 频繁切换 */
    private static final long RTT_HYSTERESIS_MS = 100;
    private static final int RTT_EWMA_OLD_WEIGHT = 7;
    private static final int RTT_EWMA_NEW_WEIGHT = 1;
    private static final long PENDING_PACKET_TTL_MILLIS = 30_000;
    private static final int MAX_PENDING_PACKETS_PER_PEER = 32;
    private static final long ON_DEMAND_PREPARE_INTERVAL_MILLIS = 2_000;
    private static final long NAT_PROBE_STALE_MILLIS = 120_000;
    private static final long SRFLX_OBSERVATION_TTL_MILLIS = 180_000;
    private static final long ALTERNATE_NAT_PROBE_MIN_INTERVAL_MILLIS = 15_000;
    private static final long STUN_CANDIDATE_REQUEST_INTERVAL_MILLIS = 60_000;
    private static final long BEHAVIOR_DISCOVERY_MIN_INTERVAL_MILLIS = 60_000;
    private static final long BEHAVIOR_PROBE_TIMEOUT_MILLIS = 1_600;
    private static final long[] BEHAVIOR_PROBE_RETRY_DELAYS_MILLIS = {250, 750};
    private static final long TURN_PERMISSION_TTL_MILLIS = 240_000;
    private static final String PUBLIC_STUN_ROLE_PREFIX = "public-stun:";
    private static final int MAX_ADAPTIVE_PREDICTED_PORTS = 16;
    private static final int MAX_ADAPTIVE_PORT_DELTA = 512;
    private static final long CONNECTIVITY_CHECK_PACING_MILLIS = 20;
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
        if (turnAuthenticator.update(nextConfig)) {
            pendingTurnRequests.clear();
        }
        if (nextConfig == null || !nextConfig.isEnabled()) {
            this.config = nextConfig;
            if (running) {
                log.info("Peer mesh 已关闭");
            }
            running = false;
            runtimeConfigKey = "";
            peers.clear();
            sessions.clear();
            sessionsById.clear();
            pendingProbes.clear();
            natProbeObservations.clear();
            payloadDropLogMillis.clear();
            packetTraceLogMillis.clear();
            pendingVirtualPackets.clear();
            pathPrepareMillis.clear();
            pendingStunBindings.clear();
            pendingTurnRequests.clear();
            turnPermissions.clear();
            srflxObservations.clear();
            serverReflexiveCandidate = null;
            serverReflexiveCandidates.clear();
            relayCandidate = null;
            releasePortMapping();
            natType = "";
            natMappingBehavior = "";
            natFilteringBehavior = "";
            natBehaviorDiscoveryMode = "";
            lastEndpoint = "";
            directSuppressedLogged.set(false);
            relayAllocationId = null;
            relayAllocationExpiresAtMillis = 0;
            lastStunCandidateRequestMillis = 0;
            lastRelayCandidateRequestMillis = 0;
            lastAlternateNatProbeRequestMillis = 0;
            lastBehaviorDiscoveryStartedMillis = 0;
            stopMaintenance();
            stopUdpSocket();
            closeVirtualDevice();
            return;
        }
        String nextRuntimeConfigKey = runtimeConfigKey(nextConfig);
        boolean sameRuntimeConfig = running && Objects.equals(runtimeConfigKey, nextRuntimeConfigKey);
        this.config = nextConfig;
        if (sameRuntimeConfig && !isFallbackVirtualDevice() && isUdpSocketReady()) {
            syncVirtualDeviceRoutes();
            requestPeerServerCandidates();
            announceCandidatesToOnlinePeers();
            log.debug("Peer mesh 配置未变化，已执行轻量刷新: client={}, virtualIp={}",
                    nextConfig.getClientName(), nextConfig.getVirtualIp());
            return;
        }
        if (!sameRuntimeConfig) {
            pendingStunBindings.clear();
            natProbeObservations.clear();
            lastStunCandidateRequestMillis = 0;
            lastRelayCandidateRequestMillis = 0;
            lastAlternateNatProbeRequestMillis = 0;
            lastBehaviorDiscoveryStartedMillis = 0;
            natMappingBehavior = "";
            natFilteringBehavior = "";
            natBehaviorDiscoveryMode = "";
        }
        running = true;
        runtimeConfigKey = nextRuntimeConfigKey;
        startUdpSocket();
        if (!sameRuntimeConfig || portMapping == null) {
            tryAcquirePortMappingAsync();
        }
        startMaintenance();
        requestPeerServerCandidates();
        PeerVirtualDevice activeDevice = startVirtualDevice(nextConfig);
        syncVirtualDeviceRoutes();
        log.info("Peer mesh 已启用: client={}, virtualIp={}, cidr={}, stun={}:{}, turn={}, publicStun={}",
                nextConfig.getClientName(),
                nextConfig.getVirtualIp(),
                nextConfig.getCidr(),
                nextConfig.getStunHost(),
                nextConfig.getStunPort(),
                nextConfig.getTurnHost() + ":" + nextConfig.getTurnPort(),
                nextConfig.getPublicStunServers() == null ? 0 : nextConfig.getPublicStunServers().size());
        log.info("Peer mesh UDP 探测端口: {}，虚拟网卡适配: {}",
                udpSocket == null ? "-" : udpSocket.getLocalPort(),
                activeDevice.name());
        announceCandidatesToOnlinePeers();
    }

    public boolean isRunning() {
        return running;
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
        // roster 只带身份与在线状态，不带 candidates。保留旧 entry 已学到的候选，
        // 否则每次 roster 推送（任意客户端上下线都会触发）都会清空全部对端候选，
        // probeKnownCandidates 失效，必须等下一轮候选交换才能恢复直连探测。
        Map<Long, PeerInfo> previous = Map.copyOf(peers);
        peers.clear();
        if (peerNodes != null && peerNodes.isArray()) {
            for (JsonNode node : peerNodes) {
                long clientId = node.path("clientId").asLong(0);
                if (clientId <= 0) {
                    continue;
                }
                PeerInfo existing = previous.get(clientId);
                peers.put(clientId, new PeerInfo(
                        clientId,
                        node.path("clientName").asText(""),
                        node.path("virtualIp").asText(""),
                        node.path("publicKey").asText(""),
                        node.path("online").asBoolean(false),
                        existing == null ? List.of() : existing.candidates()
                ));
            }
        }
        log.info("Peer mesh 可互联客户端刷新: {} 个", peers.size());
        syncVirtualDeviceRoutes();
        refreshSessionKeys();
        announceCandidatesToOnlinePeers();
    }

    private String runtimeConfigKey(ClientAuthLoginResponse.PeerMeshConfig value) {
        if (value == null || !value.isEnabled()) {
            return "disabled";
        }
        List<String> publicStun = value.getPublicStunServers() == null
                ? List.of()
                : value.getPublicStunServers();
        return PeerVirtualDevices.key(virtualDeviceOptions, value)
                + "|" + value.getClientId()
                + "|" + value.getClientName()
                + "|" + value.getStunHost()
                + "|" + value.getStunPort()
                + "|" + value.getTurnHost()
                + "|" + value.getTurnPort()
                + "|" + String.join(",", publicStun);
    }

    private boolean isFallbackVirtualDevice() {
        return virtualDeviceKey != null && virtualDeviceKey.startsWith("fallback|");
    }

    private boolean isUdpSocketReady() {
        DatagramSocket socket = udpSocket;
        return socket != null && !socket.isClosed();
    }

    private void syncVirtualDeviceRoutes() {
        PeerVirtualDevice device = virtualDevice;
        ClientAuthLoginResponse.PeerMeshConfig current = config;
        if (device == null || current == null) {
            return;
        }
        List<String> routeIps = peers.values().stream()
                .filter(PeerInfo::online)
                .map(PeerInfo::virtualIp)
                .filter(StringUtils::hasText)
                .map(String::trim)
                .filter(ip -> !ip.equals(current.getVirtualIp()))
                .distinct()
                .sorted()
                .toList();
        try {
            device.syncPeerRoutes(routeIps);
        } catch (Exception e) {
            log.warn("Peer mesh 同步 peer routes 失败: device={}, routes={}, reason={}",
                    device.name(), routeIps.size(), e.getMessage());
        }
    }

    @Override
    public void close() {
        running = false;
        runtimeConfigKey = "";
        peers.clear();
        sessions.clear();
        sessionsById.clear();
        pendingProbes.clear();
        natProbeObservations.clear();
        payloadDropLogMillis.clear();
        packetTraceLogMillis.clear();
        pendingVirtualPackets.clear();
        pathPrepareMillis.clear();
        pendingStunBindings.clear();
        pendingTurnRequests.clear();
        turnPermissions.clear();
        srflxObservations.clear();
        serverReflexiveCandidate = null;
        serverReflexiveCandidates.clear();
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
        PeerCandidate previousPortMap = portMapCandidate;
        portMapCandidate = candidate;
        portMapping = mapping;
        log.info("Peer mesh NAT 端口映射成功: protocol={}, external={}:{}, internal={}, lease={}s",
                mapping.protocol(),
                mapping.externalAddress(),
                mapping.externalPort(),
                mapping.internalPort(),
                mapping.leaseSeconds());
        if (previousPortMap == null
                || !Objects.equals(previousPortMap.getAddress(), candidate.getAddress())
                || !Objects.equals(previousPortMap.getPort(), candidate.getPort())) {
            announceCandidatesToOnlinePeers();
        }
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

        // Hairpin 检测：双方 STUN 公网地址相同，优先 LAN host；但保留 relay，避免 CGNAT
        // 共享出口 IP 或 NAT 不支持 hairpin 时被错误剪掉兜底路径。
        if (hasSameNatAddress(control.getCandidates()) && hasUsableHostCandidate(control.getCandidates())) {
            control.setCandidates(control.getCandidates().stream()
                    .filter(candidate -> !isSameNatReflexiveCandidate(candidate))
                    .toList());
        }

        sendConnectivityChecks(control);
    }

    /** 同 NAT 检测：对端 srflx/端口映射地址与本端 STUN 观测公网地址相同 */
    private boolean hasSameNatAddress(List<PeerCandidate> candidates) {
        if (candidates == null || candidates.isEmpty()) {
            return false;
        }
        return candidates.stream().anyMatch(this::isSameNatReflexiveCandidate);
    }

    private boolean isSameNatReflexiveCandidate(PeerCandidate candidate) {
        if (candidate == null || !StringUtils.hasText(candidate.getAddress()) || "relay".equalsIgnoreCase(candidate.getType())) {
            return false;
        }
        boolean reflexive = "srflx".equalsIgnoreCase(candidate.getType())
                || (StringUtils.hasText(candidate.getFoundation()) && candidate.getFoundation().startsWith("port-map-"));
        if (!reflexive) {
            return false;
        }
        String address = candidate.getAddress();
        return serverReflexiveCandidates.values().stream()
                .map(PeerCandidate::getAddress)
                .filter(StringUtils::hasText)
                .anyMatch(address::equals);
    }

    private boolean hasUsableHostCandidate(List<PeerCandidate> candidates) {
        if (candidates == null) {
            return false;
        }
        return candidates.stream().anyMatch(candidate ->
                "host".equalsIgnoreCase(candidate.getType())
                        && "udp".equalsIgnoreCase(candidate.getTransport())
                        && StringUtils.hasText(candidate.getAddress())
                        && candidate.getPort() > 0
                        && !isRecursiveDirectCandidate(candidate));
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
            sessionsById.remove(previous.sessionId(), previous);
        }
        sessionsById.put(next.sessionId(), next);
        if (previous != null) {
            boolean sameSession = previous.sessionId().equals(next.sessionId());
            if (sameSession) {
                next.outboundSequence.set(previous.outboundSequence.get());
                next.inboundReplayWindow = previous.inboundReplayWindow.copy();
            }
            next.remoteEndpoint = previous.remoteEndpoint;
            next.relayTargetAllocationId = previous.relayTargetAllocationId;
            next.directBytesSinceReport.addAndGet(previous.drainDirectBytes());
            next.endpointSuccessMillis = previous.endpointSuccessMillis;
            next.endpointRtt = previous.endpointRtt;
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
                removeSession(entry.getKey(), session);
                continue;
            }
            PeerControlMessage control = new PeerControlMessage();
            control.setSessionId(session.sessionId());
            control.setToken(session.token());
            byte[] aesKey = deriveSessionKey(control, session.peerId(), peer.publicKey());
            if (aesKey != null) {
                PeerSession next = session.withAesKey(aesKey);
                replaceSession(entry.getKey(), session, next);
            }
        }
    }

    private void replaceSession(long peerId, PeerSession previous, PeerSession next) {
        sessions.put(peerId, next);
        sessionsById.remove(previous.sessionId(), previous);
        sessionsById.put(next.sessionId(), next);
    }

    private PeerSession removeSession(long peerId) {
        PeerSession removed = sessions.remove(peerId);
        if (removed != null) {
            sessionsById.remove(removed.sessionId(), removed);
        }
        return removed;
    }

    private boolean removeSession(long peerId, PeerSession expected) {
        boolean removed = sessions.remove(peerId, expected);
        if (removed) {
            sessionsById.remove(expected.sessionId(), expected);
        }
        return removed;
    }

    private void closeSession(PeerControlMessage control) {
        long peerId = peerId(control);
        if (peerId > 0) {
            removeSession(peerId);
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
            removeSession(peerId, session);
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
        InetSocketAddress stunEndpoint = stunEndpoint();
        InetSocketAddress relayEndpoint = relayEndpoint();
        boolean hasPublicStun = config.getPublicStunServers() != null
                && !config.getPublicStunServers().isEmpty();
        if (stunEndpoint == null && relayEndpoint == null && !hasPublicStun) {
            return;
        }
        long now = System.currentTimeMillis();
        if (now - lastStunCandidateRequestMillis >= STUN_CANDIDATE_REQUEST_INTERVAL_MILLIS) {
            lastStunCandidateRequestMillis = now;
            if (stunEndpoint != null) {
                sendStunBinding(stunEndpoint, PeerRelayMessage.PROBE_PRIMARY);
            }
            requestPublicStunBindings();
        }
        if (relayEndpoint == null) {
            return;
        }

        boolean allocationExpiring = relayAllocationId == null || relayAllocationExpiresAtMillis - now <= 60_000;
        if (!allocationExpiring && now - lastRelayCandidateRequestMillis < 60_000) {
            return;
        }
        if (allocationExpiring && now - lastRelayCandidateRequestMillis < 15_000) {
            return;
        }
        lastRelayCandidateRequestMillis = now;

        if (relayAllocationId != null && relayAllocationExpiresAtMillis - now > 60_000) {
            sendStunRequest(StunMessage.of(
                    StunMessage.REFRESH_REQUEST,
                    StunMessage.newTransactionId(),
                    StunMessage.lifetime(Math.max(30, config.getSessionTtlSeconds()))), relayEndpoint);
            return;
        }
        sendStunRequest(StunMessage.of(
                StunMessage.ALLOCATE_REQUEST,
                StunMessage.newTransactionId(),
                StunMessage.requestedUdpTransportAttribute()), relayEndpoint);
    }

    private void sendStunBinding(InetSocketAddress endpoint, String probeRole) {
        byte[] transactionId = StunMessage.newTransactionId();
        StunMessage request = StunMessage.of(
                StunMessage.BINDING_REQUEST,
                transactionId,
                StunMessage.software("shuai-tunnel-peer-client"));
        pendingStunBindings.put(StunMessage.hex(transactionId), new PendingStunBinding(
                bindingProbeRole(probeRole),
                endpoint,
                endpoint,
                request,
                null,
                0,
                System.currentTimeMillis()));
        sendStunRequest(request, endpoint);
    }

    private void sendBehaviorProbe(NatBehaviorDiscovery.ProbeRequest probeRequest) {
        if (!running || probeRequest == null) {
            return;
        }
        byte[] transactionId = StunMessage.newTransactionId();
        StunMessage request = probeRequest.changeIp() || probeRequest.changePort()
                ? StunMessage.of(
                        StunMessage.BINDING_REQUEST,
                        transactionId,
                        StunMessage.software("shuai-tunnel-peer-client"),
                        StunMessage.changeRequest(probeRequest.changeIp(), probeRequest.changePort()))
                : StunMessage.of(
                        StunMessage.BINDING_REQUEST,
                        transactionId,
                        StunMessage.software("shuai-tunnel-peer-client"));
        PendingStunBinding pending = new PendingStunBinding(
                probeRequest.probe().role(),
                probeRequest.targetEndpoint(),
                probeRequest.expectedResponseEndpoint(),
                request,
                probeRequest.probe(),
                probeRequest.generation(),
                System.currentTimeMillis());
        String transactionKey = request.transactionIdHex();
        pendingStunBindings.put(transactionKey, pending);
        sendStunRequest(request, probeRequest.targetEndpoint());

        ScheduledExecutorService executor = maintenanceExecutor;
        if (executor == null || executor.isShutdown()) {
            return;
        }
        for (long delayMillis : BEHAVIOR_PROBE_RETRY_DELAYS_MILLIS) {
            executor.schedule(
                    () -> retryBehaviorProbe(transactionKey, pending),
                    delayMillis,
                    TimeUnit.MILLISECONDS);
        }
        executor.schedule(
                () -> timeoutBehaviorProbe(transactionKey, pending),
                BEHAVIOR_PROBE_TIMEOUT_MILLIS,
                TimeUnit.MILLISECONDS);
    }

    private void retryBehaviorProbe(String transactionKey, PendingStunBinding expected) {
        if (!running || pendingStunBindings.get(transactionKey) != expected) {
            return;
        }
        sendStunRequest(expected.request(), expected.targetEndpoint());
    }

    private void timeoutBehaviorProbe(String transactionKey, PendingStunBinding expected) {
        if (!pendingStunBindings.remove(transactionKey, expected) || expected.behaviorProbe() == null) {
            return;
        }
        handleNatBehaviorTransition(natBehaviorDiscovery.timedOut(
                expected.behaviorGeneration(),
                expected.behaviorProbe()));
    }

    private void requestPublicStunBindings() {
        ClientAuthLoginResponse.PeerMeshConfig current = config;
        if (current == null || current.getPublicStunServers() == null || current.getPublicStunServers().isEmpty()) {
            removePublicStunCandidates();
            return;
        }
        removePublicStunCandidates();
        List<String> sent = new ArrayList<>();
        for (String item : current.getPublicStunServers()) {
            InetSocketAddress endpoint = parseStunServer(item);
            if (endpoint == null) {
                continue;
            }
            String key = endpoint.getHostString() + ":" + endpoint.getPort();
            if (sent.contains(key)) {
                continue;
            }
            sent.add(key);
            sendStunBinding(endpoint, PUBLIC_STUN_ROLE_PREFIX + key);
        }
    }

    private void removePublicStunCandidates() {
        serverReflexiveCandidates.entrySet().removeIf(entry -> {
            PeerCandidate candidate = entry.getValue();
            return candidate != null && "public-stun".equalsIgnoreCase(candidate.getFoundation());
        });
    }

    private void sendStunRequest(StunMessage message, InetSocketAddress relayEndpoint) {
        sendStunRequest(message, relayEndpoint, 0);
    }

    private void sendStunRequest(StunMessage message,
                                 InetSocketAddress relayEndpoint,
                                 int authenticationAttempt) {
        DatagramSocket socket = udpSocket;
        if (socket == null || socket.isClosed() || relayEndpoint == null) {
            return;
        }
        boolean authenticatedTurnRequest = TurnLongTermAuthenticator.requiresAuthentication(message.type())
                && turnAuthenticator.canAuthenticate();
        String transactionKey = message.transactionIdHex();
        PendingTurnRequest pending = null;
        if (authenticatedTurnRequest) {
            pending = new PendingTurnRequest(
                    message.type(),
                    message.attributes(),
                    relayEndpoint,
                    authenticationAttempt,
                    System.currentTimeMillis());
            pendingTurnRequests.put(transactionKey, pending);
        }
        try {
            byte[] bytes = turnAuthenticator.encode(message);
            socket.send(new DatagramPacket(bytes, bytes.length, relayEndpoint));
        } catch (Exception e) {
            if (pending != null) {
                pendingTurnRequests.remove(transactionKey, pending);
            }
            log.debug("Peer mesh STUN/TURN request 发送失败: type=0x{}, reason={}",
                    Integer.toHexString(message.type()), e.getMessage());
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
        if (!directDisabled) {
            candidates.addAll(serverReflexiveCandidates.values());
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
        long delayMillis = 0;
        for (PeerCandidate candidate : control.getCandidates()) {
            if (!"udp".equalsIgnoreCase(candidate.getTransport())
                    || !StringUtils.hasText(candidate.getAddress())
                    || candidate.getPort() <= 0
                    || isRecursiveDirectCandidate(candidate)
                    || shouldSkipDirectCandidate(candidate)) {
                continue;
            }
            sendUdpProbePaced(session, candidate, delayMillis);
            delayMillis += CONNECTIVITY_CHECK_PACING_MILLIS;
            // 对称 NAT 端口预测：根据多 STUN srflx 观测到的端口变化自适应补探，
            // 不再固定扫描 ±8，避免无观测依据时制造额外 UDP 噪声。
            for (Integer predictedPort : adaptivePredictedPorts(candidate, control.getCandidates())) {
                PeerCandidate predicted = new PeerCandidate();
                predicted.setType(candidate.getType());
                predicted.setAddress(candidate.getAddress());
                predicted.setPort(predictedPort);
                predicted.setTransport("udp");
                predicted.setFoundation("adaptive-port-predict");
                sendUdpProbePaced(session, predicted, delayMillis);
                delayMillis += CONNECTIVITY_CHECK_PACING_MILLIS;
            }
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

    private void sendUdpProbePaced(PeerSession session, PeerCandidate candidate, long delayMillis) {
        if (delayMillis <= 0) {
            sendUdpProbe(session, candidate);
            return;
        }
        ScheduledExecutorService executor = maintenanceExecutor;
        if (executor == null || executor.isShutdown()) {
            sendUdpProbe(session, candidate);
            return;
        }
        Long sessionId = session.sessionId();
        executor.schedule(() -> {
            if (!running) {
                return;
            }
            PeerSession current = sessions.get(session.peerId());
            if (current == null
                    || !Objects.equals(current.sessionId(), sessionId)
                    || current.isExpired(System.currentTimeMillis())) {
                return;
            }
            sendUdpProbe(current, candidate);
        }, delayMillis, TimeUnit.MILLISECONDS);
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
        boolean relay = "relay".equalsIgnoreCase(candidate.getType());
        String relayTarget = relay ? candidate.getRelayId() : "";
        pendingProbes.put(nonce, new PendingProbe(
                session.sessionId(),
                session.peerId(),
                System.currentTimeMillis(),
                remote,
                relay,
                relayTarget));
        try {
            if (relay) {
                if (!StringUtils.hasText(relayTarget)) {
                    pendingProbes.remove(nonce);
                    return;
                }
                if (!sendRelayPayload(relayTarget, bytes)) {
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

    private List<Integer> adaptivePredictedPorts(PeerCandidate candidate, List<PeerCandidate> allCandidates) {
        if (candidate == null
                || "relay".equalsIgnoreCase(candidate.getType())
                || candidate.getPort() <= 0
                || !StringUtils.hasText(candidate.getAddress())) {
            return List.of();
        }
        List<Integer> deltas = adaptivePortDeltas(candidate, allCandidates);
        if (deltas.isEmpty()) {
            deltas = localSrflxPortDeltas();
        }
        if (deltas.isEmpty()) {
            return List.of();
        }
        List<Integer> ports = new ArrayList<>();
        for (Integer delta : deltas) {
            if (delta == null || delta <= 0 || delta > MAX_ADAPTIVE_PORT_DELTA) {
                continue;
            }
            addPredictedPort(ports, candidate.getPort() + delta, candidate.getPort());
            addPredictedPort(ports, candidate.getPort() - delta, candidate.getPort());
            if (ports.size() >= MAX_ADAPTIVE_PREDICTED_PORTS) {
                break;
            }
        }
        return ports;
    }

    private List<Integer> adaptivePortDeltas(PeerCandidate candidate, List<PeerCandidate> allCandidates) {
        if (allCandidates == null || allCandidates.isEmpty()) {
            return List.of();
        }
        List<Integer> ports = allCandidates.stream()
                .filter(item -> item != null)
                .filter(item -> !"relay".equalsIgnoreCase(item.getType()))
                .filter(item -> StringUtils.hasText(item.getAddress()) && item.getAddress().equals(candidate.getAddress()))
                .map(PeerCandidate::getPort)
                .filter(port -> port != null && port > 0 && port <= 65_535)
                .distinct()
                .sorted()
                .toList();
        return deltasFromPorts(ports);
    }

    private List<Integer> localSrflxPortDeltas() {
        long now = System.currentTimeMillis();
        pruneSrflxObservations(now);
        List<Integer> ports = srflxObservations.values().stream()
                .filter(item -> now - item.observedAtMillis() <= SRFLX_OBSERVATION_TTL_MILLIS)
                .map(SrflxObservation::mappedPort)
                .filter(port -> port > 0 && port <= 65_535)
                .distinct()
                .sorted()
                .toList();
        return deltasFromPorts(ports);
    }

    private List<Integer> deltasFromPorts(List<Integer> ports) {
        if (ports == null || ports.size() < 2) {
            return List.of();
        }
        List<Integer> deltas = new ArrayList<>();
        for (int i = 1; i < ports.size(); i++) {
            int delta = Math.abs(ports.get(i) - ports.get(i - 1));
            if (delta > 0 && delta <= MAX_ADAPTIVE_PORT_DELTA && !deltas.contains(delta)) {
                deltas.add(delta);
            }
        }
        return deltas;
    }

    private void addPredictedPort(List<Integer> ports, int port, int basePort) {
        if (port <= 0 || port > 65_535 || port == basePort || ports.contains(port)) {
            return;
        }
        ports.add(port);
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

    private void fallbackStaleDirectPaths() {
        long now = System.currentTimeMillis();
        for (PeerInfo peer : peers.values()) {
            PeerSession session = sessions.get(peer.clientId());
            if (session == null
                    || session.isExpired(now)
                    || !"DIRECT".equals(session.currentPathType)
                    || session.hasHealthyDirect(now)) {
                continue;
            }
            session.remoteEndpoint = null;
            PeerInfo currentPeer = peers.get(session.peerId());
            if (currentPeer != null && currentPeer.online()) {
                log.debug("Peer mesh direct path stale, probing fallback: session={}, peer={}",
                        session.sessionId(), session.peerId());
                preparePathForPeer(currentPeer, session);
            }
        }
    }

    /**
     * 给一个 session 的已确认 DIRECT endpoint 发一发轻量 keepalive probe。
     * 和正常 connectivity check 用同一种 PeerUdpProbe.TYPE_CHECK 报文格式，对端透明地回 ACK，
     * 借此更新本端 lastDirectSuccessMillis 把 path 一直标为「健康」。
     *
     * <p>keepalive 也做 burst（同 nonce 重发）：这里没有 NAT race，但 keepalive 25s 间隔
     * 与 45s stale 阈值之间只容得下一次机会——单包一丢，路径就会被判 stale 拆掉重打，
     * 一次普通 UDP 丢包就引发 direct→relay 抖动。收到 ACK 后 pendingProbes 里的 nonce
     * 被移除，后续 burst 自动跳过，代价可忽略。
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
            scheduleProbeBurst(socket, bytes, endpoint, nonce, session.sessionId());
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
                    fallbackStaleDirectPaths();
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
        report.setNatMappingBehavior(natMappingBehavior);
        report.setNatFilteringBehavior(natFilteringBehavior);
        report.setNatBehaviorDiscovery(natBehaviorDiscoveryMode);
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
        if (NatBehaviorDiscovery.DISCOVERY_RFC5780.equals(natBehaviorDiscoveryMode)
                && StringUtils.hasText(natMappingBehavior)) {
            return;
        }
        reportNatState(
                observedNatType,
                endpoint,
                natMappingBehavior,
                natFilteringBehavior,
                natBehaviorDiscoveryMode);
    }

    private void reportNatBehavior(NatBehaviorDiscovery.Snapshot snapshot) {
        if (snapshot == null || !snapshot.complete() || snapshot.mappedEndpoint() == null) {
            return;
        }
        String endpoint = endpointKey(snapshot.mappedEndpoint());
        String compatibleNatType = compatibleNatType(snapshot);
        reportNatState(
                compatibleNatType,
                endpoint,
                snapshot.mappingBehavior(),
                snapshot.filteringBehavior(),
                snapshot.discovery());
    }

    private void reportBasicNatDiscovery() {
        NatProbeResult fallback = classifyNat();
        reportNatState(
                StringUtils.hasText(fallback.natType()) ? fallback.natType() : natType,
                StringUtils.hasText(fallback.endpoint()) ? fallback.endpoint() : lastEndpoint,
                "",
                "",
                NatBehaviorDiscovery.DISCOVERY_BASIC);
    }

    private void reportNatState(String observedNatType,
                                String endpoint,
                                String mappingBehavior,
                                String filteringBehavior,
                                String discoveryMode) {
        String nextNatType = normalizeValue(observedNatType);
        String nextEndpoint = normalizeValue(endpoint);
        String nextMapping = normalizeValue(mappingBehavior);
        String nextFiltering = normalizeValue(filteringBehavior);
        String nextDiscovery = normalizeValue(discoveryMode);
        if (Objects.equals(nextNatType, natType)
                && Objects.equals(nextEndpoint, lastEndpoint)
                && Objects.equals(nextMapping, natMappingBehavior)
                && Objects.equals(nextFiltering, natFilteringBehavior)
                && Objects.equals(nextDiscovery, natBehaviorDiscoveryMode)) {
            return;
        }
        natType = nextNatType;
        lastEndpoint = nextEndpoint;
        natMappingBehavior = nextMapping;
        natFilteringBehavior = nextFiltering;
        natBehaviorDiscoveryMode = nextDiscovery;
        if (!shouldAvoidDirectPath()) {
            directSuppressedLogged.set(false);
        }
        log.info(
                "Peer mesh NAT 探测结果: type={}, mapping={}, filtering={}, discovery={}, mapped={}",
                nextNatType,
                nextMapping,
                nextFiltering,
                nextDiscovery,
                nextEndpoint);
        if (!running || controlSender == null) {
            return;
        }
        PeerControlMessage report = new PeerControlMessage();
        report.setType(PeerControlMessage.TYPE_DEVICE_REPORT);
        report.setNatType(nextNatType);
        report.setNatMappingBehavior(nextMapping);
        report.setNatFilteringBehavior(nextFiltering);
        report.setNatBehaviorDiscovery(nextDiscovery);
        report.setLastEndpoint(nextEndpoint);
        report.setCreatedAtMillis(System.currentTimeMillis());
        try {
            controlSender.send(null, JsonUtil.objectToString(report));
        } catch (Exception e) {
            log.debug("Peer mesh NAT 状态上报失败: {}", e.getMessage());
        }
    }

    private String compatibleNatType(NatBehaviorDiscovery.Snapshot snapshot) {
        InetSocketAddress mappedEndpoint = snapshot.mappedEndpoint();
        if (mappedEndpoint != null
                && isPortPreserved(mappedEndpoint.getPort())
                && isLocalAddress(mappedEndpoint.getAddress().getHostAddress())) {
            return "NO_NAT";
        }
        if (NatBehaviorDiscovery.ADDRESS_DEPENDENT.equals(snapshot.mappingBehavior())
                || NatBehaviorDiscovery.ADDRESS_AND_PORT_DEPENDENT.equals(snapshot.mappingBehavior())) {
            return "SYMMETRIC_NAT";
        }
        if (NatBehaviorDiscovery.ENDPOINT_INDEPENDENT.equals(snapshot.mappingBehavior())) {
            if (NatBehaviorDiscovery.ADDRESS_AND_PORT_DEPENDENT.equals(snapshot.filteringBehavior())) {
                return "PORT_RESTRICTED_NAT";
            }
            if (NatBehaviorDiscovery.ENDPOINT_INDEPENDENT.equals(snapshot.filteringBehavior())
                    || NatBehaviorDiscovery.ADDRESS_DEPENDENT.equals(snapshot.filteringBehavior())) {
                return "FULL_CONE_OR_RESTRICTED_NAT";
            }
        }
        return StringUtils.hasText(natType) ? natType : "NAT";
    }

    private String normalizeValue(String value) {
        return value == null ? "" : value.trim();
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
        return observation != null && isPortPreserved(observation.mappedPort());
    }

    private boolean isPortPreserved(int mappedPort) {
        DatagramSocket socket = udpSocket;
        int localPort = socket == null || socket.isClosed() ? -1 : socket.getLocalPort();
        return localPort > 0 && mappedPort == localPort;
    }

    private String normalizeProbeRole(String role) {
        if (PeerRelayMessage.PROBE_ALTERNATE.equals(role)
                || PeerRelayMessage.PROBE_CHANGED_PORT.equals(role)) {
            return role;
        }
        return PeerRelayMessage.PROBE_PRIMARY;
    }

    private String bindingProbeRole(String role) {
        if (isPublicStunRole(role)) {
            return role;
        }
        return normalizeProbeRole(role);
    }

    private boolean isPublicStunRole(String role) {
        return StringUtils.hasText(role) && role.startsWith(PUBLIC_STUN_ROLE_PREFIX);
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
        StunMessage stun = StunMessage.parse(packet.getData(), packet.getOffset(), packet.getLength());
        if (stun != null) {
            handleStunTurnMessage(stun, observedRemote);
            return;
        }
        handleUdpPayload(payload, observedRemote, null);
    }

    private void handleStunTurnMessage(StunMessage message, InetSocketAddress observedRemote) {
        switch (message.type()) {
            case StunMessage.BINDING_SUCCESS -> handleStunBindingSuccess(message, observedRemote);
            case StunMessage.BINDING_ERROR -> handleStunBindingError(message, observedRemote);
            case StunMessage.ALLOCATE_SUCCESS -> {
                completeTurnRequest(message, observedRemote);
                handleTurnAllocated(message);
            }
            case StunMessage.REFRESH_SUCCESS -> {
                completeTurnRequest(message, observedRemote);
                relayAllocationExpiresAtMillis = System.currentTimeMillis()
                        + Math.max(30, message.lifetimeSeconds(300)) * 1000;
            }
            case StunMessage.CREATE_PERMISSION_SUCCESS -> {
                completeTurnRequest(message, observedRemote);
                log.trace("Peer mesh TURN permission created: tx={}", message.transactionIdHex());
            }
            case StunMessage.ALLOCATE_ERROR,
                 StunMessage.REFRESH_ERROR,
                 StunMessage.CREATE_PERMISSION_ERROR -> handleTurnError(message, observedRemote);
            case StunMessage.DATA_INDICATION -> {
                InetSocketAddress peer = message.xorPeerAddress().orElse(null);
                byte[] inner = message.data().orElse(null);
                if (peer != null && inner != null) {
                    handleUdpPayload(inner, observedRemote, endpointKey(peer));
                }
            }
            default -> log.trace("Peer mesh STUN/TURN message ignored: type=0x{}",
                    Integer.toHexString(message.type()));
        }
    }

    private void handleStunBindingSuccess(StunMessage message, InetSocketAddress observedRemote) {
        InetSocketAddress mapped = message.xorMappedAddress().orElse(null);
        if (mapped == null) {
            return;
        }
        String transactionKey = message.transactionIdHex();
        PendingStunBinding pendingBinding = pendingStunBindings.get(transactionKey);
        if (pendingBinding == null) {
            log.trace("Peer mesh STUN Binding response has no pending transaction: tx={}", transactionKey);
            return;
        }
        if (!sameEndpoint(pendingBinding.expectedResponseEndpoint(), observedRemote)) {
            log.debug(
                    "Peer mesh STUN Binding response source mismatch: role={}, expected={}, actual={}",
                    pendingBinding.role(),
                    pendingBinding.expectedResponseEndpoint(),
                    observedRemote);
            return;
        }
        if (!pendingStunBindings.remove(transactionKey, pendingBinding)) {
            return;
        }

        String role = pendingBinding.role();
        boolean publicStun = isPublicStunRole(role);
        if (pendingBinding.behaviorProbe() != null) {
            handleNatBehaviorTransition(natBehaviorDiscovery.succeeded(
                    pendingBinding.behaviorGeneration(),
                    pendingBinding.behaviorProbe(),
                    mapped));
        } else if (!publicStun) {
            PeerRelayMessage observation = new PeerRelayMessage();
            observation.setType(PeerRelayMessage.TYPE_BINDING_RESPONSE);
            observation.setProbeRole(role);
            observation.setMappedAddress(mapped.getAddress().getHostAddress());
            observation.setMappedPort(mapped.getPort());
            resolveOtherAddress(message, observedRemote).ifPresent(other -> {
                observation.setAlternateAddress(other.getAddress().getHostAddress());
                observation.setAlternatePort(other.getPort());
            });
            recordNatObservation(observation, observedRemote);
            if (PeerRelayMessage.PROBE_PRIMARY.equals(normalizeProbeRole(role))) {
                Optional<InetSocketAddress> standardOther =
                        resolveStandardOtherAddress(message, observedRemote);
                if (standardOther.isPresent()) {
                    startNatBehaviorDiscovery(observedRemote, mapped, standardOther.get());
                } else {
                    reportBasicNatDiscovery();
                    requestAlternateNatProbe(observation, observedRemote);
                }
            }
        }

        PeerCandidate candidate = new PeerCandidate();
        candidate.setType("srflx");
        candidate.setTransport("udp");
        candidate.setAddress(mapped.getAddress().getHostAddress());
        candidate.setPort(mapped.getPort());
        candidate.setPriority(800);
        candidate.setFoundation(publicStun ? "public-stun" : "standard-stun");
        String candidateKey = candidateEndpointKey(candidate);
        recordSrflxObservation(role, observedRemote, mapped);
        // key 含 addr:port，put 返回 null ⇔ 观测到新映射。同一映射被周期性 STUN 反复确认
        // 时不再触发全员广播——配置 N 个公共 STUN 时每轮会到达 N+1 个 binding success，
        // 逐个广播会让每个在线 peer 连着跑 N+1 轮 connectivity check。
        boolean candidateChanged;
        if (publicStun) {
            candidateChanged = serverReflexiveCandidates.putIfAbsent(candidateKey, candidate) == null;
        } else {
            candidateChanged = serverReflexiveCandidates.put(candidateKey, candidate) == null;
            serverReflexiveCandidate = candidate;
        }
        if (candidateChanged) {
            announceCandidatesToOnlinePeers();
        }
    }

    private void handleStunBindingError(StunMessage message, InetSocketAddress observedRemote) {
        String transactionKey = message.transactionIdHex();
        PendingStunBinding pendingBinding = pendingStunBindings.get(transactionKey);
        if (pendingBinding == null) {
            return;
        }
        // RFC 5780 errors are sent by the request target, not by the changed
        // response endpoint requested for a successful Binding response.
        if (!sameEndpoint(pendingBinding.targetEndpoint(), observedRemote)) {
            log.debug(
                    "Peer mesh STUN Binding error source mismatch: role={}, expected={}, actual={}",
                    pendingBinding.role(),
                    pendingBinding.targetEndpoint(),
                    observedRemote);
            return;
        }
        if (!pendingStunBindings.remove(transactionKey, pendingBinding)) {
            return;
        }
        if (pendingBinding.behaviorProbe() == null) {
            log.debug(
                    "Peer mesh STUN Binding request failed: role={}, code={}",
                    pendingBinding.role(),
                    message.errorCode());
            return;
        }
        boolean unsupported = message.errorCode() == 420
                && (message.unknownAttributes().isEmpty()
                || message.unknownAttributes().contains(StunMessage.ATTR_CHANGE_REQUEST));
        log.debug(
                "Peer mesh RFC 5780 probe failed: probe={}, code={}, unsupported={}",
                pendingBinding.behaviorProbe(),
                message.errorCode(),
                unsupported);
        handleNatBehaviorTransition(natBehaviorDiscovery.failed(
                pendingBinding.behaviorGeneration(),
                pendingBinding.behaviorProbe(),
                unsupported));
    }

    private void recordSrflxObservation(String role, InetSocketAddress stunServer, InetSocketAddress mapped) {
        if (mapped == null || mapped.getAddress() == null || mapped.getPort() <= 0) {
            return;
        }
        String server = stunServer == null || stunServer.getAddress() == null
                ? role
                : stunServer.getAddress().getHostAddress() + ":" + stunServer.getPort();
        srflxObservations.put(server + "|" + role, new SrflxObservation(
                role,
                mapped.getAddress().getHostAddress(),
                mapped.getPort(),
                server,
                System.currentTimeMillis()));
        pruneSrflxObservations(System.currentTimeMillis());
    }

    private void pruneSrflxObservations(long now) {
        srflxObservations.entrySet().removeIf(entry -> now - entry.getValue().observedAtMillis() > SRFLX_OBSERVATION_TTL_MILLIS);
    }

    private void handleTurnAllocated(StunMessage message) {
        InetSocketAddress relayed = message.xorRelayedAddress().orElse(null);
        if (relayed == null) {
            return;
        }
        InetSocketAddress turnServer = relayEndpoint();
        if (turnServer == null) {
            return;
        }
        relayAllocationId = "turn:" + endpointKey(relayed);
        relayAllocationExpiresAtMillis = System.currentTimeMillis()
                + Math.max(30, message.lifetimeSeconds(300)) * 1000;
        PeerCandidate candidate = new PeerCandidate();
        candidate.setType("relay");
        candidate.setTransport("udp");
        candidate.setAddress(turnServer.getHostString());
        candidate.setPort(turnServer.getPort());
        candidate.setPriority(100);
        candidate.setFoundation("standard-turn");
        candidate.setRelayId(endpointKey(relayed));
        PeerCandidate previous = relayCandidate;
        relayCandidate = candidate;
        // relay 端点没变（同一 allocation 被重复确认）就不必广播
        if (previous == null
                || !Objects.equals(previous.getRelayId(), candidate.getRelayId())
                || !Objects.equals(previous.getAddress(), candidate.getAddress())
                || !Objects.equals(previous.getPort(), candidate.getPort())) {
            announceCandidatesToOnlinePeers();
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
        sendStunBinding(new InetSocketAddress(alternateAddress, response.getAlternatePort()),
                PeerRelayMessage.PROBE_ALTERNATE);
    }

    private void startNatBehaviorDiscovery(InetSocketAddress primaryEndpoint,
                                           InetSocketAddress mappedEndpoint,
                                           InetSocketAddress otherEndpoint) {
        long now = System.currentTimeMillis();
        if (now - lastBehaviorDiscoveryStartedMillis < BEHAVIOR_DISCOVERY_MIN_INTERVAL_MILLIS) {
            return;
        }
        lastBehaviorDiscoveryStartedMillis = now;
        try {
            handleNatBehaviorTransition(natBehaviorDiscovery.begin(
                    primaryEndpoint,
                    mappedEndpoint,
                    otherEndpoint));
        } catch (IllegalArgumentException e) {
            log.debug("Peer mesh RFC 5780 topology ignored: {}", e.getMessage());
            reportBasicNatDiscovery();
        }
    }

    private void handleNatBehaviorTransition(NatBehaviorDiscovery.Transition transition) {
        if (transition == null || !transition.accepted()) {
            return;
        }
        if (transition.snapshot().complete()) {
            reportNatBehavior(transition.snapshot());
        }
        if (transition.nextProbe() != null) {
            sendBehaviorProbe(transition.nextProbe());
        }
    }

    private Optional<InetSocketAddress> resolveStandardOtherAddress(StunMessage message,
                                                                    InetSocketAddress observedRemote) {
        Optional<InetSocketAddress> standardOrigin = message.responseOrigin();
        Optional<InetSocketAddress> otherAddress = message.otherAddress();
        if (standardOrigin.isEmpty()
                || otherAddress.isEmpty()
                || !sameEndpoint(standardOrigin.get(), observedRemote)
                || otherAddress.get().getAddress() == null
                || observedRemote == null
                || observedRemote.getAddress() == null
                || otherAddress.get().getAddress().equals(observedRemote.getAddress())
                || otherAddress.get().getPort() == observedRemote.getPort()) {
            return Optional.empty();
        }
        return otherAddress;
    }

    private Optional<InetSocketAddress> resolveOtherAddress(StunMessage message,
                                                            InetSocketAddress observedRemote) {
        Optional<InetSocketAddress> standardOther = resolveStandardOtherAddress(message, observedRemote);
        if (standardOther.isPresent()) {
            return standardOther;
        }
        Optional<InetSocketAddress> legacyOrigin = message.legacyXorResponseOrigin();
        if (legacyOrigin.isPresent() && sameEndpoint(legacyOrigin.get(), observedRemote)) {
            return message.legacyXorOtherAddress();
        }
        return message.otherAddress();
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
        ClientAuthLoginResponse.PeerMeshConfig currentConfig = config;
        if (currentConfig == null) {
            return;
        }
        if (!StringUtils.hasText(relayFromAllocationId) && isMeshAddress(observedRemote)) {
            log.debug("Peer mesh 忽略来自虚拟网段的加密 frame，避免 overlay 递归: remote={}", observedRemote);
            return;
        }
        Long frameSessionId = PeerDataFrameCodec.sessionId(raw);
        if (frameSessionId == null) {
            log.debug("Peer mesh encrypted frame 头部无效: remote={}", observedRemote);
            return;
        }
        PeerSession session = sessionsById.get(frameSessionId);
        if (session == null) {
            log.debug("Peer mesh encrypted frame 未匹配 session: session={}, remote={}", frameSessionId, observedRemote);
            return;
        }
        if (session.aesKey() == null) {
            log.debug("Peer mesh encrypted frame session 密钥未就绪: session={}, remote={}", frameSessionId, observedRemote);
            return;
        }
        if (session.isExpired(System.currentTimeMillis())) {
            removeSession(session.peerId(), session);
            return;
        }
        PeerDataFrame frame = PeerDataFrameCodec.decode(
                session.aesKey(),
                raw,
                session.sessionId(),
                currentConfig.getClientId()
        );
        if (frame == null || frame.fromClientId() != session.peerId() || !session.acceptInboundSequence(frame.sequence())) {
            log.debug("Peer mesh encrypted frame 无法解密或 replay 拒绝: session={}, remote={}", frameSessionId, observedRemote);
            return;
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
    }

    private void handlePlainPacket(PeerDataFrame frame) {
        if (PeerAppMessageCodec.looksLike(frame.plaintext())) {
            handlePeerAppMessage(frame);
            return;
        }

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

    private void completeTurnRequest(StunMessage response, InetSocketAddress observedRemote) {
        String transactionKey = response.transactionIdHex();
        PendingTurnRequest pending = pendingTurnRequests.get(transactionKey);
        if (pending != null && sameEndpoint(pending.endpoint(), observedRemote)) {
            pendingTurnRequests.remove(transactionKey, pending);
        }
    }

    private void handleTurnError(StunMessage response, InetSocketAddress observedRemote) {
        String transactionKey = response.transactionIdHex();
        PendingTurnRequest pending = pendingTurnRequests.remove(transactionKey);
        int errorCode = TurnLongTermAuthenticator.errorCode(response);
        if (pending == null || !sameEndpoint(pending.endpoint(), observedRemote)) {
            log.debug("Peer mesh TURN error ignored: type=0x{}, code={}, tx={}",
                    Integer.toHexString(response.type()), errorCode, transactionKey);
            return;
        }
        if ((errorCode != 401 && errorCode != 438)
                || pending.authenticationAttempt() >= 1
                || !turnAuthenticator.applyChallenge(response)) {
            log.debug("Peer mesh TURN request failed: type=0x{}, code={}, authAttempt={}",
                    Integer.toHexString(pending.requestType()), errorCode, pending.authenticationAttempt());
            return;
        }

        StunMessage retry = new StunMessage(
                pending.requestType(),
                StunMessage.newTransactionId(),
                pending.attributes());
        log.debug("Peer mesh TURN auth challenge received, retrying once: type=0x{}, code={}",
                Integer.toHexString(pending.requestType()), errorCode);
        sendStunRequest(retry, pending.endpoint(), pending.authenticationAttempt() + 1);
    }

    private boolean sameEndpoint(InetSocketAddress expected, InetSocketAddress actual) {
        if (expected == null || actual == null || expected.getPort() != actual.getPort()) {
            return false;
        }
        if (expected.getAddress() != null && actual.getAddress() != null) {
            return expected.getAddress().equals(actual.getAddress());
        }
        return expected.getHostString().equalsIgnoreCase(actual.getHostString());
    }

    private void handlePeerAppMessage(PeerDataFrame frame) {
        PeerAppMessageCodec.PeerAppMessage message = PeerAppMessageCodec.decode(frame.plaintext());
        if (message == null) {
            log.debug("Peer mesh app message decode failed: session={}, from={}",
                    frame.sessionId(), frame.fromClientId());
            return;
        }
        if (PeerAppMessageCodec.TYPE_ACK.equalsIgnoreCase(message.getType())) {
            return;
        }
        if (!PeerAppMessageCodec.TYPE_MESSAGE.equalsIgnoreCase(message.getType())) {
            return;
        }
        ClientAuthLoginResponse.PeerMeshConfig currentConfig = config;
        if (currentConfig != null
                && message.getToClientId() != 0
                && message.getToClientId() != currentConfig.getClientId()) {
            return;
        }

        String fromName = StringUtils.hasText(message.getFromClientName())
                ? message.getFromClientName()
                : String.valueOf(frame.fromClientId());
        log.info("Peer message from {}: {}", fromName, message.getMessage());
        sendPeerAppMessageAck(frame, message);
    }

    private void sendPeerAppMessageAck(PeerDataFrame frame, PeerAppMessageCodec.PeerAppMessage message) {
        ClientAuthLoginResponse.PeerMeshConfig currentConfig = config;
        if (currentConfig == null || !StringUtils.hasText(message.getId())) {
            return;
        }
        PeerInfo peer = peers.get(frame.fromClientId());
        if (peer == null || !StringUtils.hasText(peer.virtualIp())) {
            return;
        }

        PeerAppMessageCodec.PeerAppMessage ack = new PeerAppMessageCodec.PeerAppMessage();
        ack.setType(PeerAppMessageCodec.TYPE_ACK);
        ack.setId(message.getId());
        ack.setFromClientId(currentConfig.getClientId());
        ack.setFromClientName(currentConfig.getClientName());
        ack.setToClientId(frame.fromClientId());
        ack.setToClientName(StringUtils.hasText(message.getFromClientName()) ? message.getFromClientName() : peer.clientName());
        ack.setCreatedAtMillis(System.currentTimeMillis());
        sendEncryptedPayload(peer.virtualIp(), PeerAppMessageCodec.encode(ack), false);
    }

    private void replyUdpProbe(PeerUdpProbe probe, InetSocketAddress observedRemote, String relayFromAllocationId) {
        DatagramSocket socket = udpSocket;
        if (socket == null || socket.isClosed()) {
            return;
        }
        PeerSession session = sessions.get(probe.getFromClientId());
        if (session == null || !session.token().equals(probe.getToken())
                || !session.sessionId.equals(probe.getSessionId())) {
            return;
        }
        markPathFromInboundCheck(session, observedRemote, relayFromAllocationId);

        // P1-5 触发式双向探针：收到入站探针时，若 direct 路径尚未建立则再扫一轮对端端口
        if (!session.hasHealthyDirect(System.currentTimeMillis())) {
            PeerInfo peerInfo = peers.get(session.peerId());
            if (peerInfo != null && !peerInfo.candidates().isEmpty()) {
                PeerControlMessage trigger = new PeerControlMessage();
                trigger.setSessionId(session.sessionId());
                trigger.setSourceClientId(peerInfo.clientId());
                trigger.setCandidates(peerInfo.candidates());
                sendConnectivityChecks(trigger);
            }
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
        // S4.2 endpoint 粘滞（入站侧）：现有 direct endpoint 仍健康时不被其他来源地址抢占，
        // 对称 NAT 对端的多个映射地址才不会来回翻转本端的发送目标。
        InetSocketAddress currentEndpoint = session.remoteEndpoint;
        if (observedRemote.equals(currentEndpoint)) {
            session.endpointSuccessMillis = now;
        } else if (!("DIRECT".equals(session.currentPathType)
                && currentEndpoint != null
                && now - session.endpointSuccessMillis <= DIRECT_STALE_MILLIS)) {
            session.remoteEndpoint = observedRemote;
            session.relayTargetAllocationId = null;
            session.endpointSuccessMillis = now;
            // RTT 未知：留 MAX 让下一个带 RTT 的探测响应可以接管并校准
            session.endpointRtt = Long.MAX_VALUE;
        }
        session.markPath("DIRECT", now);
        flushPendingPackets(session);
    }

    private void removeExpiredSessions() {
        long now = System.currentTimeMillis();
        for (Map.Entry<Long, PeerSession> entry : sessions.entrySet()) {
            PeerSession session = entry.getValue();
            if (session.isExpired(now)) {
                removeSession(entry.getKey(), session);
            }
        }
    }

    private void cleanupPendingProbes() {
        long now = System.currentTimeMillis();
        pendingProbes.entrySet().removeIf(entry -> now - entry.getValue().sentAtMillis() > PENDING_PROBE_TTL_MILLIS);
        // STUN binding 响应正常在亚秒级到达；entry 只在成功响应时移除，
        // STUN 服务器不可达时会以每 60s × N 个 server 的速度永久累积。
        for (Map.Entry<String, PendingStunBinding> entry : pendingStunBindings.entrySet()) {
            PendingStunBinding pending = entry.getValue();
            if (now - pending.sentAtMillis() <= PENDING_PROBE_TTL_MILLIS
                    || !pendingStunBindings.remove(entry.getKey(), pending)) {
                continue;
            }
            if (pending.behaviorProbe() != null) {
                handleNatBehaviorTransition(natBehaviorDiscovery.timedOut(
                        pending.behaviorGeneration(),
                        pending.behaviorProbe()));
            }
        }
        pendingTurnRequests.entrySet().removeIf(entry -> now - entry.getValue().sentAtMillis() > PENDING_PROBE_TTL_MILLIS);
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
        // S4.1 RTT 感知选路：用 EWMA 而不是历史最小值，避免网络变化后选路依据长期失真。
        if (pending.relay()) {
            session.bestRelayRtt = smoothRtt(session.bestRelayRtt, rttMillis);
        } else {
            session.bestDirectRtt = smoothRtt(session.bestDirectRtt, rttMillis);
        }
        if (pending.relay() && session.hasHealthyDirect(now) && !shouldAvoidDirectPath()
                && !(session.bestRelayRtt + RTT_HYSTERESIS_MS < session.bestDirectRtt)) {
            log.debug("Peer mesh relay UDP path ignored because direct path is healthy: session={}, peer={}",
                    session.sessionId(), session.peerId());
            return;
        }
        // 切回 direct：direct 再次活跃且 RTT 优于 relay
        if (!pending.relay() && session.currentPathType.equals("RELAY")
                && session.bestDirectRtt + RTT_HYSTERESIS_MS < session.bestRelayRtt) {
            session.bestRelayRtt = Long.MAX_VALUE;
            session.markPath("DIRECT", now);
            session.remoteEndpoint = observedRemote;
        }
        // S4.2 endpoint 粘滞：多个 direct candidate 都能通时，RTT 大的响应最后到达，
        // 无条件覆盖会让最慢路径胜出，且 30s 周期重探导致 endpoint 反复摆动。
        // 现有 endpoint 仍健康（keepalive ACK 会持续刷新 endpointSuccessMillis）且新
        // RTT 没有明显更优时保持不动；endpoint 失效后自然放行下一个响应者接管。
        boolean adoptEndpoint = true;
        if (!pending.relay()) {
            InetSocketAddress currentEndpoint = session.remoteEndpoint;
            if (observedRemote.equals(currentEndpoint)) {
                session.endpointSuccessMillis = now;
                session.endpointRtt = rttMillis;
            } else if ("DIRECT".equals(session.currentPathType)
                    && currentEndpoint != null
                    && now - session.endpointSuccessMillis <= DIRECT_STALE_MILLIS
                    && rttMillis + RTT_HYSTERESIS_MS >= session.endpointRtt) {
                adoptEndpoint = false;
                log.trace("Peer mesh direct endpoint sticky: session={}, keep={}, ignore={} ({}ms)",
                        session.sessionId(), currentEndpoint, observedRemote, rttMillis);
            }
        }
        String remote = pending.relay()
                ? "relay:" + (StringUtils.hasText(relayFromAllocationId) ? relayFromAllocationId : pending.relayId())
                : observedRemote.getAddress().getHostAddress() + ":" + observedRemote.getPort();
        String local = localEndpoint();
        String previousPath = session.currentPathType;
        String previousRemote = session.lastPathRemoteText;
        String pathType = pending.relay() ? "RELAY" : "DIRECT";
        if (adoptEndpoint) {
            session.remoteEndpoint = pending.relay() ? relayEndpoint() : observedRemote;
            session.relayTargetAllocationId = pending.relay() ? pending.relayId() : null;
            if (!pending.relay()) {
                session.endpointSuccessMillis = now;
                session.endpointRtt = rttMillis;
            }
        } else {
            remote = previousRemote;
        }
        session.markPath(pathType, now);
        boolean changed = !pathType.equals(previousPath) || !remote.equals(previousRemote);
        session.lastPathRemoteText = remote;
        if (changed || now - session.lastPathLogMillis >= 60_000) {
            log.debug("Peer mesh {} UDP path active: session={}, peer={}, remote={}, rtt={}ms",
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

    private static long smoothRtt(long previous, long sample) {
        if (sample < 0) {
            return previous;
        }
        if (previous == Long.MAX_VALUE) {
            return sample;
        }
        return ((previous * RTT_EWMA_OLD_WEIGHT) + (sample * RTT_EWMA_NEW_WEIGHT))
                / (RTT_EWMA_OLD_WEIGHT + RTT_EWMA_NEW_WEIGHT);
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
            long now = System.currentTimeMillis();
            if ("DIRECT".equals(session.currentPathType) && !session.hasHealthyDirect(now)) {
                session.remoteEndpoint = null;
                if (allowPendingQueue) {
                    queuePendingPacket(peer, payload);
                    preparePathForPeer(peer, session);
                }
                logPayloadDrop(targetVirtualIp, "direct-stale-waiting-relay");
                return false;
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
        if (shouldIgnoreVirtualPacketTarget(targetVirtualIp)) {
            logIgnoredVirtualPacket(targetVirtualIp, "non-peer-unicast");
            return false;
        }
        if (!isKnownOnlinePeerVirtualIp(targetVirtualIp)) {
            logIgnoredVirtualPacket(targetVirtualIp, "unknown-peer-route");
            return false;
        }
        tracePacket("outbound-from-tun", ipv4Packet);
        return sendEncryptedPayload(targetVirtualIp, ipv4Packet);
    }

    private boolean isKnownOnlinePeerVirtualIp(String targetVirtualIp) {
        return peers.values().stream()
                .anyMatch(peer -> peer.online() && targetVirtualIp.equals(peer.virtualIp()));
    }

    private boolean shouldIgnoreVirtualPacketTarget(String targetVirtualIp) {
        Long ip = ipv4ToLong(targetVirtualIp);
        if (ip == null) {
            return true;
        }
        int firstOctet = (int) ((ip >>> 24) & 0xFF);
        if (firstOctet >= 224 || firstOctet == 0 || targetVirtualIp.equals("255.255.255.255")) {
            return true;
        }
        ClientAuthLoginResponse.PeerMeshConfig current = config;
        if (current != null && targetVirtualIp.equals(current.getVirtualIp())) {
            return true;
        }
        return isMeshBoundaryAddress(targetVirtualIp);
    }

    private boolean isMeshBoundaryAddress(String targetVirtualIp) {
        ClientAuthLoginResponse.PeerMeshConfig current = config;
        if (current == null || !StringUtils.hasText(current.getCidr())) {
            return false;
        }
        String[] parts = current.getCidr().split("/", 2);
        if (parts.length != 2) {
            return false;
        }
        Long ip = ipv4ToLong(targetVirtualIp);
        Long base = ipv4ToLong(parts[0]);
        if (ip == null || base == null) {
            return false;
        }
        int prefix;
        try {
            prefix = Integer.parseInt(parts[1].trim());
        } catch (NumberFormatException e) {
            return false;
        }
        if (prefix < 0 || prefix >= 31) {
            return false;
        }
        long mask = prefix == 0 ? 0 : (0xFFFF_FFFFL << (32 - prefix)) & 0xFFFF_FFFFL;
        long network = base & mask;
        long broadcast = network | (~mask & 0xFFFF_FFFFL);
        return ip == network || ip == broadcast;
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
            log.debug("Peer mesh pending virtual packet flushed: peer={}, count={}", session.peerId(), flushed);
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
        log.debug("Peer mesh packet {}: {} bytes={}",
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

    private void logIgnoredVirtualPacket(String targetVirtualIp, String reason) {
        long now = System.currentTimeMillis();
        String key = "ignored|" + targetVirtualIp + "|" + reason;
        Long previous = payloadDropLogMillis.get(key);
        if (previous != null && now - previous < 30_000) {
            return;
        }
        payloadDropLogMillis.put(key, now);
        log.debug("Peer mesh 忽略非对端虚拟包: target={}, reason={}, peers={}, sessions={}",
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

    private boolean sendRelayPayload(String targetRelayEndpoint, byte[] payload) {
        if (!StringUtils.hasText(relayAllocationId) || !StringUtils.hasText(targetRelayEndpoint) || payload == null) {
            return false;
        }
        InetSocketAddress turnServer = relayEndpoint();
        InetSocketAddress peer = parseEndpoint(targetRelayEndpoint);
        if (turnServer == null || peer == null) {
            return false;
        }
        DatagramSocket socket = udpSocket;
        if (socket == null || socket.isClosed()) {
            return false;
        }
        try {
            ensureTurnPermission(peer);
            byte[] transactionId = StunMessage.newTransactionId();
            StunMessage indication = StunMessage.of(
                    StunMessage.SEND_INDICATION,
                    transactionId,
                    StunMessage.xorPeerAddress(peer, transactionId),
                    StunMessage.data(payload));
            byte[] bytes = indication.toBytes();
            socket.send(new DatagramPacket(bytes, bytes.length, turnServer));
            return true;
        } catch (Exception e) {
            log.debug("Peer mesh relay payload 发送失败: reason={}", e.getMessage());
            return false;
        }
    }

    private void ensureTurnPermission(InetSocketAddress peer) {
        InetSocketAddress turnServer = relayEndpoint();
        if (peer == null || turnServer == null) {
            return;
        }
        long now = System.currentTimeMillis();
        String key = endpointKey(peer);
        Long expiresAt = turnPermissions.get(key);
        if (expiresAt != null && expiresAt - now > 30_000) {
            return;
        }
        byte[] transactionId = StunMessage.newTransactionId();
        sendStunRequest(StunMessage.of(
                StunMessage.CREATE_PERMISSION_REQUEST,
                transactionId,
                StunMessage.xorPeerAddress(peer, transactionId)), turnServer);
        turnPermissions.put(key, now + TURN_PERMISSION_TTL_MILLIS);
    }

    private InetSocketAddress relayEndpoint() {
        if (config == null || !StringUtils.hasText(config.getTurnHost()) || config.getTurnPort() <= 0) {
            return null;
        }
        return new InetSocketAddress(config.getTurnHost(), config.getTurnPort());
    }

    private InetSocketAddress stunEndpoint() {
        if (config == null || !StringUtils.hasText(config.getStunHost()) || config.getStunPort() <= 0) {
            return null;
        }
        return new InetSocketAddress(config.getStunHost(), config.getStunPort());
    }

    private String endpointKey(InetSocketAddress endpoint) {
        if (endpoint == null || endpoint.getAddress() == null) {
            return "";
        }
        return endpoint.getAddress().getHostAddress() + ":" + endpoint.getPort();
    }

    private InetSocketAddress parseEndpoint(String value) {
        if (!StringUtils.hasText(value)) {
            return null;
        }
        String normalized = value.trim();
        if (normalized.startsWith("turn:")) {
            normalized = normalized.substring("turn:".length());
        }
        int colon = normalized.lastIndexOf(':');
        if (colon <= 0 || colon >= normalized.length() - 1) {
            return null;
        }
        try {
            String host = normalized.substring(0, colon);
            int port = Integer.parseInt(normalized.substring(colon + 1));
            return new InetSocketAddress(host, port);
        } catch (Exception e) {
            return null;
        }
    }

    private InetSocketAddress parseStunServer(String value) {
        if (!StringUtils.hasText(value)) {
            return null;
        }
        String normalized = value.trim();
        String lower = normalized.toLowerCase();
        if (lower.startsWith("stun://")) {
            normalized = normalized.substring("stun://".length());
        } else if (lower.startsWith("stun:")) {
            normalized = normalized.substring("stun:".length());
        }
        int slash = normalized.indexOf('/');
        if (slash >= 0) {
            normalized = normalized.substring(0, slash);
        }
        if (!StringUtils.hasText(normalized)) {
            return null;
        }
        String host = normalized;
        int port = 3478;
        if (normalized.startsWith("[")) {
            int close = normalized.indexOf(']');
            if (close <= 1) {
                return null;
            }
            host = normalized.substring(1, close);
            if (close + 1 < normalized.length() && normalized.charAt(close + 1) == ':') {
                port = parsePort(normalized.substring(close + 2), 3478);
            }
        } else {
            int firstColon = normalized.indexOf(':');
            int lastColon = normalized.lastIndexOf(':');
            if (firstColon > 0 && firstColon == lastColon && lastColon < normalized.length() - 1) {
                host = normalized.substring(0, lastColon);
                port = parsePort(normalized.substring(lastColon + 1), 3478);
            }
        }
        if (!StringUtils.hasText(host) || port <= 0 || port > 65535) {
            return null;
        }
        return new InetSocketAddress(host.trim(), port);
    }

    private int parsePort(String value, int fallback) {
        try {
            return Integer.parseInt(value.trim());
        } catch (Exception ignored) {
            return fallback;
        }
    }

    private String candidateEndpointKey(PeerCandidate candidate) {
        if (candidate == null || !StringUtils.hasText(candidate.getAddress()) || candidate.getPort() <= 0) {
            return "";
        }
        return candidate.getType() + ":" + candidate.getAddress() + ":" + candidate.getPort();
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
        syncVirtualDeviceRoutes();
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
        /** S4.1 RTT 追踪：用于 direct/relay 择优切换 */
        private volatile long bestDirectRtt = Long.MAX_VALUE;
        private volatile long bestRelayRtt = Long.MAX_VALUE;
        /** S4.2 endpoint 粘滞：当前 direct endpoint 最近一次响应时间与 RTT，用于抑制慢响应者抢占 */
        private volatile long endpointSuccessMillis;
        private volatile long endpointRtt = Long.MAX_VALUE;
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
            next.endpointSuccessMillis = endpointSuccessMillis;
            next.endpointRtt = endpointRtt;
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
            return lastDirectSuccessMillis > 0
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

    private record PendingStunBinding(String role,
                                      InetSocketAddress targetEndpoint,
                                      InetSocketAddress expectedResponseEndpoint,
                                      StunMessage request,
                                      NatBehaviorDiscovery.Probe behaviorProbe,
                                      int behaviorGeneration,
                                      long sentAtMillis) {
    }

    private record PendingTurnRequest(int requestType,
                                      List<StunMessage.Attribute> attributes,
                                      InetSocketAddress endpoint,
                                      int authenticationAttempt,
                                      long sentAtMillis) {
        private PendingTurnRequest {
            attributes = attributes == null ? List.of() : List.copyOf(attributes);
        }
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

    private record SrflxObservation(String role,
                                    String mappedAddress,
                                    int mappedPort,
                                    String serverEndpoint,
                                    long observedAtMillis) {
    }

    private record NatProbeResult(String natType, String endpoint) {
    }
}
