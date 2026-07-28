package com.theshuai.specusclient.peer;

import com.fasterxml.jackson.databind.JsonNode;
import com.theshuai.common.peermesh.PeerCandidate;
import com.theshuai.common.peermesh.PeerControlMessage;
import com.theshuai.common.peermesh.PeerCrypto;
import com.theshuai.common.peermesh.PeerRelayMessage;
import com.theshuai.common.peermesh.PeerUdpProbe;
import com.theshuai.common.clientauth.ClientAuthLoginResponse;
import com.theshuai.common.stun.StunMessage;
import com.theshuai.common.stun.TurnChannelData;
import com.theshuai.common.util.JsonUtil;
import com.theshuai.specusclient.peer.portmap.NatPortMapping;
import com.theshuai.specusclient.peer.portmap.NatPortMappingService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.util.StringUtils;

import javax.crypto.spec.SecretKeySpec;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.Inet6Address;
import java.net.Inet4Address;
import java.net.InetSocketAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.Deque;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;

@Slf4j
public class PeerMeshClient implements AutoCloseable {
    private volatile PeerIndex peerIndex = PeerIndex.empty();
    private final Map<Long, PeerSession> sessions = new ConcurrentHashMap<>();
    private final Map<Long, PeerSession> sessionsById = new ConcurrentHashMap<>();
    private final Map<String, PendingProbe> pendingProbes = new ConcurrentHashMap<>();
    private final Map<String, NatProbeObservation> natProbeObservations = new ConcurrentHashMap<>();
    private final Map<String, Long> payloadDropLogMillis = new ConcurrentHashMap<>();
    private final Map<String, Long> packetTraceLogMillis = new ConcurrentHashMap<>();
    private final Map<Long, Deque<PendingVirtualPacket>> pendingVirtualPackets = new ConcurrentHashMap<>();
    private final Map<Long, Long> pathPrepareMillis = new ConcurrentHashMap<>();
    /** 已上报过 path-report 的 sessionId：peerId -> sessionId，用于识别会话换号后必须重新上报 */
    private final Map<Long, Long> lastReportedSessionIds = new ConcurrentHashMap<>();
    /** H-1 候选回礼节流状态：peerId -> 上次回发时间 */
    private final Map<Long, Long> candidateReciprocateMillis = new ConcurrentHashMap<>();
    /** H-2 密集重试状态：sessionId -> 已调度的打洞重试轮次，避免同一 session 重复排程 */
    private final Map<Long, Boolean> holePunchRetryScheduled = new ConcurrentHashMap<>();
    private final Map<String, PendingStunBinding> pendingStunBindings = new ConcurrentHashMap<>();
    private final Map<String, PendingTurnRequest> pendingTurnRequests = new ConcurrentHashMap<>();
    private final Map<String, Long> turnPermissions = new ConcurrentHashMap<>();
    private final Map<String, TurnChannelBinding> turnChannelsByPeer = new ConcurrentHashMap<>();
    private final Map<Integer, TurnChannelBinding> turnChannelsByNumber = new ConcurrentHashMap<>();
    private final Map<String, SrflxObservation> srflxObservations = new ConcurrentHashMap<>();
    private final Map<String, CachedPathMtu> pathMtuCache = new ConcurrentHashMap<>();
    private final AtomicBoolean directSuppressedLogged = new AtomicBoolean(false);
    private final SecureRandom secureRandom = new SecureRandom();
    private final TurnLongTermAuthenticator turnAuthenticator = new TurnLongTermAuthenticator();
    private final NatBehaviorDiscovery natBehaviorDiscovery = new NatBehaviorDiscovery();
    private final PeerUdpProbeRateLimiter udpProbeRateLimiter = new PeerUdpProbeRateLimiter();
    private final AtomicLong invalidUdpPackets = new AtomicLong();
    private final AtomicLong udpProbeRateLimited = new AtomicLong();
    private final AtomicLong dataWorkerRejected = new AtomicLong();
    private final AtomicLong dataDecryptRejected = new AtomicLong();
    private final AtomicLong tunWriteCount = new AtomicLong();
    private final AtomicLong tunWriteNanos = new AtomicLong();
    private final AtomicLong dataWorkerQueueHighWater = new AtomicLong();
    private final Object tunWriteLock = new Object();
    private final ControlSender controlSender;
    private final PeerKeyStore.KeyMaterial keyMaterial;
    /**
     * 本次运行实例的 SPM2 key epoch。进程内固定、重启后必然变化，是 AES-GCM nonce 唯一性的锚点：
     * sessionId/token 会在服务端 TTL 内被复用，X25519 私钥又持久化在磁盘，只有 epoch 能保证
     * 重启后 sequence 从 1 重新开始时不会落回同一段 nonce 空间。
     */
    private final String localKeyEpoch = newKeyEpoch();
    private final PeerVirtualDeviceOptions virtualDeviceOptions;
    private volatile ClientAuthLoginResponse.PeerMeshConfig config;
    private volatile boolean running;
    private volatile DatagramSocket udpSocket;
    private volatile Thread receiverThread;
    private volatile DataPlaneWorker[] dataPlaneWorkers = new DataPlaneWorker[0];
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
    private static final int MAX_LOG_RATE_KEYS = 4_096;
    private static final long LOG_RATE_KEY_TTL_MILLIS = 60_000;
    private static final int DATA_WORKER_QUEUE_CAPACITY = 2_048;
    private static final int DATA_FRAME_VERSION = 2;
    private static final long ON_DEMAND_PREPARE_INTERVAL_MILLIS = 2_000;
    /** H-1 候选回礼节流，防止两端互相触发形成信令循环 */
    private static final long CANDIDATE_RECIPROCATE_INTERVAL_MILLIS = 2_000;
    /**
     * H-2 打洞收敛：session 建立后前若干秒做密集重试，而不是等 30s maintenance tick。
     * 退避序列覆盖约 15 秒，之后交给 30s 周期兜底。
     */
    private static final long[] HOLE_PUNCH_RETRY_DELAYS_MILLIS = {1_000, 2_000, 4_000, 8_000};
    private static final long NAT_PROBE_STALE_MILLIS = 120_000;
    private static final long SRFLX_OBSERVATION_TTL_MILLIS = 180_000;
    private static final long ALTERNATE_NAT_PROBE_MIN_INTERVAL_MILLIS = 15_000;
    private static final long STUN_CANDIDATE_REQUEST_INTERVAL_MILLIS = 60_000;
    private static final long BEHAVIOR_DISCOVERY_MIN_INTERVAL_MILLIS = 60_000;
    private static final long BEHAVIOR_PROBE_TIMEOUT_MILLIS = 1_600;
    private static final long[] BEHAVIOR_PROBE_RETRY_DELAYS_MILLIS = {250, 750};
    private static final long TURN_PERMISSION_TTL_MILLIS = 240_000;
    private static final long TURN_CHANNEL_TTL_MILLIS = 540_000;
    private static final long TURN_CHANNEL_PENDING_MILLIS = 10_000;
    private static final String PUBLIC_STUN_ROLE_PREFIX = "public-stun:";
    private static final String SUPPLEMENTAL_STUN_ROLE_PREFIX = "family-stun:";
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
                "noop", "specus0", PeerVirtualDeviceOptions.DEFAULT_MTU));
    }

    public PeerMeshClient(ClientAuthLoginResponse.PeerMeshConfig config,
                          ControlSender controlSender,
                          PeerVirtualDeviceOptions virtualDeviceOptions) {
        this.controlSender = controlSender;
        this.keyMaterial = PeerKeyStore.keyMaterial();
        this.virtualDeviceOptions = virtualDeviceOptions == null
                ? new PeerVirtualDeviceOptions("noop", "specus0", PeerVirtualDeviceOptions.DEFAULT_MTU)
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
            peerIndex = PeerIndex.empty();
            sessions.clear();
            sessionsById.clear();
            pendingProbes.clear();
            natProbeObservations.clear();
            payloadDropLogMillis.clear();
            packetTraceLogMillis.clear();
            pendingVirtualPackets.clear();
            pathPrepareMillis.clear();
            candidateReciprocateMillis.clear();
            holePunchRetryScheduled.clear();
            lastReportedSessionIds.clear();
            pendingStunBindings.clear();
            pendingTurnRequests.clear();
            turnPermissions.clear();
            turnChannelsByPeer.clear();
            turnChannelsByNumber.clear();
            srflxObservations.clear();
            pathMtuCache.clear();
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
        Map<Long, PeerInfo> previous = peerIndex.byId();
        Map<Long, PeerInfo> nextPeers = new HashMap<>();
        if (peerNodes != null && peerNodes.isArray()) {
            for (JsonNode node : peerNodes) {
                long clientId = node.path("clientId").asLong(0);
                if (clientId <= 0) {
                    continue;
                }
                PeerInfo existing = previous.get(clientId);
                nextPeers.put(clientId, new PeerInfo(
                        clientId,
                        node.path("clientName").asText(""),
                        node.path("virtualIp").asText(""),
                        node.path("publicKey").asText(""),
                        // roster 不携带 key epoch，只能由对端 candidates 信令学习；保留已学到的值
                        existing == null ? "" : existing.keyEpoch(),
                        node.path("online").asBoolean(false),
                        existing == null ? List.of() : existing.candidates()
                ));
            }
        }
        peerIndex = PeerIndex.of(nextPeers);
        log.info("Peer mesh 可互联客户端刷新: {} 个", nextPeers.size());
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
        List<String> routeIps = peerIndex.byId().values().stream()
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
        peerIndex = PeerIndex.empty();
        sessions.clear();
        sessionsById.clear();
        pendingProbes.clear();
        natProbeObservations.clear();
        payloadDropLogMillis.clear();
        packetTraceLogMillis.clear();
        pendingVirtualPackets.clear();
        pathPrepareMillis.clear();
        candidateReciprocateMillis.clear();
        holePunchRetryScheduled.clear();
        lastReportedSessionIds.clear();
        pendingStunBindings.clear();
        pendingTurnRequests.clear();
        turnPermissions.clear();
        turnChannelsByPeer.clear();
        turnChannelsByNumber.clear();
        srflxObservations.clear();
        pathMtuCache.clear();
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
                    "specus peer mesh");
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
        candidate.setAddressFamily(addressFamily(mapping.externalAddress()));
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
                "specus peer mesh");
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

        // H-6 Hairpin：双方 STUN 公网地址相同时优先 LAN host，但只降权不剪除。
        // 同 NAT 下 host 未必可达（AP 隔离、同 NAT 不同子网），而支持 hairpin 的 NAT 上
        // srflx 反而能通；直接剪掉会把这条可用路径永久丢弃。
        if (hasSameNatAddress(control.getCandidates()) && hasUsableHostCandidate(control.getCandidates())) {
            control.setCandidates(demoteSameNatReflexiveCandidates(control.getCandidates()));
        }

        sendConnectivityChecks(control);
        // H-1 候选回礼：port-restricted 组合下打洞要求双方几乎同时互射。对端已经在向我们打洞，
        // 若此时本端还没有健康 direct 路径，立刻回发一份自身候选，让对端马上开始反向探测，
        // 把两端 burst 窗口从"最坏等一个 30s maintenance tick"压到一个信令 RTT 内对齐。
        reciprocateCandidates(peer);
    }

    /**
     * H-1：向刚发来候选的对端回发本端候选。带节流，避免两端互相触发形成信令循环。
     */
    private void reciprocateCandidates(PeerInfo peer) {
        if (peer == null || config == null || !peer.online()) {
            return;
        }
        PeerSession session = sessions.get(peer.clientId());
        long now = System.currentTimeMillis();
        if (session != null && session.hasHealthyDirect(now)) {
            return;
        }
        Long previous = candidateReciprocateMillis.get(peer.clientId());
        if (previous != null && now - previous < CANDIDATE_RECIPROCATE_INTERVAL_MILLIS) {
            return;
        }
        candidateReciprocateMillis.put(peer.clientId(), now);
        sendCandidatesToPeer(peer, session == null ? reusableSession(peer.clientId()) : session, null);
    }

    /** H-6：把同 NAT 的 reflexive 候选降到最低优先级，而不是从候选集中删除 */
    private List<PeerCandidate> demoteSameNatReflexiveCandidates(List<PeerCandidate> candidates) {
        List<PeerCandidate> adjusted = new ArrayList<>(candidates.size());
        for (PeerCandidate candidate : candidates) {
            if (candidate != null && isSameNatReflexiveCandidate(candidate)) {
                PeerCandidate demoted = new PeerCandidate();
                demoted.setType(candidate.getType());
                demoted.setTransport(candidate.getTransport());
                demoted.setAddress(candidate.getAddress());
                demoted.setPort(candidate.getPort());
                demoted.setFoundation(candidate.getFoundation());
                demoted.setRelayId(candidate.getRelayId());
                demoted.setAddressFamily(candidate.getAddressFamily());
                demoted.setPriority(1);
                adjusted.add(demoted);
                continue;
            }
            adjusted.add(candidate);
        }
        return sortedCandidates(adjusted);
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
        if (control.getDataFrameVersion() != DATA_FRAME_VERSION) {
            log.warn("Peer mesh session rejected: required dataFrameVersion={}, received={}",
                    DATA_FRAME_VERSION, control.getDataFrameVersion());
            return;
        }
        long peerId = peerId(control);
        if (peerId <= 0) {
            return;
        }
        PeerInfo peer = peerIndex.byId().get(peerId);
        String peerPublicKey = peer == null ? "" : peer.publicKey();
        PeerSession next = new PeerSession(
                control.getSessionId(),
                peerId,
                control.getToken(),
                control.getExpiresAt(),
                deriveSessionKey(control, peerId, peerPublicKey)
        );
        next.setLocalKeyEpoch(localKeyEpoch);
        // 对端 epoch 优先取本条信令携带的值，否则回退到 roster/candidates 已学到的值
        String signalEpoch = control.getSourceKeyEpoch();
        next.applyRemoteKeyEpoch(StringUtils.hasText(signalEpoch) && !isLocalClient(control.getSourceClientId())
                ? signalEpoch
                : (peer == null ? "" : peer.keyEpoch()));
        PeerSession previous = sessions.put(peerId, next);
        if (previous != null) {
            sessionsById.remove(previous.sessionId(), previous);
        }
        sessionsById.put(next.sessionId(), next);
        if (previous != null) {
            boolean sameSession = previous.sessionId().equals(next.sessionId());
            if (sameSession) {
                next.outboundSequence.set(previous.outboundSequence.get());
                previous.copyInboundStateTo(next);
                // 本条信令没带 epoch 时，继承上一份 session 已学到的值；
                // 带了新 epoch（对端重启）时必须保留新值，不能被旧值覆盖
                if (!StringUtils.hasText(next.remoteKeyEpoch())) {
                    next.applyRemoteKeyEpoch(previous.remoteKeyEpoch());
                }
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
            PeerInfo peer = peerIndex.byId().get(entry.getKey());
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
                next.setLocalKeyEpoch(localKeyEpoch);
                next.applyRemoteKeyEpoch(peer.keyEpoch());
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
            PeerInfo peer = peerIndex.byId().get(peerId);
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
        for (PeerInfo peer : peerIndex.byId().values()) {
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
        // candidates 是唯一的 peer->peer 信令通道，SPM2 key epoch 随它传播
        message.setSourceKeyEpoch(localKeyEpoch);
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
        message.setDataFrameVersion(DATA_FRAME_VERSION);
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
        List<InetSocketAddress> stunEndpoints = stunEndpoints();
        InetSocketAddress relayEndpoint = relayEndpoint();
        boolean hasPublicStun = config.getPublicStunServers() != null
                && !config.getPublicStunServers().isEmpty();
        if (stunEndpoints.isEmpty() && relayEndpoint == null && !hasPublicStun) {
            return;
        }
        long now = System.currentTimeMillis();
        if (now - lastStunCandidateRequestMillis >= STUN_CANDIDATE_REQUEST_INTERVAL_MILLIS) {
            lastStunCandidateRequestMillis = now;
            for (int index = 0; index < stunEndpoints.size(); index++) {
                InetSocketAddress endpoint = stunEndpoints.get(index);
                String role = index == 0
                        ? PeerRelayMessage.PROBE_PRIMARY
                        : SUPPLEMENTAL_STUN_ROLE_PREFIX + endpointKey(endpoint);
                sendStunBinding(endpoint, role);
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
                StunMessage.software("specus-peer-client"));
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
                        StunMessage.software("specus-peer-client"),
                        StunMessage.changeRequest(probeRequest.changeIp(), probeRequest.changePort()))
                : StunMessage.of(
                        StunMessage.BINDING_REQUEST,
                        transactionId,
                        StunMessage.software("specus-peer-client"));
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
            for (InetSocketAddress endpoint : parseStunServers(item)) {
                String key = endpointKey(endpoint);
                if (sent.contains(key)) {
                    continue;
                }
                sent.add(key);
                sendStunBinding(endpoint, PUBLIC_STUN_ROLE_PREFIX + key);
            }
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
                    message.transactionId(),
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
                        candidate.setPriority(address instanceof Inet6Address ? 1_200 : 1_000);
                        candidate.setFoundation(networkInterface.getName());
                        candidate.setAddressFamily(address instanceof Inet6Address ? "IPv6" : "IPv4");
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
        for (PeerCandidate candidate : sortedCandidates(control.getCandidates())) {
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
                predicted.setAddressFamily(candidate.getAddressFamily());
                sendUdpProbePaced(session, predicted, delayMillis);
                delayMillis += CONNECTIVITY_CHECK_PACING_MILLIS;
            }
        }
        scheduleHolePunchRetries(session);
    }

    /**
     * H-2：session 首次发起连通性检查后，在前约 15 秒内按 1s/2s/4s/8s 退避重试，
     * 而不是等 30s maintenance tick。已建立健康 direct 路径时自动停止。
     *
     * <p>这不改变最终成功率，但把"打洞成功前的丢包窗口"从最坏 30-60s 压缩到数秒，
     * 也让 {@code pendingVirtualPackets} 的 30s TTL 有机会在路径就绪前不被耗尽。
     */
    private void scheduleHolePunchRetries(PeerSession session) {
        Long sessionId = session.sessionId();
        if (sessionId == null || holePunchRetryScheduled.putIfAbsent(sessionId, Boolean.TRUE) != null) {
            return;
        }
        ScheduledExecutorService executor = maintenanceExecutor;
        if (executor == null || executor.isShutdown()) {
            holePunchRetryScheduled.remove(sessionId);
            return;
        }
        try {
            for (long delay : HOLE_PUNCH_RETRY_DELAYS_MILLIS) {
                executor.schedule(() -> retryHolePunch(sessionId), delay, TimeUnit.MILLISECONDS);
            }
            // 本轮结束后释放标记，路径后续失效时可以重新进入密集重试
            long lastDelay = HOLE_PUNCH_RETRY_DELAYS_MILLIS[HOLE_PUNCH_RETRY_DELAYS_MILLIS.length - 1];
            executor.schedule(() -> holePunchRetryScheduled.remove(sessionId),
                    lastDelay + 1_000, TimeUnit.MILLISECONDS);
        } catch (RuntimeException e) {
            holePunchRetryScheduled.remove(sessionId);
            log.debug("Peer mesh 打洞重试排程失败: session={}, reason={}", sessionId, e.getMessage());
        }
    }

    private void retryHolePunch(long sessionId) {
        if (!running) {
            return;
        }
        PeerSession session = sessionsById.get(sessionId);
        long now = System.currentTimeMillis();
        if (session == null || session.isExpired(now)) {
            holePunchRetryScheduled.remove(sessionId);
            return;
        }
        if (session.hasHealthyDirect(now)) {
            // 已经打通，剩余轮次不必再发
            holePunchRetryScheduled.remove(sessionId);
            return;
        }
        PeerInfo peer = peerIndex.byId().get(session.peerId());
        if (peer == null || !peer.online() || peer.candidates().isEmpty()) {
            return;
        }
        PeerControlMessage control = new PeerControlMessage();
        control.setSourceClientId(config == null ? null : config.getClientId());
        control.setTargetClientId(peer.clientId());
        control.setSessionId(session.sessionId());
        control.setToken(session.token());
        control.setCandidates(peer.candidates());
        sendConnectivityChecks(control);
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
        for (PeerInfo peer : peerIndex.byId().values()) {
            PeerSession session = sessions.get(peer.clientId());
            if (session == null
                    || session.isExpired(now)
                    || !"DIRECT".equals(session.currentPathType)
                    || session.hasHealthyDirect(now)) {
                continue;
            }
            session.remoteEndpoint = null;
            PeerInfo currentPeer = peerIndex.byId().get(session.peerId());
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
            configureUdpSocket(next);
            startDataPlaneWorkers();
            udpSocket = next;
            Thread thread = new Thread(this::receiveLoop, "peer-mesh-udp");
            thread.setDaemon(true);
            receiverThread = thread;
            thread.start();
        } catch (Exception e) {
            stopDataPlaneWorkers();
            log.warn("Peer mesh UDP socket 启动失败: {}", e.getMessage());
        }
    }

    private void configureUdpSocket(DatagramSocket socket) {
        try {
            socket.setReceiveBufferSize(4 * 1024 * 1024);
        } catch (Exception e) {
            log.debug("Peer mesh UDP receive buffer 配置失败: {}", e.getMessage());
        }
        try {
            socket.setSendBufferSize(4 * 1024 * 1024);
        } catch (Exception e) {
            log.debug("Peer mesh UDP send buffer 配置失败: {}", e.getMessage());
        }
        try {
            socket.setTrafficClass(0x10);
        } catch (Exception e) {
            log.debug("Peer mesh UDP traffic class 不受当前平台支持: {}", e.getMessage());
        }
    }

    private synchronized void startDataPlaneWorkers() {
        if (dataPlaneWorkers.length > 0) {
            return;
        }
        int workerCount = Math.max(2, Math.min(8, Runtime.getRuntime().availableProcessors()));
        DataPlaneWorker[] workers = new DataPlaneWorker[workerCount];
        for (int index = 0; index < workerCount; index++) {
            workers[index] = new DataPlaneWorker(index, DATA_WORKER_QUEUE_CAPACITY);
        }
        dataPlaneWorkers = workers;
    }

    private synchronized void stopDataPlaneWorkers() {
        DataPlaneWorker[] workers = dataPlaneWorkers;
        dataPlaneWorkers = new DataPlaneWorker[0];
        for (DataPlaneWorker worker : workers) {
            worker.close();
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
        stopDataPlaneWorkers();
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
                    cleanupRateLimitState();
                    reportDataPlaneMetrics();
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

    public DataPlaneStats dataPlaneStats() {
        DataPlaneWorker[] workers = dataPlaneWorkers;
        int queueDepth = 0;
        for (DataPlaneWorker worker : workers) {
            queueDepth += worker.queueSize();
        }
        long writes = tunWriteCount.get();
        long writeNanos = tunWriteNanos.get();
        return new DataPlaneStats(
                invalidUdpPackets.get(),
                udpProbeRateLimited.get(),
                dataWorkerRejected.get(),
                dataDecryptRejected.get(),
                queueDepth,
                dataWorkerQueueHighWater.get(),
                writes,
                writes == 0 ? 0 : writeNanos / writes);
    }

    private void reportDataPlaneMetrics() {
        DataPlaneStats stats = dataPlaneStats();
        if (stats.invalidUdpPackets() == 0
                && stats.udpProbeRateLimited() == 0
                && stats.workerRejected() == 0
                && stats.decryptRejected() == 0
                && stats.tunWrites() == 0) {
            return;
        }
        log.info("Peer mesh data-plane stats: invalidUdp={}, probeRateLimited={}, workerRejected={}, "
                        + "decryptRejected={}, queueDepth={}, queueHighWater={}, tunWrites={}, avgTunWriteNanos={}",
                stats.invalidUdpPackets(),
                stats.udpProbeRateLimited(),
                stats.workerRejected(),
                stats.decryptRejected(),
                stats.queueDepth(),
                stats.queueHighWater(),
                stats.tunWrites(),
                stats.averageTunWriteNanos());
    }

    private void cleanupRateLimitState() {
        long now = System.currentTimeMillis();
        udpProbeRateLimiter.cleanup(now);
        packetTraceLogMillis.entrySet().removeIf(entry -> now - entry.getValue() > LOG_RATE_KEY_TTL_MILLIS);
        payloadDropLogMillis.entrySet().removeIf(entry -> now - entry.getValue() > LOG_RATE_KEY_TTL_MILLIS);
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
        return StringUtils.hasText(role)
                && (role.startsWith(PUBLIC_STUN_ROLE_PREFIX)
                || role.startsWith(SUPPLEMENTAL_STUN_ROLE_PREFIX));
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
        InetSocketAddress observedRemote = new InetSocketAddress(packet.getAddress(), packet.getPort());
        TurnChannelData.Frame channelData = TurnChannelData.parse(
                packet.getData(), packet.getOffset(), packet.getLength());
        if (channelData != null) {
            TurnChannelBinding binding = turnChannelsByNumber.get(channelData.channelNumber());
            if (binding != null && binding.activeAt(System.currentTimeMillis())) {
                byte[] inner = channelData.payload();
                handleUdpPayload(
                        inner,
                        0,
                        inner.length,
                        observedRemote,
                        endpointKey(binding.peer),
                        binding.peer.getAddress(),
                        true);
            }
            return;
        }
        StunMessage stun = StunMessage.parse(packet.getData(), packet.getOffset(), packet.getLength());
        if (stun != null) {
            handleStunTurnMessage(stun, observedRemote);
            return;
        }
        handleUdpPayload(
                packet.getData(),
                packet.getOffset(),
                packet.getLength(),
                observedRemote,
                null,
                packet.getAddress(),
                false);
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
            case StunMessage.CHANNEL_BIND_SUCCESS -> activateTurnChannel(
                    completeTurnRequest(message, observedRemote), message);
            case StunMessage.ALLOCATE_ERROR,
                 StunMessage.REFRESH_ERROR,
                 StunMessage.CREATE_PERMISSION_ERROR,
                 StunMessage.CHANNEL_BIND_ERROR -> handleTurnError(message, observedRemote);
            case StunMessage.DATA_INDICATION -> {
                InetSocketAddress peer = message.xorPeerAddress().orElse(null);
                byte[] inner = message.data().orElse(null);
                if (peer != null && inner != null) {
                    handleUdpPayload(inner, 0, inner.length, observedRemote, endpointKey(peer), peer.getAddress(), true);
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
        candidate.setPriority(mapped.getAddress() instanceof Inet6Address ? 900 : 800);
        candidate.setFoundation(publicStun ? "public-stun" : "standard-stun");
        candidate.setAddressFamily(mapped.getAddress() instanceof Inet6Address ? "IPv6" : "IPv4");
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
        candidate.setAddressFamily(turnServer.getAddress() instanceof Inet6Address ? "IPv6" : "IPv4");
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

    private void handleUdpPayload(byte[] payload,
                                  int offset,
                                  int length,
                                  InetSocketAddress observedRemote,
                                  String relayFromAllocationId,
                                  InetAddress sourceAddress,
                                  boolean ownedBuffer) {
        if (PeerDataFrameCodec.looksLikeDataFrame(payload, offset, length)) {
            dispatchDataFrame(payload, offset, length, observedRemote, relayFromAllocationId, ownedBuffer);
            return;
        }
        long now = System.currentTimeMillis();
        if (!udpProbeRateLimiter.tryAcquire(sourceAddress, now)) {
            udpProbeRateLimited.incrementAndGet();
            return;
        }
        PeerUdpProbe probe = PeerUdpProbeCodec.decode(payload, offset, length);
        if (probe == null
                || config == null
                || probe.getToClientId() == null
                || !probe.getToClientId().equals(config.getClientId())) {
            invalidUdpPackets.incrementAndGet();
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
            dataDecryptRejected.incrementAndGet();
            return;
        }
        Long frameSessionId = PeerDataFrameCodec.sessionId(raw);
        if (frameSessionId == null) {
            dataDecryptRejected.incrementAndGet();
            return;
        }
        PeerSession session = sessionsById.get(frameSessionId);
        if (session == null) {
            dataDecryptRejected.incrementAndGet();
            return;
        }
        if (session.aesKeySpec() == null) {
            dataDecryptRejected.incrementAndGet();
            return;
        }
        if (session.isExpired(System.currentTimeMillis())) {
            removeSession(session.peerId(), session);
            return;
        }
        PeerDataFrame frame = PeerDataFrameCodec.decode(
                session.inboundTrafficKey(currentConfig.getClientId()),
                raw,
                session.sessionId());
        if (frame == null) {
            dataDecryptRejected.incrementAndGet();
            return;
        }
        if (!session.acceptInboundSequence(frame.sequence())) {
            dataDecryptRejected.incrementAndGet();
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
        log.trace("Peer mesh encrypted frame 收到: session={}, from={}, bytes={}",
                frame.sessionId(), session.peerId(), frame.plaintext().length);
        handlePlainPacket(frame, session);
    }

    private void handlePlainPacket(PeerDataFrame frame, PeerSession session) {
        if (PeerPathMtu.looksLike(frame.plaintext())) {
            handlePathMtuMessage(frame.plaintext(), session);
            return;
        }
        if (PeerAppMessageCodec.looksLike(frame.plaintext())) {
            handlePeerAppMessage(frame, session);
            return;
        }

        PeerVirtualDevice device = virtualDevice;
        if (device != null && !(device instanceof NoopPeerVirtualDevice)) {
            long writeStartedNanos = System.nanoTime();
            try {
                tracePacket("inbound-to-tun", frame.plaintext());
                synchronized (tunWriteLock) {
                    device.writePacket(frame.plaintext());
                }
            } catch (Exception e) {
                log.warn("Peer mesh 写入虚拟网卡失败: session={}, packet={}, reason={}",
                        frame.sessionId(), PeerIpPacket.describe(frame.plaintext()), e.getMessage());
            } finally {
                tunWriteNanos.addAndGet(System.nanoTime() - writeStartedNanos);
                tunWriteCount.incrementAndGet();
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

    private void dispatchDataFrame(byte[] payload,
                                   int offset,
                                   int length,
                                   InetSocketAddress observedRemote,
                                   String relayFromAllocationId,
                                   boolean ownedBuffer) {
        Long frameSessionId = PeerDataFrameCodec.sessionId(payload, offset, length);
        PeerSession session = frameSessionId == null ? null : sessionsById.get(frameSessionId);
        if (session == null || session.aesKeySpec() == null || session.isExpired(System.currentTimeMillis())) {
            dataDecryptRejected.incrementAndGet();
            return;
        }
        byte[] frame = ownedBuffer && offset == 0 && length == payload.length
                ? payload
                : Arrays.copyOfRange(payload, offset, offset + length);
        DataPlaneWorker[] workers = dataPlaneWorkers;
        if (workers.length == 0) {
            handleDataFrame(frame, observedRemote, relayFromAllocationId);
            return;
        }
        DataPlaneWorker worker = workers[Math.floorMod(Long.hashCode(frameSessionId), workers.length)];
        if (!worker.submit(() -> handleDataFrame(frame, observedRemote, relayFromAllocationId))) {
            dataWorkerRejected.incrementAndGet();
            return;
        }
        dataWorkerQueueHighWater.accumulateAndGet(worker.queueSize(), Math::max);
    }

    private PendingTurnRequest completeTurnRequest(StunMessage response, InetSocketAddress observedRemote) {
        String transactionKey = response.transactionIdHex();
        PendingTurnRequest pending = pendingTurnRequests.get(transactionKey);
        if (pending != null && sameEndpoint(pending.endpoint(), observedRemote)) {
            pendingTurnRequests.remove(transactionKey, pending);
            return pending;
        }
        return null;
    }

    private void activateTurnChannel(PendingTurnRequest pending, StunMessage response) {
        if (pending == null || pending.requestType() != StunMessage.CHANNEL_BIND_REQUEST) {
            return;
        }
        StunMessage request = new StunMessage(
                pending.requestType(), pending.transactionId(), pending.attributes());
        int channelNumber = request.channelNumber().orElse(-1);
        InetSocketAddress peer = request.xorPeerAddress().orElse(null);
        TurnChannelBinding binding = peer == null ? null : turnChannelsByPeer.get(endpointKey(peer));
        if (binding == null || binding.channelNumber != channelNumber) {
            return;
        }
        binding.active = true;
        binding.expiresAtMillis = System.currentTimeMillis() + TURN_CHANNEL_TTL_MILLIS;
        log.trace("Peer mesh TURN channel bound: channel=0x{}, peer={}",
                Integer.toHexString(channelNumber), peer);
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
            if (pending.requestType() == StunMessage.CHANNEL_BIND_REQUEST) {
                removePendingTurnChannel(pending);
            }
            log.debug("Peer mesh TURN request failed: type=0x{}, code={}, authAttempt={}",
                    Integer.toHexString(pending.requestType()), errorCode, pending.authenticationAttempt());
            return;
        }

        byte[] retryTransactionId = StunMessage.newTransactionId();
        StunMessage retry = new StunMessage(
                pending.requestType(),
                retryTransactionId,
                retryAttributes(pending, retryTransactionId));
        log.debug("Peer mesh TURN auth challenge received, retrying once: type=0x{}, code={}",
                Integer.toHexString(pending.requestType()), errorCode);
        sendStunRequest(retry, pending.endpoint(), pending.authenticationAttempt() + 1);
    }

    private List<StunMessage.Attribute> retryAttributes(PendingTurnRequest pending, byte[] retryTransactionId) {
        List<StunMessage.Attribute> result = new ArrayList<>(pending.attributes().size());
        for (StunMessage.Attribute attribute : pending.attributes()) {
            if (attribute.type() != StunMessage.ATTR_XOR_PEER_ADDRESS) {
                result.add(attribute);
                continue;
            }
            StunMessage original = new StunMessage(
                    pending.requestType(), pending.transactionId(), List.of(attribute));
            original.xorPeerAddress()
                    .map(peer -> StunMessage.xorPeerAddress(peer, retryTransactionId))
                    .ifPresent(result::add);
        }
        return result;
    }

    private void removePendingTurnChannel(PendingTurnRequest pending) {
        StunMessage request = new StunMessage(
                pending.requestType(), pending.transactionId(), pending.attributes());
        int channelNumber = request.channelNumber().orElse(-1);
        InetSocketAddress peer = request.xorPeerAddress().orElse(null);
        if (peer == null) {
            return;
        }
        TurnChannelBinding binding = turnChannelsByPeer.get(endpointKey(peer));
        if (binding != null && binding.channelNumber == channelNumber && !binding.active) {
            turnChannelsByPeer.remove(endpointKey(peer), binding);
            turnChannelsByNumber.remove(channelNumber, binding);
        }
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

    private void handlePeerAppMessage(PeerDataFrame frame, PeerSession session) {
        PeerAppMessageCodec.PeerAppMessage message = PeerAppMessageCodec.decode(frame.plaintext());
        if (message == null) {
            log.debug("Peer mesh app message decode failed: session={}, from={}",
                    frame.sessionId(), session.peerId());
            return;
        }
        if (message.getFromClientId() != 0 && message.getFromClientId() != session.peerId()) {
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
                : String.valueOf(session.peerId());
        log.info("Peer message from {}: {}", fromName, message.getMessage());
        sendPeerAppMessageAck(session, message);
    }

    private void sendPeerAppMessageAck(PeerSession session, PeerAppMessageCodec.PeerAppMessage message) {
        ClientAuthLoginResponse.PeerMeshConfig currentConfig = config;
        if (currentConfig == null || !StringUtils.hasText(message.getId())) {
            return;
        }
        PeerInfo peer = peerIndex.byId().get(session.peerId());
        if (peer == null || !StringUtils.hasText(peer.virtualIp())) {
            return;
        }

        PeerAppMessageCodec.PeerAppMessage ack = new PeerAppMessageCodec.PeerAppMessage();
        ack.setType(PeerAppMessageCodec.TYPE_ACK);
        ack.setId(message.getId());
        ack.setFromClientId(currentConfig.getClientId());
        ack.setFromClientName(currentConfig.getClientName());
        ack.setToClientId(session.peerId());
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
            PeerInfo peerInfo = peerIndex.byId().get(session.peerId());
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
            // 只由入站探针建立路径的一方此前从不上报，session 会一直停在 NEGOTIATING；
            // relay 业务帧要求会话已激活，于是中继"看起来通了"但数据全被服务端丢弃。
            maybeReportPath(session, "RELAY", localEndpointText(), endpointText(session.remoteEndpoint), -1);
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
        maybeReportPath(session, "DIRECT", localEndpointText(), endpointText(session.remoteEndpoint), -1);
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
        for (Map.Entry<String, PendingTurnRequest> entry : pendingTurnRequests.entrySet()) {
            PendingTurnRequest pending = entry.getValue();
            if (now - pending.sentAtMillis() > PENDING_PROBE_TTL_MILLIS
                    && pendingTurnRequests.remove(entry.getKey(), pending)
                    && pending.requestType() == StunMessage.CHANNEL_BIND_REQUEST) {
                removePendingTurnChannel(pending);
            }
        }
        turnChannelsByNumber.entrySet().removeIf(entry -> entry.getValue().expiresAtMillis <= now);
        turnChannelsByPeer.entrySet().removeIf(entry -> entry.getValue().expiresAtMillis <= now);
    }

    private void probeKnownCandidates() {
        if (!running || config == null) {
            return;
        }
        long now = System.currentTimeMillis();
        for (PeerInfo peer : peerIndex.byId().values()) {
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
        // 先上报再 flush：待发数据一旦先于 path-report 到达服务端，relay 会因会话尚未激活
        // 而丢弃它们，而 peer 应用消息没有重传。
        maybeReportPath(session, pathType, local, remote, rttMillis);
        flushPendingPackets(session);
    }

    /**
     * 按需上报路径状态。除"路径变化"和"距上次上报满 60 秒"外，
     * <b>sessionId 变化时必须强制上报</b>：服务端每次签发新 grant 都是新 session + NEGOTIATING，
     * 而客户端重建 PeerSession 时会继承旧的 currentPathType / lastPathReportMillis，
     * 导致抑制条件同时不满足，新会话在服务端长期停在 NEGOTIATING、relay 业务帧被全部丢弃。
     */
    private void maybeReportPath(PeerSession session,
                                 String pathType,
                                 String local,
                                 String remote,
                                 long rttMillis) {
        if (session == null || session.sessionId() == null) {
            return;
        }
        long now = System.currentTimeMillis();
        boolean newSession = !session.sessionId().equals(lastReportedSessionIds.get(session.peerId()));
        boolean pathChanged = !pathType.equals(session.lastReportedPathType)
                || !remote.equals(session.lastReportedRemoteText);
        if (!newSession && !pathChanged && now - session.lastPathReportMillis < 60_000) {
            return;
        }
        reportPath(session, pathType, local, remote, rttMillis);
        session.lastPathReportMillis = now;
        session.lastReportedPathType = pathType;
        session.lastReportedRemoteText = remote;
        lastReportedSessionIds.put(session.peerId(), session.sessionId());
    }

    private String localEndpointText() {
        DatagramSocket socket = udpSocket;
        return socket == null || socket.isClosed() ? "" : "0.0.0.0:" + socket.getLocalPort();
    }

    private String endpointText(InetSocketAddress endpoint) {
        return endpoint == null ? "" : endpointKey(endpoint);
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
        PeerInfo peer = peerIndex.byId().get(session.peerId());
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
            PeerInfo peer = peerIndex.byId().get(session.peerId());
            report.setTargetClientName(peer == null ? "" : peer.clientName());
            report.setTargetVirtualIp(peer == null ? "" : peer.virtualIp());
            report.setTargetPublicKey(peer == null ? "" : peer.publicKey());
            report.setDirectBytes(directBytes);
            report.setCreatedAtMillis(System.currentTimeMillis());
            controlSender.send("", JsonUtil.objectToString(report));
        }
    }

    public boolean sendEncryptedPayload(String targetVirtualIp, byte[] payload) {
        Integer targetIp = PeerIpPacket.ipv4ToInt(targetVirtualIp);
        PeerInfo peer = targetIp == null ? null : peerIndex.byVirtualIpv4().get(targetIp);
        return sendEncryptedPayload(peer, targetVirtualIp, payload, 0, payload == null ? 0 : payload.length, true);
    }

    private boolean sendEncryptedPayload(String targetVirtualIp, byte[] payload, boolean allowPendingQueue) {
        if (!running || !StringUtils.hasText(targetVirtualIp) || payload == null) {
            return false;
        }
        Integer targetIp = PeerIpPacket.ipv4ToInt(targetVirtualIp);
        PeerInfo peer = targetIp == null ? null : peerIndex.byVirtualIpv4().get(targetIp);
        return sendEncryptedPayload(peer, targetVirtualIp, payload, 0, payload.length, allowPendingQueue);
    }

    private boolean sendEncryptedPayload(PeerInfo peer,
                                         String targetVirtualIp,
                                         byte[] payload,
                                         boolean allowPendingQueue) {
        return sendEncryptedPayload(
                peer, targetVirtualIp, payload, 0, payload == null ? 0 : payload.length, allowPendingQueue);
    }

    private boolean sendEncryptedPayload(PeerInfo peer,
                                         String targetVirtualIp,
                                         byte[] payload,
                                         int offset,
                                         int length,
                                         boolean allowPendingQueue) {
        if (!running
                || payload == null
                || offset < 0
                || length <= 0
                || offset > payload.length - length) {
            return false;
        }
        if (peer == null) {
            logPayloadDrop(targetVirtualIp, "peer-not-found");
            return false;
        }
        PeerSession session = sessions.get(peer.clientId());
        if (session == null || !session.canSend()) {
            if (allowPendingQueue) {
                queuePendingPacket(peer, payload, offset, length);
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
        boolean relay = StringUtils.hasText(session.relayTargetAllocationId);
        if (!relay) {
            long now = System.currentTimeMillis();
            if ("DIRECT".equals(session.currentPathType) && !session.hasHealthyDirect(now)) {
                session.remoteEndpoint = null;
                if (allowPendingQueue) {
                    queuePendingPacket(peer, payload, offset, length);
                    preparePathForPeer(peer, session);
                }
                logPayloadDrop(targetVirtualIp, "direct-stale-waiting-relay");
                return false;
            }
            if (shouldAvoidDirectPath()) {
                if (allowPendingQueue) {
                    queuePendingPacket(peer, payload, offset, length);
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
        }
        ClientAuthLoginResponse.PeerMeshConfig currentConfig = config;
        if (currentConfig == null) {
            return false;
        }
        ensurePathMtuDiscovery(session);
        if (PeerIpPacket.destinationIpv4Int(payload, offset, length) != null) {
            int pathMtu = session.pathMtu.effectiveMtu(virtualDeviceOptions.mtu());
            byte[] packet = offset == 0 && length == payload.length
                    ? payload
                    : Arrays.copyOfRange(payload, offset, offset + length);
            packet = PeerIpPacket.clampTcpMss(packet, pathMtu);
            if (packet.length > pathMtu) {
                injectPacketTooBig(packet, pathMtu);
                logPayloadDrop(targetVirtualIp, "path-mtu-" + pathMtu);
                return true;
            }
            payload = packet;
            offset = 0;
            length = packet.length;
        }
        try {
            long sequence = session.nextOutboundSequence();
            byte[] frame = PeerDataFrameCodec.encode(
                    session.outboundTrafficKey(currentConfig.getClientId()),
                    session.sessionId(),
                    sequence,
                    payload,
                    offset,
                    length);
            if (relay) {
                return sendRelayPayload(session.relayTargetAllocationId, frame);
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

    private void ensurePathMtuDiscovery(PeerSession session) {
        String pathKey = pathMtuPathKey(session);
        if (!StringUtils.hasText(pathKey)) {
            return;
        }
        long now = System.currentTimeMillis();
        CachedPathMtu cached = pathMtuCache.get(pathKey);
        if (cached != null && cached.validUntilMillis() <= now) {
            pathMtuCache.remove(pathKey, cached);
            cached = null;
        }
        PeerPathMtu.Transition transition = session.pathMtu.activate(
                pathKey,
                virtualDeviceOptions.mtu(),
                cached == null ? null : cached.innerMtu(),
                cached == null ? 0 : cached.validUntilMillis(),
                now,
                secureRandom::nextLong);
        applyPathMtuTransition(session, transition);
    }

    private void handlePathMtuMessage(byte[] payload, PeerSession session) {
        PeerPathMtu.Message message = PeerPathMtu.decode(payload);
        if (message == null) {
            return;
        }
        if (message.probe()) {
            sendRawEncryptedPayload(session, PeerPathMtu.ack(message.nonce(), message.innerMtu()));
            return;
        }
        PeerPathMtu.Transition transition = session.pathMtu.acknowledge(
                message.nonce(), message.innerMtu(), System.currentTimeMillis(), secureRandom::nextLong);
        applyPathMtuTransition(session, transition);
    }

    private void applyPathMtuTransition(PeerSession session, PeerPathMtu.Transition transition) {
        if (transition == null) {
            return;
        }
        if (transition.completedMtu() != null && StringUtils.hasText(session.pathMtu.pathKey())) {
            pathMtuCache.put(session.pathMtu.pathKey(), new CachedPathMtu(
                    transition.completedMtu(), System.currentTimeMillis() + PeerPathMtu.CACHE_TTL_MILLIS));
            log.debug("Peer mesh path MTU discovered: session={}, peer={}, path={}, mtu={}",
                    session.sessionId(), session.peerId(), session.pathMtu.pathKey(), transition.completedMtu());
        }
        if (transition.probe() != null) {
            sendPathMtuProbe(session, transition.probe());
        }
    }

    private void sendPathMtuProbe(PeerSession session, PeerPathMtu.Probe probe) {
        if (session == null || probe == null) {
            return;
        }
        sendRawEncryptedPayload(session, PeerPathMtu.probe(probe.nonce(), probe.innerMtu()));
        ScheduledExecutorService executor = maintenanceExecutor;
        if (executor == null || executor.isShutdown()) {
            return;
        }
        executor.schedule(
                () -> onPathMtuProbeTimeout(session.sessionId(), probe.nonce()),
                PeerPathMtu.PROBE_TIMEOUT_MILLIS,
                TimeUnit.MILLISECONDS);
    }

    private void onPathMtuProbeTimeout(Long sessionId, long nonce) {
        PeerSession session = sessionsById.get(sessionId);
        if (session == null || session.isExpired(System.currentTimeMillis())) {
            return;
        }
        applyPathMtuTransition(session, session.pathMtu.timeout(
                nonce, System.currentTimeMillis(), secureRandom::nextLong));
    }

    private boolean sendRawEncryptedPayload(PeerSession session, byte[] payload) {
        DatagramSocket socket = udpSocket;
        ClientAuthLoginResponse.PeerMeshConfig currentConfig = config;
        if (session == null || payload == null || socket == null || socket.isClosed()
                || currentConfig == null || sessions.get(session.peerId()) != session || !session.canSend()) {
            return false;
        }
        try {
            byte[] frame = PeerDataFrameCodec.encode(
                    session.outboundTrafficKey(currentConfig.getClientId()),
                    session.sessionId(),
                    session.nextOutboundSequence(),
                    payload);
            if (StringUtils.hasText(session.relayTargetAllocationId)) {
                return sendRelayPayload(session.relayTargetAllocationId, frame);
            }
            socket.send(new DatagramPacket(frame, frame.length, session.remoteEndpoint));
            session.addDirectBytes(frame.length);
            return true;
        } catch (Exception e) {
            log.trace("Peer mesh path MTU frame send failed: session={}, reason={}",
                    session.sessionId(), e.getMessage());
            return false;
        }
    }

    private String pathMtuPathKey(PeerSession session) {
        if (session == null) {
            return "";
        }
        if (StringUtils.hasText(session.relayTargetAllocationId)) {
            return "relay|" + session.relayTargetAllocationId;
        }
        return session.remoteEndpoint == null ? "" : "direct|" + endpointKey(session.remoteEndpoint);
    }

    private void injectPacketTooBig(byte[] packet, int pathMtu) {
        byte[] response = PeerIpPacket.icmpFragmentationNeededFor(packet, pathMtu);
        PeerVirtualDevice device = virtualDevice;
        if (response == null || device == null || device instanceof NoopPeerVirtualDevice) {
            return;
        }
        try {
            synchronized (tunWriteLock) {
                device.writePacket(response);
            }
        } catch (Exception e) {
            log.debug("Peer mesh ICMP fragmentation-needed injection failed: {}", e.getMessage());
        }
    }

    public boolean sendVirtualPacket(byte[] ipv4Packet) {
        return sendVirtualPacket(ipv4Packet, 0, ipv4Packet == null ? 0 : ipv4Packet.length);
    }

    private boolean sendVirtualPacket(byte[] ipv4Packet, int offset, int length) {
        Integer targetVirtualIpv4 = PeerIpPacket.destinationIpv4Int(ipv4Packet, offset, length);
        if (targetVirtualIpv4 == null) {
            log.trace("Peer mesh 忽略非 IPv4 或无效 IP 包");
            return false;
        }
        String targetVirtualIp = PeerIpPacket.ipv4ToString(targetVirtualIpv4);
        if (shouldIgnoreVirtualPacketTarget(targetVirtualIpv4)) {
            logIgnoredVirtualPacket(targetVirtualIp, "non-peer-unicast");
            return false;
        }
        PeerInfo peer = peerIndex.byVirtualIpv4().get(targetVirtualIpv4);
        if (peer == null || !peer.online()) {
            logIgnoredVirtualPacket(targetVirtualIp, "unknown-peer-route");
            return false;
        }
        tracePacket("outbound-from-tun", ipv4Packet, offset, length);
        return sendEncryptedPayload(peer, peer.virtualIp(), ipv4Packet, offset, length, true);
    }

    private boolean shouldIgnoreVirtualPacketTarget(int targetVirtualIp) {
        int firstOctet = (targetVirtualIp >>> 24) & 0xFF;
        if (firstOctet >= 224 || firstOctet == 0 || targetVirtualIp == -1) {
            return true;
        }
        ClientAuthLoginResponse.PeerMeshConfig current = config;
        Integer localVirtualIp = current == null ? null : PeerIpPacket.ipv4ToInt(current.getVirtualIp());
        if (localVirtualIp != null && targetVirtualIp == localVirtualIp) {
            return true;
        }
        return isMeshBoundaryAddress(targetVirtualIp);
    }

    private boolean isMeshBoundaryAddress(int targetVirtualIp) {
        ClientAuthLoginResponse.PeerMeshConfig current = config;
        if (current == null || !StringUtils.hasText(current.getCidr())) {
            return false;
        }
        String[] parts = current.getCidr().split("/", 2);
        if (parts.length != 2) {
            return false;
        }
        Integer baseValue = PeerIpPacket.ipv4ToInt(parts[0]);
        if (baseValue == null) {
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
        long ip = Integer.toUnsignedLong(targetVirtualIp);
        long base = Integer.toUnsignedLong(baseValue);
        long network = base & mask;
        long broadcast = network | (~mask & 0xFFFF_FFFFL);
        return ip == network || ip == broadcast;
    }

    private void queuePendingPacket(PeerInfo peer, byte[] payload, int offset, int length) {
        if (peer == null
                || payload == null
                || offset < 0
                || length <= 0
                || offset > payload.length - length) {
            return;
        }
        long now = System.currentTimeMillis();
        Deque<PendingVirtualPacket> queue = pendingVirtualPackets.computeIfAbsent(peer.clientId(), ignored -> new ArrayDeque<>());
        synchronized (queue) {
            queue.removeIf(item -> now - item.createdAtMillis() > PENDING_PACKET_TTL_MILLIS);
            while (queue.size() >= MAX_PENDING_PACKETS_PER_PEER) {
                queue.removeFirst();
            }
            queue.addLast(new PendingVirtualPacket(Arrays.copyOfRange(payload, offset, offset + length), now));
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
        Deque<PendingVirtualPacket> queue = pendingVirtualPackets.remove(session.peerId());
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
                PeerInfo peer = peerIndex.byId().get(session.peerId());
                if (peer != null && sendEncryptedPayload(peer, peer.virtualIp(), item.packet(), false)) {
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
            Deque<PendingVirtualPacket> queue = entry.getValue();
            synchronized (queue) {
                queue.removeIf(item -> now - item.createdAtMillis() > PENDING_PACKET_TTL_MILLIS);
                return queue.isEmpty();
            }
        });
    }

    private void tracePacket(String direction, byte[] packet) {
        tracePacket(direction, packet, 0, packet == null ? 0 : packet.length);
    }

    private void tracePacket(String direction, byte[] packet, int offset, int length) {
        if (!log.isDebugEnabled()) {
            return;
        }
        if (packet == null || offset < 0 || length <= 0 || offset > packet.length - length) {
            return;
        }
        byte[] inspected = offset == 0 && length == packet.length
                ? packet
                : Arrays.copyOfRange(packet, offset, offset + length);
        int protocol = PeerIpPacket.protocol(inspected);
        if (protocol != 6 && protocol != 17) {
            return;
        }
        long now = System.currentTimeMillis();
        String key = direction + "|" + PeerIpPacket.flowKey(inspected);
        if (!allowRateLimitedLog(packetTraceLogMillis, key, now, 10_000)) {
            return;
        }
        log.debug("Peer mesh packet {}: {} bytes={}",
                direction, PeerIpPacket.describe(inspected), length);
    }

    private void logPayloadDrop(String targetVirtualIp, String reason) {
        long now = System.currentTimeMillis();
        String key = targetVirtualIp + "|" + reason;
        if (!allowRateLimitedLog(payloadDropLogMillis, key, now, 10_000)) {
            return;
        }
        log.warn("Peer mesh 虚拟包未发送: target={}, reason={}, peers={}, sessions={}",
                targetVirtualIp, reason, peerIndex.byId().size(), sessions.size());
    }

    private void logIgnoredVirtualPacket(String targetVirtualIp, String reason) {
        long now = System.currentTimeMillis();
        String key = "ignored|" + targetVirtualIp + "|" + reason;
        if (!allowRateLimitedLog(payloadDropLogMillis, key, now, 30_000)) {
            return;
        }
        log.debug("Peer mesh 忽略非对端虚拟包: target={}, reason={}, peers={}, sessions={}",
                targetVirtualIp, reason, peerIndex.byId().size(), sessions.size());
    }

    private boolean allowRateLimitedLog(Map<String, Long> timestamps,
                                        String key,
                                        long nowMillis,
                                        long intervalMillis) {
        Long previous = timestamps.get(key);
        if (previous != null && nowMillis - previous < intervalMillis) {
            return false;
        }
        if (previous == null && timestamps.size() >= MAX_LOG_RATE_KEYS) {
            return false;
        }
        timestamps.put(key, nowMillis);
        return true;
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
            TurnChannelBinding binding = ensureTurnChannel(peer);
            if (binding != null && binding.activeAt(System.currentTimeMillis())) {
                byte[] bytes = TurnChannelData.encode(binding.channelNumber, payload);
                socket.send(new DatagramPacket(bytes, bytes.length, turnServer));
                return true;
            }
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

    private synchronized TurnChannelBinding ensureTurnChannel(InetSocketAddress peer) {
        InetSocketAddress turnServer = relayEndpoint();
        if (peer == null || turnServer == null) {
            return null;
        }
        long now = System.currentTimeMillis();
        String peerKey = endpointKey(peer);
        TurnChannelBinding existing = turnChannelsByPeer.get(peerKey);
        if (existing != null
                && ((existing.active && existing.expiresAtMillis - now > 60_000)
                || (!existing.active && existing.expiresAtMillis > now))) {
            return existing;
        }
        if (existing != null) {
            turnChannelsByPeer.remove(peerKey, existing);
            turnChannelsByNumber.remove(existing.channelNumber, existing);
        }
        int channelNumber = allocateTurnChannelNumber();
        if (channelNumber < 0) {
            return null;
        }
        TurnChannelBinding binding = new TurnChannelBinding(
                channelNumber,
                peer,
                now + TURN_CHANNEL_PENDING_MILLIS);
        turnChannelsByPeer.put(peerKey, binding);
        turnChannelsByNumber.put(channelNumber, binding);
        byte[] transactionId = StunMessage.newTransactionId();
        sendStunRequest(StunMessage.of(
                StunMessage.CHANNEL_BIND_REQUEST,
                transactionId,
                StunMessage.channelNumber(channelNumber),
                StunMessage.xorPeerAddress(peer, transactionId)), turnServer);
        return binding;
    }

    private int allocateTurnChannelNumber() {
        for (int channel = TurnChannelData.MIN_CHANNEL; channel <= TurnChannelData.MAX_CHANNEL; channel++) {
            TurnChannelBinding existing = turnChannelsByNumber.get(channel);
            if (existing == null || !existing.activeAt(System.currentTimeMillis())) {
                return channel;
            }
        }
        return -1;
    }

    private InetSocketAddress stunEndpoint() {
        List<InetSocketAddress> endpoints = stunEndpoints();
        return endpoints.isEmpty() ? null : endpoints.getFirst();
    }

    private List<InetSocketAddress> stunEndpoints() {
        if (config == null || !StringUtils.hasText(config.getStunHost()) || config.getStunPort() <= 0) {
            return List.of();
        }
        return resolveEndpoints(config.getStunHost(), config.getStunPort());
    }

    private String endpointKey(InetSocketAddress endpoint) {
        if (endpoint == null || endpoint.getAddress() == null) {
            return "";
        }
        String address = endpoint.getAddress().getHostAddress();
        return address.contains(":")
                ? "[" + address + "]:" + endpoint.getPort()
                : address + ":" + endpoint.getPort();
    }

    private InetSocketAddress parseEndpoint(String value) {
        if (!StringUtils.hasText(value)) {
            return null;
        }
        String normalized = value.trim();
        if (normalized.startsWith("turn:")) {
            normalized = normalized.substring("turn:".length());
        }
        HostPort hostPort = parseHostPort(normalized, -1);
        if (hostPort == null || hostPort.port() <= 0) {
            return null;
        }
        List<InetSocketAddress> endpoints = resolveEndpoints(hostPort.host(), hostPort.port());
        return endpoints.isEmpty() ? null : endpoints.getFirst();
    }

    private InetSocketAddress parseStunServer(String value) {
        List<InetSocketAddress> endpoints = parseStunServers(value);
        return endpoints.isEmpty() ? null : endpoints.getFirst();
    }

    private List<InetSocketAddress> parseStunServers(String value) {
        if (!StringUtils.hasText(value)) {
            return List.of();
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
            return List.of();
        }
        HostPort hostPort = parseHostPort(normalized, 3478);
        if (hostPort == null) {
            return List.of();
        }
        return resolveEndpoints(hostPort.host(), hostPort.port());
    }

    private HostPort parseHostPort(String value, int defaultPort) {
        if (!StringUtils.hasText(value)) {
            return null;
        }
        String host = value.trim();
        int port = defaultPort;
        if (host.startsWith("[")) {
            int close = host.indexOf(']');
            if (close <= 1) {
                return null;
            }
            String suffix = host.substring(close + 1);
            String address = host.substring(1, close);
            if (!suffix.isEmpty()) {
                if (!suffix.startsWith(":") || suffix.length() == 1) {
                    return null;
                }
                port = parsePort(suffix.substring(1), -1);
            }
            host = address;
        } else {
            int firstColon = host.indexOf(':');
            int lastColon = host.lastIndexOf(':');
            if (firstColon > 0 && firstColon == lastColon) {
                port = parsePort(host.substring(lastColon + 1), -1);
                host = host.substring(0, lastColon);
            } else if (firstColon < 0 && defaultPort < 0) {
                return null;
            }
        }
        if (!StringUtils.hasText(host) || port <= 0 || port > 65_535) {
            return null;
        }
        return new HostPort(host.trim(), port);
    }

    private List<InetSocketAddress> resolveEndpoints(String host, int port) {
        try {
            return Arrays.stream(InetAddress.getAllByName(host))
                    .filter(address -> address instanceof Inet4Address || address instanceof Inet6Address)
                    .sorted(Comparator.comparingInt((InetAddress address) -> address instanceof Inet4Address ? 0 : 1)
                            .thenComparing(InetAddress::getHostAddress))
                    .map(address -> new InetSocketAddress(address, port))
                    .distinct()
                    .toList();
        } catch (Exception e) {
            log.debug("Peer mesh endpoint 解析失败: host={}, reason={}", host, e.getMessage());
            return List.of();
        }
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

    private static String addressFamily(String address) {
        if (!StringUtils.hasText(address)) {
            return "";
        }
        try {
            return InetAddress.getByName(address) instanceof Inet6Address ? "IPv6" : "IPv4";
        } catch (Exception ignored) {
            return address.contains(":") ? "IPv6" : "IPv4";
        }
    }

    private void mergePeerFromSignal(PeerControlMessage control, List<PeerCandidate> candidates) {
        PeerInfo peer = peerFromSignal(control);
        if (peer != null) {
            mergePeer(peer, candidates);
        }
    }

    private synchronized void mergePeer(PeerInfo peer, List<PeerCandidate> candidates) {
        if (peer == null || peer.clientId() <= 0) {
            return;
        }
        Map<Long, PeerInfo> nextPeers = new HashMap<>(peerIndex.byId());
        PeerInfo current = nextPeers.get(peer.clientId());
        List<PeerCandidate> nextCandidates = candidates == null
                ? (current == null ? peer.candidates() : current.candidates())
                : sortedCandidates(candidates);
        // 对端上报的 epoch 非空时必须覆盖旧值：对端重启后 epoch 变化，继续用旧 epoch 派生的
        // inbound key 无法解密新帧。为空（roster 或本端发起的信令）时保留已学到的值。
        String nextKeyEpoch = firstText(peer.keyEpoch(), current == null ? "" : current.keyEpoch());
        nextPeers.put(peer.clientId(), new PeerInfo(
                peer.clientId(),
                firstText(peer.clientName(), current == null ? "" : current.clientName()),
                firstText(peer.virtualIp(), current == null ? "" : current.virtualIp()),
                firstText(peer.publicKey(), current == null ? "" : current.publicKey()),
                nextKeyEpoch,
                peer.online() || (current != null && current.online()),
                nextCandidates
        ));
        peerIndex = PeerIndex.of(nextPeers);
        applyRemoteKeyEpoch(peer.clientId(), nextKeyEpoch);
        syncVirtualDeviceRoutes();
    }

    /**
     * 把对端最新 epoch 应用到已建立的 session。epoch 变化意味着对端重启并从 sequence=1 重新发送，
     * 因此必须同时丢弃 inbound traffic key 缓存和 replay window，否则新帧会被旧窗口当作重放拒绝。
     */
    private void applyRemoteKeyEpoch(long peerId, String keyEpoch) {
        if (!StringUtils.hasText(keyEpoch)) {
            return;
        }
        PeerSession session = sessions.get(peerId);
        if (session != null && session.applyRemoteKeyEpoch(keyEpoch)) {
            log.info("Peer mesh 对端 key epoch 更新，已重置 inbound 解密状态: peer={}, epoch={}", peerId, keyEpoch);
        }
    }

    private List<PeerCandidate> sortedCandidates(List<PeerCandidate> candidates) {
        if (candidates == null || candidates.isEmpty()) {
            return List.of();
        }
        return candidates.stream()
                .filter(Objects::nonNull)
                .sorted(Comparator.comparingLong(PeerCandidate::getPriority).reversed()
                        .thenComparing(PeerCandidate::getType, Comparator.nullsLast(String::compareTo)))
                .toList();
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
            // source 是对端：sourceKeyEpoch 就是对端 epoch
            return new PeerInfo(
                    sourceId,
                    control.getSourceClientName(),
                    control.getSourceVirtualIp(),
                    control.getSourcePublicKey(),
                    control.getSourceKeyEpoch() == null ? "" : control.getSourceKeyEpoch(),
                    true,
                    List.of()
            );
        }
        if (targetId != null && !targetId.equals(config.getClientId())) {
            // target 是对端：此时 sourceKeyEpoch 是本端自己的 epoch，不能当作对端 epoch
            return new PeerInfo(
                    targetId,
                    control.getTargetClientName(),
                    control.getTargetVirtualIp(),
                    control.getTargetPublicKey(),
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

    private boolean isLocalClient(Long clientId) {
        ClientAuthLoginResponse.PeerMeshConfig current = config;
        return clientId != null && current != null && clientId.equals(current.getClientId());
    }

    /** 128 bit 随机 epoch，碰撞概率可忽略；用静态方法是因为它在字段初始化阶段就要就绪 */
    private static String newKeyEpoch() {
        byte[] bytes = new byte[16];
        new SecureRandom().nextBytes(bytes);
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

    public record DataPlaneStats(long invalidUdpPackets,
                                 long udpProbeRateLimited,
                                 long workerRejected,
                                 long decryptRejected,
                                 int queueDepth,
                                 long queueHighWater,
                                 long tunWrites,
                                 long averageTunWriteNanos) {
    }

    private static final class DataPlaneWorker implements AutoCloseable {
        private final ThreadPoolExecutor executor;

        private DataPlaneWorker(int index, int queueCapacity) {
            executor = new ThreadPoolExecutor(
                    1,
                    1,
                    0L,
                    TimeUnit.MILLISECONDS,
                    new ArrayBlockingQueue<>(queueCapacity),
                    runnable -> {
                        Thread thread = new Thread(runnable, "peer-mesh-data-" + index);
                        thread.setDaemon(true);
                        return thread;
                    },
                    new ThreadPoolExecutor.AbortPolicy());
        }

        private boolean submit(Runnable task) {
            try {
                executor.execute(task);
                return true;
            } catch (RuntimeException ignored) {
                return false;
            }
        }

        private int queueSize() {
            return executor.getQueue().size();
        }

        @Override
        public void close() {
            executor.shutdownNow();
        }
    }

    private record PeerInfo(long clientId,
                            String clientName,
                            String virtualIp,
                            String publicKey,
                            String keyEpoch,
                            boolean online,
                            List<PeerCandidate> candidates) {
    }

    private record PeerIndex(Map<Long, PeerInfo> byId, Map<Integer, PeerInfo> byVirtualIpv4) {
        private static PeerIndex empty() {
            return new PeerIndex(Map.of(), Map.of());
        }

        private static PeerIndex of(Map<Long, PeerInfo> source) {
            if (source == null || source.isEmpty()) {
                return empty();
            }
            Map<Long, PeerInfo> byId = Map.copyOf(source);
            Map<Integer, PeerInfo> byVirtualIpv4 = new HashMap<>();
            for (PeerInfo peer : byId.values()) {
                Integer address = PeerIpPacket.ipv4ToInt(peer.virtualIp());
                if (address != null) {
                    byVirtualIpv4.put(address, peer);
                }
            }
            return new PeerIndex(byId, Map.copyOf(byVirtualIpv4));
        }
    }

    static final class PeerSession {
        private final Long sessionId;
        private final long peerId;
        private final String token;
        private final String expiresAt;
        private final byte[] aesKey;
        private final SecretKeySpec aesKeySpec;
        private final long createdAtMillis;
        private final AtomicLong outboundSequence = new AtomicLong();
        private final AtomicLong directBytesSinceReport = new AtomicLong();
        private volatile PeerReplayWindow inboundReplayWindow = new PeerReplayWindow();
        private volatile PeerDataFrameCodec.TrafficKey outboundTrafficKey;
        private volatile PeerDataFrameCodec.TrafficKey inboundTrafficKey;
        /** 本端本次运行实例的 key epoch；出站 traffic key 绑定它 */
        private volatile String localKeyEpoch = "";
        /** 对端最近上报的 key epoch；入站 traffic key 绑定它，未知时无法解密 */
        private volatile String remoteKeyEpoch = "";
        private volatile long lastDirectSuccessMillis;
        private volatile long lastRelaySuccessMillis;
        private volatile long lastDirectKeepaliveMillis;
        private volatile long lastPathLogMillis;
        private volatile long lastPathReportMillis;
        /** 最近一次实际上报出去的路径与对端，独立于 lastPathRemoteText（后者还用于日志抑制） */
        private volatile String lastReportedPathType = "";
        private volatile String lastReportedRemoteText = "";
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
        private final PeerPathMtu.Discovery pathMtu = new PeerPathMtu.Discovery();

        PeerSession(Long sessionId, long peerId, String token, String expiresAt, byte[] aesKey) {
            this(sessionId, peerId, token, expiresAt, aesKey, System.currentTimeMillis());
        }

        private PeerSession(Long sessionId, long peerId, String token, String expiresAt, byte[] aesKey, long createdAtMillis) {
            this.sessionId = sessionId;
            this.peerId = peerId;
            this.token = token;
            this.expiresAt = expiresAt;
            this.aesKey = aesKey;
            this.aesKeySpec = aesKey == null ? null : new SecretKeySpec(aesKey.clone(), "AES");
            this.createdAtMillis = createdAtMillis;
        }

        PeerSession withAesKey(byte[] nextKey) {
            PeerSession next = new PeerSession(sessionId, peerId, token, expiresAt, nextKey, createdAtMillis);
            next.outboundSequence.set(outboundSequence.get());
            next.directBytesSinceReport.set(directBytesSinceReport.get());
            next.remoteEndpoint = remoteEndpoint;
            // epoch 必须随 session 迁移：同一 sessionId 下 outboundSequence 是延续的，
            // 换 epoch 会让 sequence 与 key 的对应关系错乱
            next.localKeyEpoch = localKeyEpoch;
            next.remoteKeyEpoch = remoteKeyEpoch;
            copyInboundStateTo(next);
            next.relayTargetAllocationId = relayTargetAllocationId;
            next.endpointSuccessMillis = endpointSuccessMillis;
            next.endpointRtt = endpointRtt;
            next.lastDirectSuccessMillis = lastDirectSuccessMillis;
            next.lastRelaySuccessMillis = lastRelaySuccessMillis;
            next.lastDirectKeepaliveMillis = lastDirectKeepaliveMillis;
            next.lastPathLogMillis = lastPathLogMillis;
            next.lastPathReportMillis = lastPathReportMillis;
            next.lastReportedPathType = lastReportedPathType;
            next.lastReportedRemoteText = lastReportedRemoteText;
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

        SecretKeySpec aesKeySpec() {
            return aesKeySpec;
        }

        synchronized PeerDataFrameCodec.TrafficKey outboundTrafficKey(long localClientId) {
            if (aesKeySpec == null || !StringUtils.hasText(localKeyEpoch)) {
                return null;
            }
            if (outboundTrafficKey == null) {
                outboundTrafficKey = PeerDataFrameCodec.trafficKey(
                        aesKeySpec, sessionId, localClientId, peerId, localKeyEpoch);
            }
            return outboundTrafficKey;
        }

        synchronized PeerDataFrameCodec.TrafficKey inboundTrafficKey(long localClientId) {
            if (aesKeySpec == null || !StringUtils.hasText(remoteKeyEpoch)) {
                return null;
            }
            if (inboundTrafficKey == null) {
                inboundTrafficKey = PeerDataFrameCodec.trafficKey(
                        aesKeySpec, sessionId, peerId, localClientId, remoteKeyEpoch);
            }
            return inboundTrafficKey;
        }

        synchronized void setLocalKeyEpoch(String epoch) {
            if (!StringUtils.hasText(epoch) || epoch.equals(localKeyEpoch)) {
                return;
            }
            localKeyEpoch = epoch;
            outboundTrafficKey = null;
        }

        /**
         * @return true 表示 epoch 确实发生了变化（对端重启），此时 inbound key 与 replay window 已重置
         */
        synchronized boolean applyRemoteKeyEpoch(String epoch) {
            if (!StringUtils.hasText(epoch) || epoch.equals(remoteKeyEpoch)) {
                return false;
            }
            boolean changed = StringUtils.hasText(remoteKeyEpoch);
            remoteKeyEpoch = epoch;
            inboundTrafficKey = null;
            // 对端从 sequence=1 重新开始，旧窗口会把新帧全部当作重放拒绝
            inboundReplayWindow = new PeerReplayWindow();
            return changed;
        }

        synchronized String remoteKeyEpoch() {
            return remoteKeyEpoch;
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

        synchronized boolean acceptInboundSequence(long sequence) {
            return inboundReplayWindow.accept(sequence);
        }

        synchronized void copyInboundStateTo(PeerSession target) {
            target.inboundReplayWindow = inboundReplayWindow.copy();
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

    private record CachedPathMtu(int innerMtu, long validUntilMillis) {
    }

    private record HostPort(String host, int port) {
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
                                      byte[] transactionId,
                                      List<StunMessage.Attribute> attributes,
                                      InetSocketAddress endpoint,
                                      int authenticationAttempt,
                                      long sentAtMillis) {
        private PendingTurnRequest {
            transactionId = transactionId == null ? new byte[0] : transactionId.clone();
            attributes = attributes == null ? List.of() : List.copyOf(attributes);
        }

        @Override
        public byte[] transactionId() {
            return transactionId.clone();
        }
    }

    private static final class TurnChannelBinding {
        private final int channelNumber;
        private final InetSocketAddress peer;
        private volatile long expiresAtMillis;
        private volatile boolean active;

        private TurnChannelBinding(int channelNumber, InetSocketAddress peer, long expiresAtMillis) {
            this.channelNumber = channelNumber;
            this.peer = peer;
            this.expiresAtMillis = expiresAtMillis;
        }

        private boolean activeAt(long nowMillis) {
            return active && expiresAtMillis > nowMillis;
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
