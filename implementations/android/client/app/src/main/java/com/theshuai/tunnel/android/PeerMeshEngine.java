package com.theshuai.tunnel.android;

import android.content.Context;
import android.content.SharedPreferences;

import org.json.JSONArray;
import org.json.JSONObject;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import java.io.Closeable;
import java.math.BigInteger;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetSocketAddress;
import java.net.NetworkInterface;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;

final class PeerMeshEngine implements Closeable {
    private static final String TYPE_CONFIG = "peer-config";
    private static final String TYPE_ROSTER = "roster";
    private static final String TYPE_SESSION_GRANT = "session-grant";
    private static final String TYPE_CANDIDATES = "candidates";
    private static final String TYPE_CLOSE = "close";
    private static final String PROBE_MAGIC = "shuai-peer-mesh";
    private static final int MAX_PENDING_PACKETS = 32;
    private static final long PENDING_PACKET_TTL_MS = 30_000L;
    private static final long RELAY_REQUEST_MIN_INTERVAL_MS = 15_000L;
    private static final long RELAY_REFRESH_WINDOW_MS = 60_000L;
    private static final long STUN_REQUEST_INTERVAL_MS = 60_000L;
    private static final long BEHAVIOR_DISCOVERY_MIN_INTERVAL_MS = 60_000L;
    private static final long BEHAVIOR_PROBE_TIMEOUT_MS = 1_600L;
    private static final long TURN_PERMISSION_TTL_MS = 240_000L;
    private static final long TURN_REQUEST_TTL_MS = 15_000L;
	private static final long TURN_CHANNEL_ACTIVE_TTL_MS = 540_000L;
    private static final long SESSION_REFRESH_MIN_WINDOW_MS = 60_000L;
    private static final long SESSION_REFRESH_MAX_WINDOW_MS = 300_000L;
    private static final long REPORT_INTERVAL_MS = 60_000L;
    private static final long MAINTENANCE_INTERVAL_MS = 30_000L;
    private static final long DIRECT_STALE_MS = 45_000L;
    // H-2：session 首次发起连通性检查后的密集退避重试节奏，对齐 Java
    // HOLE_PUNCH_RETRY_DELAYS_MILLIS={1k,2k,4k,8k}。把"打洞成功前的丢包窗口"从最坏 30s
    // maintenance tick 压缩到数秒，不改变最终成功率。打通或过期即停。
    private static final long[] HOLE_PUNCH_RETRY_DELAYS_MS = {1_000L, 2_000L, 4_000L, 8_000L};
    // H-1：候选回礼节流间隔，避免两端互相触发形成信令循环，对齐 Java
    // CANDIDATE_RECIPROCATE_INTERVAL_MILLIS=2000。
    private static final long CANDIDATE_RECIPROCATE_INTERVAL_MS = 2_000L;
    private static final long APP_MESSAGE_SESSION_WAIT_MS = 1_500L;
    private static final long APP_MESSAGE_ACK_WAIT_MS = 1_500L;

    interface AppMessageSink {
        void onAppMessage(String fromClientName, String body);
    }

    private final TunnelCore.TunnelSession tunnelSession;
    private final TunnelCore.VpnPlatform vpnPlatform;
    private final ExecutorService ioPool;
    private final ControlSender controlSender;
    private final StatusPublisher status;
    private final AppMessageSink appMessageSink;
    private final KeyStore.KeyMaterial keyMaterial;
    /**
     * 本次运行实例的 SPM2 key epoch。sessionId/token 会在服务端 TTL 内复用、X25519 密钥又
     * 持久化在磁盘，只有 epoch 能保证重启后 sequence 从 1 重新开始时不落回同一段 nonce 空间。
     */
    private final String localKeyEpoch;
    private final Map<Long, String> peerKeyEpochs = new ConcurrentHashMap<>();
    private final SecureRandom secureRandom = new SecureRandom();
    private final AtomicBoolean enabled = new AtomicBoolean(false);
    private final Map<Long, PeerInfo> peers = new ConcurrentHashMap<>();
    private final Map<String, PeerInfo> peersByVirtualIp = new ConcurrentHashMap<>();
    private final Map<Long, PeerSession> sessions = new ConcurrentHashMap<>();
    private final Map<Long, PeerSession> sessionsById = new ConcurrentHashMap<>();
    private final Map<Long, ArrayDeque<PendingPacket>> pendingPackets = new ConcurrentHashMap<>();
    private final Map<String, PeerCandidate> serverReflexiveCandidates = new ConcurrentHashMap<>();
    private final Map<String, PendingStunBinding> pendingStunBindings = new ConcurrentHashMap<>();
    private final Map<String, PendingTurnRequest> pendingTurnRequests = new ConcurrentHashMap<>();
    private final Map<String, Long> turnPermissions = new ConcurrentHashMap<>();
	private final Map<String, TurnChannelBinding> turnChannelsByPeer = new ConcurrentHashMap<>();
	private final Map<Integer, TurnChannelBinding> turnChannelsByNumber = new ConcurrentHashMap<>();
	private final AtomicLong nextTurnChannel = new AtomicLong(TurnChannelData.MIN_CHANNEL);
    private final Map<String, PendingAppMessageAck> pendingMessageAcks = new ConcurrentHashMap<>();
    private final Map<String, PathMtuCacheEntry> pathMtuCache = new ConcurrentHashMap<>();
    // H-2：记录已排程密集退避重试的 session，防止重复排程；本轮结束后释放以便路径失效后重新进入。
    private final Set<Long> holePunchRetryScheduled = ConcurrentHashMap.newKeySet();
    // H-1：记录每个 peer 最近一次候选回礼时间，2s 节流防信令循环。
    private final Map<Long, Long> candidateReciprocateAt = new ConcurrentHashMap<>();
    private final ScheduledExecutorService pathMtuScheduler = Executors.newSingleThreadScheduledExecutor(task -> {
        Thread thread = new Thread(task, "shuai-peer-mesh-path-mtu");
        thread.setDaemon(true);
        return thread;
    });
    private final NatBehaviorDiscovery natBehaviorDiscovery = new NatBehaviorDiscovery();
    private volatile TunnelCore.PeerMeshConfig config;
    private volatile DatagramSocket udpSocket;
    private volatile Thread receiverThread;
    private volatile PeerCandidate relayCandidate;
    private volatile String relayAllocationId;
    private volatile long relayAllocationExpiresAtMillis;
    private volatile long lastStunCandidateRequestMillis;
    private volatile long lastRelayCandidateRequestMillis;
    private volatile long lastBehaviorDiscoveryStartedMillis;
    private volatile String natType = "";
    private volatile String natMappingBehavior = "";
    private volatile String natFilteringBehavior = "";
    private volatile String natBehaviorDiscoveryMode = "";
    private volatile String lastEndpoint = "";
    private volatile Thread maintenanceThread;
    private volatile long lastDeviceReportMillis;

    PeerMeshEngine(TunnelCore.TunnelSession tunnelSession,
                   TunnelCore.VpnPlatform vpnPlatform,
                   ExecutorService ioPool,
                   ControlSender controlSender,
                   StatusPublisher status,
                   AppMessageSink appMessageSink) {
        this.tunnelSession = tunnelSession;
        this.vpnPlatform = vpnPlatform;
        this.ioPool = ioPool;
        this.controlSender = controlSender;
        this.status = status;
        this.appMessageSink = appMessageSink;
        this.keyMaterial = KeyStore.keyMaterial();
        this.localKeyEpoch = newKeyEpoch();
    }

    synchronized void startOrUpdate(TunnelCore.PeerMeshConfig nextConfig) throws Exception {
        if (nextConfig == null || !nextConfig.enabled) {
            stop();
            return;
        }
        boolean stunConfigChanged = config == null
                || !equals(config.stunHost, nextConfig.stunHost)
                || config.stunPort != nextConfig.stunPort;
        pendingTurnRequests.clear();
		turnChannelsByPeer.clear();
		turnChannelsByNumber.clear();
		nextTurnChannel.set(TurnChannelData.MIN_CHANNEL);
        if (stunConfigChanged) {
            pendingStunBindings.clear();
            lastStunCandidateRequestMillis = 0L;
            lastBehaviorDiscoveryStartedMillis = 0L;
            natType = "";
            natMappingBehavior = "";
            natFilteringBehavior = "";
            natBehaviorDiscoveryMode = "";
            lastEndpoint = "";
        }
        nextConfig.peerRoutes = TunnelCore.PeerMeshConfig.normalizePeerRoutes(
                onlinePeerVirtualIps(), nextConfig.virtualIp);
        config = nextConfig;
        enabled.set(true);
        startUdpSocket();
        startMaintenance();
        if (vpnPlatform != null) {
            vpnPlatform.startVpn(nextConfig, this::sendVirtualPacket);
        }
        reportDevice("ACTIVE", "");
        requestPeerServerCandidates();
        announceCandidatesToOnlinePeers();
        publish("Peer mesh enabled", nextConfig.virtualIp + " " + nextConfig.cidr);
    }

    void handleControlMessage(String message) throws Exception {
        JSONObject json = new JSONObject(message == null ? "{}" : message);
        String type = json.optString("type", "");
        if (TYPE_CONFIG.equals(type)) {
            TunnelCore.PeerMeshConfig next = TunnelCore.PeerMeshConfig.parse(json.optJSONObject("peerMesh"));
            next.mtu = config == null ? 1280 : config.mtu;
            tunnelSession.peerMesh = next;
            startOrUpdate(next);
            return;
        }
        if (!enabled.get()) {
            return;
        }
        if (TYPE_ROSTER.equals(type)) {
            updateRoster(json.optJSONArray("peers"));
            return;
        }
        if (TYPE_SESSION_GRANT.equals(type)) {
            PeerInfo peer = peerFromSignal(json);
            mergePeer(peer, null);
            rememberSession(json);
            if (peer != null) {
                sendCandidatesToPeer(peer, sessions.get(peer.clientId));
                flushPending(peer.clientId);
            }
            return;
        }
        if (TYPE_CANDIDATES.equals(type)) {
            PeerInfo peer = peerFromSignal(json);
            List<PeerCandidate> candidates = parseCandidates(json.optJSONArray("candidates"));
            mergePeer(peer, candidates);
            applyRemoteKeyEpochFromSignal(json);
            PeerSession session = rememberSession(json);
            if (peer != null) {
                preparePath(peer, session);
                flushPending(peer.clientId);
                // H-1 候选回礼：port-restricted 组合下打洞要求双方几乎同时互射，本端无健康 direct
                // 路径时立刻回发自身候选，把双端 burst 窗口对齐到一个信令 RTT 内。
                reciprocateCandidates(peer);
            }
            return;
        }
        if (TYPE_CLOSE.equals(type)) {
            long peerId = peerId(json);
            if (peerId > 0) {
                PeerSession removed = sessions.remove(peerId);
                if (removed != null) {
                    sessionsById.remove(removed.sessionId);
                }
            }
        }
    }

    ClientMessageSendResult sendClientMessage(String toClientName, String body) throws Exception {
        String target = toClientName == null ? "" : toClientName.trim();
        String message = body == null ? "" : body.trim();
        TunnelCore.PeerMeshConfig current = config;
        if (target.isEmpty() || message.isEmpty() || current == null || !enabled.get()) {
            return null;
        }
        PeerInfo peer = findOnlinePeerByName(target);
        if (peer == null) {
            return null;
        }
        PeerSession session = sessions.get(peer.clientId);
        if (session == null || !session.canSend()) {
            preparePath(peer, session);
            session = waitForReadySession(peer.clientId, System.currentTimeMillis() + APP_MESSAGE_SESSION_WAIT_MS);
        }
        if (session == null || !session.canSend()) {
            return null;
        }

        String messageId = UUID.randomUUID().toString().replace("-", "");
        PeerAppMessageCodec.PeerAppMessage appMessage = new PeerAppMessageCodec.PeerAppMessage();
        appMessage.type = PeerAppMessageCodec.TYPE_MESSAGE;
        appMessage.id = messageId;
        appMessage.fromClientId = current.clientId;
        appMessage.fromClientName = current.clientName;
        appMessage.toClientId = peer.clientId;
        appMessage.toClientName = firstText(peer.clientName, target);
        appMessage.message = message;
        appMessage.createdAtMillis = System.currentTimeMillis();

        PendingAppMessageAck pending = new PendingAppMessageAck();
        pendingMessageAcks.put(messageId, pending);
        try {
            if (!sendEncryptedPayload(peer, session, PeerAppMessageCodec.encode(appMessage))) {
                preparePath(peer, session);
                return null;
            }
            if (pending.latch.await(APP_MESSAGE_ACK_WAIT_MS, TimeUnit.MILLISECONDS) && pending.delivered) {
                return new ClientMessageSendResult(messageId, peerTransportFor(peer.clientId));
            }
            preparePath(peer, session);
            return null;
        } finally {
            pendingMessageAcks.remove(messageId);
        }
    }

    private void updateRoster(JSONArray array) throws Exception {
        Map<Long, PeerInfo> previous = new HashMap<>(peers);
        peers.clear();
        peersByVirtualIp.clear();
        if (array != null) {
            for (int i = 0; i < array.length(); i++) {
                JSONObject item = array.optJSONObject(i);
                if (item == null) {
                    continue;
                }
                PeerInfo peer = new PeerInfo(
                        item.optLong("clientId", 0L),
                        item.optString("clientName", ""),
                        item.optString("virtualIp", ""),
                        item.optString("publicKey", ""),
                        item.optBoolean("online", false),
                        item.optBoolean("messageSendCapable", false),
                        item.optBoolean("messageReceiveCapable", false),
                        item.optBoolean("messageAttachmentsCapable", false),
                        item.optBoolean("messageMediaPreviewCapable", false),
                        item.optLong("messageMaxAttachmentBytes", 0L),
                        previous.containsKey(item.optLong("clientId", 0L))
                                ? previous.get(item.optLong("clientId", 0L)).candidates
                                : List.of());
                mergePeer(peer, null);
            }
        }
        refreshVpnRoutes();
        announceCandidatesToOnlinePeers();
        refreshSessionKeys();
        publish("Peer roster", peers.size() + " peer(s)");
    }

    private List<String> onlinePeerVirtualIps() {
        List<String> routes = new ArrayList<>();
        for (PeerInfo peer : peers.values()) {
            if (peer != null && peer.online && !isBlank(peer.virtualIp)) {
                routes.add(peer.virtualIp);
            }
        }
        return routes;
    }

    private void refreshVpnRoutes() throws Exception {
        TunnelCore.PeerMeshConfig current = config;
        if (current == null) {
            return;
        }
        current.peerRoutes = TunnelCore.PeerMeshConfig.normalizePeerRoutes(
                onlinePeerVirtualIps(), current.virtualIp);
        if (vpnPlatform != null && current.enabled) {
            vpnPlatform.startVpn(current, this::sendVirtualPacket);
        }
    }

    private void sendVirtualPacket(byte[] ipv4Packet) {
        if (!enabled.get() || config == null) {
            return;
        }
        String targetIp = IpPacket.destinationIpv4(ipv4Packet);
        if (isIgnoredTarget(targetIp)) {
            return;
        }
        PeerInfo peer = peersByVirtualIp.get(targetIp);
        if (peer == null || !peer.online) {
            return;
        }
        PeerSession session = sessions.get(peer.clientId);
        if (session == null || !session.canSend()) {
            queuePending(peer.clientId, ipv4Packet);
            preparePath(peer, session);
            return;
        }
        sendEncryptedPayload(peer, session, ipv4Packet);
    }

    private boolean sendEncryptedPayload(PeerInfo peer, PeerSession session, byte[] payload) {
        TunnelCore.PeerMeshConfig current = config;
        if (current == null || session == null || !session.canSend()) {
            return false;
        }
        ensurePathMtuDiscovery(peer, session, current);
        if (!IpPacket.destinationIpv4(payload).isEmpty()) {
            int pathMtu = session.pathMtu.effectiveMtu(current.mtu);
            payload = IpPacket.clampTcpMss(payload, pathMtu);
            if (payload.length > pathMtu) {
                injectPacketTooBig(payload, pathMtu);
                return true;
            }
        }
        return sendRawPeerPayload(peer, session, payload);
    }

    private boolean sendRawPeerPayload(PeerInfo peer, PeerSession session, byte[] payload) {
        DatagramSocket socket = udpSocket;
        TunnelCore.PeerMeshConfig current = config;
        if (socket == null || socket.isClosed() || current == null
                || session == null || !session.canSend()) {
            return false;
        }
        try {
            if (!session.ensureTrafficCodecs(current.clientId)) {
                return false;
            }
            long sequence = session.nextSequence();
            byte[] frame = session.outboundCodec.encode(
                    session.sessionId, sequence, payload);
            String relayTarget = relayFallbackTarget(peer, session);
            if (!isBlank(relayTarget)) {
                return sendRelayPayload(relayTarget, frame);
            }
            InetSocketAddress remote = session.remoteEndpoint;
            socket.send(new DatagramPacket(frame, frame.length, remote));
            session.addDirectBytes(frame.length);
            return true;
        } catch (Exception e) {
            publish("Peer send failed", e.getMessage());
            return false;
        }
    }

    private void ensurePathMtuDiscovery(PeerInfo peer,
                                        PeerSession session,
                                        TunnelCore.PeerMeshConfig current) {
        String relayTarget = relayFallbackTarget(peer, session);
        String pathKey = pathMtuKey(session, relayTarget);
        if (pathKey.isEmpty()) {
            return;
        }
        long now = System.currentTimeMillis();
        PathMtuCacheEntry cached = pathMtuCache.get(pathKey);
        if (cached != null && cached.validUntilMillis <= now) {
            pathMtuCache.remove(pathKey, cached);
            cached = null;
        }
        applyPathMtuTransition(peer, session, session.pathMtu.activate(
                pathKey,
                current.mtu,
                cached == null ? null : cached.innerMtu,
                cached == null ? 0L : cached.validUntilMillis,
                now,
                secureRandom::nextLong));
    }

    private boolean handlePathMtuMessage(byte[] payload, PeerSession session) {
        if (!PeerPathMtu.looksLike(payload)) {
            return false;
        }
        PeerPathMtu.Message message = PeerPathMtu.decode(payload);
        if (message == null) {
            return true;
        }
        PeerInfo peer = peers.get(session.peerId);
        if (peer == null) {
            return true;
        }
        if (message.probe) {
            sendRawPeerPayload(peer, session, PeerPathMtu.ack(message.nonce, message.innerMtu));
            return true;
        }
        applyPathMtuTransition(peer, session, session.pathMtu.acknowledge(
                message.nonce,
                message.innerMtu,
                System.currentTimeMillis(),
                secureRandom::nextLong));
        return true;
    }

    private void applyPathMtuTransition(PeerInfo peer,
                                        PeerSession session,
                                        PeerPathMtu.Transition transition) {
        if (transition.completedMtu != null) {
            String pathKey = session.pathMtu.pathKey();
            if (!pathKey.isEmpty()) {
                pathMtuCache.put(pathKey, new PathMtuCacheEntry(
                        transition.completedMtu,
                        System.currentTimeMillis() + PeerPathMtu.CACHE_TTL_MILLIS));
            }
        }
        if (transition.probe != null) {
            sendPathMtuProbe(peer, session, transition.probe);
        }
    }

    private void sendPathMtuProbe(PeerInfo peer, PeerSession session, PeerPathMtu.Probe probe) {
        sendRawPeerPayload(peer, session, PeerPathMtu.probe(probe.nonce, probe.innerMtu));
        try {
            pathMtuScheduler.schedule(() -> {
                if (!enabled.get() || sessionsById.get(session.sessionId) != session) {
                    return;
                }
                applyPathMtuTransition(peer, session, session.pathMtu.timeout(
                        probe.nonce,
                        System.currentTimeMillis(),
                        secureRandom::nextLong));
            }, PeerPathMtu.PROBE_TIMEOUT_MILLIS, TimeUnit.MILLISECONDS);
        } catch (RejectedExecutionException ignored) {
            // Engine shutdown raced with a final probe.
        }
    }

    private String pathMtuKey(PeerSession session, String relayTarget) {
        if (!isBlank(relayTarget)) {
            return "relay|" + relayTarget;
        }
        return session.remoteEndpoint == null ? "" : "direct|" + endpointKey(session.remoteEndpoint);
    }

    private void injectPacketTooBig(byte[] packet, int pathMtu) {
        byte[] response = IpPacket.icmpFragmentationNeeded(packet, pathMtu);
        if (response != null && vpnPlatform != null) {
            try {
                vpnPlatform.writeVpnPacket(response);
            } catch (Exception e) {
                publish("Peer path MTU feedback failed", e.getMessage());
            }
        }
    }

    private void startUdpSocket() throws Exception {
        DatagramSocket existing = udpSocket;
        if (existing != null && !existing.isClosed()) {
            return;
        }
        DatagramSocket socket = new DatagramSocket(0);
        if (vpnPlatform != null) {
            vpnPlatform.protectDatagramSocket(socket);
        }
        udpSocket = socket;
        receiverThread = new Thread(() -> receiveLoop(socket), "shuai-peer-mesh-udp");
        receiverThread.setDaemon(true);
        receiverThread.start();
    }

    private synchronized void startMaintenance() {
        Thread current = maintenanceThread;
        if (current != null && current.isAlive()) {
            return;
        }
        Thread next = new Thread(this::maintenanceLoop, "shuai-peer-mesh-maintenance");
        next.setDaemon(true);
        maintenanceThread = next;
        next.start();
    }

    private void maintenanceLoop() {
        while (enabled.get()) {
            try {
                Thread.sleep(MAINTENANCE_INTERVAL_MS);
                if (!enabled.get()) {
                    return;
                }
                reportTrafficDeltas();
                removeExpiredSessions();
                removeExpiredStunBindings();
                removeExpiredTurnRequests();
                requestPeerServerCandidates();
                announceCandidatesToOnlinePeers();
                keepaliveActivePaths();
                reportDeviceIfDue();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return;
            } catch (Exception e) {
                publish("Peer maintenance failed", e.getMessage());
            }
        }
    }

    private void receiveLoop(DatagramSocket socket) {
        byte[] buffer = new byte[64 * 1024];
        while (enabled.get() && !socket.isClosed()) {
            try {
                DatagramPacket packet = new DatagramPacket(buffer, buffer.length);
                socket.receive(packet);
                byte[] data = new byte[packet.getLength()];
                System.arraycopy(packet.getData(), packet.getOffset(), data, 0, packet.getLength());
                InetSocketAddress remote = new InetSocketAddress(packet.getAddress(), packet.getPort());
                handleUdpPacket(data, remote);
            } catch (Exception e) {
                if (enabled.get()) {
                    publish("Peer UDP receive failed", e.getMessage());
                }
            }
        }
    }

    private void handleUdpPacket(byte[] data, InetSocketAddress remote) throws Exception {
		TurnChannelData channelData = TurnChannelData.parse(data);
		if (channelData != null) {
			TurnChannelBinding binding = turnChannelsByNumber.get(channelData.channelNumber);
			if (binding != null && binding.active
					&& binding.expiresAtMillis > System.currentTimeMillis()
					&& sameEndpoint(relayEndpoint(), remote)) {
				handleUdpPayload(channelData.payload, remote, endpointKey(binding.peer));
			}
			return;
		}
        StunMessage stun = StunMessage.parse(data);
        if (stun != null) {
            handleStunTurnMessage(stun, remote);
            return;
        }
        handleUdpPayload(data, remote, null);
    }

    private void handleUdpPayload(byte[] data, InetSocketAddress remote, String relayFromAllocationId) throws Exception {
        if (DataFrameCodec.looksLike(data)) {
            handleDataFrame(data, remote, relayFromAllocationId);
            return;
        }
        JSONObject json = tryJson(data);
        if (json == null || !PROBE_MAGIC.equals(json.optString("magic", ""))) {
            return;
        }
        String type = json.optString("type", "");
        if ("check".equals(type)) {
            handleProbeCheck(json, remote, relayFromAllocationId);
        } else if ("check-response".equals(type)) {
            handleProbeResponse(json, remote, relayFromAllocationId);
        }
    }

    private void handleStunTurnMessage(StunMessage message, InetSocketAddress remote) throws Exception {
        PendingTurnRequest pendingTurn = pendingTurnRequests.remove(message.transactionIdHex());
        if (pendingTurn != null && !sameEndpoint(pendingTurn.endpoint, remote)) {
            pendingTurn = null;
        }
        switch (message.type) {
            case StunMessage.BINDING_SUCCESS:
                handleStunBindingSuccess(message, remote);
                break;
            case StunMessage.BINDING_ERROR:
                handleStunBindingError(message, remote);
                break;
            case StunMessage.ALLOCATE_SUCCESS:
                handleTurnAllocated(message);
                break;
            case StunMessage.REFRESH_SUCCESS:
                relayAllocationExpiresAtMillis = System.currentTimeMillis()
                        + Math.max(30L, message.lifetimeSeconds(300L)) * 1000L;
                break;
            case StunMessage.CREATE_PERMISSION_SUCCESS:
                if (pendingTurn != null && pendingTurn.peer != null) {
                    turnPermissions.put(endpointKey(pendingTurn.peer),
                            System.currentTimeMillis() + TURN_PERMISSION_TTL_MS);
                }
                break;
			case StunMessage.CHANNEL_BIND_SUCCESS:
				activateTurnChannel(pendingTurn);
				break;
            case StunMessage.ALLOCATE_ERROR:
            case StunMessage.REFRESH_ERROR:
            case StunMessage.CREATE_PERMISSION_ERROR:
			case StunMessage.CHANNEL_BIND_ERROR:
                handleTurnError(message, pendingTurn);
                break;
            case StunMessage.DATA_INDICATION:
                InetSocketAddress peer = message.xorPeerAddress();
                byte[] inner = message.data();
                if (peer != null && inner != null) {
                    handleUdpPayload(inner, remote, endpointKey(peer));
                }
                break;
            default:
                break;
        }
    }

    private void handleTurnError(StunMessage message, PendingTurnRequest pending) {
        TurnChallenge challenge = TurnChallenge.from(message);
        if (pending == null || challenge == null) {
            return;
        }
        PendingTurnRequest retry = pending.retryOnce();
        TunnelCore.PeerMeshConfig current = config;
        if (!challenge.retryable()
                || retry == null
                || current == null
                || !challenge.applyTo(current)) {
            clearFailedTurnPermission(pending);
            publish("Peer TURN rejected", challenge.code + " " + challenge.reason);
            return;
        }
        publish("Peer TURN challenge", challenge.code + " retrying " + pending.operation.name().toLowerCase(Locale.ROOT));
        sendTurnRequest(retry);
    }

    private void clearFailedTurnPermission(PendingTurnRequest pending) {
        if (pending != null && pending.peer != null) {
            turnPermissions.remove(endpointKey(pending.peer));
			if (pending.operation == TurnOperation.CHANNEL_BIND) {
				TurnChannelBinding binding = turnChannelsByNumber.remove(pending.channelNumber);
				if (binding != null) {
					turnChannelsByPeer.remove(endpointKey(binding.peer), binding);
				}
			}
        }
    }

	private void activateTurnChannel(PendingTurnRequest pending) {
		if (pending == null || pending.operation != TurnOperation.CHANNEL_BIND || pending.peer == null) {
			return;
		}
		TurnChannelBinding binding = turnChannelsByNumber.get(pending.channelNumber);
		if (binding != null && sameEndpoint(binding.peer, pending.peer)) {
			binding.active = true;
			binding.expiresAtMillis = System.currentTimeMillis() + TURN_CHANNEL_ACTIVE_TTL_MS;
		}
	}

    private void handleStunBindingSuccess(StunMessage message,
                                          InetSocketAddress observedRemote) throws Exception {
        InetSocketAddress mapped = message.xorMappedAddress();
        if (mapped == null) {
            mapped = message.mappedAddress();
        }
        if (mapped == null || mapped.getAddress() == null || mapped.getPort() <= 0) {
            return;
        }
        String transactionKey = message.transactionIdHex();
        PendingStunBinding pending = pendingStunBindings.get(transactionKey);
        if (pending == null || !sameEndpoint(pending.expectedResponseEndpoint, observedRemote)
                || !pendingStunBindings.remove(transactionKey, pending)) {
            return;
        }
        String foundation = pending.publicStun ? "public-stun" : "standard-stun";
        PeerCandidate candidate = new PeerCandidate();
        candidate.type = "srflx";
        candidate.transport = "udp";
        candidate.address = mapped.getAddress().getHostAddress();
        candidate.port = mapped.getPort();
        candidate.addressFamily = mapped.getAddress() instanceof Inet6Address ? "IPv6" : "IPv4";
        candidate.priority = mapped.getAddress() instanceof Inet6Address ? 900 : 800;
        candidate.foundation = foundation;
        String key = candidateEndpointKey(candidate);
        boolean candidateChanged = serverReflexiveCandidates.putIfAbsent(key, candidate) == null;

        if (pending.behaviorProbe != null) {
            handleNatBehaviorTransition(natBehaviorDiscovery.succeeded(
                    pending.behaviorGeneration,
                    pending.behaviorProbe,
                    mapped));
        } else if (!pending.publicStun) {
            natType = basicNatType(mapped);
            natMappingBehavior = "";
            natFilteringBehavior = "";
            natBehaviorDiscoveryMode = NatBehaviorDiscovery.DISCOVERY_BASIC;
            lastEndpoint = endpointKey(mapped);
            reportDevice("ACTIVE", "");
            InetSocketAddress standardOther =
                    resolveStandardOtherAddress(message, observedRemote);
            if (standardOther != null) {
                startNatBehaviorDiscovery(observedRemote, mapped, standardOther);
            }
        }
        if (candidateChanged) {
            announceCandidatesToOnlinePeers();
        }
    }

    private void handleStunBindingError(StunMessage message,
                                        InetSocketAddress observedRemote) {
        String transactionKey = message.transactionIdHex();
        PendingStunBinding pending = pendingStunBindings.get(transactionKey);
        if (pending == null || !sameEndpoint(pending.targetEndpoint, observedRemote)
                || !pendingStunBindings.remove(transactionKey, pending)) {
            return;
        }
        if (pending.behaviorProbe == null) {
            return;
        }
        List<Integer> unknown = message.unknownAttributes();
        boolean unsupported = message.errorCode() == 420
                && (unknown.isEmpty() || unknown.contains(StunMessage.ATTR_CHANGE_REQUEST));
        handleNatBehaviorTransition(natBehaviorDiscovery.failed(
                pending.behaviorGeneration,
                pending.behaviorProbe,
                unsupported));
    }

    private void startNatBehaviorDiscovery(InetSocketAddress primaryEndpoint,
                                           InetSocketAddress mappedEndpoint,
                                           InetSocketAddress otherEndpoint) {
        long now = System.currentTimeMillis();
        if (now - lastBehaviorDiscoveryStartedMillis < BEHAVIOR_DISCOVERY_MIN_INTERVAL_MS) {
            return;
        }
        lastBehaviorDiscoveryStartedMillis = now;
        try {
            handleNatBehaviorTransition(natBehaviorDiscovery.begin(
                    primaryEndpoint,
                    mappedEndpoint,
                    otherEndpoint));
        } catch (IllegalArgumentException e) {
            publish("Peer NAT discovery", e.getMessage());
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

    private void reportNatBehavior(NatBehaviorDiscovery.Snapshot snapshot) {
        if (snapshot == null || !snapshot.complete() || snapshot.mappedEndpoint() == null) {
            return;
        }
        natType = compatibleNatType(snapshot);
        natMappingBehavior = snapshot.mappingBehavior();
        natFilteringBehavior = snapshot.filteringBehavior();
        natBehaviorDiscoveryMode = snapshot.discovery();
        lastEndpoint = endpointKey(snapshot.mappedEndpoint());
        reportDevice("ACTIVE", "");
    }

    private String compatibleNatType(NatBehaviorDiscovery.Snapshot snapshot) {
        InetSocketAddress mapped = snapshot.mappedEndpoint();
        if (mapped != null
                && isPortPreserved(mapped)
                && isLocalAddress(mapped.getAddress())) {
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
        return isBlank(natType) ? "NAT" : natType;
    }

    private String basicNatType(InetSocketAddress mapped) {
        if (mapped != null && isPortPreserved(mapped) && isLocalAddress(mapped.getAddress())) {
            return "NO_NAT";
        }
        return mapped != null && isPortPreserved(mapped) ? "PORT_PRESERVED_NAT" : "NAT";
    }

    private boolean isPortPreserved(InetSocketAddress mapped) {
        DatagramSocket socket = udpSocket;
        return mapped != null
                && socket != null
                && !socket.isClosed()
                && mapped.getPort() == socket.getLocalPort();
    }

    private boolean isLocalAddress(InetAddress address) {
        if (address == null) {
            return false;
        }
        try {
            return NetworkInterface.getByInetAddress(address) != null;
        } catch (Exception ignored) {
            return false;
        }
    }

    private InetSocketAddress resolveStandardOtherAddress(StunMessage message,
                                                          InetSocketAddress observedRemote) {
        InetSocketAddress origin = message.responseOrigin();
        InetSocketAddress other = message.otherAddress();
        if (origin == null
                || other == null
                || !sameEndpoint(origin, observedRemote)
                || other.getAddress() == null
                || observedRemote == null
                || observedRemote.getAddress() == null
                || other.getAddress().equals(observedRemote.getAddress())
                || other.getPort() == observedRemote.getPort()) {
            return null;
        }
        return other;
    }

    private void handleTurnAllocated(StunMessage message) throws Exception {
        InetSocketAddress relayed = message.xorRelayedAddress();
        InetSocketAddress turn = relayEndpoint();
        if (relayed == null || relayed.getAddress() == null || turn == null) {
            return;
        }
        relayAllocationId = "turn:" + endpointKey(relayed);
        relayAllocationExpiresAtMillis = System.currentTimeMillis()
                + Math.max(30L, message.lifetimeSeconds(300L)) * 1000L;
        PeerCandidate candidate = new PeerCandidate();
        candidate.type = "relay";
        candidate.transport = "udp";
        candidate.address = turn.getHostString();
        candidate.port = turn.getPort();
        candidate.priority = 100;
        candidate.foundation = "standard-turn";
        candidate.relayId = endpointKey(relayed);
        candidate.addressFamily = turn.getAddress() instanceof Inet6Address ? "IPv6" : addressFamily(turn.getHostString());
        PeerCandidate previous = relayCandidate;
        relayCandidate = candidate;
		boolean changed = previous == null
                || !equals(previous.relayId, candidate.relayId)
                || !equals(previous.address, candidate.address)
				|| previous.port != candidate.port;
		if (changed) {
			turnPermissions.clear();
			turnChannelsByPeer.clear();
			turnChannelsByNumber.clear();
			nextTurnChannel.set(TurnChannelData.MIN_CHANNEL);
            announceCandidatesToOnlinePeers();
        }
    }

    private void handleDataFrame(byte[] data, InetSocketAddress remote, String relayFromAllocationId) throws Exception {
        Long sessionId = DataFrameCodec.sessionId(data);
        PeerSession session = sessionId == null ? null : sessionsById.get(sessionId);
        TunnelCore.PeerMeshConfig current = config;
        if (session == null || current == null || !session.ensureTrafficCodecs(current.clientId)) {
            return;
        }
        DataFrame frame = session.inboundCodec.decode(data, session.sessionId);
        if (frame == null || !session.accept(frame)) {
            return;
        }
        markSessionPath(session, remote, relayFromAllocationId, -1L);
        session.pathReady = true;
        if (handlePathMtuMessage(frame.plaintext, session)) {
            return;
        }
        if (handlePeerAppMessage(frame.plaintext, session, relayFromAllocationId)) {
            return;
        }
        if (vpnPlatform != null) {
            vpnPlatform.writeVpnPacket(frame.plaintext);
        }
    }

    private boolean handlePeerAppMessage(byte[] payload, PeerSession session, String relayFromAllocationId) throws Exception {
        if (!PeerAppMessageCodec.looksLike(payload)) {
            return false;
        }
        PeerAppMessageCodec.PeerAppMessage message = PeerAppMessageCodec.decode(payload);
        if (message == null) {
            publish("Peer message dropped", "decode failed");
            return true;
        }
        if (PeerAppMessageCodec.TYPE_ACK.equalsIgnoreCase(message.type)) {
            completePeerMessageAck(message.id);
            return true;
        }
        if (!PeerAppMessageCodec.TYPE_MESSAGE.equalsIgnoreCase(message.type)) {
            return true;
        }
        TunnelCore.PeerMeshConfig current = config;
        if (current == null
                || (message.fromClientId != 0L && message.fromClientId != session.peerId)
                || (message.toClientId != 0L && message.toClientId != current.clientId)) {
            return true;
        }
        PeerInfo peer = peers.get(session.peerId);
        String from = firstText(message.fromClientName,
                peer == null ? String.valueOf(session.peerId) : peer.clientName);
        publish("Message received", from + ": " + peerAppMessageText(message));
        if (appMessageSink != null) {
            appMessageSink.onAppMessage(from, message.attachment == null
                    ? message.message
                    : PeerAppMessageCodec.displayText(message));
        }
        sendPeerClientMessageAck(message, session, current);
        return true;
    }

    private String peerAppMessageText(PeerAppMessageCodec.PeerAppMessage message) {
        return PeerAppMessageCodec.displayText(message);
    }

    private void completePeerMessageAck(String messageId) {
        if (isBlank(messageId)) {
            return;
        }
        PendingAppMessageAck pending = pendingMessageAcks.remove(messageId.trim());
        if (pending != null) {
            pending.delivered = true;
            pending.latch.countDown();
        }
    }

    private void sendPeerClientMessageAck(PeerAppMessageCodec.PeerAppMessage message,
                                          PeerSession session,
                                          TunnelCore.PeerMeshConfig current) throws Exception {
        if (message == null || session == null || current == null || isBlank(message.id)) {
            return;
        }
        PeerInfo peer = peers.get(session.peerId);
        if (peer == null) {
            return;
        }
        PeerAppMessageCodec.PeerAppMessage ack = new PeerAppMessageCodec.PeerAppMessage();
        ack.type = PeerAppMessageCodec.TYPE_ACK;
        ack.id = message.id;
        ack.fromClientId = current.clientId;
        ack.fromClientName = current.clientName;
        ack.toClientId = session.peerId;
        ack.toClientName = firstText(message.fromClientName, peer.clientName);
        ack.createdAtMillis = System.currentTimeMillis();
        sendEncryptedPayload(peer, session, PeerAppMessageCodec.encode(ack));
    }

    private void handleProbeCheck(JSONObject probe, InetSocketAddress remote, String relayFromAllocationId) throws Exception {
        long peerId = probe.optLong("fromClientId", 0L);
        PeerSession session = sessions.get(peerId);
        if (session == null
                || session.sessionId != probe.optLong("sessionId", 0L)
                || !equals(session.token, probe.optString("token", ""))) {
            return;
        }
        markSessionPath(session, remote, relayFromAllocationId, -1L);
        session.pathReady = true;
        flushPending(peerId);

        JSONObject response = new JSONObject();
        response.put("magic", PROBE_MAGIC);
        response.put("type", "check-response");
        response.put("sessionId", session.sessionId);
        response.put("fromClientId", config == null ? 0L : config.clientId);
        response.put("toClientId", peerId);
        response.put("nonce", probe.optString("nonce", ""));
        response.put("token", session.token);
        response.put("sentAtMillis", probe.optLong("sentAtMillis", System.currentTimeMillis()));
        if (!isBlank(relayFromAllocationId)) {
            sendRelayPayload(relayFromAllocationId, response.toString().getBytes(StandardCharsets.UTF_8));
        } else {
            sendUdpJson(response, remote);
        }
    }

    private void handleProbeResponse(JSONObject probe, InetSocketAddress remote, String relayFromAllocationId) {
        long peerId = probe.optLong("fromClientId", 0L);
        PeerSession session = sessions.get(peerId);
        if (session == null
                || session.sessionId != probe.optLong("sessionId", 0L)
                || !equals(session.token, probe.optString("token", ""))) {
            return;
        }
        long sentAt = probe.optLong("sentAtMillis", 0L);
        long rtt = sentAt <= 0 ? -1L : Math.max(0L, System.currentTimeMillis() - sentAt);
        markSessionPath(session, remote, relayFromAllocationId, rtt);
        session.pathReady = true;
        flushPending(peerId);
    }

    private void markSessionPath(PeerSession session, InetSocketAddress remote, String relayFromAllocationId, long rttMillis) {
        if (session == null) {
            return;
        }
        long now = System.currentTimeMillis();
        String pathType;
        String remoteText;
        if (!isBlank(relayFromAllocationId)) {
            InetSocketAddress turn = relayEndpoint();
            session.remoteEndpoint = turn == null ? remote : turn;
            session.relayTargetAllocationId = relayFromAllocationId;
            pathType = "RELAY";
            remoteText = "relay:" + relayFromAllocationId;
        } else {
            session.remoteEndpoint = remote;
            session.relayTargetAllocationId = "";
            pathType = "DIRECT";
            remoteText = endpointKey(remote);
        }
        boolean changed = !pathType.equals(session.currentPathType) || !remoteText.equals(session.lastPathRemoteText);
        session.currentPathType = pathType;
        session.lastPathRemoteText = remoteText;
        if ("DIRECT".equals(pathType)) {
            session.lastDirectSuccessMillis = now;
            session.bestDirectRtt = smoothRtt(session.bestDirectRtt, rttMillis);
        } else {
            session.lastRelaySuccessMillis = now;
            session.bestRelayRtt = smoothRtt(session.bestRelayRtt, rttMillis);
        }
        if (changed || now - session.lastPathReportMillis >= REPORT_INTERVAL_MS) {
            reportPath(session, pathType, localEndpointText(pathType), remoteText, rttMillis);
            session.lastPathReportMillis = now;
        }
    }

    private void preparePath(PeerInfo peer, PeerSession session) {
        if (peer == null || !peer.online) {
            return;
        }
        long now = System.currentTimeMillis();
        if (session != null && session.isExpired(now)) {
            sessions.remove(peer.clientId);
            sessionsById.remove(session.sessionId);
            session = null;
        }
        if (session == null || session.shouldRefresh(now)) {
            try {
                sendCandidatesToPeer(peer, null);
            } catch (Exception e) {
                publish("Peer signal failed", e.getMessage());
            }
            if (session == null) {
                return;
            }
        }
        if (session.aesKey == null) {
            refreshSessionKey(peer, session);
        }
        requestPeerServerCandidates();
        InetSocketAddress first = firstDirectCandidate(peer.candidates);
        if (first != null && session.remoteEndpoint == null) {
            session.remoteEndpoint = first;
        }
        sendConnectivityChecks(peer, session);
    }

    private PeerInfo findOnlinePeerByName(String clientName) {
        if (isBlank(clientName)) {
            return null;
        }
        for (PeerInfo peer : peers.values()) {
            if (peer != null && peer.online && peer.messageReceiveCapable && clientName.equalsIgnoreCase(peer.clientName)) {
                return peer;
            }
        }
        return null;
    }

    private PeerSession waitForReadySession(long peerId, long deadlineMillis) {
        while (System.currentTimeMillis() < deadlineMillis) {
            PeerSession session = sessions.get(peerId);
            if (session != null && session.canSend()) {
                return session;
            }
            PeerInfo peer = peers.get(peerId);
            if (peer != null && peer.online) {
                preparePath(peer, session);
            }
            try {
                Thread.sleep(50L);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return null;
            }
        }
        PeerSession session = sessions.get(peerId);
        return session != null && session.canSend() ? session : null;
    }

    private String peerTransportFor(long peerId) {
        PeerSession session = sessions.get(peerId);
        if (session == null) {
            return "peer";
        }
        return !isBlank(session.relayTargetAllocationId)
                || "RELAY".equalsIgnoreCase(session.currentPathType)
                ? "peer-relay"
                : "peer-direct";
    }

    private void sendConnectivityChecks(PeerInfo peer, PeerSession session) {
        if (peer == null || session == null || config == null) {
            return;
        }
        List<InetSocketAddress> targets = directCandidates(peer.candidates);
        if (targets.isEmpty() && session.remoteEndpoint != null) {
            targets = List.of(session.remoteEndpoint);
        }
        for (InetSocketAddress target : targets) {
            for (int i = 0; i < 3; i++) {
                try {
                    JSONObject probe = new JSONObject();
                    probe.put("magic", PROBE_MAGIC);
                    probe.put("type", "check");
                    probe.put("sessionId", session.sessionId);
                    probe.put("fromClientId", config.clientId);
                    probe.put("toClientId", peer.clientId);
                    probe.put("nonce", UUID.randomUUID().toString().replace("-", ""));
                    probe.put("token", session.token);
                    probe.put("sentAtMillis", System.currentTimeMillis());
                    sendUdpJson(probe, target);
                } catch (Exception e) {
                    publish("Peer probe failed", e.getMessage());
                }
            }
        }
        for (PeerCandidate candidate : relayCandidates(peer.candidates)) {
            if (isBlank(candidate.relayId)) {
                continue;
            }
            try {
                JSONObject probe = buildProbe(peer, session);
                sendRelayPayload(candidate.relayId, probe.toString().getBytes(StandardCharsets.UTF_8));
            } catch (Exception e) {
                publish("Peer relay probe failed", e.getMessage());
            }
        }
        scheduleHolePunchRetries(session);
    }

    /**
     * H-2：session 首次发起连通性检查后按 1s/2s/4s/8s 退避重试，而不是等 30s maintenance tick。
     * 已建立健康 direct 路径时自动停止。本轮结束后释放标记，路径后续失效时可以重新进入密集重试。
     * 复用 pathMtuScheduler 做延迟调度，回调里重新校验 session 身份。对齐 Java scheduleHolePunchRetries。
     */
    private void scheduleHolePunchRetries(PeerSession session) {
        if (session == null || !holePunchRetryScheduled.add(session.sessionId)) {
            return;
        }
        long sessionId = session.sessionId;
        for (long delay : HOLE_PUNCH_RETRY_DELAYS_MS) {
            pathMtuScheduler.schedule(() -> {
                if (!enabled.get()) {
                    return;
                }
                PeerSession current = sessionsById.get(sessionId);
                if (current != session) {
                    return; // session 已被替换，停止旧的重试
                }
                retryHolePunch(sessionId, session);
            }, delay, TimeUnit.MILLISECONDS);
        }
        // 本轮结束后释放标记，路径后续失效时可以重新进入密集重试。
        long lastDelay = HOLE_PUNCH_RETRY_DELAYS_MS[HOLE_PUNCH_RETRY_DELAYS_MS.length - 1];
        pathMtuScheduler.schedule(() -> holePunchRetryScheduled.remove(sessionId),
                lastDelay + 1_000L, TimeUnit.MILLISECONDS);
    }

    /** H-2 退避重试的实际执行体：重新查找 session，过期或已打通则停止。 */
    private void retryHolePunch(long sessionId, PeerSession expected) {
        PeerSession session = sessionsById.get(sessionId);
        if (session != expected) {
            holePunchRetryScheduled.remove(sessionId);
            return;
        }
        long now = System.currentTimeMillis();
        if (session.isExpired(now) || session.hasHealthyDirect(now)) {
            holePunchRetryScheduled.remove(sessionId);
            return;
        }
        PeerInfo peer = peers.get(session.peerId);
        if (peer == null || !peer.online || peer.candidates == null || peer.candidates.isEmpty()) {
            return;
        }
        sendConnectivityChecks(peer, session);
    }

    /**
     * H-1 候选回礼：收到对端候选后，若本端尚无健康 direct 路径，立即回发自身候选，把双端打洞
     * 窗口从最坏 30s maintenance tick 压到一个信令 RTT 内对齐。带 2s 节流防两端互触发形成信令
     * 循环。对齐 Java reciprocateCandidates。
     */
    private void reciprocateCandidates(PeerInfo peer) {
        if (peer == null) {
            return;
        }
        long now = System.currentTimeMillis();
        PeerSession session = sessions.get(peer.clientId);
        if (session != null && session.hasHealthyDirect(now)) {
            return;
        }
        Long previous = candidateReciprocateAt.get(peer.clientId);
        if (previous != null && now - previous < CANDIDATE_RECIPROCATE_INTERVAL_MS) {
            return;
        }
        candidateReciprocateAt.put(peer.clientId, now);
        try {
            sendCandidatesToPeer(peer, session);
        } catch (Exception e) {
            publish("Peer reciprocated candidates send failed", e.getMessage());
        }
    }

    private JSONObject buildProbe(PeerInfo peer, PeerSession session) throws Exception {
        JSONObject probe = new JSONObject();
        probe.put("magic", PROBE_MAGIC);
        probe.put("type", "check");
        probe.put("sessionId", session.sessionId);
        probe.put("fromClientId", config.clientId);
        probe.put("toClientId", peer.clientId);
        probe.put("nonce", UUID.randomUUID().toString().replace("-", ""));
        probe.put("token", session.token);
        probe.put("sentAtMillis", System.currentTimeMillis());
        return probe;
    }

    private void sendUdpJson(JSONObject json, InetSocketAddress target) throws Exception {
        DatagramSocket socket = udpSocket;
        if (socket == null || socket.isClosed() || target == null) {
            return;
        }
        byte[] bytes = json.toString().getBytes(StandardCharsets.UTF_8);
        socket.send(new DatagramPacket(bytes, bytes.length, target));
    }

    private void announceCandidatesToOnlinePeers() throws Exception {
        if (!enabled.get() || config == null) {
            return;
        }
        List<PeerCandidate> candidates = gatherHostCandidates();
        if (candidates.isEmpty()) {
            return;
        }
        for (PeerInfo peer : peers.values()) {
            if (peer.online && !isBlank(peer.clientName)) {
                sendCandidatesToPeer(peer, sessions.get(peer.clientId), candidates);
            }
        }
    }

    private void sendCandidatesToPeer(PeerInfo peer, PeerSession session) throws Exception {
        sendCandidatesToPeer(peer, session, gatherHostCandidates());
    }

    private void sendCandidatesToPeer(PeerInfo peer, PeerSession session, List<PeerCandidate> candidates) throws Exception {
        if (peer == null || config == null || isBlank(peer.clientName) || candidates == null || candidates.isEmpty()) {
            return;
        }
        JSONObject message = new JSONObject();
        message.put("type", TYPE_CANDIDATES);
        message.put("sourceClientId", config.clientId);
        message.put("sourceClientName", config.clientName);
        message.put("sourceVirtualIp", config.virtualIp);
        message.put("sourcePublicKey", keyMaterial.publicKeyBase64);
        // candidates 是唯一的 peer->peer 信令通道，SPM2 key epoch 随它传播
        message.put("sourceKeyEpoch", localKeyEpoch);
        message.put("targetClientId", peer.clientId);
        message.put("targetClientName", peer.clientName);
        message.put("targetVirtualIp", peer.virtualIp);
        message.put("targetPublicKey", peer.publicKey);
        if (session != null) {
            message.put("sessionId", session.sessionId);
            message.put("token", session.token);
            message.put("expiresAt", session.expiresAt);
        }
        message.put("createdAtMillis", System.currentTimeMillis());
        message.put("dataFrameVersion", 2);
        message.put("candidates", candidatesToJson(candidates));
        controlSender.send(peer.clientName, message.toString());
    }

    private List<PeerCandidate> gatherHostCandidates() {
        DatagramSocket socket = udpSocket;
        if (socket == null || socket.isClosed()) {
            return List.of();
        }
        List<PeerCandidate> result = new ArrayList<>();
        try {
            for (NetworkInterface ni : Collections.list(NetworkInterface.getNetworkInterfaces())) {
                if (!ni.isUp() || ni.isLoopback() || ni.isVirtual()) {
                    continue;
                }
                for (InetAddress address : Collections.list(ni.getInetAddresses())) {
                    if (!isUsableHostCandidate(address)) {
                        continue;
                    }
                    String host = address.getHostAddress();
                    PeerCandidate candidate = new PeerCandidate();
                    candidate.type = "host";
                    candidate.transport = "udp";
                    candidate.address = host;
                    candidate.port = socket.getLocalPort();
                    candidate.addressFamily = address instanceof Inet6Address ? "IPv6" : "IPv4";
                    candidate.priority = address instanceof Inet6Address ? 1200 : 1000;
                    candidate.foundation = "android-host";
                    result.add(candidate);
                }
            }
        } catch (Exception ignored) {
        }
        result.addAll(serverReflexiveCandidates.values());
        PeerCandidate relay = relayCandidate;
        if (relay != null) {
            result.add(relay);
        }
        return result;
    }

    private void requestPeerServerCandidates() {
        if (!enabled.get() || config == null) {
            return;
        }
        long now = System.currentTimeMillis();
        if (now - lastStunCandidateRequestMillis >= STUN_REQUEST_INTERVAL_MS) {
            lastStunCandidateRequestMillis = now;
            InetSocketAddress stun = stunEndpoint();
            if (stun != null) {
                sendStunBinding(stun, false);
            }
            for (String item : config.publicStunServers == null ? List.<String>of() : config.publicStunServers) {
                InetSocketAddress publicStun = parseStunServer(item);
                if (publicStun != null) {
                    sendStunBinding(publicStun, true);
                }
            }
        }

        InetSocketAddress turn = relayEndpoint();
        if (turn == null) {
            return;
        }
        boolean allocationExpiring = relayAllocationId == null || relayAllocationExpiresAtMillis - now <= RELAY_REFRESH_WINDOW_MS;
        if (!allocationExpiring && now - lastRelayCandidateRequestMillis < 60_000L) {
            return;
        }
        if (allocationExpiring && now - lastRelayCandidateRequestMillis < RELAY_REQUEST_MIN_INTERVAL_MS) {
            return;
        }
        lastRelayCandidateRequestMillis = now;

        if (relayAllocationId != null && relayAllocationExpiresAtMillis - now > RELAY_REFRESH_WINDOW_MS) {
            sendTurnRequest(PendingTurnRequest.refresh(Math.max(30L, config.sessionTtlSeconds)));
            return;
        }
        sendTurnRequest(PendingTurnRequest.allocate());
    }

    private void sendStunBinding(InetSocketAddress endpoint, boolean publicStun) {
        byte[] transactionId = StunMessage.newTransactionId();
        StunMessage request = StunMessage.of(
                StunMessage.BINDING_REQUEST,
                transactionId,
                StunMessage.software("shuai-tunnel-android"));
        PendingStunBinding pending = new PendingStunBinding(
                publicStun,
                publicStun ? "public-stun" : "primary",
                endpoint,
                endpoint,
                request,
                null,
                0,
                System.currentTimeMillis());
        pendingStunBindings.put(request.transactionIdHex(), pending);
        if (!sendStunRequest(request, endpoint)) {
            pendingStunBindings.remove(request.transactionIdHex(), pending);
        }
    }

    private void sendBehaviorProbe(NatBehaviorDiscovery.ProbeRequest probe) {
        if (probe == null || !enabled.get()) {
            return;
        }
        byte[] transactionId = StunMessage.newTransactionId();
        StunMessage request = probe.changeIp() || probe.changePort()
                ? StunMessage.of(
                        StunMessage.BINDING_REQUEST,
                        transactionId,
                        StunMessage.software("shuai-tunnel-android"),
                        StunMessage.changeRequest(probe.changeIp(), probe.changePort()))
                : StunMessage.of(
                        StunMessage.BINDING_REQUEST,
                        transactionId,
                        StunMessage.software("shuai-tunnel-android"));
        PendingStunBinding pending = new PendingStunBinding(
                false,
                probe.probe().name(),
                probe.targetEndpoint(),
                probe.expectedResponseEndpoint(),
                request,
                probe.probe(),
                probe.generation(),
                System.currentTimeMillis());
        String transactionKey = request.transactionIdHex();
        pendingStunBindings.put(transactionKey, pending);
        if (!sendStunRequest(request, probe.targetEndpoint())) {
            pendingStunBindings.remove(transactionKey, pending);
            return;
        }

        Thread timer = new Thread(
                () -> runBehaviorProbeTimer(transactionKey, pending),
                "shuai-peer-nat-behavior");
        timer.setDaemon(true);
        timer.start();
    }

    private void runBehaviorProbeTimer(String transactionKey,
                                       PendingStunBinding pending) {
        long started = System.currentTimeMillis();
        try {
            sleepUntil(started + 250L);
            retryBehaviorProbe(transactionKey, pending);
            sleepUntil(started + 750L);
            retryBehaviorProbe(transactionKey, pending);
            sleepUntil(started + BEHAVIOR_PROBE_TIMEOUT_MS);
            timeoutBehaviorProbe(transactionKey, pending);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    private void retryBehaviorProbe(String transactionKey,
                                    PendingStunBinding pending) {
        if (!enabled.get() || pendingStunBindings.get(transactionKey) != pending) {
            return;
        }
        sendStunRequest(pending.request, pending.targetEndpoint);
    }

    private void timeoutBehaviorProbe(String transactionKey,
                                      PendingStunBinding pending) {
        if (!pendingStunBindings.remove(transactionKey, pending)
                || pending.behaviorProbe == null) {
            return;
        }
        handleNatBehaviorTransition(natBehaviorDiscovery.timedOut(
                pending.behaviorGeneration,
                pending.behaviorProbe));
    }

    private void sleepUntil(long deadlineMillis) throws InterruptedException {
        while (enabled.get()) {
            long remaining = deadlineMillis - System.currentTimeMillis();
            if (remaining <= 0L) {
                return;
            }
            Thread.sleep(remaining);
        }
        throw new InterruptedException("Peer Mesh stopped");
    }

    private boolean sendStunRequest(StunMessage message, InetSocketAddress endpoint) {
        DatagramSocket socket = udpSocket;
        if (socket == null || socket.isClosed() || endpoint == null) {
            return false;
        }
        try {
            byte[] bytes = message.hasAttribute(StunMessage.ATTR_USERNAME)
                    ? message.toBytes(turnMessageIntegrityKey())
                    : message.toBytes();
            socket.send(new DatagramPacket(bytes, bytes.length, endpoint));
            return true;
        } catch (Exception e) {
            publish("Peer STUN failed", e.getMessage());
            return false;
        }
    }

    private void sendTurnRequest(PendingTurnRequest pending) {
        InetSocketAddress turn = relayEndpoint();
        if (pending == null || turn == null) {
            return;
        }
        long now = System.currentTimeMillis();
        removeExpiredTurnRequests();
        byte[] transactionId = StunMessage.newTransactionId();
        StunMessage message = StunMessage.of(
                pending.operation.requestType,
                transactionId,
                authenticatedTurnAttributes(pending.operationAttributes(transactionId)));
        PendingTurnRequest tracked = pending.withEndpointAndCreatedAt(turn, now);
        pendingTurnRequests.put(message.transactionIdHex(), tracked);
        if (!sendStunRequest(message, turn)) {
            pendingTurnRequests.remove(message.transactionIdHex(), tracked);
        }
    }

    private void removeExpiredTurnRequests() {
        long now = System.currentTimeMillis();
		for (Map.Entry<String, PendingTurnRequest> entry : pendingTurnRequests.entrySet()) {
			PendingTurnRequest pending = entry.getValue();
			if (now - pending.createdAtMillis > TURN_REQUEST_TTL_MS
					&& pendingTurnRequests.remove(entry.getKey(), pending)) {
				clearFailedTurnPermission(pending);
			}
		}
		for (TurnChannelBinding binding : new ArrayList<>(turnChannelsByNumber.values())) {
			if (binding.expiresAtMillis <= now) {
				turnChannelsByNumber.remove(binding.channelNumber, binding);
				turnChannelsByPeer.remove(endpointKey(binding.peer), binding);
			}
		}
    }

    private void removeExpiredStunBindings() {
        long now = System.currentTimeMillis();
        pendingStunBindings.entrySet().removeIf(
                entry -> now - entry.getValue().sentAtMillis > TURN_REQUEST_TTL_MS);
    }

    private StunMessage.Attribute[] authenticatedTurnAttributes(StunMessage.Attribute... attributes) {
        TunnelCore.PeerMeshConfig current = config;
        if (current == null
                || isBlank(current.iceUsername)
                || isBlank(current.iceCredential)
                || isBlank(current.iceRealm)
                || isBlank(current.iceNonce)) {
            return attributes;
        }
        List<StunMessage.Attribute> result = new ArrayList<>();
        if (attributes != null) {
            result.addAll(Arrays.asList(attributes));
        }
        result.add(StunMessage.username(current.iceUsername));
        result.add(StunMessage.realm(current.iceRealm));
        result.add(StunMessage.nonce(current.iceNonce));
        return result.toArray(new StunMessage.Attribute[0]);
    }

    private byte[] turnMessageIntegrityKey() throws Exception {
        TunnelCore.PeerMeshConfig current = config;
        if (current == null
                || isBlank(current.iceUsername)
                || isBlank(current.iceCredential)
                || isBlank(current.iceRealm)) {
            return null;
        }
        String text = current.iceUsername + ":" + current.iceRealm + ":" + current.iceCredential;
        return MessageDigest.getInstance("MD5").digest(text.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * 记录并应用对端上报的 key epoch。只有 source 侧携带自己的 epoch；本端作为 source 时
     * 该字段是本端 epoch，不能当作对端值。
     */
    private void applyRemoteKeyEpochFromSignal(JSONObject json) {
        TunnelCore.PeerMeshConfig current = config;
        if (json == null || current == null) {
            return;
        }
        long sourceId = json.optLong("sourceClientId", 0L);
        String epoch = json.optString("sourceKeyEpoch", "");
        if (sourceId <= 0 || sourceId == current.clientId || isBlank(epoch)) {
            return;
        }
        peerKeyEpochs.put(sourceId, epoch);
        PeerSession session = sessions.get(sourceId);
        if (session != null && session.applyRemoteKeyEpoch(epoch)) {
            publish("Peer mesh", "remote key epoch changed, inbound state reset: peer=" + sourceId);
        }
    }

    private PeerSession rememberSession(JSONObject json) {
        long peerId = peerId(json);
        long sessionId = json.optLong("sessionId", 0L);
        String token = json.optString("token", "");
        if (peerId <= 0 || sessionId <= 0 || isBlank(token)) {
            return null;
        }
        if (json.optInt("dataFrameVersion", 0) != 2) {
            publish("Peer session rejected", "dataFrameVersion 2 required");
            return null;
        }
        PeerInfo peer = peers.get(peerId);
        PeerSession previous = sessions.get(peerId);
        PeerSession next = new PeerSession(peerId, sessionId, token, json.optString("expiresAt", ""));
        if (previous != null) {
            next.inheritTransportState(previous);
            sessionsById.remove(previous.sessionId, previous);
        }
        next.setLocalKeyEpoch(localKeyEpoch);
        String signalEpoch = json.optString("sourceKeyEpoch", "");
        if (!isBlank(signalEpoch) && json.optLong("sourceClientId", 0L) == peerId) {
            peerKeyEpochs.put(peerId, signalEpoch);
        }
        String knownEpoch = peerKeyEpochs.get(peerId);
        if (!isBlank(knownEpoch)) {
            next.applyRemoteKeyEpoch(knownEpoch);
        } else if (previous != null) {
            next.applyRemoteKeyEpoch(previous.remoteKeyEpoch);
        }
        if (peer != null) {
            next.setAesKey(deriveSessionKey(next, peer.publicKey));
        }
        sessions.put(peerId, next);
        sessionsById.put(sessionId, next);
        return next;
    }

    private void refreshSessionKeys() {
        for (PeerSession session : sessions.values()) {
            PeerInfo peer = peers.get(session.peerId);
            refreshSessionKey(peer, session);
        }
    }

    private void refreshSessionKey(PeerInfo peer, PeerSession session) {
        if (peer == null || session == null || session.aesKey != null || isBlank(peer.publicKey)) {
            return;
        }
        session.setAesKey(deriveSessionKey(session, peer.publicKey));
    }

    /** 128 bit 随机 epoch，进程内固定、重启后必然变化 */
    private static String newKeyEpoch() {
        byte[] bytes = new byte[16];
        new SecureRandom().nextBytes(bytes);
        StringBuilder result = new StringBuilder(bytes.length * 2);
        for (byte item : bytes) {
            result.append(Character.forDigit((item >>> 4) & 0x0F, 16));
            result.append(Character.forDigit(item & 0x0F, 16));
        }
        return result.toString();
    }

    private byte[] deriveSessionKey(PeerSession session, String peerPublicKeyBase64) {
        TunnelCore.PeerMeshConfig current = config;
        if (current == null || isBlank(peerPublicKeyBase64) || isBlank(keyMaterial.privateKeyBase64)) {
            return null;
        }
        try {
            byte[] shared = PeerCrypto.sharedSecret(keyMaterial.privateKeyBase64, peerPublicKeyBase64);
            byte[] salt = sha256("shuai-peer-mesh\n"
                    + session.sessionId + "\n"
                    + session.token + "\n"
                    + Math.min(current.clientId, session.peerId) + "\n"
                    + Math.max(current.clientId, session.peerId));
            byte[] prk = hmac(salt, shared);
            return hkdfExpand(prk, "shuai-peer-mesh/aes-gcm/v1", 32);
        } catch (Exception e) {
            publish("Peer key failed", e.getMessage());
            return null;
        }
    }

    private PeerInfo peerFromSignal(JSONObject json) {
        if (config == null) {
            return null;
        }
        long sourceId = json.optLong("sourceClientId", 0L);
        long targetId = json.optLong("targetClientId", 0L);
        if (sourceId > 0 && sourceId != config.clientId) {
            return new PeerInfo(sourceId,
                    json.optString("sourceClientName", ""),
                    json.optString("sourceVirtualIp", ""),
                    json.optString("sourcePublicKey", ""),
                    true,
                    false,
                    false,
                    false,
                    false,
                    0L,
                    parseCandidates(json.optJSONArray("candidates")));
        }
        if (targetId > 0 && targetId != config.clientId) {
            return new PeerInfo(targetId,
                    json.optString("targetClientName", ""),
                    json.optString("targetVirtualIp", ""),
                    json.optString("targetPublicKey", ""),
                    true,
                    false,
                    false,
                    false,
                    false,
                    0L,
                    parseCandidates(json.optJSONArray("candidates")));
        }
        return null;
    }

    private long peerId(JSONObject json) {
        if (config == null) {
            return 0L;
        }
        long sourceId = json.optLong("sourceClientId", 0L);
        long targetId = json.optLong("targetClientId", 0L);
        if (sourceId > 0 && sourceId != config.clientId) {
            return sourceId;
        }
        if (targetId > 0 && targetId != config.clientId) {
            return targetId;
        }
        return 0L;
    }

    private void mergePeer(PeerInfo peer, List<PeerCandidate> candidates) {
        if (peer == null || peer.clientId <= 0) {
            return;
        }
        PeerInfo current = peers.get(peer.clientId);
        List<PeerCandidate> nextCandidates = candidates != null && !candidates.isEmpty()
                ? candidates
                : current == null ? peer.candidates : current.candidates;
        PeerInfo merged = new PeerInfo(
                peer.clientId,
                firstText(peer.clientName, current == null ? "" : current.clientName),
                firstText(peer.virtualIp, current == null ? "" : current.virtualIp),
                firstText(peer.publicKey, current == null ? "" : current.publicKey),
                peer.online || (current != null && current.online),
                peer.messageSendCapable || (current != null && current.messageSendCapable),
                peer.messageReceiveCapable || (current != null && current.messageReceiveCapable),
                peer.messageAttachmentsCapable || (current != null && current.messageAttachmentsCapable),
                peer.messageMediaPreviewCapable || (current != null && current.messageMediaPreviewCapable),
                Math.max(peer.messageMaxAttachmentBytes, current == null ? 0L : current.messageMaxAttachmentBytes),
                nextCandidates == null ? List.of() : List.copyOf(nextCandidates));
        peers.put(merged.clientId, merged);
        if (!isBlank(merged.virtualIp)) {
            peersByVirtualIp.put(merged.virtualIp, merged);
        }
        PeerSession session = sessions.get(merged.clientId);
        refreshSessionKey(merged, session);
    }

    private void queuePending(long peerId, byte[] packet) {
        if (packet == null || packet.length == 0) {
            return;
        }
        ArrayDeque<PendingPacket> queue = pendingPackets.computeIfAbsent(peerId, ignored -> new ArrayDeque<>());
        synchronized (queue) {
            long now = System.currentTimeMillis();
            while (!queue.isEmpty() && now - queue.peekFirst().createdAt > PENDING_PACKET_TTL_MS) {
                queue.removeFirst();
            }
            while (queue.size() >= MAX_PENDING_PACKETS) {
                queue.removeFirst();
            }
            queue.addLast(new PendingPacket(packet.clone(), now));
        }
    }

    private void flushPending(long peerId) {
        PeerInfo peer = peers.get(peerId);
        PeerSession session = sessions.get(peerId);
        if (peer == null || session == null || !session.canSend()) {
            return;
        }
        ArrayDeque<PendingPacket> queue = pendingPackets.get(peerId);
        if (queue == null) {
            return;
        }
        List<byte[]> packets = new ArrayList<>();
        synchronized (queue) {
            while (!queue.isEmpty()) {
                PendingPacket packet = queue.removeFirst();
                if (System.currentTimeMillis() - packet.createdAt <= PENDING_PACKET_TTL_MS) {
                    packets.add(packet.bytes);
                }
            }
        }
        for (byte[] packet : packets) {
            sendEncryptedPayload(peer, session, packet);
        }
    }

    private List<PeerCandidate> parseCandidates(JSONArray array) {
        List<PeerCandidate> result = new ArrayList<>();
        if (array == null) {
            return result;
        }
        for (int i = 0; i < array.length(); i++) {
            JSONObject json = array.optJSONObject(i);
            if (json == null) {
                continue;
            }
            PeerCandidate candidate = new PeerCandidate();
            candidate.type = json.optString("type", "");
            candidate.transport = json.optString("transport", "");
            candidate.address = json.optString("address", "");
            candidate.port = json.optInt("port", 0);
            candidate.priority = json.optLong("priority", 0L);
            candidate.foundation = json.optString("foundation", "");
            candidate.relayId = json.optString("relayId", "");
            candidate.addressFamily = json.optString("addressFamily", addressFamily(candidate.address));
            result.add(candidate);
        }
        return result;
    }

    private JSONArray candidatesToJson(List<PeerCandidate> candidates) throws Exception {
        JSONArray array = new JSONArray();
        for (PeerCandidate candidate : candidates) {
            JSONObject json = new JSONObject();
            json.put("type", candidate.type);
            json.put("transport", candidate.transport);
            json.put("address", candidate.address);
            json.put("port", candidate.port);
            json.put("priority", candidate.priority);
            json.put("foundation", candidate.foundation);
            json.put("relayId", candidate.relayId);
            json.put("addressFamily", isBlank(candidate.addressFamily)
                    ? addressFamily(candidate.address) : candidate.addressFamily);
            array.put(json);
        }
        return array;
    }

    private InetSocketAddress firstDirectCandidate(List<PeerCandidate> candidates) {
        List<InetSocketAddress> endpoints = directCandidates(candidates);
        return endpoints.isEmpty() ? null : endpoints.get(0);
    }

    private List<InetSocketAddress> directCandidates(List<PeerCandidate> candidates) {
        if (candidates == null) {
            return List.of();
        }
        java.util.Set<String> localAddresses = new java.util.HashSet<>();
        for (PeerCandidate candidate : serverReflexiveCandidates.values()) {
            if (candidate != null && !isBlank(candidate.address)) {
                localAddresses.add(candidate.address);
            }
        }
        return sortedDirectCandidateEndpoints(candidates, localAddresses);
    }

    /**
     * H-3 + H-6 纯逻辑：先做同 NAT reflexive 降权（priority=1，不剪除），再按 priority 降序排序，
     * 过滤出可用的 UDP direct 端点。抽成静态方法便于单测，不依赖引擎实例状态。
     */
    static List<InetSocketAddress> sortedDirectCandidateEndpoints(List<PeerCandidate> candidates,
                                                                  java.util.Set<String> localAddresses) {
        if (candidates == null) {
            return List.of();
        }
        List<PeerCandidate> sorted = new ArrayList<>(demoteSameNatReflexiveCandidates(candidates, localAddresses));
        sorted.sort((a, b) -> Long.compare(b.priority, a.priority));
        List<InetSocketAddress> result = new ArrayList<>();
        for (PeerCandidate candidate : sorted) {
            if (!"udp".equalsIgnoreCase(candidate.transport)
                    || "relay".equalsIgnoreCase(candidate.type)
                    || isBlank(candidate.address)
                    || candidate.port <= 0) {
                continue;
            }
            result.add(new InetSocketAddress(candidate.address, candidate.port));
        }
        return result;
    }

    /**
     * H-6 纯逻辑：给定本地 STUN 公网地址集合，把与之相同的 reflexive 候选降到 priority=1。
     * 抽成静态方法便于单测，不依赖引擎实例状态。
     */
    static List<PeerCandidate> demoteSameNatReflexiveCandidates(List<PeerCandidate> candidates,
                                                                java.util.Set<String> localAddresses) {
        if (candidates == null || candidates.isEmpty()) {
            return candidates;
        }
        if (localAddresses == null || localAddresses.isEmpty()) {
            return candidates;
        }
        List<PeerCandidate> demoted = new ArrayList<>(candidates.size());
        for (PeerCandidate candidate : candidates) {
            if (candidate != null && isReflexiveCandidate(candidate)
                    && !isBlank(candidate.address)
                    && localAddresses.contains(candidate.address)) {
                PeerCandidate copy = new PeerCandidate();
                copy.type = candidate.type;
                copy.transport = candidate.transport;
                copy.address = candidate.address;
                copy.port = candidate.port;
                copy.priority = 1L;
                copy.foundation = candidate.foundation;
                copy.relayId = candidate.relayId;
                copy.addressFamily = candidate.addressFamily;
                demoted.add(copy);
            } else {
                demoted.add(candidate);
            }
        }
        return demoted;
    }

    /** 判断候选是否为反射型（srflx 或端口映射），同 NAT 检测只针对这类候选。 */
    private static boolean isReflexiveCandidate(PeerCandidate candidate) {
        if ("srflx".equalsIgnoreCase(candidate.type)) {
            return true;
        }
        return candidate.foundation != null && candidate.foundation.startsWith("port-map-");
    }

    private List<PeerCandidate> relayCandidates(List<PeerCandidate> candidates) {
        if (candidates == null) {
            return List.of();
        }
        List<PeerCandidate> result = new ArrayList<>();
        for (PeerCandidate candidate : candidates) {
            if ("relay".equalsIgnoreCase(candidate.type)
                    && "udp".equalsIgnoreCase(candidate.transport)
                    && !isBlank(candidate.relayId)) {
                result.add(candidate);
            }
        }
        return result;
    }

    private String relayFallbackTarget(PeerInfo peer, PeerSession session) {
        if (session == null) {
            return "";
        }
        if (!isBlank(session.relayTargetAllocationId)) {
            return session.relayTargetAllocationId;
        }
        if (session.hasHealthyDirect(System.currentTimeMillis())) {
            return "";
        }
        for (PeerCandidate candidate : relayCandidates(peer == null ? null : peer.candidates)) {
            if (!isBlank(candidate.relayId)) {
                return candidate.relayId;
            }
        }
        return "";
    }

    private boolean sendRelayPayload(String targetRelayEndpoint, byte[] payload) {
        if (isBlank(relayAllocationId) || isBlank(targetRelayEndpoint) || payload == null) {
            return false;
        }
        InetSocketAddress turn = relayEndpoint();
        InetSocketAddress peer = parseEndpoint(targetRelayEndpoint);
        DatagramSocket socket = udpSocket;
        if (turn == null || peer == null || socket == null || socket.isClosed()) {
            return false;
        }
        try {
            ensureTurnPermission(peer);
			TurnChannelBinding binding = ensureTurnChannel(peer);
			if (binding != null && binding.active && binding.expiresAtMillis > System.currentTimeMillis()) {
				byte[] channelData = TurnChannelData.encode(binding.channelNumber, payload);
				socket.send(new DatagramPacket(channelData, channelData.length, turn));
				return true;
			}
            byte[] transactionId = StunMessage.newTransactionId();
            byte[] bytes = StunMessage.of(
                    StunMessage.SEND_INDICATION,
                    transactionId,
                    StunMessage.xorPeerAddress(peer, transactionId),
                    StunMessage.data(payload)).toBytes();
            socket.send(new DatagramPacket(bytes, bytes.length, turn));
            return true;
        } catch (Exception e) {
            publish("Peer relay failed", e.getMessage());
            return false;
        }
    }

	private TurnChannelBinding ensureTurnChannel(InetSocketAddress peer) {
		if (peer == null || relayEndpoint() == null) {
			return null;
		}
		long now = System.currentTimeMillis();
		String peerKey = endpointKey(peer);
		TurnChannelBinding existing = turnChannelsByPeer.get(peerKey);
		if (existing != null && existing.expiresAtMillis - now > 30_000L) {
			return existing;
		}
		int channel = allocateTurnChannel(now);
		if (channel == 0) {
			return null;
		}
		TurnChannelBinding binding = new TurnChannelBinding(channel, peer, now + TURN_REQUEST_TTL_MS);
		turnChannelsByPeer.put(peerKey, binding);
		turnChannelsByNumber.put(channel, binding);
		sendTurnRequest(PendingTurnRequest.channelBind(peer, channel));
		return binding;
	}

	private synchronized int allocateTurnChannel(long now) {
		int start = (int) nextTurnChannel.get();
		if (start < TurnChannelData.MIN_CHANNEL || start > TurnChannelData.MAX_CHANNEL) {
			start = TurnChannelData.MIN_CHANNEL;
		}
		int channel = start;
		do {
			TurnChannelBinding binding = turnChannelsByNumber.get(channel);
			if (binding == null || binding.expiresAtMillis <= now) {
				nextTurnChannel.set(channel == TurnChannelData.MAX_CHANNEL
						? TurnChannelData.MIN_CHANNEL : channel + 1L);
				return channel;
			}
			channel = channel == TurnChannelData.MAX_CHANNEL ? TurnChannelData.MIN_CHANNEL : channel + 1;
		} while (channel != start);
		return 0;
	}

    private void ensureTurnPermission(InetSocketAddress peer) {
        InetSocketAddress turn = relayEndpoint();
        if (peer == null || turn == null) {
            return;
        }
        long now = System.currentTimeMillis();
        String key = endpointKey(peer);
        Long expiresAt = turnPermissions.get(key);
        if (expiresAt != null && expiresAt - now > 30_000L) {
            return;
        }
        sendTurnRequest(PendingTurnRequest.createPermission(peer));
        turnPermissions.put(key, now + TURN_PERMISSION_TTL_MS);
    }

    private InetSocketAddress stunEndpoint() {
        TunnelCore.PeerMeshConfig current = config;
        if (current == null) {
            return null;
        }
        String host = isBlank(current.stunHost) ? current.turnHost : current.stunHost;
        int port = current.stunPort > 0 ? current.stunPort : current.turnPort;
        if (isBlank(host) || port <= 0) {
            return null;
        }
        return new InetSocketAddress(host, port);
    }

    private InetSocketAddress relayEndpoint() {
        TunnelCore.PeerMeshConfig current = config;
        if (current == null || isBlank(current.turnHost) || current.turnPort <= 0) {
            return null;
        }
        return new InetSocketAddress(current.turnHost, current.turnPort);
    }

    private InetSocketAddress parseStunServer(String value) {
        if (isBlank(value)) {
            return null;
        }
        String normalized = value.trim();
        String lower = normalized.toLowerCase(Locale.ROOT);
        if (lower.startsWith("stun://")) {
            normalized = normalized.substring("stun://".length());
        } else if (lower.startsWith("stun:")) {
            normalized = normalized.substring("stun:".length());
        }
        return parseHostPort(normalized, 3478, false);
    }

    private InetSocketAddress parseEndpoint(String value) {
        if (isBlank(value)) {
            return null;
        }
        String normalized = value.trim();
        if (normalized.startsWith("turn:")) {
            normalized = normalized.substring("turn:".length());
        }
        return parseHostPort(normalized, 0, true);
    }

    private String endpointKey(InetSocketAddress endpoint) {
        if (endpoint == null) {
            return "";
        }
        String host = endpoint.getAddress() == null ? endpoint.getHostString() : endpoint.getAddress().getHostAddress();
        return host.contains(":") ? "[" + host + "]:" + endpoint.getPort() : host + ":" + endpoint.getPort();
    }

    static boolean sameEndpoint(InetSocketAddress expected, InetSocketAddress actual) {
        if (expected == null || actual == null || expected.getPort() != actual.getPort()) {
            return false;
        }
        if (expected.getAddress() != null && actual.getAddress() != null) {
            return expected.getAddress().equals(actual.getAddress());
        }
        return expected.getHostString().equalsIgnoreCase(actual.getHostString());
    }

    private String candidateEndpointKey(PeerCandidate candidate) {
        if (candidate == null) {
            return "";
        }
        return candidate.type + ":" + candidate.address + ":" + candidate.port;
    }

    private void reportPath(PeerSession session, String pathType, String localEndpoint,
                            String remoteEndpoint, long rttMillis) {
        TunnelCore.PeerMeshConfig current = config;
        if (session == null || current == null) {
            return;
        }
        try {
            JSONObject report = basePeerReport("path-report", session);
            report.put("pathType", pathType);
            report.put("status", "ACTIVE");
            report.put("localEndpoint", localEndpoint);
            report.put("remoteEndpoint", remoteEndpoint);
            if (rttMillis >= 0) {
                report.put("rttMillis", rttMillis);
            }
            controlSender.send("", report.toString());
        } catch (Exception e) {
            publish("Peer path report failed", e.getMessage());
        }
    }

    private void reportTrafficDeltas() {
        TunnelCore.PeerMeshConfig current = config;
        if (current == null) {
            return;
        }
        for (PeerSession session : sessions.values()) {
            long directBytes = session.drainDirectBytes();
            if (directBytes <= 0) {
                continue;
            }
            try {
                JSONObject report = basePeerReport("traffic-report", session);
                report.put("directBytes", directBytes);
                controlSender.send("", report.toString());
            } catch (Exception e) {
                session.addDirectBytes(directBytes);
                publish("Peer traffic report failed", e.getMessage());
            }
        }
    }

    private JSONObject basePeerReport(String type, PeerSession session) throws Exception {
        TunnelCore.PeerMeshConfig current = config;
        JSONObject report = new JSONObject();
        report.put("type", type);
        report.put("sessionId", session.sessionId);
        report.put("sourceClientId", current == null ? 0L : current.clientId);
        report.put("sourceClientName", current == null ? "" : current.clientName);
        report.put("sourceVirtualIp", current == null ? "" : current.virtualIp);
        report.put("sourcePublicKey", keyMaterial.publicKeyBase64);
        report.put("targetClientId", session.peerId);
        PeerInfo peer = peers.get(session.peerId);
        report.put("targetClientName", peer == null ? "" : peer.clientName);
        report.put("targetVirtualIp", peer == null ? "" : peer.virtualIp);
        report.put("targetPublicKey", peer == null ? "" : peer.publicKey);
        report.put("createdAtMillis", System.currentTimeMillis());
        return report;
    }

    private void reportDevice(String statusText, String error) {
        TunnelCore.PeerMeshConfig current = config;
        if (current == null) {
            return;
        }
        try {
            JSONObject report = new JSONObject();
            report.put("type", "device-report");
            report.put("sourceClientId", current.clientId);
            report.put("sourceClientName", current.clientName);
            report.put("sourceVirtualIp", current.virtualIp);
            report.put("sourcePublicKey", keyMaterial.publicKeyBase64);
            report.put("virtualDeviceMode", "android-vpn");
            report.put("virtualDeviceName", "shuai-tunnel");
            report.put("virtualDeviceStatus", statusText);
            report.put("virtualDeviceError", error == null ? "" : error);
            report.put("natType", natTypeText());
            report.put("natMappingBehavior", natMappingBehavior);
            report.put("natFilteringBehavior", natFilteringBehavior);
            report.put("natBehaviorDiscovery", natBehaviorDiscoveryMode);
            report.put("lastEndpoint", lastEndpointText());
            report.put("createdAtMillis", System.currentTimeMillis());
            controlSender.send("", report.toString());
            lastDeviceReportMillis = System.currentTimeMillis();
        } catch (Exception e) {
            publish("Peer device report failed", e.getMessage());
        }
    }

    private void reportDeviceIfDue() {
        if (System.currentTimeMillis() - lastDeviceReportMillis >= REPORT_INTERVAL_MS) {
            reportDevice("ACTIVE", "");
        }
    }

    private String natTypeText() {
        if (!isBlank(natType)) {
            return natType;
        }
        if (!serverReflexiveCandidates.isEmpty()) {
            return "SERVER_REFLEXIVE";
        }
        return "UNKNOWN";
    }

    private String lastEndpointText() {
        if (!isBlank(lastEndpoint)) {
            return lastEndpoint;
        }
        for (PeerCandidate candidate : serverReflexiveCandidates.values()) {
            if (!isBlank(candidate.address) && candidate.port > 0) {
                return candidate.address + ":" + candidate.port;
            }
        }
        if (!isBlank(relayAllocationId)) {
            return relayAllocationId;
        }
        DatagramSocket socket = udpSocket;
        return socket == null || socket.isClosed() ? "" : "0.0.0.0:" + socket.getLocalPort();
    }

    private String localEndpointText(String pathType) {
        if ("RELAY".equals(pathType) && !isBlank(relayAllocationId)) {
            return relayAllocationId;
        }
        DatagramSocket socket = udpSocket;
        return socket == null || socket.isClosed() ? "" : "0.0.0.0:" + socket.getLocalPort();
    }

    private void removeExpiredSessions() {
        long now = System.currentTimeMillis();
        for (Iterator<Map.Entry<Long, PeerSession>> it = sessions.entrySet().iterator(); it.hasNext(); ) {
            Map.Entry<Long, PeerSession> entry = it.next();
            PeerSession session = entry.getValue();
            if (session != null && session.isExpired(now)) {
                it.remove();
                sessionsById.remove(session.sessionId);
                pendingPackets.remove(entry.getKey());
            }
        }
    }

    private void keepaliveActivePaths() {
        for (PeerSession session : sessions.values()) {
            if (session == null || session.isExpired(System.currentTimeMillis())) {
                continue;
            }
            PeerInfo peer = peers.get(session.peerId);
            if (peer != null && peer.online) {
                preparePath(peer, session);
            }
        }
    }

    private static long smoothRtt(long previous, long sample) {
        if (sample < 0) {
            return previous;
        }
        if (previous == Long.MAX_VALUE) {
            return sample;
        }
        return ((previous * 3L) + sample) / 4L;
    }

    private boolean isIgnoredTarget(String ip) {
        if (isBlank(ip) || config == null || ip.equals(config.virtualIp) || "255.255.255.255".equals(ip)) {
            return true;
        }
        Long value = ipv4ToLong(ip);
        if (value == null) {
            return true;
        }
        int first = (int) ((value >>> 24) & 0xFF);
        return first == 0 || first >= 224;
    }

    private JSONObject tryJson(byte[] data) {
        try {
            return new JSONObject(new String(data, StandardCharsets.UTF_8));
        } catch (Exception ignored) {
            return null;
        }
    }

    private void stop() {
        reportDevice("STOPPED", "");
        enabled.set(false);
        Thread maintenance = maintenanceThread;
        maintenanceThread = null;
        if (maintenance != null) {
            maintenance.interrupt();
        }
        peers.clear();
        peersByVirtualIp.clear();
        sessions.clear();
        sessionsById.clear();
        pendingPackets.clear();
        for (PendingAppMessageAck pending : pendingMessageAcks.values()) {
            pending.latch.countDown();
        }
        pendingMessageAcks.clear();
        pathMtuCache.clear();
        serverReflexiveCandidates.clear();
        pendingStunBindings.clear();
        pendingTurnRequests.clear();
        turnPermissions.clear();
		turnChannelsByPeer.clear();
		turnChannelsByNumber.clear();
		nextTurnChannel.set(TurnChannelData.MIN_CHANNEL);
        relayCandidate = null;
        relayAllocationId = null;
        relayAllocationExpiresAtMillis = 0L;
        lastStunCandidateRequestMillis = 0L;
        lastRelayCandidateRequestMillis = 0L;
        lastBehaviorDiscoveryStartedMillis = 0L;
        natType = "";
        natMappingBehavior = "";
        natFilteringBehavior = "";
        natBehaviorDiscoveryMode = "";
        lastEndpoint = "";
        DatagramSocket socket = udpSocket;
        udpSocket = null;
        if (socket != null) {
            socket.close();
        }
        if (vpnPlatform != null) {
            vpnPlatform.stopVpn();
        }
    }

    @Override
    public void close() {
        stop();
        pathMtuScheduler.shutdownNow();
    }

    private void publish(String text, String detail) {
        if (status != null) {
            status.publish(text, detail == null ? "" : detail, true);
        }
    }

    private static String firstText(String value, String fallback) {
        return isBlank(value) ? (fallback == null ? "" : fallback) : value;
    }

    static boolean isUsableHostCandidate(InetAddress address) {
        if (address == null || address.isAnyLocalAddress() || address.isLoopbackAddress()
                || address.isLinkLocalAddress() || address.isMulticastAddress()) {
            return false;
        }
        if (address instanceof Inet4Address) {
            return true;
        }
        if (!(address instanceof Inet6Address)) {
            return false;
        }
        byte[] bytes = address.getAddress();
        return (bytes[0] & 0xfe) != 0xfc;
    }

    static InetSocketAddress parseHostPort(String value, int defaultPort, boolean requirePort) {
        if (isBlank(value)) {
            return null;
        }
        String normalized = value.trim();
        String host;
        int port = defaultPort;
        if (normalized.startsWith("[")) {
            int end = normalized.indexOf(']');
            if (end <= 1) {
                return null;
            }
            host = normalized.substring(1, end);
            if (normalized.length() > end + 1) {
                if (normalized.charAt(end + 1) != ':' || normalized.length() <= end + 2) {
                    return null;
                }
                try {
                    port = Integer.parseInt(normalized.substring(end + 2));
                } catch (NumberFormatException ignored) {
                    return null;
                }
            } else if (requirePort) {
                return null;
            }
        } else {
            int firstColon = normalized.indexOf(':');
            int lastColon = normalized.lastIndexOf(':');
            if (firstColon > 0 && firstColon == lastColon) {
                host = normalized.substring(0, firstColon);
                try {
                    port = Integer.parseInt(normalized.substring(firstColon + 1));
                } catch (NumberFormatException ignored) {
                    return null;
                }
            } else {
                host = normalized;
                if (requirePort) {
                    return null;
                }
            }
        }
        return isBlank(host) || port <= 0 || port > 65535 ? null : new InetSocketAddress(host, port);
    }

    private static String addressFamily(String address) {
        return isBlank(address) ? "" : address.contains(":") ? "IPv6" : "IPv4";
    }

    private static boolean isBlank(String value) {
        return value == null || value.trim().isEmpty();
    }

    private static boolean equals(String left, String right) {
        return left == null ? right == null : left.equals(right);
    }

    private static Long ipv4ToLong(String ip) {
        if (isBlank(ip)) {
            return null;
        }
        String[] parts = ip.split("\\.", -1);
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

    private static byte[] sha256(String value) throws Exception {
        return java.security.MessageDigest.getInstance("SHA-256")
                .digest(value.getBytes(StandardCharsets.UTF_8));
    }

    private static byte[] hmac(byte[] key, byte[] data) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(key, "HmacSHA256"));
        return mac.doFinal(data);
    }

    private static byte[] hkdfExpand(byte[] prk, String info, int length) throws Exception {
        byte[] infoBytes = info.getBytes(StandardCharsets.UTF_8);
        byte[] result = new byte[length];
        byte[] previous = new byte[0];
        int copied = 0;
        int counter = 1;
        while (copied < length) {
            ByteBuffer input = ByteBuffer.allocate(previous.length + infoBytes.length + 1);
            input.put(previous);
            input.put(infoBytes);
            input.put((byte) counter);
            previous = hmac(prk, input.array());
            int count = Math.min(previous.length, length - copied);
            System.arraycopy(previous, 0, result, copied, count);
            copied += count;
            counter++;
        }
        return result;
    }

    interface ControlSender {
        void send(String toClientName, String message) throws Exception;
    }

    interface StatusPublisher {
        void publish(String status, String detail, boolean running);
    }

    private static final class PeerInfo {
        final long clientId;
        final String clientName;
        final String virtualIp;
        final String publicKey;
        final boolean online;
        final boolean messageSendCapable;
        final boolean messageReceiveCapable;
        final boolean messageAttachmentsCapable;
        final boolean messageMediaPreviewCapable;
        final long messageMaxAttachmentBytes;
        final List<PeerCandidate> candidates;

        PeerInfo(long clientId, String clientName, String virtualIp, String publicKey,
                 boolean online,
                 boolean messageSendCapable,
                 boolean messageReceiveCapable,
                 boolean messageAttachmentsCapable,
                 boolean messageMediaPreviewCapable,
                 long messageMaxAttachmentBytes,
                 List<PeerCandidate> candidates) {
            this.clientId = clientId;
            this.clientName = clientName;
            this.virtualIp = virtualIp;
            this.publicKey = publicKey;
            this.online = online;
            this.messageSendCapable = messageSendCapable;
            this.messageReceiveCapable = messageReceiveCapable;
            this.messageAttachmentsCapable = messageAttachmentsCapable;
            this.messageMediaPreviewCapable = messageMediaPreviewCapable;
            this.messageMaxAttachmentBytes = messageMaxAttachmentBytes;
            this.candidates = candidates == null ? List.of() : candidates;
        }
    }

    static final class PeerCandidate {
        String type;
        String transport;
        String address;
        int port;
        long priority;
        String foundation;
        String relayId;
        String addressFamily;
    }

    private static final class PathMtuCacheEntry {
        final int innerMtu;
        final long validUntilMillis;

        PathMtuCacheEntry(int innerMtu, long validUntilMillis) {
            this.innerMtu = innerMtu;
            this.validUntilMillis = validUntilMillis;
        }
    }

    static final class PeerSession {
        final long peerId;
        final long sessionId;
        final String token;
        final String expiresAt;
        final long createdAtMillis = System.currentTimeMillis();
        final AtomicLong sequence = new AtomicLong();
        final AtomicLong directBytesSinceReport = new AtomicLong();
        final PeerPathMtu.Discovery pathMtu = new PeerPathMtu.Discovery();
        volatile ReplayWindow replay = new ReplayWindow();
        volatile byte[] aesKey;
        /** 本端本次运行实例的 SPM2 key epoch，绑定出站 traffic key */
        volatile String localKeyEpoch = "";
        /** 对端最近上报的 epoch，绑定入站 traffic key；未知时无法解密 */
        volatile String remoteKeyEpoch = "";
        volatile DataFrameCodec.TrafficCodec outboundCodec;
        volatile DataFrameCodec.TrafficCodec inboundCodec;
        volatile InetSocketAddress remoteEndpoint;
        volatile String relayTargetAllocationId = "";
        volatile long lastDirectSuccessMillis;
        volatile long lastRelaySuccessMillis;
        volatile long lastPathReportMillis;
        volatile String lastPathRemoteText = "";
        volatile String currentPathType = "";
        volatile long bestDirectRtt = Long.MAX_VALUE;
        volatile long bestRelayRtt = Long.MAX_VALUE;
        volatile boolean pathReady;

        PeerSession(long peerId, long sessionId, String token, String expiresAt) {
            this.peerId = peerId;
            this.sessionId = sessionId;
            this.token = token;
            this.expiresAt = expiresAt;
        }

        void inheritTransportState(PeerSession previous) {
            if (previous == null) {
                return;
            }
            if (previous.sessionId == sessionId) {
                sequence.set(previous.sequence.get());
                synchronized (previous) {
                    replay = previous.replay.copy();
                }
            }
            remoteEndpoint = previous.remoteEndpoint;
            relayTargetAllocationId = previous.relayTargetAllocationId;
            pathReady = previous.pathReady;
            directBytesSinceReport.addAndGet(previous.drainDirectBytes());
            lastDirectSuccessMillis = previous.lastDirectSuccessMillis;
            lastRelaySuccessMillis = previous.lastRelaySuccessMillis;
            lastPathReportMillis = previous.lastPathReportMillis;
            lastPathRemoteText = previous.lastPathRemoteText;
            currentPathType = previous.currentPathType;
            bestDirectRtt = previous.bestDirectRtt;
            bestRelayRtt = previous.bestRelayRtt;
        }

        long nextSequence() {
            return sequence.incrementAndGet();
        }

        boolean canSend() {
            return aesKey != null && remoteEndpoint != null && pathReady && !isExpired();
        }

        synchronized void setLocalKeyEpoch(String epoch) {
            if (epoch == null || epoch.isEmpty() || epoch.equals(localKeyEpoch)) {
                return;
            }
            localKeyEpoch = epoch;
            outboundCodec = null;
        }

        /**
         * 对端 epoch 变化说明它重启并从 sequence=1 重新发送，必须同时丢弃入站 codec 缓存
         * 和 replay window，否则新帧会被旧窗口当作重放拒绝。
         */
        synchronized boolean applyRemoteKeyEpoch(String epoch) {
            if (epoch == null || epoch.isEmpty() || epoch.equals(remoteKeyEpoch)) {
                return false;
            }
            boolean changed = !remoteKeyEpoch.isEmpty();
            remoteKeyEpoch = epoch;
            inboundCodec = null;
            replay = new ReplayWindow();
            return changed;
        }

        synchronized void setAesKey(byte[] nextKey) {
            if (!Arrays.equals(aesKey, nextKey)) {
                aesKey = nextKey;
                outboundCodec = null;
                inboundCodec = null;
            }
        }

        synchronized boolean ensureTrafficCodecs(long localClientId) {
            if (aesKey == null || aesKey.length != 32
                    || localKeyEpoch == null || localKeyEpoch.isEmpty()
                    || remoteKeyEpoch == null || remoteKeyEpoch.isEmpty()) {
                return false;
            }
            if (outboundCodec != null && inboundCodec != null) {
                return true;
            }
            try {
                outboundCodec = DataFrameCodec.trafficCodec(
                        aesKey, sessionId, localClientId, peerId, localKeyEpoch);
                inboundCodec = DataFrameCodec.trafficCodec(
                        aesKey, sessionId, peerId, localClientId, remoteKeyEpoch);
                return true;
            } catch (Exception ignored) {
                outboundCodec = null;
                inboundCodec = null;
                return false;
            }
        }

        boolean isExpired() {
            return isExpired(System.currentTimeMillis());
        }

        boolean isExpired(long nowMillis) {
            if (isBlank(expiresAt)) {
                return false;
            }
            try {
                return Instant.parse(expiresAt).toEpochMilli() <= nowMillis;
            } catch (Exception ignored) {
                return false;
            }
        }

        boolean shouldRefresh(long nowMillis) {
            long expiresAtMillis = expiresAtMillis();
            if (expiresAtMillis == Long.MAX_VALUE) {
                return false;
            }
            long lifetimeMillis = Math.max(0L, expiresAtMillis - createdAtMillis);
            long window = Math.min(
                    SESSION_REFRESH_MAX_WINDOW_MS,
                    Math.max(SESSION_REFRESH_MIN_WINDOW_MS, lifetimeMillis / 4L));
            return expiresAtMillis - nowMillis <= window;
        }

        boolean hasHealthyDirect(long nowMillis) {
            return lastDirectSuccessMillis > 0L && nowMillis - lastDirectSuccessMillis <= DIRECT_STALE_MS;
        }

        void addDirectBytes(long bytes) {
            if (bytes > 0) {
                directBytesSinceReport.addAndGet(bytes);
            }
        }

        long drainDirectBytes() {
            return directBytesSinceReport.getAndSet(0L);
        }

        synchronized boolean accept(DataFrame frame) {
            return frame != null && replay.accept(frame.sequence);
        }

        boolean accept(long inboundSequence) {
            return accept(new DataFrame(sessionId, inboundSequence, new byte[0]));
        }

        private long expiresAtMillis() {
            if (isBlank(expiresAt)) {
                return Long.MAX_VALUE;
            }
            try {
                return Instant.parse(expiresAt).toEpochMilli();
            } catch (Exception ignored) {
                return Long.MAX_VALUE;
            }
        }
    }

    private static final class PendingStunBinding {
        final boolean publicStun;
        final String role;
        final InetSocketAddress targetEndpoint;
        final InetSocketAddress expectedResponseEndpoint;
        final StunMessage request;
        final NatBehaviorDiscovery.Probe behaviorProbe;
        final int behaviorGeneration;
        final long sentAtMillis;

        PendingStunBinding(boolean publicStun,
                           String role,
                           InetSocketAddress targetEndpoint,
                           InetSocketAddress expectedResponseEndpoint,
                           StunMessage request,
                           NatBehaviorDiscovery.Probe behaviorProbe,
                           int behaviorGeneration,
                           long sentAtMillis) {
            this.publicStun = publicStun;
            this.role = role == null ? "" : role;
            this.targetEndpoint = targetEndpoint;
            this.expectedResponseEndpoint = expectedResponseEndpoint;
            this.request = request;
            this.behaviorProbe = behaviorProbe;
            this.behaviorGeneration = behaviorGeneration;
            this.sentAtMillis = sentAtMillis;
        }
    }

    enum TurnOperation {
        ALLOCATE(StunMessage.ALLOCATE_REQUEST),
        REFRESH(StunMessage.REFRESH_REQUEST),
		CREATE_PERMISSION(StunMessage.CREATE_PERMISSION_REQUEST),
		CHANNEL_BIND(StunMessage.CHANNEL_BIND_REQUEST);

        final int requestType;

        TurnOperation(int requestType) {
            this.requestType = requestType;
        }
    }

    static final class PendingTurnRequest {
        final TurnOperation operation;
        final long lifetimeSeconds;
        final InetSocketAddress peer;
        final InetSocketAddress endpoint;
		final int channelNumber;
        final boolean retried;
        final long createdAtMillis;

        private PendingTurnRequest(TurnOperation operation, long lifetimeSeconds,
                                   InetSocketAddress peer, InetSocketAddress endpoint,
								   int channelNumber, boolean retried, long createdAtMillis) {
            this.operation = operation;
            this.lifetimeSeconds = lifetimeSeconds;
            this.peer = peer;
            this.endpoint = endpoint;
			this.channelNumber = channelNumber;
            this.retried = retried;
            this.createdAtMillis = createdAtMillis;
        }

        static PendingTurnRequest allocate() {
			return new PendingTurnRequest(TurnOperation.ALLOCATE, 0L, null, null, 0, false, 0L);
        }

        static PendingTurnRequest refresh(long lifetimeSeconds) {
			return new PendingTurnRequest(TurnOperation.REFRESH, lifetimeSeconds, null, null, 0, false, 0L);
        }

        static PendingTurnRequest createPermission(InetSocketAddress peer) {
			return new PendingTurnRequest(TurnOperation.CREATE_PERMISSION, 0L, peer, null, 0, false, 0L);
        }

		static PendingTurnRequest channelBind(InetSocketAddress peer, int channelNumber) {
			return new PendingTurnRequest(TurnOperation.CHANNEL_BIND, 0L, peer, null,
					channelNumber, false, 0L);
		}

        PendingTurnRequest retryOnce() {
            if (retried) {
                return null;
            }
			return new PendingTurnRequest(operation, lifetimeSeconds, peer, endpoint, channelNumber, true, 0L);
        }

        PendingTurnRequest withEndpointAndCreatedAt(InetSocketAddress endpoint, long createdAtMillis) {
			return new PendingTurnRequest(operation, lifetimeSeconds, peer, endpoint,
					channelNumber, retried, createdAtMillis);
        }

        StunMessage.Attribute[] operationAttributes(byte[] transactionId) {
            switch (operation) {
                case ALLOCATE:
                    return new StunMessage.Attribute[]{StunMessage.requestedUdpTransportAttribute()};
                case REFRESH:
                    return new StunMessage.Attribute[]{StunMessage.lifetime(lifetimeSeconds)};
                case CREATE_PERMISSION:
                    return new StunMessage.Attribute[]{StunMessage.xorPeerAddress(peer, transactionId)};
				case CHANNEL_BIND:
					return new StunMessage.Attribute[]{
							StunMessage.channelNumber(channelNumber),
							StunMessage.xorPeerAddress(peer, transactionId)};
                default:
                    throw new IllegalStateException("unsupported TURN operation");
            }
        }
    }

	static final class TurnChannelBinding {
		final int channelNumber;
		final InetSocketAddress peer;
		volatile long expiresAtMillis;
		volatile boolean active;

		TurnChannelBinding(int channelNumber, InetSocketAddress peer, long expiresAtMillis) {
			this.channelNumber = channelNumber;
			this.peer = peer;
			this.expiresAtMillis = expiresAtMillis;
		}
	}

	static final class TurnChannelData {
		static final int MIN_CHANNEL = 0x4000;
		static final int MAX_CHANNEL = 0x7FFF;
		final int channelNumber;
		final byte[] payload;

		private TurnChannelData(int channelNumber, byte[] payload) {
			this.channelNumber = channelNumber;
			this.payload = payload;
		}

		static TurnChannelData parse(byte[] packet) {
			if (packet == null || packet.length < 4) {
				return null;
			}
			int channel = Short.toUnsignedInt(ByteBuffer.wrap(packet, 0, 2).getShort());
			if (channel < MIN_CHANNEL || channel > MAX_CHANNEL) {
				return null;
			}
			int payloadLength = Short.toUnsignedInt(ByteBuffer.wrap(packet, 2, 2).getShort());
			int end = 4 + payloadLength;
			if (end > packet.length || packet.length - end > 3) {
				return null;
			}
			for (int index = end; index < packet.length; index++) {
				if (packet[index] != 0) {
					return null;
				}
			}
			return new TurnChannelData(channel, Arrays.copyOfRange(packet, 4, end));
		}

		static byte[] encode(int channel, byte[] payload) {
			byte[] body = payload == null ? new byte[0] : payload;
			if (channel < MIN_CHANNEL || channel > MAX_CHANNEL || body.length > 0xFFFF) {
				throw new IllegalArgumentException("invalid TURN ChannelData");
			}
			int padding = (4 - body.length % 4) % 4;
			return ByteBuffer.allocate(4 + body.length + padding)
					.putShort((short) channel)
					.putShort((short) body.length)
					.put(body)
					.array();
		}
	}

    static final class TurnChallenge {
        final int code;
        final String reason;
        final String realm;
        final String nonce;

        private TurnChallenge(int code, String reason, String realm, String nonce) {
            this.code = code;
            this.reason = reason;
            this.realm = realm;
            this.nonce = nonce;
        }

        static TurnChallenge from(StunMessage message) {
            if (message == null) {
                return null;
            }
            int code = message.errorCode();
            if (code <= 0) {
                return null;
            }
            return new TurnChallenge(
                    code,
                    message.errorReason(),
                    message.textAttribute(StunMessage.ATTR_REALM),
                    message.textAttribute(StunMessage.ATTR_NONCE));
        }

        boolean retryable() {
            return code == 401 || code == 438;
        }

        boolean applyTo(TunnelCore.PeerMeshConfig config) {
            if (!retryable() || config == null || isBlank(nonce)) {
                return false;
            }
            if (!isBlank(realm)) {
                config.iceRealm = realm;
            }
            config.iceNonce = nonce;
            return !isBlank(config.iceUsername)
                    && !isBlank(config.iceCredential)
                    && !isBlank(config.iceRealm);
        }
    }

    private static final class PendingPacket {
        final byte[] bytes;
        final long createdAt;

        PendingPacket(byte[] bytes, long createdAt) {
            this.bytes = bytes;
            this.createdAt = createdAt;
        }
    }

    static final class ClientMessageSendResult {
        final String messageId;
        final String transport;

        ClientMessageSendResult(String messageId, String transport) {
            this.messageId = messageId;
            this.transport = transport;
        }
    }

    private static final class PendingAppMessageAck {
        final CountDownLatch latch = new CountDownLatch(1);
        volatile boolean delivered;
    }

    static final class StunMessage {
        static final int MAGIC_COOKIE = 0x2112A442;
        static final int HEADER_BYTES = 20;
        static final int TRANSACTION_ID_BYTES = 12;
        static final int BINDING_REQUEST = 0x0001;
        static final int BINDING_SUCCESS = 0x0101;
        static final int BINDING_ERROR = 0x0111;
        static final int ALLOCATE_REQUEST = 0x0003;
        static final int ALLOCATE_SUCCESS = 0x0103;
        static final int ALLOCATE_ERROR = 0x0113;
        static final int REFRESH_REQUEST = 0x0004;
        static final int REFRESH_SUCCESS = 0x0104;
        static final int REFRESH_ERROR = 0x0114;
        static final int CREATE_PERMISSION_REQUEST = 0x0008;
        static final int CREATE_PERMISSION_SUCCESS = 0x0108;
        static final int CREATE_PERMISSION_ERROR = 0x0118;
		static final int CHANNEL_BIND_REQUEST = 0x0009;
		static final int CHANNEL_BIND_SUCCESS = 0x0109;
		static final int CHANNEL_BIND_ERROR = 0x0119;
        static final int SEND_INDICATION = 0x0016;
        static final int DATA_INDICATION = 0x0017;
        static final int ATTR_MAPPED_ADDRESS = 0x0001;
        static final int ATTR_CHANGE_REQUEST = 0x0003;
        static final int ATTR_USERNAME = 0x0006;
        static final int ATTR_MESSAGE_INTEGRITY = 0x0008;
        static final int ATTR_ERROR_CODE = 0x0009;
        static final int ATTR_UNKNOWN_ATTRIBUTES = 0x000A;
        static final int ATTR_LIFETIME = 0x000D;
		static final int ATTR_CHANNEL_NUMBER = 0x000C;
        static final int ATTR_XOR_PEER_ADDRESS = 0x0012;
        static final int ATTR_DATA = 0x0013;
        static final int ATTR_REALM = 0x0014;
        static final int ATTR_NONCE = 0x0015;
        static final int ATTR_XOR_RELAYED_ADDRESS = 0x0016;
        static final int ATTR_REQUESTED_TRANSPORT = 0x0019;
        static final int ATTR_XOR_MAPPED_ADDRESS = 0x0020;
        static final int ATTR_SOFTWARE = 0x8022;
        static final int ATTR_RESPONSE_ORIGIN = 0x802B;
        static final int ATTR_OTHER_ADDRESS = 0x802C;
        static final int TRANSPORT_UDP = 17;
        private static final SecureRandom RANDOM = new SecureRandom();

        final int type;
        final byte[] transactionId;
        final List<Attribute> attributes;

        private StunMessage(int type, byte[] transactionId, List<Attribute> attributes) {
            this.type = type & 0xFFFF;
            this.transactionId = normalizeTransactionId(transactionId);
            this.attributes = attributes == null ? List.of() : List.copyOf(attributes);
        }

        static StunMessage of(int type, byte[] transactionId, Attribute... attributes) {
            List<Attribute> values = new ArrayList<>();
            if (attributes != null) {
                values.addAll(Arrays.asList(attributes));
            }
            return new StunMessage(type, transactionId, values);
        }

        static byte[] newTransactionId() {
            byte[] bytes = new byte[TRANSACTION_ID_BYTES];
            RANDOM.nextBytes(bytes);
            return bytes;
        }

        static StunMessage parse(byte[] packet) {
            if (packet == null || packet.length < HEADER_BYTES || (packet[0] & 0xC0) != 0) {
                return null;
            }
            ByteBuffer buffer = ByteBuffer.wrap(packet);
            int type = Short.toUnsignedInt(buffer.getShort());
            int length = Short.toUnsignedInt(buffer.getShort());
			if (buffer.getInt() != MAGIC_COOKIE || length + HEADER_BYTES != packet.length) {
                return null;
            }
            byte[] transactionId = new byte[TRANSACTION_ID_BYTES];
            buffer.get(transactionId);
            int end = HEADER_BYTES + length;
            List<Attribute> attributes = new ArrayList<>();
            while (buffer.position() < end) {
                if (end - buffer.position() < 4) {
                    return null;
                }
                int attrType = Short.toUnsignedInt(buffer.getShort());
                int attrLength = Short.toUnsignedInt(buffer.getShort());
                if (attrLength > end - buffer.position()) {
                    return null;
                }
                byte[] value = new byte[attrLength];
                buffer.get(value);
                int padding = padding(attrLength);
                if (padding > end - buffer.position()) {
                    return null;
                }
                buffer.position(buffer.position() + padding);
                attributes.add(new Attribute(attrType, value));
            }
            return new StunMessage(type, transactionId, attributes);
        }

        byte[] toBytes() {
            return toBytes(null);
        }

        byte[] toBytes(byte[] messageIntegrityKey) {
            int attributeBytes = 0;
            for (Attribute attribute : attributes) {
                attributeBytes += 4 + attribute.value.length + padding(attribute.value.length);
            }
            if (messageIntegrityKey != null && messageIntegrityKey.length > 0) {
                byte[] beforeIntegrity = serialize(attributeBytes + 24, attributes);
                byte[] digest;
                try {
                    Mac mac = Mac.getInstance("HmacSHA1");
                    mac.init(new SecretKeySpec(messageIntegrityKey, "HmacSHA1"));
                    digest = mac.doFinal(beforeIntegrity);
                } catch (Exception e) {
                    throw new IllegalStateException("cannot compute STUN message integrity", e);
                }
                ByteBuffer packet = ByteBuffer.allocate(beforeIntegrity.length + 24);
                packet.put(beforeIntegrity);
                packet.putShort((short) ATTR_MESSAGE_INTEGRITY);
                packet.putShort((short) digest.length);
                packet.put(digest);
                return packet.array();
            }
            return serialize(attributeBytes, attributes);
        }

        private byte[] serialize(int declaredAttributeBytes, List<Attribute> serializedAttributes) {
            int attributeBytes = 0;
            for (Attribute attribute : serializedAttributes) {
                attributeBytes += 4 + attribute.value.length + padding(attribute.value.length);
            }
            ByteBuffer buffer = ByteBuffer.allocate(HEADER_BYTES + attributeBytes);
            buffer.putShort((short) type);
            buffer.putShort((short) declaredAttributeBytes);
            buffer.putInt(MAGIC_COOKIE);
            buffer.put(transactionId);
            for (Attribute attribute : serializedAttributes) {
                buffer.putShort((short) attribute.type);
                buffer.putShort((short) attribute.value.length);
                buffer.put(attribute.value);
                for (int i = 0; i < padding(attribute.value.length); i++) {
                    buffer.put((byte) 0);
                }
            }
            return buffer.array();
        }

        String transactionIdHex() {
            return hex(transactionId);
        }

        InetSocketAddress xorMappedAddress() {
            return firstXorAddress(ATTR_XOR_MAPPED_ADDRESS);
        }

        InetSocketAddress mappedAddress() {
            return firstAddress(ATTR_MAPPED_ADDRESS);
        }

        InetSocketAddress xorRelayedAddress() {
            return firstXorAddress(ATTR_XOR_RELAYED_ADDRESS);
        }

        InetSocketAddress xorPeerAddress() {
            return firstXorAddress(ATTR_XOR_PEER_ADDRESS);
        }

        InetSocketAddress responseOrigin() {
            return firstAddress(ATTR_RESPONSE_ORIGIN);
        }

        InetSocketAddress otherAddress() {
            return firstAddress(ATTR_OTHER_ADDRESS);
        }

        InetSocketAddress legacyXorResponseOrigin() {
            return firstXorAddress(ATTR_RESPONSE_ORIGIN);
        }

        InetSocketAddress legacyXorOtherAddress() {
            return firstXorAddress(ATTR_OTHER_ADDRESS);
        }

        ChangeRequest changeRequest() {
            Attribute attribute = first(ATTR_CHANGE_REQUEST);
            if (attribute == null || attribute.value.length != Integer.BYTES) {
                return null;
            }
            int flags = ByteBuffer.wrap(attribute.value).getInt();
            return new ChangeRequest((flags & 0x04) != 0, (flags & 0x02) != 0);
        }

        List<Integer> unknownAttributes() {
            Attribute attribute = first(ATTR_UNKNOWN_ATTRIBUTES);
            if (attribute == null || attribute.value.length < Short.BYTES) {
                return List.of();
            }
            List<Integer> result = new ArrayList<>(attribute.value.length / Short.BYTES);
            ByteBuffer buffer = ByteBuffer.wrap(attribute.value);
            while (buffer.remaining() >= Short.BYTES) {
                result.add(Short.toUnsignedInt(buffer.getShort()));
            }
            return result;
        }

        byte[] data() {
            Attribute attribute = first(ATTR_DATA);
            return attribute == null ? null : attribute.value.clone();
        }

        long lifetimeSeconds(long fallback) {
            Attribute attribute = first(ATTR_LIFETIME);
            if (attribute == null || attribute.value.length != Integer.BYTES) {
                return fallback;
            }
            return Integer.toUnsignedLong(ByteBuffer.wrap(attribute.value).getInt());
        }

		int channelNumber() {
			Attribute attribute = first(ATTR_CHANNEL_NUMBER);
			if (attribute == null || attribute.value.length != Integer.BYTES) {
				return 0;
			}
			int channel = Short.toUnsignedInt(ByteBuffer.wrap(attribute.value, 0, 2).getShort());
			return channel >= TurnChannelData.MIN_CHANNEL && channel <= TurnChannelData.MAX_CHANNEL
					? channel : 0;
		}

        int errorCode() {
            Attribute attribute = first(ATTR_ERROR_CODE);
            if (attribute == null || attribute.value.length < 4) {
                return 0;
            }
            return (attribute.value[2] & 0x07) * 100 + (attribute.value[3] & 0xFF);
        }

        String errorReason() {
            Attribute attribute = first(ATTR_ERROR_CODE);
            if (attribute == null || attribute.value.length <= 4) {
                return "";
            }
            return new String(attribute.value, 4, attribute.value.length - 4, StandardCharsets.UTF_8);
        }

        String textAttribute(int type) {
            Attribute attribute = first(type);
            return attribute == null ? "" : new String(attribute.value, StandardCharsets.UTF_8);
        }

        private Attribute first(int type) {
            for (Attribute attribute : attributes) {
                if (attribute.type == type) {
                    return attribute;
                }
            }
            return null;
        }

        boolean hasAttribute(int type) {
            return first(type) != null;
        }

        private InetSocketAddress firstXorAddress(int type) {
            Attribute attribute = first(type);
            return attribute == null ? null : decodeXorAddress(attribute.value);
        }

        private InetSocketAddress firstAddress(int type) {
            Attribute attribute = first(type);
            return attribute == null ? null : decodeAddress(attribute.value);
        }

        private InetSocketAddress decodeAddress(byte[] value) {
            if (value == null || (value.length != 8 && value.length != 20)) {
                return null;
            }
            int family = value[1] & 0xFF;
            int port = Short.toUnsignedInt(ByteBuffer.wrap(value, 2, Short.BYTES).getShort());
            try {
                if (family == 0x01 && value.length == 8) {
                    return new InetSocketAddress(
                            InetAddress.getByAddress(Arrays.copyOfRange(value, 4, 8)),
                            port);
                }
                if (family == 0x02 && value.length == 20) {
                    return new InetSocketAddress(
                            InetAddress.getByAddress(Arrays.copyOfRange(value, 4, 20)),
                            port);
                }
                return null;
            } catch (Exception ignored) {
                return null;
            }
        }

        private InetSocketAddress decodeXorAddress(byte[] value) {
            if (value == null || (value.length != 8 && value.length != 20)) {
                return null;
            }
            int family = value[1] & 0xFF;
            int port = (((value[2] & 0xFF) << 8) | (value[3] & 0xFF)) ^ (MAGIC_COOKIE >>> 16);
            try {
                byte[] address;
                if (family == 0x01 && value.length == 8) {
                    address = new byte[4];
                    for (int i = 0; i < address.length; i++) {
                        address[i] = (byte) (value[4 + i] ^ ((MAGIC_COOKIE >>> (24 - i * 8)) & 0xFF));
                    }
                } else if (family == 0x02 && value.length == 20) {
                    byte[] mask = new byte[16];
                    ByteBuffer.wrap(mask).putInt(MAGIC_COOKIE).put(transactionId);
                    address = new byte[16];
                    for (int i = 0; i < address.length; i++) {
                        address[i] = (byte) (value[4 + i] ^ mask[i]);
                    }
                } else {
                    return null;
                }
                return new InetSocketAddress(InetAddress.getByAddress(address), port);
            } catch (Exception ignored) {
                return null;
            }
        }

        static Attribute xorPeerAddress(InetSocketAddress address, byte[] transactionId) {
            return new Attribute(ATTR_XOR_PEER_ADDRESS, encodeXorAddress(address, transactionId));
        }

        static Attribute xorMappedAddress(InetSocketAddress address, byte[] transactionId) {
            return new Attribute(ATTR_XOR_MAPPED_ADDRESS, encodeXorAddress(address, transactionId));
        }

        static Attribute responseOrigin(InetSocketAddress address) {
            return new Attribute(ATTR_RESPONSE_ORIGIN, encodeAddress(address));
        }

        static Attribute otherAddress(InetSocketAddress address) {
            return new Attribute(ATTR_OTHER_ADDRESS, encodeAddress(address));
        }

        static Attribute changeRequest(boolean changeIp, boolean changePort) {
            int flags = (changeIp ? 0x04 : 0) | (changePort ? 0x02 : 0);
            return new Attribute(
                    ATTR_CHANGE_REQUEST,
                    ByteBuffer.allocate(Integer.BYTES).putInt(flags).array());
        }

        static Attribute unknownAttributes(int... types) {
            int[] normalized = types == null ? new int[0] : types;
            ByteBuffer buffer = ByteBuffer.allocate(normalized.length * Short.BYTES);
            for (int type : normalized) {
                buffer.putShort((short) (type & 0xFFFF));
            }
            return new Attribute(ATTR_UNKNOWN_ATTRIBUTES, buffer.array());
        }

        static Attribute data(byte[] payload) {
            return new Attribute(ATTR_DATA, payload == null ? new byte[0] : payload.clone());
        }

		static Attribute channelNumber(int channelNumber) {
			return new Attribute(ATTR_CHANNEL_NUMBER,
					ByteBuffer.allocate(Integer.BYTES).putShort((short) channelNumber).putShort((short) 0).array());
		}

        static Attribute lifetime(long seconds) {
            ByteBuffer buffer = ByteBuffer.allocate(Integer.BYTES);
            buffer.putInt((int) Math.max(0, Math.min(0xFFFF_FFFFL, seconds)));
            return new Attribute(ATTR_LIFETIME, buffer.array());
        }

        static Attribute requestedUdpTransportAttribute() {
            return new Attribute(ATTR_REQUESTED_TRANSPORT, new byte[]{(byte) TRANSPORT_UDP, 0, 0, 0});
        }

        static Attribute software(String value) {
            return new Attribute(ATTR_SOFTWARE, (value == null ? "" : value).getBytes(StandardCharsets.UTF_8));
        }

        static Attribute username(String value) {
            return new Attribute(ATTR_USERNAME, (value == null ? "" : value).getBytes(StandardCharsets.UTF_8));
        }

        static Attribute realm(String value) {
            return new Attribute(ATTR_REALM, (value == null ? "" : value).getBytes(StandardCharsets.UTF_8));
        }

        static Attribute nonce(String value) {
            return new Attribute(ATTR_NONCE, (value == null ? "" : value).getBytes(StandardCharsets.UTF_8));
        }

        static Attribute errorCode(int code, String reason) {
            byte[] reasonBytes = (reason == null ? "" : reason).getBytes(StandardCharsets.UTF_8);
            ByteBuffer buffer = ByteBuffer.allocate(4 + reasonBytes.length);
            buffer.putShort((short) 0);
            buffer.put((byte) ((code / 100) & 0x07));
            buffer.put((byte) (code % 100));
            buffer.put(reasonBytes);
            return new Attribute(ATTR_ERROR_CODE, buffer.array());
        }

        private static byte[] encodeXorAddress(InetSocketAddress address, byte[] transactionId) {
            if (address == null || address.getAddress() == null) {
                throw new IllegalArgumentException("address is required");
            }
            byte[] raw = address.getAddress().getAddress();
            byte family = raw.length == 4 ? (byte) 0x01 : (byte) 0x02;
            byte[] tx = normalizeTransactionId(transactionId);
            ByteBuffer buffer = ByteBuffer.allocate(raw.length == 4 ? 8 : 20);
            buffer.put((byte) 0);
            buffer.put(family);
            buffer.putShort((short) (address.getPort() ^ (MAGIC_COOKIE >>> 16)));
            if (raw.length == 4) {
                for (int i = 0; i < raw.length; i++) {
                    buffer.put((byte) (raw[i] ^ ((MAGIC_COOKIE >>> (24 - i * 8)) & 0xFF)));
                }
            } else if (raw.length == 16) {
                byte[] mask = new byte[16];
                ByteBuffer.wrap(mask).putInt(MAGIC_COOKIE).put(tx);
                for (int i = 0; i < raw.length; i++) {
                    buffer.put((byte) (raw[i] ^ mask[i]));
                }
            } else {
                throw new IllegalArgumentException("unsupported address family");
            }
            return buffer.array();
        }

        private static byte[] encodeAddress(InetSocketAddress address) {
            if (address == null || address.getAddress() == null) {
                throw new IllegalArgumentException("address is required");
            }
            byte[] raw = address.getAddress().getAddress();
            byte family = raw.length == 4 ? (byte) 0x01 : (byte) 0x02;
            ByteBuffer buffer = ByteBuffer.allocate(raw.length == 4 ? 8 : 20);
            buffer.put((byte) 0);
            buffer.put(family);
            buffer.putShort((short) address.getPort());
            buffer.put(raw);
            return buffer.array();
        }

        static String hex(byte[] bytes) {
            StringBuilder result = new StringBuilder(bytes == null ? 0 : bytes.length * 2);
            if (bytes != null) {
                for (byte item : bytes) {
                    result.append(Character.forDigit((item >>> 4) & 0x0F, 16));
                    result.append(Character.forDigit(item & 0x0F, 16));
                }
            }
            return result.toString();
        }

        private static byte[] normalizeTransactionId(byte[] transactionId) {
            if (transactionId == null || transactionId.length != TRANSACTION_ID_BYTES) {
                return newTransactionId();
            }
            return transactionId.clone();
        }

        private static int padding(int length) {
            return (4 - (length % 4)) % 4;
        }

        static final class Attribute {
            final int type;
            final byte[] value;

            Attribute(int type, byte[] value) {
                this.type = type;
                this.value = value == null ? new byte[0] : value.clone();
            }
        }

        static final class ChangeRequest {
            final boolean changeIp;
            final boolean changePort;

            ChangeRequest(boolean changeIp, boolean changePort) {
                this.changeIp = changeIp;
                this.changePort = changePort;
            }
        }
    }

    static final class DataFrame {
        final long sessionId;
        final long sequence;
        final byte[] plaintext;

        DataFrame(long sessionId, long sequence, byte[] plaintext) {
            this.sessionId = sessionId;
            this.sequence = sequence;
            this.plaintext = plaintext;
        }
    }

    static final class DataFrameCodec {
        private static final int MAGIC = 0x53504D32;
        private static final int NONCE_BYTES = 12;
        private static final int TAG_BITS = 128;
        private static final int TAG_BYTES = TAG_BITS / Byte.SIZE;
        private static final int HEADER_BYTES = Integer.BYTES + Long.BYTES * 2;
        private static final int MIN_BYTES = HEADER_BYTES + TAG_BYTES;
        private static final int MAX_BYTES = 65_535;

        static byte[] encode(byte[] aesKey, long sessionId, long fromClientId, long toClientId,
                             String senderKeyEpoch, long sequence, byte[] plaintext) throws Exception {
            return trafficCodec(aesKey, sessionId, fromClientId, toClientId, senderKeyEpoch)
                    .encode(sessionId, sequence, plaintext);
        }

        static DataFrame decode(byte[] aesKey, byte[] packet, long expectedSessionId,
                                long expectedFromClientId, long expectedToClientId,
                                String senderKeyEpoch) {
            try {
                if (aesKey == null || aesKey.length != 32 || packet == null
                        || packet.length < MIN_BYTES || packet.length > MAX_BYTES) {
                    return null;
                }
                ByteBuffer header = ByteBuffer.wrap(packet);
                if (header.getInt() != MAGIC) {
                    return null;
                }
                long sessionId = header.getLong();
                long sequence = header.getLong();
                if (sessionId != expectedSessionId || sequence <= 0L) {
                    return null;
                }
                return trafficCodec(aesKey, sessionId, expectedFromClientId, expectedToClientId,
                        senderKeyEpoch).decode(packet, expectedSessionId);
            } catch (Exception e) {
                return null;
            }
        }

        static Long sessionId(byte[] packet) {
            if (packet == null || packet.length < MIN_BYTES || packet.length > MAX_BYTES) {
                return null;
            }
            ByteBuffer header = ByteBuffer.wrap(packet);
            return header.getInt() == MAGIC ? header.getLong() : null;
        }

        static boolean looksLike(byte[] packet) {
            return packet != null && packet.length >= Integer.BYTES
                    && ByteBuffer.wrap(packet, 0, Integer.BYTES).getInt() == MAGIC;
        }

        static TrafficCodec trafficCodec(byte[] aesKey, long sessionId,
                                         long fromClientId, long toClientId,
                                         String senderKeyEpoch) throws Exception {
            if (aesKey == null || aesKey.length != 32 || sessionId <= 0L
                    || fromClientId <= 0L || toClientId <= 0L || fromClientId == toClientId) {
                throw new IllegalArgumentException("invalid SPM2 key, session, or direction");
            }
            if (senderKeyEpoch == null || senderKeyEpoch.trim().isEmpty()) {
                throw new IllegalArgumentException("SPM2 traffic key requires the sender key epoch");
            }
            byte[] material = trafficMaterial(aesKey, sessionId, fromClientId, toClientId, senderKeyEpoch);
            return new TrafficCodec(
                    new SecretKeySpec(Arrays.copyOf(material, 32), "AES"),
                    ByteBuffer.wrap(material, 32, 4).getInt());
        }

        /**
         * senderKeyEpoch 是发送方本次运行实例的随机 epoch，必填：sessionId/token 会在服务端
         * TTL 内复用、X25519 密钥又持久化在磁盘，没有 epoch 时客户端重启会在同一 key 下
         * 重放同一段 nonce 空间。
         */
        private static byte[] trafficMaterial(byte[] aesKey, long sessionId,
                                              long fromClientId, long toClientId,
                                              String senderKeyEpoch) throws Exception {
            byte[] salt = ByteBuffer.allocate(Long.BYTES).putLong(sessionId).array();
            byte[] prk = hmac(salt, aesKey);
            return hkdfExpand(prk, "shuai-peer-mesh/spm2/aes-gcm\n"
                    + sessionId + "\n" + fromClientId + "\n" + toClientId
                    + "\n" + senderKeyEpoch, 36);
        }

        private static byte[] nonce(int prefix, long sequence) {
            return ByteBuffer.allocate(NONCE_BYTES)
                    .putInt(prefix)
                    .putLong(sequence)
                    .array();
        }

        static final class TrafficCodec {
            private final SecretKeySpec key;
            private final int noncePrefix;
            private final Cipher cipher;

            TrafficCodec(SecretKeySpec key, int noncePrefix) throws Exception {
                this.key = key;
                this.noncePrefix = noncePrefix;
                this.cipher = Cipher.getInstance("AES/GCM/NoPadding");
            }

            synchronized byte[] encode(long sessionId, long sequence, byte[] plaintext) throws Exception {
                if (sessionId <= 0L || sequence <= 0L) {
                    throw new IllegalArgumentException("invalid SPM2 session or sequence");
                }
                byte[] input = plaintext == null ? new byte[0] : plaintext;
                if (HEADER_BYTES + input.length + TAG_BYTES > MAX_BYTES) {
                    throw new IllegalArgumentException("SPM2 peer data frame is too large");
                }
                byte[] frame = new byte[HEADER_BYTES + input.length + TAG_BYTES];
                ByteBuffer header = ByteBuffer.wrap(frame);
                header.putInt(MAGIC);
                header.putLong(sessionId);
                header.putLong(sequence);
                cipher.init(Cipher.ENCRYPT_MODE, key,
                        new GCMParameterSpec(TAG_BITS, nonce(noncePrefix, sequence)));
                cipher.updateAAD(frame, 0, HEADER_BYTES);
                cipher.doFinal(input, 0, input.length, frame, HEADER_BYTES);
                return frame;
            }

            synchronized DataFrame decode(byte[] packet, long expectedSessionId) {
                try {
                    if (packet == null || packet.length < MIN_BYTES || packet.length > MAX_BYTES) {
                        return null;
                    }
                    ByteBuffer header = ByteBuffer.wrap(packet);
                    if (header.getInt() != MAGIC) {
                        return null;
                    }
                    long sessionId = header.getLong();
                    long sequence = header.getLong();
                    if (sessionId != expectedSessionId || sequence <= 0L) {
                        return null;
                    }
                    cipher.init(Cipher.DECRYPT_MODE, key,
                            new GCMParameterSpec(TAG_BITS, nonce(noncePrefix, sequence)));
                    cipher.updateAAD(packet, 0, HEADER_BYTES);
                    return new DataFrame(sessionId, sequence,
                            cipher.doFinal(packet, HEADER_BYTES, packet.length - HEADER_BYTES));
                } catch (Exception ignored) {
                    return null;
                }
            }
        }
    }

    static final class ReplayWindow {
        private static final int WINDOW_SIZE = 4096;
        private static final int WINDOW_MASK = WINDOW_SIZE - 1;
        private long highest;
        private final long[] sequences = new long[WINDOW_SIZE];

        synchronized boolean accept(long sequence) {
            if (sequence <= 0) {
                return false;
            }
            if (highest >= WINDOW_SIZE && sequence <= highest - WINDOW_SIZE) {
                return false;
            }
            int slot = (int) sequence & WINDOW_MASK;
            if (sequences[slot] == sequence) {
                return false;
            }
            sequences[slot] = sequence;
            if (sequence > highest) {
                highest = sequence;
            }
            return true;
        }

        synchronized ReplayWindow copy() {
            ReplayWindow copy = new ReplayWindow();
            copy.highest = highest;
            System.arraycopy(sequences, 0, copy.sequences, 0, sequences.length);
            return copy;
        }
    }

    static final class IpPacket {
        private static final int PROTOCOL_ICMP = 1;
        private static final int PROTOCOL_TCP = 6;

        static String destinationIpv4(byte[] packet) {
            if (!isIpv4(packet)) {
                return "";
            }
            return (packet[16] & 0xFF) + "."
                    + (packet[17] & 0xFF) + "."
                    + (packet[18] & 0xFF) + "."
                    + (packet[19] & 0xFF);
        }

        static byte[] clampTcpMss(byte[] packet, int pathMtu) {
            if (!isIpv4(packet) || (packet[9] & 0xFF) != PROTOCOL_TCP) {
                return packet;
            }
            int ipHeaderLength = (packet[0] & 0x0F) * 4;
            int totalLength = totalLength(packet);
            if (totalLength < ipHeaderLength + 20
                    || (packet[ipHeaderLength + 13] & 0x02) == 0) {
                return packet;
            }
            int tcpHeaderLength = ((packet[ipHeaderLength + 12] >>> 4) & 0x0F) * 4;
            if (tcpHeaderLength < 20 || totalLength < ipHeaderLength + tcpHeaderLength) {
                return packet;
            }
            int maxMss = Math.max(536, pathMtu - ipHeaderLength - 20);
            int limit = ipHeaderLength + tcpHeaderLength;
            for (int cursor = ipHeaderLength + 20; cursor < limit; ) {
                int kind = packet[cursor] & 0xFF;
                if (kind == 0) {
                    break;
                }
                if (kind == 1) {
                    cursor++;
                    continue;
                }
                if (cursor + 1 >= limit) {
                    break;
                }
                int optionLength = packet[cursor + 1] & 0xFF;
                if (optionLength < 2 || cursor + optionLength > limit) {
                    break;
                }
                if (kind == 2 && optionLength == 4) {
                    int advertised = readUnsignedShort(packet, cursor + 2);
                    if (advertised <= maxMss) {
                        return packet;
                    }
                    byte[] clamped = Arrays.copyOf(packet, packet.length);
                    writeUnsignedShort(clamped, cursor + 2, maxMss);
                    writeUnsignedShort(clamped, ipHeaderLength + 16, 0);
                    writeUnsignedShort(clamped, ipHeaderLength + 16,
                            tcpChecksum(clamped, ipHeaderLength, totalLength - ipHeaderLength));
                    return clamped;
                }
                cursor += optionLength;
            }
            return packet;
        }

        static byte[] icmpFragmentationNeeded(byte[] packet, int pathMtu) {
            if (!isIpv4(packet)) {
                return null;
            }
            int originalHeaderLength = (packet[0] & 0x0F) * 4;
            int originalLength = totalLength(packet);
            int quotedLength = Math.min(originalLength, originalHeaderLength + 8);
            byte[] response = new byte[20 + 8 + quotedLength];
            response[0] = 0x45;
            writeUnsignedShort(response, 2, response.length);
            response[8] = 64;
            response[9] = PROTOCOL_ICMP;
            System.arraycopy(packet, 16, response, 12, 4);
            System.arraycopy(packet, 12, response, 16, 4);
            response[20] = 3;
            response[21] = 4;
            writeUnsignedShort(response, 26, Math.max(0, Math.min(0xFFFF, pathMtu)));
            System.arraycopy(packet, 0, response, 28, quotedLength);
            writeUnsignedShort(response, 22, checksum(response, 20, response.length - 20));
            writeUnsignedShort(response, 10, checksum(response, 0, 20));
            return response;
        }

        static int checksum(byte[] data, int offset, int length) {
            long sum = 0L;
            int limit = offset + length;
            int cursor = offset;
            while (cursor + 1 < limit) {
                sum += readUnsignedShort(data, cursor);
                cursor += 2;
            }
            if (cursor < limit) {
                sum += (data[cursor] & 0xFFL) << 8;
            }
            while ((sum >>> 16) != 0L) {
                sum = (sum & 0xFFFFL) + (sum >>> 16);
            }
            return (int) (~sum) & 0xFFFF;
        }

        private static int tcpChecksum(byte[] packet, int tcpOffset, int tcpLength) {
            long sum = 0L;
            for (int cursor = 12; cursor < 20; cursor += 2) {
                sum += readUnsignedShort(packet, cursor);
            }
            sum += PROTOCOL_TCP;
            sum += tcpLength;
            int limit = tcpOffset + tcpLength;
            int cursor = tcpOffset;
            while (cursor + 1 < limit) {
                sum += readUnsignedShort(packet, cursor);
                cursor += 2;
            }
            if (cursor < limit) {
                sum += (packet[cursor] & 0xFFL) << 8;
            }
            while ((sum >>> 16) != 0L) {
                sum = (sum & 0xFFFFL) + (sum >>> 16);
            }
            return (int) (~sum) & 0xFFFF;
        }

        private static int totalLength(byte[] packet) {
            int headerLength = (packet[0] & 0x0F) * 4;
            int declared = readUnsignedShort(packet, 2);
            return declared >= headerLength && declared <= packet.length ? declared : packet.length;
        }

        private static int readUnsignedShort(byte[] data, int offset) {
            return ((data[offset] & 0xFF) << 8) | (data[offset + 1] & 0xFF);
        }

        private static void writeUnsignedShort(byte[] data, int offset, int value) {
            data[offset] = (byte) (value >>> 8);
            data[offset + 1] = (byte) value;
        }

        private static boolean isIpv4(byte[] packet) {
            if (packet == null || packet.length < 20) {
                return false;
            }
            int version = (packet[0] >>> 4) & 0x0F;
            int ihl = packet[0] & 0x0F;
            return version == 4 && ihl >= 5 && packet.length >= ihl * 4;
        }
    }

    static final class KeyStore {
        private static final String PREFS = "shuai_tunnel_peer_keys";
        private static final String PRIVATE = "x25519_private";
        private static final String PUBLIC = "x25519_public";

        static String publicKeyBase64(Context context) {
            return keyMaterial(context).publicKeyBase64;
        }

        private static KeyMaterial keyMaterial() {
            return keyMaterial(AppContextHolder.context);
        }

        private static KeyMaterial keyMaterial(Context context) {
            if (context == null) {
                return new KeyMaterial("", "");
            }
            SharedPreferences prefs = context.getApplicationContext().getSharedPreferences(PREFS, Context.MODE_PRIVATE);
            String privateKey = prefs.getString(PRIVATE, "");
            String publicKey = prefs.getString(PUBLIC, "");
            if (!isBlank(privateKey) && !isBlank(publicKey)) {
                return new KeyMaterial(privateKey, publicKey);
            }
            try {
                KeyMaterial generated = PeerCrypto.generateKeyMaterial();
                prefs.edit()
                        .putString(PRIVATE, generated.privateKeyBase64)
                        .putString(PUBLIC, generated.publicKeyBase64)
                        .apply();
                return generated;
            } catch (Exception e) {
                return new KeyMaterial("", "");
            }
        }

        static final class KeyMaterial {
            final String privateKeyBase64;
            final String publicKeyBase64;

            KeyMaterial(String privateKeyBase64, String publicKeyBase64) {
                this.privateKeyBase64 = privateKeyBase64;
                this.publicKeyBase64 = publicKeyBase64;
            }
        }
    }

    private static final class PeerCrypto {
        private static final int X25519_KEY_SIZE = 32;
        private static final BigInteger P = BigInteger.ONE.shiftLeft(255).subtract(BigInteger.valueOf(19));
        private static final BigInteger A24 = BigInteger.valueOf(121665);
        private static final byte[] PUBLIC_DER_PREFIX = new byte[]{
                0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x03, 0x21, 0x00
        };
        private static final byte[] PRIVATE_DER_PREFIX = new byte[]{
                0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03,
                0x2b, 0x65, 0x6e, 0x04, 0x22, 0x04, 0x20
        };
        private static final SecureRandom RANDOM = new SecureRandom();

        private PeerCrypto() {
        }

        static KeyStore.KeyMaterial generateKeyMaterial() {
            byte[] privateKey = new byte[X25519_KEY_SIZE];
            RANDOM.nextBytes(privateKey);
            byte[] publicKey = x25519(privateKey, basePoint());
            return new KeyStore.KeyMaterial(
                    Base64.getEncoder().encodeToString(concat(PRIVATE_DER_PREFIX, privateKey)),
                    Base64.getEncoder().encodeToString(concat(PUBLIC_DER_PREFIX, publicKey)));
        }

        static byte[] sharedSecret(String privateKeyBase64, String publicKeyBase64) {
            byte[] privateKey = decodePrivateKey(privateKeyBase64);
            byte[] publicKey = decodePublicKey(publicKeyBase64);
            byte[] shared = x25519(privateKey, publicKey);
            if (isAllZero(shared)) {
                throw new IllegalArgumentException("X25519 shared secret is all zero");
            }
            return shared;
        }

        private static byte[] x25519(byte[] scalar, byte[] uCoordinate) {
            if (scalar.length != X25519_KEY_SIZE || uCoordinate.length != X25519_KEY_SIZE) {
                throw new IllegalArgumentException("X25519 keys must be 32 bytes");
            }
            byte[] k = scalar.clone();
            k[0] = (byte) (k[0] & 248);
            k[31] = (byte) (k[31] & 127);
            k[31] = (byte) (k[31] | 64);

            byte[] u = uCoordinate.clone();
            u[31] = (byte) (u[31] & 127);

            BigInteger x1 = fromLittleEndian(u);
            BigInteger x2 = BigInteger.ONE;
            BigInteger z2 = BigInteger.ZERO;
            BigInteger x3 = x1;
            BigInteger z3 = BigInteger.ONE;
            int swap = 0;

            for (int t = 254; t >= 0; t--) {
                int kt = ((k[t >> 3] & 0xFF) >>> (t & 7)) & 1;
                swap ^= kt;
                if (swap != 0) {
                    BigInteger temp = x2;
                    x2 = x3;
                    x3 = temp;
                    temp = z2;
                    z2 = z3;
                    z3 = temp;
                }
                swap = kt;

                BigInteger a = mod(x2.add(z2));
                BigInteger aa = mod(a.multiply(a));
                BigInteger b = mod(x2.subtract(z2));
                BigInteger bb = mod(b.multiply(b));
                BigInteger e = mod(aa.subtract(bb));
                BigInteger c = mod(x3.add(z3));
                BigInteger d = mod(x3.subtract(z3));
                BigInteger da = mod(d.multiply(a));
                BigInteger cb = mod(c.multiply(b));
                x3 = mod(da.add(cb).multiply(da.add(cb)));
                z3 = mod(x1.multiply(mod(da.subtract(cb).multiply(da.subtract(cb)))));
                x2 = mod(aa.multiply(bb));
                z2 = mod(e.multiply(mod(aa.add(A24.multiply(e)))));
            }

            if (swap != 0) {
                BigInteger temp = x2;
                x2 = x3;
                x3 = temp;
                temp = z2;
                z2 = z3;
                z3 = temp;
            }

            byte[] result = toLittleEndian32(mod(x2.multiply(z2.modInverse(P))));
            Arrays.fill(k, (byte) 0);
            Arrays.fill(u, (byte) 0);
            return result;
        }

        private static byte[] decodePublicKey(String value) {
            return decodeKey(value, PUBLIC_DER_PREFIX, "public");
        }

        private static byte[] decodePrivateKey(String value) {
            return decodeKey(value, PRIVATE_DER_PREFIX, "private");
        }

        private static byte[] decodeKey(String value, byte[] prefix, String kind) {
            byte[] decoded = Base64.getDecoder().decode(value);
            if (decoded.length == X25519_KEY_SIZE) {
                return decoded;
            }
            if (decoded.length == prefix.length + X25519_KEY_SIZE && startsWith(decoded, prefix)) {
                byte[] result = new byte[X25519_KEY_SIZE];
                System.arraycopy(decoded, prefix.length, result, 0, result.length);
                return result;
            }
            throw new IllegalArgumentException("unsupported peer " + kind + " key format");
        }

        private static byte[] concat(byte[] left, byte[] right) {
            byte[] result = new byte[left.length + right.length];
            System.arraycopy(left, 0, result, 0, left.length);
            System.arraycopy(right, 0, result, left.length, right.length);
            return result;
        }

        private static byte[] basePoint() {
            byte[] result = new byte[X25519_KEY_SIZE];
            result[0] = 9;
            return result;
        }

        private static BigInteger fromLittleEndian(byte[] value) {
            byte[] reversed = value.clone();
            reverse(reversed);
            return new BigInteger(1, reversed);
        }

        private static byte[] toLittleEndian32(BigInteger value) {
            byte[] bigEndian = value.toByteArray();
            if (bigEndian.length > 1 && bigEndian[0] == 0) {
                bigEndian = Arrays.copyOfRange(bigEndian, 1, bigEndian.length);
            }
            if (bigEndian.length > X25519_KEY_SIZE) {
                throw new IllegalArgumentException("X25519 field element overflow");
            }
            reverse(bigEndian);
            byte[] result = new byte[X25519_KEY_SIZE];
            System.arraycopy(bigEndian, 0, result, 0, bigEndian.length);
            return result;
        }

        private static BigInteger mod(BigInteger value) {
            BigInteger result = value.mod(P);
            return result.signum() < 0 ? result.add(P) : result;
        }

        private static boolean startsWith(byte[] value, byte[] prefix) {
            if (value.length < prefix.length) {
                return false;
            }
            for (int i = 0; i < prefix.length; i++) {
                if (value[i] != prefix[i]) {
                    return false;
                }
            }
            return true;
        }

        private static boolean isAllZero(byte[] value) {
            int aggregate = 0;
            for (byte item : value) {
                aggregate |= item;
            }
            return aggregate == 0;
        }

        private static void reverse(byte[] value) {
            for (int i = 0, j = value.length - 1; i < j; i++, j--) {
                byte temp = value[i];
                value[i] = value[j];
                value[j] = temp;
            }
        }
    }

    static final class AppContextHolder {
        static volatile Context context;
    }
}
