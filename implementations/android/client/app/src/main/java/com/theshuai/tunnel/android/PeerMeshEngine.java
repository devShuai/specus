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
import java.net.InetSocketAddress;
import java.net.NetworkInterface;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
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
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
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
    private static final long TURN_PERMISSION_TTL_MS = 240_000L;
    private static final long SESSION_REFRESH_MIN_WINDOW_MS = 60_000L;
    private static final long SESSION_REFRESH_MAX_WINDOW_MS = 300_000L;
    private static final long REPORT_INTERVAL_MS = 60_000L;
    private static final long MAINTENANCE_INTERVAL_MS = 30_000L;
    private static final long DIRECT_STALE_MS = 45_000L;
    private static final long APP_MESSAGE_SESSION_WAIT_MS = 1_500L;
    private static final long APP_MESSAGE_ACK_WAIT_MS = 1_500L;

    private final TunnelCore.TunnelSession tunnelSession;
    private final TunnelCore.VpnPlatform vpnPlatform;
    private final ExecutorService ioPool;
    private final ControlSender controlSender;
    private final StatusPublisher status;
    private final KeyStore.KeyMaterial keyMaterial;
    private final SecureRandom secureRandom = new SecureRandom();
    private final AtomicBoolean enabled = new AtomicBoolean(false);
    private final Map<Long, PeerInfo> peers = new ConcurrentHashMap<>();
    private final Map<String, PeerInfo> peersByVirtualIp = new ConcurrentHashMap<>();
    private final Map<Long, PeerSession> sessions = new ConcurrentHashMap<>();
    private final Map<Long, PeerSession> sessionsById = new ConcurrentHashMap<>();
    private final Map<Long, ArrayDeque<PendingPacket>> pendingPackets = new ConcurrentHashMap<>();
    private final Map<String, PeerCandidate> serverReflexiveCandidates = new ConcurrentHashMap<>();
    private final Map<String, PendingStunBinding> pendingStunBindings = new ConcurrentHashMap<>();
    private final Map<String, Long> turnPermissions = new ConcurrentHashMap<>();
    private final Map<String, PendingAppMessageAck> pendingMessageAcks = new ConcurrentHashMap<>();
    private volatile TunnelCore.PeerMeshConfig config;
    private volatile DatagramSocket udpSocket;
    private volatile Thread receiverThread;
    private volatile PeerCandidate relayCandidate;
    private volatile String relayAllocationId;
    private volatile long relayAllocationExpiresAtMillis;
    private volatile long lastRelayCandidateRequestMillis;
    private volatile Thread maintenanceThread;
    private volatile long lastDeviceReportMillis;

    PeerMeshEngine(TunnelCore.TunnelSession tunnelSession,
                   TunnelCore.VpnPlatform vpnPlatform,
                   ExecutorService ioPool,
                   ControlSender controlSender,
                   StatusPublisher status) {
        this.tunnelSession = tunnelSession;
        this.vpnPlatform = vpnPlatform;
        this.ioPool = ioPool;
        this.controlSender = controlSender;
        this.status = status;
        this.keyMaterial = KeyStore.keyMaterial();
    }

    synchronized void startOrUpdate(TunnelCore.PeerMeshConfig nextConfig) throws Exception {
        if (nextConfig == null || !nextConfig.enabled) {
            stop();
            return;
        }
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
            PeerSession session = rememberSession(json);
            if (peer != null) {
                preparePath(peer, session);
                flushPending(peer.clientId);
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
                        previous.containsKey(item.optLong("clientId", 0L))
                                ? previous.get(item.optLong("clientId", 0L)).candidates
                                : List.of());
                mergePeer(peer, null);
            }
        }
        announceCandidatesToOnlinePeers();
        refreshSessionKeys();
        publish("Peer roster", peers.size() + " peer(s)");
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
        DatagramSocket socket = udpSocket;
        TunnelCore.PeerMeshConfig current = config;
        if (socket == null || socket.isClosed() || current == null || session == null || !session.canSend()) {
            return false;
        }
        try {
            byte[] frame = DataFrameCodec.encode(
                    session.aesKey,
                    session.sessionId,
                    current.clientId,
                    peer.clientId,
                    session.nextSequence(),
                    payload);
            String relayTarget = relayFallbackTarget(peer, session);
            if (!isBlank(relayTarget)) {
                boolean sent = sendRelayPayload(relayTarget, frame);
                if (sent) {
                    session.addRelayBytes(frame.length);
                }
                return sent;
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
        switch (message.type) {
            case StunMessage.BINDING_SUCCESS:
                handleStunBindingSuccess(message);
                break;
            case StunMessage.ALLOCATE_SUCCESS:
                handleTurnAllocated(message);
                break;
            case StunMessage.REFRESH_SUCCESS:
                relayAllocationExpiresAtMillis = System.currentTimeMillis()
                        + Math.max(30L, message.lifetimeSeconds(300L)) * 1000L;
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

    private void handleStunBindingSuccess(StunMessage message) throws Exception {
        InetSocketAddress mapped = message.xorMappedAddress();
        if (mapped == null || mapped.getAddress() == null || mapped.getPort() <= 0) {
            return;
        }
        PendingStunBinding pending = pendingStunBindings.remove(message.transactionIdHex());
        String foundation = pending != null && pending.publicStun ? "public-stun" : "standard-stun";
        PeerCandidate candidate = new PeerCandidate();
        candidate.type = "srflx";
        candidate.transport = "udp";
        candidate.address = mapped.getAddress().getHostAddress();
        candidate.port = mapped.getPort();
        candidate.priority = 800;
        candidate.foundation = foundation;
        String key = candidateEndpointKey(candidate);
        if (serverReflexiveCandidates.putIfAbsent(key, candidate) == null) {
            announceCandidatesToOnlinePeers();
        }
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
        PeerCandidate previous = relayCandidate;
        relayCandidate = candidate;
        if (previous == null
                || !equals(previous.relayId, candidate.relayId)
                || !equals(previous.address, candidate.address)
                || previous.port != candidate.port) {
            announceCandidatesToOnlinePeers();
        }
    }

    private void handleDataFrame(byte[] data, InetSocketAddress remote, String relayFromAllocationId) throws Exception {
        Long sessionId = DataFrameCodec.sessionId(data);
        PeerSession session = sessionId == null ? null : sessionsById.get(sessionId);
        TunnelCore.PeerMeshConfig current = config;
        if (session == null || session.aesKey == null || current == null) {
            return;
        }
        DataFrame frame = DataFrameCodec.decode(session.aesKey, data, session.sessionId, current.clientId);
        if (frame == null || frame.fromClientId != session.peerId || !session.accept(frame.sequence)) {
            return;
        }
        markSessionPath(session, remote, relayFromAllocationId, -1L);
        session.pathReady = true;
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
        if (current == null || (message.toClientId != 0L && message.toClientId != current.clientId)) {
            return true;
        }
        PeerInfo peer = peers.get(session.peerId);
        String from = firstText(message.fromClientName,
                peer == null ? String.valueOf(session.peerId) : peer.clientName);
        publish("Message received", from + ": " + firstText(message.message, ""));
        sendPeerClientMessageAck(message, session, current);
        return true;
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
            if (peer != null && peer.online && clientName.equalsIgnoreCase(peer.clientName)) {
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
                    String host = address.getHostAddress();
                    if (address.isLoopbackAddress() || address.isLinkLocalAddress() || host.contains(":")) {
                        continue;
                    }
                    PeerCandidate candidate = new PeerCandidate();
                    candidate.type = "host";
                    candidate.transport = "udp";
                    candidate.address = host;
                    candidate.port = socket.getLocalPort();
                    candidate.priority = 100;
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
        boolean allocationExpiring = relayAllocationId == null || relayAllocationExpiresAtMillis - now <= RELAY_REFRESH_WINDOW_MS;
        if (!allocationExpiring && now - lastRelayCandidateRequestMillis < 60_000L) {
            return;
        }
        if (allocationExpiring && now - lastRelayCandidateRequestMillis < RELAY_REQUEST_MIN_INTERVAL_MS) {
            return;
        }
        lastRelayCandidateRequestMillis = now;

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

        InetSocketAddress turn = relayEndpoint();
        if (turn == null) {
            return;
        }
        sendStunBinding(turn, false);
        if (relayAllocationId != null && relayAllocationExpiresAtMillis - now > RELAY_REFRESH_WINDOW_MS) {
            sendStunRequest(StunMessage.of(
                    StunMessage.REFRESH_REQUEST,
                    StunMessage.newTransactionId(),
                    StunMessage.lifetime(Math.max(30L, config.sessionTtlSeconds))), turn);
            return;
        }
        sendStunRequest(StunMessage.of(
                StunMessage.ALLOCATE_REQUEST,
                StunMessage.newTransactionId(),
                StunMessage.requestedUdpTransportAttribute()), turn);
    }

    private void sendStunBinding(InetSocketAddress endpoint, boolean publicStun) {
        byte[] transactionId = StunMessage.newTransactionId();
        pendingStunBindings.put(StunMessage.hex(transactionId), new PendingStunBinding(publicStun));
        sendStunRequest(StunMessage.of(
                StunMessage.BINDING_REQUEST,
                transactionId,
                StunMessage.software("shuai-tunnel-android")), endpoint);
    }

    private void sendStunRequest(StunMessage message, InetSocketAddress endpoint) {
        DatagramSocket socket = udpSocket;
        if (socket == null || socket.isClosed() || endpoint == null) {
            return;
        }
        try {
            byte[] bytes = message.toBytes();
            socket.send(new DatagramPacket(bytes, bytes.length, endpoint));
        } catch (Exception e) {
            publish("Peer STUN failed", e.getMessage());
        }
    }

    private PeerSession rememberSession(JSONObject json) {
        long peerId = peerId(json);
        long sessionId = json.optLong("sessionId", 0L);
        String token = json.optString("token", "");
        if (peerId <= 0 || sessionId <= 0 || isBlank(token)) {
            return null;
        }
        PeerInfo peer = peers.get(peerId);
        PeerSession previous = sessions.get(peerId);
        PeerSession next = new PeerSession(peerId, sessionId, token, json.optString("expiresAt", ""));
        if (peer != null) {
            next.aesKey = deriveSessionKey(next, peer.publicKey);
        }
        if (previous != null) {
            next.remoteEndpoint = previous.remoteEndpoint;
            next.relayTargetAllocationId = previous.relayTargetAllocationId;
            next.pathReady = previous.pathReady;
            next.sequence.set(previous.sequence.get());
            next.directBytesSinceReport.addAndGet(previous.drainDirectBytes());
            next.relayBytesSinceReport.addAndGet(previous.drainRelayBytes());
            next.lastDirectSuccessMillis = previous.lastDirectSuccessMillis;
            next.lastRelaySuccessMillis = previous.lastRelaySuccessMillis;
            next.lastPathReportMillis = previous.lastPathReportMillis;
            next.lastPathRemoteText = previous.lastPathRemoteText;
            next.currentPathType = previous.currentPathType;
            next.bestDirectRtt = previous.bestDirectRtt;
            next.bestRelayRtt = previous.bestRelayRtt;
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
        session.aesKey = deriveSessionKey(session, peer.publicKey);
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
                    parseCandidates(json.optJSONArray("candidates")));
        }
        if (targetId > 0 && targetId != config.clientId) {
            return new PeerInfo(targetId,
                    json.optString("targetClientName", ""),
                    json.optString("targetVirtualIp", ""),
                    json.optString("targetPublicKey", ""),
                    true,
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
        List<PeerCandidate> sorted = new ArrayList<>(candidates);
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
        byte[] transactionId = StunMessage.newTransactionId();
        sendStunRequest(StunMessage.of(
                StunMessage.CREATE_PERMISSION_REQUEST,
                transactionId,
                StunMessage.xorPeerAddress(peer, transactionId)), turn);
        turnPermissions.put(key, now + TURN_PERMISSION_TTL_MS);
    }

    private InetSocketAddress stunEndpoint() {
        TunnelCore.PeerMeshConfig current = config;
        if (current == null || isBlank(current.stunHost) || current.stunPort <= 0) {
            return null;
        }
        return new InetSocketAddress(current.stunHost, current.stunPort);
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
        String host = normalized;
        int port = 3478;
        int colon = normalized.lastIndexOf(':');
        if (colon > 0 && colon < normalized.length() - 1) {
            host = normalized.substring(0, colon);
            try {
                port = Integer.parseInt(normalized.substring(colon + 1));
            } catch (NumberFormatException ignored) {
                return null;
            }
        }
        return isBlank(host) || port <= 0 ? null : new InetSocketAddress(host, port);
    }

    private InetSocketAddress parseEndpoint(String value) {
        if (isBlank(value)) {
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
            return new InetSocketAddress(normalized.substring(0, colon), Integer.parseInt(normalized.substring(colon + 1)));
        } catch (NumberFormatException ignored) {
            return null;
        }
    }

    private String endpointKey(InetSocketAddress endpoint) {
        if (endpoint == null) {
            return "";
        }
        String host = endpoint.getAddress() == null ? endpoint.getHostString() : endpoint.getAddress().getHostAddress();
        return host + ":" + endpoint.getPort();
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
            long relayBytes = session.drainRelayBytes();
            if (directBytes <= 0 && relayBytes <= 0) {
                continue;
            }
            try {
                JSONObject report = basePeerReport("traffic-report", session);
                report.put("directBytes", directBytes);
                report.put("relayBytes", relayBytes);
                controlSender.send("", report.toString());
            } catch (Exception e) {
                session.addDirectBytes(directBytes);
                session.addRelayBytes(relayBytes);
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
        if (!serverReflexiveCandidates.isEmpty()) {
            return "SERVER_REFLEXIVE";
        }
        return "UNKNOWN";
    }

    private String lastEndpointText() {
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
        serverReflexiveCandidates.clear();
        pendingStunBindings.clear();
        turnPermissions.clear();
        relayCandidate = null;
        relayAllocationId = null;
        relayAllocationExpiresAtMillis = 0L;
        lastRelayCandidateRequestMillis = 0L;
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
    }

    private void publish(String text, String detail) {
        if (status != null) {
            status.publish(text, detail == null ? "" : detail, true);
        }
    }

    private static String firstText(String value, String fallback) {
        return isBlank(value) ? (fallback == null ? "" : fallback) : value;
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
        final List<PeerCandidate> candidates;

        PeerInfo(long clientId, String clientName, String virtualIp, String publicKey,
                 boolean online, List<PeerCandidate> candidates) {
            this.clientId = clientId;
            this.clientName = clientName;
            this.virtualIp = virtualIp;
            this.publicKey = publicKey;
            this.online = online;
            this.candidates = candidates == null ? List.of() : candidates;
        }
    }

    private static final class PeerCandidate {
        String type;
        String transport;
        String address;
        int port;
        long priority;
        String foundation;
        String relayId;
    }

    private static final class PeerSession {
        final long peerId;
        final long sessionId;
        final String token;
        final String expiresAt;
        final long createdAtMillis = System.currentTimeMillis();
        final AtomicLong sequence = new AtomicLong();
        final AtomicLong directBytesSinceReport = new AtomicLong();
        final AtomicLong relayBytesSinceReport = new AtomicLong();
        final ReplayWindow replay = new ReplayWindow();
        volatile byte[] aesKey;
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

        long nextSequence() {
            return sequence.incrementAndGet();
        }

        boolean canSend() {
            return aesKey != null && remoteEndpoint != null && pathReady && !isExpired();
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

        void addRelayBytes(long bytes) {
            if (bytes > 0) {
                relayBytesSinceReport.addAndGet(bytes);
            }
        }

        long drainDirectBytes() {
            return directBytesSinceReport.getAndSet(0L);
        }

        long drainRelayBytes() {
            return relayBytesSinceReport.getAndSet(0L);
        }

        boolean accept(long inboundSequence) {
            return replay.accept(inboundSequence);
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

        PendingStunBinding(boolean publicStun) {
            this.publicStun = publicStun;
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

    private static final class StunMessage {
        static final int MAGIC_COOKIE = 0x2112A442;
        static final int HEADER_BYTES = 20;
        static final int TRANSACTION_ID_BYTES = 12;
        static final int BINDING_REQUEST = 0x0001;
        static final int BINDING_SUCCESS = 0x0101;
        static final int ALLOCATE_REQUEST = 0x0003;
        static final int ALLOCATE_SUCCESS = 0x0103;
        static final int REFRESH_REQUEST = 0x0004;
        static final int REFRESH_SUCCESS = 0x0104;
        static final int CREATE_PERMISSION_REQUEST = 0x0008;
        static final int SEND_INDICATION = 0x0016;
        static final int DATA_INDICATION = 0x0017;
        static final int ATTR_LIFETIME = 0x000D;
        static final int ATTR_XOR_PEER_ADDRESS = 0x0012;
        static final int ATTR_DATA = 0x0013;
        static final int ATTR_XOR_RELAYED_ADDRESS = 0x0016;
        static final int ATTR_REQUESTED_TRANSPORT = 0x0019;
        static final int ATTR_XOR_MAPPED_ADDRESS = 0x0020;
        static final int ATTR_SOFTWARE = 0x8022;
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
            if (buffer.getInt() != MAGIC_COOKIE || length + HEADER_BYTES > packet.length) {
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
            int attributeBytes = 0;
            for (Attribute attribute : attributes) {
                attributeBytes += 4 + attribute.value.length + padding(attribute.value.length);
            }
            ByteBuffer buffer = ByteBuffer.allocate(HEADER_BYTES + attributeBytes);
            buffer.putShort((short) type);
            buffer.putShort((short) attributeBytes);
            buffer.putInt(MAGIC_COOKIE);
            buffer.put(transactionId);
            for (Attribute attribute : attributes) {
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

        InetSocketAddress xorRelayedAddress() {
            return firstXorAddress(ATTR_XOR_RELAYED_ADDRESS);
        }

        InetSocketAddress xorPeerAddress() {
            return firstXorAddress(ATTR_XOR_PEER_ADDRESS);
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

        private Attribute first(int type) {
            for (Attribute attribute : attributes) {
                if (attribute.type == type) {
                    return attribute;
                }
            }
            return null;
        }

        private InetSocketAddress firstXorAddress(int type) {
            Attribute attribute = first(type);
            return attribute == null ? null : decodeXorAddress(attribute.value);
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

        static Attribute data(byte[] payload) {
            return new Attribute(ATTR_DATA, payload == null ? new byte[0] : payload.clone());
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

        private static final class Attribute {
            final int type;
            final byte[] value;

            Attribute(int type, byte[] value) {
                this.type = type;
                this.value = value == null ? new byte[0] : value.clone();
            }
        }
    }

    private static final class DataFrame {
        final long sessionId;
        final long fromClientId;
        final long toClientId;
        final long sequence;
        final byte[] plaintext;

        DataFrame(long sessionId, long fromClientId, long toClientId, long sequence, byte[] plaintext) {
            this.sessionId = sessionId;
            this.fromClientId = fromClientId;
            this.toClientId = toClientId;
            this.sequence = sequence;
            this.plaintext = plaintext;
        }
    }

    private static final class DataFrameCodec {
        private static final int MAGIC = 0x53504D31;
        private static final byte VERSION = 1;
        private static final byte TYPE_DATA = 1;
        private static final int NONCE_BYTES = 12;
        private static final int TAG_BITS = 128;
        private static final int AAD_BYTES = Integer.BYTES + 2 + Long.BYTES * 4 + NONCE_BYTES;
        private static final SecureRandom RANDOM = new SecureRandom();

        static byte[] encode(byte[] aesKey, long sessionId, long fromClientId, long toClientId,
                             long sequence, byte[] plaintext) throws Exception {
            byte[] nonce = new byte[NONCE_BYTES];
            RANDOM.nextBytes(nonce);
            byte[] aad = aad(sessionId, fromClientId, toClientId, sequence, nonce);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(aesKey, "AES"), new GCMParameterSpec(TAG_BITS, nonce));
            cipher.updateAAD(aad);
            byte[] ciphertext = cipher.doFinal(plaintext == null ? new byte[0] : plaintext);
            ByteBuffer buffer = ByteBuffer.allocate(aad.length + Integer.BYTES + ciphertext.length);
            buffer.put(aad);
            buffer.putInt(ciphertext.length);
            buffer.put(ciphertext);
            return buffer.array();
        }

        static DataFrame decode(byte[] aesKey, byte[] packet, long expectedSessionId, long expectedToClientId) {
            try {
                if (packet == null || packet.length < AAD_BYTES + Integer.BYTES) {
                    return null;
                }
                ByteBuffer buffer = ByteBuffer.wrap(packet);
                byte[] aad = new byte[AAD_BYTES];
                buffer.get(aad);
                ByteBuffer header = ByteBuffer.wrap(aad);
                int magic = header.getInt();
                byte version = header.get();
                byte type = header.get();
                long sessionId = header.getLong();
                long fromClientId = header.getLong();
                long toClientId = header.getLong();
                long sequence = header.getLong();
                byte[] nonce = new byte[NONCE_BYTES];
                header.get(nonce);
                if (magic != MAGIC || version != VERSION || type != TYPE_DATA
                        || sessionId != expectedSessionId || toClientId != expectedToClientId) {
                    return null;
                }
                int ciphertextLength = buffer.getInt();
                if (ciphertextLength < 0 || ciphertextLength > buffer.remaining()) {
                    return null;
                }
                byte[] ciphertext = new byte[ciphertextLength];
                buffer.get(ciphertext);
                Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
                cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(aesKey, "AES"), new GCMParameterSpec(TAG_BITS, nonce));
                cipher.updateAAD(aad);
                return new DataFrame(sessionId, fromClientId, toClientId, sequence, cipher.doFinal(ciphertext));
            } catch (Exception e) {
                return null;
            }
        }

        static Long sessionId(byte[] packet) {
            if (packet == null || packet.length < AAD_BYTES + Integer.BYTES) {
                return null;
            }
            ByteBuffer header = ByteBuffer.wrap(packet, 0, AAD_BYTES);
            if (header.getInt() != MAGIC || header.get() != VERSION || header.get() != TYPE_DATA) {
                return null;
            }
            return header.getLong();
        }

        static boolean looksLike(byte[] packet) {
            return packet != null && packet.length >= Integer.BYTES && ByteBuffer.wrap(packet, 0, 4).getInt() == MAGIC;
        }

        private static byte[] aad(long sessionId, long fromClientId, long toClientId, long sequence, byte[] nonce) {
            ByteBuffer buffer = ByteBuffer.allocate(AAD_BYTES);
            buffer.putInt(MAGIC);
            buffer.put(VERSION);
            buffer.put(TYPE_DATA);
            buffer.putLong(sessionId);
            buffer.putLong(fromClientId);
            buffer.putLong(toClientId);
            buffer.putLong(sequence);
            buffer.put(nonce);
            return buffer.array();
        }
    }

    private static final class ReplayWindow {
        private long highest;
        private long bitmap;

        synchronized boolean accept(long sequence) {
            if (sequence <= 0) {
                return false;
            }
            if (sequence > highest) {
                long shift = sequence - highest;
                bitmap = shift >= 64 ? 1L : (bitmap << shift) | 1L;
                highest = sequence;
                return true;
            }
            long offset = highest - sequence;
            if (offset >= 64) {
                return false;
            }
            long mask = 1L << offset;
            if ((bitmap & mask) != 0) {
                return false;
            }
            bitmap |= mask;
            return true;
        }
    }

    private static final class IpPacket {
        static String destinationIpv4(byte[] packet) {
            if (!isIpv4(packet)) {
                return "";
            }
            return (packet[16] & 0xFF) + "."
                    + (packet[17] & 0xFF) + "."
                    + (packet[18] & 0xFF) + "."
                    + (packet[19] & 0xFF);
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
