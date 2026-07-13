package com.theshuai.tunnelserver.peer;

import com.theshuai.common.peermesh.PeerDataFrameHeader;
import com.theshuai.common.stun.StunMessage;
import com.theshuai.tunnelserver.config.PeerMeshProperties;
import com.theshuai.tunnelserver.management.service.PeerMeshService;
import jakarta.annotation.PreDestroy;
import lombok.extern.slf4j.Slf4j;
import org.jspecify.annotations.NonNull;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.ThreadLocalRandom;
import java.util.concurrent.TimeUnit;

@Component
@Slf4j
public class StunTurnServer implements ApplicationRunner {
    private static final String SOFTWARE = "shuai-tunnel-standard-stun-turn";
    private static final long PERMISSION_TTL_SECONDS = 300;

    private final PeerMeshProperties properties;
    private final PeerMeshService peerMeshService;
    private final TurnCredentialService turnCredentialService;
    private final Map<String, Allocation> allocations = new ConcurrentHashMap<>();
    private final Map<String, String> allocationByEndpoint = new ConcurrentHashMap<>();
    private DatagramSocket primarySocket;
    private DatagramSocket alternateSocket;
    private ExecutorService relayExecutor;
    private volatile boolean running;

    public StunTurnServer(PeerMeshProperties properties,
                          PeerMeshService peerMeshService,
                          TurnCredentialService turnCredentialService) {
        this.properties = properties;
        this.peerMeshService = peerMeshService;
        this.turnCredentialService = turnCredentialService;
    }

    @Override
    public void run(@NonNull ApplicationArguments args) {
        if (!properties.isEnabled()) {
            return;
        }
        try {
            primarySocket = new DatagramSocket(properties.getStunTurnPort());
            relayExecutor = createRelayExecutor();
            running = true;
            Thread primaryThread = new Thread(
                    () -> receiveLoop(primarySocket, "primary"),
                    "peer-mesh-stun-turn");
            primaryThread.setDaemon(true);
            primaryThread.start();
            startAlternateSocket();
            log.info("[peer-mesh] standard STUN/TURN UDP server listening on {}", properties.getStunTurnPort());
        } catch (Exception e) {
            log.warn("[peer-mesh] standard STUN/TURN UDP server failed to start on {}: {}",
                    properties.getStunTurnPort(), e.getMessage());
        }
    }

    private void startAlternateSocket() {
        int alternatePort = natProbeAlternatePort();
        if (alternatePort <= 0 || alternatePort == properties.getStunTurnPort()) {
            return;
        }
        try {
            alternateSocket = new DatagramSocket(alternatePort);
            Thread alternateThread = new Thread(
                    () -> receiveLoop(alternateSocket, "alternate"),
                    "peer-mesh-stun-probe-alt");
            alternateThread.setDaemon(true);
            alternateThread.start();
            log.info("[peer-mesh] standard STUN alternate UDP port listening on {}", alternatePort);
        } catch (Exception e) {
            log.warn("[peer-mesh] standard STUN alternate UDP port {} unavailable: {}", alternatePort, e.getMessage());
        }
    }

    private void receiveLoop(DatagramSocket receiveSocket, String probeRole) {
        byte[] buffer = new byte[65_507];
        while (running && receiveSocket != null && !receiveSocket.isClosed()) {
            DatagramPacket packet = new DatagramPacket(buffer, buffer.length);
            try {
                receiveSocket.receive(packet);
                handle(packet, receiveSocket, probeRole);
            } catch (Exception e) {
                if (running) {
                    log.debug("[peer-mesh] STUN/TURN receive failed: {}", e.toString());
                }
            }
        }
    }

    private void handle(DatagramPacket packet, DatagramSocket receiveSocket, String probeRole) throws Exception {
        InetSocketAddress remote = new InetSocketAddress(packet.getAddress(), packet.getPort());
        StunMessage message = StunMessage.parse(packet.getData(), packet.getOffset(), packet.getLength());
        if (message == null) {
            return;
        }
        switch (message.type()) {
            case StunMessage.BINDING_REQUEST -> binding(message, remote, receiveSocket, probeRole);
            case StunMessage.ALLOCATE_REQUEST -> allocate(message, packet, remote);
            case StunMessage.REFRESH_REQUEST -> refresh(message, packet, remote);
            case StunMessage.CREATE_PERMISSION_REQUEST -> createPermission(message, packet, remote);
            case StunMessage.SEND_INDICATION -> sendIndication(message, remote);
            default -> sendError(receiveSocket, remote, message, errorType(message.type()), 400, "unsupported-method");
        }
    }

    private void binding(StunMessage request,
                         InetSocketAddress remote,
                         DatagramSocket receiveSocket,
                         String probeRole) throws Exception {
        InetSocketAddress responseOrigin = advertisedSocketAddress(receiveSocket);
        StunMessage response = alternateSocket != null && !alternateSocket.isClosed()
                ? StunMessage.of(
                StunMessage.BINDING_SUCCESS,
                request.transactionId(),
                StunMessage.xorMappedAddress(remote, request.transactionId()),
                StunMessage.software(SOFTWARE),
                new StunMessage.Attribute(StunMessage.ATTR_RESPONSE_ORIGIN,
                        StunMessage.encodeXorAddress(responseOrigin, request.transactionId())),
                StunMessage.otherAddress(advertisedSocketAddress(alternateSocket), request.transactionId()))
                : StunMessage.of(
                StunMessage.BINDING_SUCCESS,
                request.transactionId(),
                StunMessage.xorMappedAddress(remote, request.transactionId()),
                StunMessage.software(SOFTWARE),
                new StunMessage.Attribute(StunMessage.ATTR_RESPONSE_ORIGIN,
                        StunMessage.encodeXorAddress(responseOrigin, request.transactionId())));
        sendStun(receiveSocket, remote, response);
        log.trace("[peer-mesh] STUN binding role={} remote={}", probeRole, remote);
    }

    private void allocate(StunMessage request, DatagramPacket packet, InetSocketAddress remote) throws Exception {
        TurnAuth auth = authenticate(request, packet, remote, StunMessage.ALLOCATE_ERROR);
        if (!auth.allowed()) {
            return;
        }
        if (!request.requestedUdpTransport()) {
            sendError(primarySocket, remote, request, StunMessage.ALLOCATE_ERROR, 442, "unsupported-transport");
            return;
        }
        String endpointKey = endpointKey(remote);
        Allocation allocation = allocationByEndpoint.containsKey(endpointKey)
                ? allocations.get(allocationByEndpoint.get(endpointKey))
                : null;
        if (allocation == null || allocation.isExpired(Instant.now())) {
            allocation = createAllocation(remote);
        } else {
            allocation.expiresAt = Instant.now().plusSeconds(properties.getAllocationTtlSeconds());
        }
        StunMessage response = StunMessage.of(
                StunMessage.ALLOCATE_SUCCESS,
                request.transactionId(),
                StunMessage.xorRelayedAddress(allocation.relayAddress, request.transactionId()),
                StunMessage.xorMappedAddress(remote, request.transactionId()),
                StunMessage.lifetime(properties.getAllocationTtlSeconds()),
                StunMessage.software(SOFTWARE)
        );
        sendStun(primarySocket, remote, response, auth.messageIntegrityKey());
    }

    private Allocation createAllocation(InetSocketAddress remote) throws Exception {
        DatagramSocket relaySocket = bindRelaySocket();
        Allocation allocation = new Allocation(
                UUID.randomUUID().toString(),
                remote,
                relaySocket,
                advertisedSocketAddress(relaySocket),
                Instant.now().plusSeconds(properties.getAllocationTtlSeconds())
        );
        allocations.put(allocation.id, allocation);
        allocationByEndpoint.put(endpointKey(remote), allocation.id);

        Thread thread = new Thread(() -> relayReceiveLoop(allocation), "peer-turn-relay-" + relaySocket.getLocalPort());
        thread.setDaemon(true);
        allocation.relayThread = thread;
        thread.start();
        log.info("[peer-mesh] TURN allocation created: client={}, relay={}", remote, allocation.relayAddress);
        return allocation;
    }

    private DatagramSocket bindRelaySocket() throws Exception {
        int min = Math.clamp(properties.getRelayMinPort(), 1, 65_535);
        int max = Math.clamp(properties.getRelayMaxPort(), 1, 65_535);
        if (min > max) {
            int tmp = min;
            min = max;
            max = tmp;
        }
        int capacity = max - min + 1;
        int attempts = Math.clamp(capacity, 16, 128);
        int start = min + ThreadLocalRandom.current().nextInt(capacity);
        Exception last = null;
        for (int i = 0; i < attempts; i++) {
            int port = min + ((start - min + i) % capacity);
            try {
                return new DatagramSocket(port);
            } catch (Exception e) {
                last = e;
            }
        }
        if (last != null) {
            throw last;
        }
        return new DatagramSocket(0);
    }

    private void refresh(StunMessage request, DatagramPacket packet, InetSocketAddress remote) throws Exception {
        TurnAuth auth = authenticate(request, packet, remote, StunMessage.REFRESH_ERROR);
        if (!auth.allowed()) {
            return;
        }
        Allocation allocation = allocationForRemote(remote);
        if (allocation == null) {
            sendError(primarySocket, remote, request, StunMessage.REFRESH_ERROR, 437, "allocation-mismatch");
            return;
        }
        long lifetime = request.lifetimeSeconds(properties.getAllocationTtlSeconds());
        if (lifetime <= 0) {
            closeAllocation(allocation);
        } else {
            allocation.expiresAt = Instant.now().plusSeconds(Math.min(lifetime, properties.getAllocationTtlSeconds()));
        }
        StunMessage response = StunMessage.of(
                StunMessage.REFRESH_SUCCESS,
                request.transactionId(),
                StunMessage.lifetime(lifetime <= 0 ? 0 : properties.getAllocationTtlSeconds()),
                StunMessage.software(SOFTWARE)
        );
        sendStun(primarySocket, remote, response, auth.messageIntegrityKey());
    }

    private void createPermission(StunMessage request, DatagramPacket packet, InetSocketAddress remote) throws Exception {
        TurnAuth auth = authenticate(request, packet, remote, StunMessage.CREATE_PERMISSION_ERROR);
        if (!auth.allowed()) {
            return;
        }
        Allocation allocation = allocationForRemote(remote);
        if (allocation == null) {
            sendError(primarySocket, remote, request, StunMessage.CREATE_PERMISSION_ERROR, 437, "allocation-mismatch");
            return;
        }
        Instant expiresAt = Instant.now().plusSeconds(PERMISSION_TTL_SECONDS);
        for (StunMessage.Attribute attribute : request.all(StunMessage.ATTR_XOR_PEER_ADDRESS)) {
            new StunMessage(request.type(), request.transactionId(), java.util.List.of(attribute))
                    .xorPeerAddress()
                    .ifPresent(address -> allocation.permissions.put(permissionKey(address), expiresAt));
        }
        StunMessage response = StunMessage.of(
                StunMessage.CREATE_PERMISSION_SUCCESS,
                request.transactionId(),
                StunMessage.software(SOFTWARE)
        );
        sendStun(primarySocket, remote, response, auth.messageIntegrityKey());
    }

    private TurnAuth authenticate(StunMessage request,
                                  DatagramPacket packet,
                                  InetSocketAddress remote,
                                  int responseType) throws Exception {
        if (!turnCredentialService.authRequired()) {
            return TurnAuth.none();
        }
        String username = request.username().orElse("");
        String realm = request.realm().orElse("");
        String nonce = request.nonce().orElse("");
        if (!turnCredentialService.realm().equals(realm)
                || username.isBlank()
                || nonce.isBlank()) {
            sendTurnAuthError(remote, request, responseType, 401, "unauthorized");
            return TurnAuth.denied();
        }
        if (!turnCredentialService.nonce().equals(nonce)) {
            sendTurnAuthError(remote, request, responseType, 438, "stale-nonce");
            return TurnAuth.denied();
        }
        String credential = turnCredentialService.credentialForUsername(username);
        if (!turnCredentialService.usernameCredentialValid(username, credential)) {
            sendTurnAuthError(remote, request, responseType, 401, "unauthorized");
            return TurnAuth.denied();
        }
        byte[] key = turnCredentialService.longTermKey(username, credential);
        if (!StunMessage.verifyMessageIntegrity(
                packet.getData(), packet.getOffset(), packet.getLength(), key)) {
            sendTurnAuthError(remote, request, responseType, 401, "bad-message-integrity");
            return TurnAuth.denied();
        }
        return TurnAuth.allowed(key);
    }

    private void sendTurnAuthError(InetSocketAddress remote,
                                   StunMessage request,
                                   int responseType,
                                   int code,
                                   String reason) throws Exception {
        sendError(
                primarySocket,
                remote,
                request,
                responseType,
                code,
                reason,
                StunMessage.realm(turnCredentialService.realm()),
                StunMessage.nonce(turnCredentialService.nonce()));
    }

    private void sendIndication(StunMessage indication, InetSocketAddress remote) throws Exception {
        Allocation allocation = allocationForRemote(remote);
        if (allocation == null) {
            return;
        }
        InetSocketAddress peer = indication.xorPeerAddress().orElse(null);
        byte[] payload = indication.data().orElse(null);
        if (peer == null || payload == null || hasNotPermission(allocation, peer)) {
            return;
        }
        PeerDataFrameHeader header = PeerDataFrameHeader.parse(payload);
        if (header != null && !peerMeshService.authorizeRelayFrameForRelay(header, payload.length)) {
            return;
        }
        allocation.relaySocket.send(new DatagramPacket(payload, payload.length, peer));
    }

    private void relayReceiveLoop(Allocation allocation) {
        byte[] buffer = new byte[65_507];
        while (running && !allocation.closed && allocation.relaySocket != null && !allocation.relaySocket.isClosed()) {
            DatagramPacket packet = new DatagramPacket(buffer, buffer.length);
            try {
                allocation.relaySocket.receive(packet);
                InetSocketAddress peer = new InetSocketAddress(packet.getAddress(), packet.getPort());
                if (hasNotPermission(allocation, peer)) {
                    continue;
                }
                byte[] payload = java.util.Arrays.copyOfRange(packet.getData(), packet.getOffset(), packet.getOffset() + packet.getLength());
                dispatchDataIndication(allocation, peer, payload);
            } catch (Exception e) {
                if (running && !allocation.closed) {
                    log.debug("[peer-mesh] TURN relay receive failed: {}", e.toString());
                }
            }
        }
    }

    private void dispatchDataIndication(Allocation allocation, InetSocketAddress peer, byte[] payload) {
        ExecutorService executor = relayExecutor;
        Runnable task = () -> {
            try {
                byte[] transactionId = StunMessage.newTransactionId();
                StunMessage data = StunMessage.of(
                        StunMessage.DATA_INDICATION,
                        transactionId,
                        StunMessage.xorPeerAddress(peer, transactionId),
                        StunMessage.data(payload)
                );
                sendStun(primarySocket, allocation.clientRemote, data);
            } catch (Exception e) {
                log.debug("[peer-mesh] TURN data indication failed: {}", e.toString());
            }
        };
        if (executor == null) {
            task.run();
            return;
        }
        try {
            executor.execute(task);
        } catch (RuntimeException e) {
            log.debug("[peer-mesh] TURN data indication dropped: {}", e.toString());
        }
    }

    private Allocation allocationForRemote(InetSocketAddress remote) {
        String id = allocationByEndpoint.get(endpointKey(remote));
        Allocation allocation = id == null ? null : allocations.get(id);
        if (allocation == null || allocation.isExpired(Instant.now())) {
            if (allocation != null) {
                closeAllocation(allocation);
            }
            return null;
        }
        allocation.clientRemote = remote;
        return allocation;
    }

    private boolean hasNotPermission(Allocation allocation, InetSocketAddress peer) {
        Instant expiresAt = allocation.permissions.get(permissionKey(peer));
        return expiresAt == null || !expiresAt.isAfter(Instant.now());
    }

    private void sendStun(DatagramSocket socket, InetSocketAddress remote, StunMessage message) throws Exception {
        sendStun(socket, remote, message, null);
    }

    private void sendStun(DatagramSocket socket,
                          InetSocketAddress remote,
                          StunMessage message,
                          byte[] messageIntegrityKey) throws Exception {
        if (socket == null || socket.isClosed() || remote == null) {
            return;
        }
        byte[] bytes = message.toBytes(messageIntegrityKey);
        socket.send(new DatagramPacket(bytes, bytes.length, remote));
    }

    private void sendError(DatagramSocket socket,
                           InetSocketAddress remote,
                           StunMessage request,
                           int responseType,
                           int code,
                           String reason,
                           StunMessage.Attribute... extraAttributes) throws Exception {
        List<StunMessage.Attribute> attributes = new ArrayList<>();
        attributes.add(StunMessage.errorCode(code, reason));
        attributes.add(StunMessage.software(SOFTWARE));
        if (extraAttributes != null) {
            attributes.addAll(List.of(extraAttributes));
        }
        StunMessage response = new StunMessage(responseType, request.transactionId(), attributes);
        sendStun(socket, remote, response);
    }

    private int errorType(int requestType) {
        return switch (requestType) {
            case StunMessage.ALLOCATE_REQUEST -> StunMessage.ALLOCATE_ERROR;
            case StunMessage.REFRESH_REQUEST -> StunMessage.REFRESH_ERROR;
            case StunMessage.CREATE_PERMISSION_REQUEST -> StunMessage.CREATE_PERMISSION_ERROR;
            default -> StunMessage.BINDING_ERROR;
        };
    }

    @Scheduled(fixedDelay = 30_000)
    public void cleanupExpiredAllocations() {
        Instant now = Instant.now();
        for (Allocation allocation : allocations.values()) {
            allocation.permissions.entrySet().removeIf(entry -> entry.getValue().isBefore(now));
            if (allocation.isExpired(now)) {
                closeAllocation(allocation);
            }
        }
    }

    @PreDestroy
    public void stop() {
        running = false;
        if (primarySocket != null) {
            primarySocket.close();
        }
        if (alternateSocket != null) {
            alternateSocket.close();
        }
        for (Allocation allocation : allocations.values()) {
            closeAllocation(allocation);
        }
        if (relayExecutor != null) {
            relayExecutor.shutdownNow();
        }
    }

    private void closeAllocation(Allocation allocation) {
        if (allocation == null || allocation.closed) {
            return;
        }
        allocation.closed = true;
        allocations.remove(allocation.id);
        allocationByEndpoint.remove(endpointKey(allocation.clientRemote), allocation.id);
        if (allocation.relaySocket != null) {
            allocation.relaySocket.close();
        }
        if (allocation.relayThread != null) {
            allocation.relayThread.interrupt();
        }
    }

    private String endpointKey(InetSocketAddress remote) {
        if (remote == null || remote.getAddress() == null) {
            return "";
        }
        return remote.getAddress().getHostAddress() + ":" + remote.getPort();
    }

    private String permissionKey(InetSocketAddress remote) {
        if (remote == null || remote.getAddress() == null) {
            return "";
        }
        return remote.getAddress().getHostAddress();
    }

    private int natProbeAlternatePort() {
        int configured = properties.getNatProbeAlternatePort();
        if (configured > 0) {
            return configured;
        }
        int next = properties.getStunTurnPort() + 1;
        return next > 0 && next <= 65_535 ? next : 0;
    }

    private InetSocketAddress advertisedSocketAddress(DatagramSocket socket) {
        return new InetSocketAddress(advertisedAddress(socket), socket == null ? 0 : socket.getLocalPort());
    }

    private InetAddress advertisedAddress(DatagramSocket socket) {
        try {
            if (properties.getPublicAddress() != null && !properties.getPublicAddress().isBlank()) {
                return InetAddress.getByName(properties.getPublicAddress().trim());
            }
            if (socket != null && socket.getLocalAddress() != null && !socket.getLocalAddress().isAnyLocalAddress()) {
                return socket.getLocalAddress();
            }
            return InetAddress.getLocalHost();
        } catch (Exception e) {
            throw new IllegalStateException("cannot resolve advertised TURN address", e);
        }
    }

    private ExecutorService createRelayExecutor() {
        int configuredThreads = properties.getRelayWorkerThreads();
        int workers = configuredThreads > 0
                ? configuredThreads
                : Math.clamp(Runtime.getRuntime().availableProcessors(), 2, 8);
        int queueCapacity = Math.max(1, properties.getRelayWorkerQueueCapacity());
        ThreadFactory threadFactory = new ThreadFactory() {
            private int index;

            @Override
            public Thread newThread(@NonNull Runnable runnable) {
                Thread thread = new Thread(runnable, "peer-mesh-relay-" + (++index));
                thread.setDaemon(true);
                return thread;
            }
        };
        return new ThreadPoolExecutor(
                workers,
                workers,
                0L,
                TimeUnit.MILLISECONDS,
                new ArrayBlockingQueue<>(queueCapacity),
                threadFactory,
                new ThreadPoolExecutor.DiscardPolicy());
    }

    private static final class Allocation {
        private final String id;
        private volatile InetSocketAddress clientRemote;
        private final DatagramSocket relaySocket;
        private final InetSocketAddress relayAddress;
        private final Map<String, Instant> permissions = new ConcurrentHashMap<>();
        private volatile Instant expiresAt;
        private volatile Thread relayThread;
        private volatile boolean closed;

        private Allocation(String id,
                           InetSocketAddress clientRemote,
                           DatagramSocket relaySocket,
                           InetSocketAddress relayAddress,
                           Instant expiresAt) {
            this.id = Objects.requireNonNull(id, "id");
            this.clientRemote = clientRemote;
            this.relaySocket = relaySocket;
            this.relayAddress = relayAddress;
            this.expiresAt = expiresAt;
        }

        private boolean isExpired(Instant now) {
            return closed || expiresAt == null || !expiresAt.isAfter(now);
        }
    }

    private record TurnAuth(boolean allowed, byte[] messageIntegrityKey) {
        private static TurnAuth none() {
            return new TurnAuth(true, null);
        }

        private static TurnAuth denied() {
            return new TurnAuth(false, null);
        }

        private static TurnAuth allowed(byte[] messageIntegrityKey) {
            return new TurnAuth(true, messageIntegrityKey);
        }
    }
}
