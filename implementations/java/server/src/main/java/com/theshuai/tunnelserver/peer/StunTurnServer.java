package com.theshuai.tunnelserver.peer;

import com.theshuai.common.peermesh.PeerDataFrameHeader;
import com.theshuai.common.peermesh.PeerRelayBinaryFrame;
import com.theshuai.common.peermesh.PeerRelayMessage;
import com.theshuai.common.util.JsonUtil;
import com.theshuai.tunnelserver.config.PeerMeshProperties;
import com.theshuai.tunnelserver.management.service.PeerMeshService;
import jakarta.annotation.PreDestroy;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

@Component
@Slf4j
public class StunTurnServer implements ApplicationRunner {
    private final PeerMeshProperties properties;
    private final PeerMeshService peerMeshService;
    private final Map<String, Allocation> allocations = new ConcurrentHashMap<>();
    private final Map<String, String> allocationByEndpoint = new ConcurrentHashMap<>();
    private DatagramSocket primarySocket;
    private DatagramSocket alternateSocket;
    private Thread primaryThread;
    private Thread alternateThread;
    private ExecutorService relayExecutor;
    private volatile boolean running;

    public StunTurnServer(PeerMeshProperties properties, PeerMeshService peerMeshService) {
        this.properties = properties;
        this.peerMeshService = peerMeshService;
    }

    @Override
    public void run(ApplicationArguments args) {
        if (!properties.isEnabled()) {
            return;
        }
        try {
            primarySocket = new DatagramSocket(properties.getStunTurnPort());
            relayExecutor = createRelayExecutor();
            running = true;
            primaryThread = new Thread(
                    () -> receiveLoop(primarySocket, PeerRelayMessage.PROBE_PRIMARY),
                    "peer-mesh-stun-turn");
            primaryThread.setDaemon(true);
            primaryThread.start();
            startAlternateSocket();
            log.info("[peer-mesh] STUN/TURN-lite UDP server listening on {}", properties.getStunTurnPort());
        } catch (Exception e) {
            log.warn("[peer-mesh] STUN/TURN-lite UDP server failed to start on {}: {}",
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
            alternateThread = new Thread(
                    () -> receiveLoop(alternateSocket, PeerRelayMessage.PROBE_ALTERNATE),
                    "peer-mesh-stun-probe-alt");
            alternateThread.setDaemon(true);
            alternateThread.start();
            log.info("[peer-mesh] NAT probe alternate UDP port listening on {}", alternatePort);
        } catch (Exception e) {
            log.warn("[peer-mesh] NAT probe alternate UDP port {} unavailable: {}", alternatePort, e.getMessage());
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
                    log.debug("[peer-mesh] STUN/TURN-lite receive failed: {}", e.toString());
                }
            }
        }
    }

    private void handle(DatagramPacket packet, DatagramSocket receiveSocket, String probeRole) throws Exception {
        InetSocketAddress remote = new InetSocketAddress(packet.getAddress(), packet.getPort());
        PeerRelayBinaryFrame binaryFrame = PeerRelayBinaryFrame.parse(packet.getData(), packet.getOffset(), packet.getLength());
        if (binaryFrame != null) {
            dispatchRelayBinaryFrame(binaryFrame, remote);
            return;
        }
        String message = new String(packet.getData(), packet.getOffset(), packet.getLength(), StandardCharsets.UTF_8).trim();
        if (message.startsWith("{")) {
            PeerRelayMessage relayMessage = JsonUtil.stringToObject(message, PeerRelayMessage.class);
            if (relayMessage != null && PeerRelayMessage.MAGIC.equals(relayMessage.getMagic())) {
                handleRelayMessage(relayMessage, remote, receiveSocket, probeRole);
                return;
            }
        }
        String response;
        if (message.startsWith("BINDING")) {
            response = "MAPPED " + packet.getAddress().getHostAddress() + " " + packet.getPort();
        } else if (message.startsWith("ALLOCATE")) {
            String id = UUID.randomUUID().toString();
            allocations.put(id, new Allocation(id, remote, Instant.now().plusSeconds(properties.getAllocationTtlSeconds())));
            response = "ALLOCATED " + id + " " + properties.getAllocationTtlSeconds();
        } else if (message.startsWith("REFRESH ")) {
            String id = message.substring("REFRESH ".length()).trim();
            Allocation allocation = allocations.get(id);
            if (allocation == null) {
                response = "ERROR allocation-not-found";
            } else {
                allocations.put(id, new Allocation(id, remote, Instant.now().plusSeconds(properties.getAllocationTtlSeconds())));
                response = "REFRESHED " + id + " " + properties.getAllocationTtlSeconds();
            }
        } else {
            response = "ERROR unsupported-command";
        }
        byte[] bytes = response.getBytes(StandardCharsets.UTF_8);
        receiveSocket.send(new DatagramPacket(bytes, bytes.length, packet.getAddress(), packet.getPort()));
    }

    private void dispatchRelayBinaryFrame(PeerRelayBinaryFrame frame, InetSocketAddress remote) {
        ExecutorService executor = relayExecutor;
        if (executor == null) {
            try {
                handleRelayBinaryFrame(frame, remote);
            } catch (Exception e) {
                log.debug("[peer-mesh] binary relay frame failed: {}", e.toString());
            }
            return;
        }
        try {
            executor.execute(() -> {
                try {
                    handleRelayBinaryFrame(frame, remote);
                } catch (Exception e) {
                    log.debug("[peer-mesh] binary relay frame failed: {}", e.toString());
                }
            });
        } catch (RuntimeException e) {
            log.debug("[peer-mesh] binary relay frame dropped: {}", e.toString());
        }
    }

    private void handleRelayMessage(PeerRelayMessage message,
                                    InetSocketAddress remote,
                                    DatagramSocket receiveSocket,
                                    String probeRole) throws Exception {
        switch (message.getType()) {
            case PeerRelayMessage.TYPE_BINDING -> binding(message, remote, receiveSocket, probeRole);
            case PeerRelayMessage.TYPE_ALLOCATE -> allocate(message, remote);
            case PeerRelayMessage.TYPE_REFRESH -> refresh(message, remote);
            case PeerRelayMessage.TYPE_SEND -> relayData(message, remote);
            default -> sendRelayResponse(primarySocket, remote, error(message, "unsupported-command"));
        }
    }

    private void handleRelayBinaryFrame(PeerRelayBinaryFrame frame, InetSocketAddress remote) throws Exception {
        if (frame.type() != PeerRelayBinaryFrame.TYPE_SEND) {
            return;
        }
        Allocation source = allocations.get(frame.fromAllocationId());
        if (source == null || !sameEndpoint(source.remote(), remote)) {
            return;
        }
        Allocation target = allocations.get(frame.toAllocationId());
        if (target == null) {
            return;
        }
        byte[] payload = frame.payload();
        PeerDataFrameHeader header = PeerDataFrameHeader.parse(payload);
        if (header != null && !peerMeshService.authorizeRelayFrameForRelay(header, payload.length)) {
            return;
        }
        PeerRelayBinaryFrame data = PeerRelayBinaryFrame.data(source.id(), target.id(), payload);
        sendRelayBinary(primarySocket, target.remote(), data);
    }

    private void binding(PeerRelayMessage request,
                         InetSocketAddress remote,
                         DatagramSocket receiveSocket,
                         String probeRole) throws Exception {
        sendRelayResponse(receiveSocket, remote, bindingResponse(request, remote, receiveSocket, probeRole));
        if (PeerRelayMessage.PROBE_PRIMARY.equals(probeRole)
                && alternateSocket != null
                && !alternateSocket.isClosed()) {
            sendRelayResponse(alternateSocket, remote, bindingResponse(
                    request,
                    remote,
                    alternateSocket,
                    PeerRelayMessage.PROBE_CHANGED_PORT));
        }
    }

    private PeerRelayMessage bindingResponse(PeerRelayMessage request,
                                             InetSocketAddress remote,
                                             DatagramSocket responseSocket,
                                             String probeRole) {
        PeerRelayMessage response = baseResponse(request, PeerRelayMessage.TYPE_BINDING_RESPONSE);
        response.setProbeRole(probeRole);
        response.setMappedAddress(remote.getAddress().getHostAddress());
        response.setMappedPort(remote.getPort());
        response.setObservedByAddress(advertisedAddress(responseSocket));
        response.setObservedByPort(responseSocket.getLocalPort());
        if (alternateSocket != null && !alternateSocket.isClosed()) {
            response.setAlternateAddress(advertisedAddress(alternateSocket));
            response.setAlternatePort(alternateSocket.getLocalPort());
        }
        return response;
    }

    private void allocate(PeerRelayMessage request, InetSocketAddress remote) throws Exception {
        String endpointKey = endpointKey(remote);
        String existingId = allocationByEndpoint.get(endpointKey);
        Allocation allocation = existingId == null ? null : allocations.get(existingId);
        String id = allocation == null ? UUID.randomUUID().toString() : allocation.id();
        Instant expiresAt = Instant.now().plusSeconds(properties.getAllocationTtlSeconds());
        allocations.put(id, new Allocation(id, remote, expiresAt));
        allocationByEndpoint.put(endpointKey, id);

        PeerRelayMessage response = baseResponse(request, PeerRelayMessage.TYPE_ALLOCATED);
        response.setAllocationId(id);
        response.setTtlSeconds(properties.getAllocationTtlSeconds());
        sendRelayResponse(primarySocket, remote, response);
    }

    private void refresh(PeerRelayMessage request, InetSocketAddress remote) throws Exception {
        Allocation allocation = allocations.get(request.getAllocationId());
        if (allocation == null || !sameEndpoint(allocation.remote(), remote)) {
            sendRelayResponse(primarySocket, remote, error(request, "allocation-not-found"));
            return;
        }
        allocations.put(allocation.id(), new Allocation(
                allocation.id(),
                remote,
                Instant.now().plusSeconds(properties.getAllocationTtlSeconds())));
        sendRelayResponse(primarySocket, remote, allocatedResponse(request, allocation.id()));
    }

    private void relayData(PeerRelayMessage request, InetSocketAddress remote) throws Exception {
        Allocation source = allocations.get(request.getAllocationId());
        if (source == null || !sameEndpoint(source.remote(), remote)) {
            sendRelayResponse(primarySocket, remote, error(request, "allocation-not-found"));
            return;
        }
        Allocation target = allocations.get(request.getToAllocationId());
        if (target == null) {
            sendRelayResponse(primarySocket, remote, error(request, "target-allocation-not-found"));
            return;
        }
        byte[] payload;
        try {
            payload = Base64.getDecoder().decode(request.getPayloadBase64());
        } catch (Exception e) {
            sendRelayResponse(primarySocket, remote, error(request, "invalid-payload"));
            return;
        }
        PeerDataFrameHeader header = PeerDataFrameHeader.parse(payload);
        if (header != null && !peerMeshService.authorizeRelayFrameForRelay(header, payload.length)) {
            sendRelayResponse(primarySocket, remote, error(request, "relay-session-denied"));
            return;
        }
        PeerRelayMessage data = new PeerRelayMessage();
        data.setType(PeerRelayMessage.TYPE_DATA);
        data.setTransactionId(request.getTransactionId());
        data.setFromAllocationId(source.id());
        data.setToAllocationId(target.id());
        data.setPayloadBase64(request.getPayloadBase64());
        sendRelayResponse(primarySocket, target.remote(), data);
    }

    private PeerRelayMessage allocatedResponse(PeerRelayMessage request, String id) {
        PeerRelayMessage response = baseResponse(request, PeerRelayMessage.TYPE_ALLOCATED);
        response.setAllocationId(id);
        response.setTtlSeconds(properties.getAllocationTtlSeconds());
        return response;
    }

    private PeerRelayMessage baseResponse(PeerRelayMessage request, String type) {
        PeerRelayMessage response = new PeerRelayMessage();
        response.setType(type);
        response.setTransactionId(request.getTransactionId());
        return response;
    }

    private PeerRelayMessage error(PeerRelayMessage request, String reason) {
        PeerRelayMessage response = baseResponse(request, PeerRelayMessage.TYPE_ERROR);
        response.setError(reason);
        return response;
    }

    private void sendRelayResponse(DatagramSocket outbound, InetSocketAddress remote, PeerRelayMessage response) throws Exception {
        if (outbound == null || outbound.isClosed()) {
            return;
        }
        byte[] bytes = JsonUtil.objectToString(response).getBytes(StandardCharsets.UTF_8);
        outbound.send(new DatagramPacket(bytes, bytes.length, remote));
    }

    private void sendRelayBinary(DatagramSocket outbound, InetSocketAddress remote, PeerRelayBinaryFrame frame) throws Exception {
        if (outbound == null || outbound.isClosed()) {
            return;
        }
        byte[] bytes = frame.toBytes();
        outbound.send(new DatagramPacket(bytes, bytes.length, remote));
    }

    @Scheduled(fixedDelay = 30_000)
    public void cleanupExpiredAllocations() {
        Instant now = Instant.now();
        allocations.entrySet().removeIf(entry -> {
            boolean expired = entry.getValue().expiresAt().isBefore(now);
            if (expired) {
                allocationByEndpoint.remove(endpointKey(entry.getValue().remote()), entry.getKey());
            }
            return expired;
        });
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
        if (relayExecutor != null) {
            relayExecutor.shutdownNow();
        }
    }

    private record Allocation(String id, InetSocketAddress remote, Instant expiresAt) {
    }

    private boolean sameEndpoint(InetSocketAddress left, InetSocketAddress right) {
        return Objects.equals(endpointKey(left), endpointKey(right));
    }

    private String endpointKey(InetSocketAddress remote) {
        if (remote == null || remote.getAddress() == null) {
            return "";
        }
        return remote.getAddress().getHostAddress() + ":" + remote.getPort();
    }

    private int natProbeAlternatePort() {
        int configured = properties.getNatProbeAlternatePort();
        if (configured > 0) {
            return configured;
        }
        int next = properties.getStunTurnPort() + 1;
        return next > 0 && next <= 65_535 ? next : 0;
    }

    private String advertisedAddress(DatagramSocket responseSocket) {
        if (properties.getPublicAddress() != null && !properties.getPublicAddress().isBlank()) {
            return properties.getPublicAddress().trim();
        }
        if (responseSocket == null || responseSocket.getLocalAddress() == null) {
            return "";
        }
        if (responseSocket.getLocalAddress().isAnyLocalAddress()) {
            return "";
        }
        return responseSocket.getLocalAddress().getHostAddress();
    }

    private ExecutorService createRelayExecutor() {
        int configuredThreads = properties.getRelayWorkerThreads();
        int workers = configuredThreads > 0
                ? configuredThreads
                : Math.max(2, Math.min(8, Runtime.getRuntime().availableProcessors()));
        int queueCapacity = Math.max(1, properties.getRelayWorkerQueueCapacity());
        ThreadFactory threadFactory = new ThreadFactory() {
            private int index;

            @Override
            public Thread newThread(Runnable runnable) {
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
}
