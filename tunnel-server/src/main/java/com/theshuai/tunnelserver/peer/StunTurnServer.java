package com.theshuai.tunnelserver.peer;

import com.theshuai.common.peermesh.PeerRelayMessage;
import com.theshuai.common.util.JsonUtil;
import com.theshuai.tunnelserver.config.PeerMeshProperties;
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
import java.util.Map;
import java.util.Objects;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

@Component
@Slf4j
public class StunTurnServer implements ApplicationRunner {
    private final PeerMeshProperties properties;
    private final Map<String, Allocation> allocations = new ConcurrentHashMap<>();
    private final Map<String, String> allocationByEndpoint = new ConcurrentHashMap<>();
    private DatagramSocket socket;
    private Thread thread;
    private volatile boolean running;

    public StunTurnServer(PeerMeshProperties properties) {
        this.properties = properties;
    }

    @Override
    public void run(ApplicationArguments args) {
        if (!properties.isEnabled()) {
            return;
        }
        try {
            socket = new DatagramSocket(properties.getStunTurnPort());
            running = true;
            thread = new Thread(this::receiveLoop, "peer-mesh-stun-turn");
            thread.setDaemon(true);
            thread.start();
            log.info("[peer-mesh] STUN/TURN-lite UDP server listening on {}", properties.getStunTurnPort());
        } catch (Exception e) {
            log.warn("[peer-mesh] STUN/TURN-lite UDP server failed to start on {}: {}",
                    properties.getStunTurnPort(), e.getMessage());
        }
    }

    private void receiveLoop() {
        byte[] buffer = new byte[65_507];
        while (running && socket != null && !socket.isClosed()) {
            DatagramPacket packet = new DatagramPacket(buffer, buffer.length);
            try {
                socket.receive(packet);
                handle(packet);
            } catch (Exception e) {
                if (running) {
                    log.debug("[peer-mesh] STUN/TURN-lite receive failed: {}", e.toString());
                }
            }
        }
    }

    private void handle(DatagramPacket packet) throws Exception {
        String message = new String(packet.getData(), packet.getOffset(), packet.getLength(), StandardCharsets.UTF_8).trim();
        InetSocketAddress remote = new InetSocketAddress(packet.getAddress(), packet.getPort());
        if (message.startsWith("{")) {
            PeerRelayMessage relayMessage = JsonUtil.stringToObject(message, PeerRelayMessage.class);
            if (relayMessage != null && PeerRelayMessage.MAGIC.equals(relayMessage.getMagic())) {
                handleRelayMessage(relayMessage, remote);
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
        socket.send(new DatagramPacket(bytes, bytes.length, packet.getAddress(), packet.getPort()));
    }

    private void handleRelayMessage(PeerRelayMessage message, InetSocketAddress remote) throws Exception {
        switch (message.getType()) {
            case PeerRelayMessage.TYPE_BINDING -> sendRelayResponse(remote, bindingResponse(message, remote));
            case PeerRelayMessage.TYPE_ALLOCATE -> allocate(message, remote);
            case PeerRelayMessage.TYPE_REFRESH -> refresh(message, remote);
            case PeerRelayMessage.TYPE_SEND -> relayData(message, remote);
            default -> sendRelayResponse(remote, error(message, "unsupported-command"));
        }
    }

    private PeerRelayMessage bindingResponse(PeerRelayMessage request, InetSocketAddress remote) {
        PeerRelayMessage response = baseResponse(request, PeerRelayMessage.TYPE_BINDING_RESPONSE);
        response.setMappedAddress(remote.getAddress().getHostAddress());
        response.setMappedPort(remote.getPort());
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
        sendRelayResponse(remote, response);
    }

    private void refresh(PeerRelayMessage request, InetSocketAddress remote) throws Exception {
        Allocation allocation = allocations.get(request.getAllocationId());
        if (allocation == null || !sameEndpoint(allocation.remote(), remote)) {
            sendRelayResponse(remote, error(request, "allocation-not-found"));
            return;
        }
        allocations.put(allocation.id(), new Allocation(
                allocation.id(),
                remote,
                Instant.now().plusSeconds(properties.getAllocationTtlSeconds())));
        sendRelayResponse(remote, allocatedResponse(request, allocation.id()));
    }

    private void relayData(PeerRelayMessage request, InetSocketAddress remote) throws Exception {
        Allocation source = allocations.get(request.getAllocationId());
        if (source == null || !sameEndpoint(source.remote(), remote)) {
            sendRelayResponse(remote, error(request, "allocation-not-found"));
            return;
        }
        Allocation target = allocations.get(request.getToAllocationId());
        if (target == null) {
            sendRelayResponse(remote, error(request, "target-allocation-not-found"));
            return;
        }
        PeerRelayMessage data = new PeerRelayMessage();
        data.setType(PeerRelayMessage.TYPE_DATA);
        data.setTransactionId(request.getTransactionId());
        data.setFromAllocationId(source.id());
        data.setToAllocationId(target.id());
        data.setPayloadBase64(request.getPayloadBase64());
        sendRelayResponse(target.remote(), data);
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

    private void sendRelayResponse(InetSocketAddress remote, PeerRelayMessage response) throws Exception {
        byte[] bytes = JsonUtil.objectToString(response).getBytes(StandardCharsets.UTF_8);
        socket.send(new DatagramPacket(bytes, bytes.length, remote));
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
        if (socket != null) {
            socket.close();
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
}
