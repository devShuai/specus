package com.theshuai.tunnelserver.peer;

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
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

@Component
@Slf4j
public class StunTurnServer implements ApplicationRunner {
    private final PeerMeshProperties properties;
    private final Map<String, Allocation> allocations = new ConcurrentHashMap<>();
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
        byte[] buffer = new byte[2048];
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

    @Scheduled(fixedDelay = 30_000)
    public void cleanupExpiredAllocations() {
        Instant now = Instant.now();
        allocations.entrySet().removeIf(entry -> entry.getValue().expiresAt().isBefore(now));
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
}
