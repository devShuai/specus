package com.theshuai.specus.android;

import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicBoolean;

final class PeerServiceUdpBridge implements AutoCloseable {
    private final String virtualIp;
    private final SpecusCore.LocalPeerService service;
    private final DatagramSocket inbound;
    private final InetSocketAddress target;
    private final ExecutorService executor;
    private final AtomicBoolean open = new AtomicBoolean(true);
    private final ConcurrentHashMap<SocketAddress, DatagramSocket> peers = new ConcurrentHashMap<>();

    private PeerServiceUdpBridge(String virtualIp, SpecusCore.LocalPeerService service, DatagramSocket inbound) {
        this.virtualIp = virtualIp;
        this.service = service;
        this.inbound = inbound;
        this.target = new InetSocketAddress(service.targetHost, service.targetPort);
        this.executor = Executors.newCachedThreadPool(r -> {
            Thread thread = new Thread(r, "peer-service-udp-" + service.serviceId);
            thread.setDaemon(true);
            return thread;
        });
        executor.execute(this::acceptLoop);
    }

    static PeerServiceUdpBridge bind(String virtualIp, SpecusCore.LocalPeerService service) throws Exception {
        DatagramSocket socket = new DatagramSocket(new InetSocketAddress(InetAddress.getByName(virtualIp),
                service.publishedPort));
        socket.setReuseAddress(true);
        return new PeerServiceUdpBridge(virtualIp, service, socket);
    }

    boolean matches(String virtualIp, SpecusCore.LocalPeerService service) {
        return Objects.equals(this.virtualIp, virtualIp)
                && Objects.equals(this.service.serviceId, service.serviceId)
                && this.service.publishedPort == service.publishedPort
                && Objects.equals(this.service.targetHost, service.targetHost)
                && this.service.targetPort == service.targetPort;
    }

    private void acceptLoop() {
        byte[] buffer = new byte[65507];
        while (open.get() && !inbound.isClosed()) {
            try {
                DatagramPacket packet = new DatagramPacket(buffer, buffer.length);
                inbound.receive(packet);
                DatagramSocket outbound = peers.computeIfAbsent(packet.getSocketAddress(), this::openPeer);
                outbound.send(new DatagramPacket(packet.getData(), packet.getOffset(), packet.getLength(), target));
            } catch (Exception e) {
                return;
            }
        }
    }

    private DatagramSocket openPeer(SocketAddress peer) {
        try {
            DatagramSocket socket = new DatagramSocket();
            socket.connect(target);
            executor.execute(() -> replyLoop(socket, peer));
            return socket;
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private void replyLoop(DatagramSocket socket, SocketAddress peer) {
        byte[] buffer = new byte[65507];
        while (open.get() && !socket.isClosed()) {
            try {
                DatagramPacket packet = new DatagramPacket(buffer, buffer.length);
                socket.receive(packet);
                inbound.send(new DatagramPacket(packet.getData(), packet.getOffset(), packet.getLength(), peer));
            } catch (Exception ignored) {
                return;
            }
        }
    }

    @Override
    public void close() {
        open.set(false);
        inbound.close();
        peers.values().forEach(DatagramSocket::close);
        peers.clear();
        executor.shutdownNow();
    }
}
