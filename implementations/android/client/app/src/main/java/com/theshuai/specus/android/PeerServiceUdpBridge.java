package com.theshuai.specus.android;

import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.logging.Logger;

final class PeerServiceUdpBridge implements AutoCloseable {
    private static final int MAX_PEERS = 64;
    private static final int PEER_IDLE_TIMEOUT_MILLIS = 60_000;
    private static final Logger LOG = Logger.getLogger(PeerServiceUdpBridge.class.getName());
    private final String virtualIp;
    private final SpecusCore.LocalPeerService service;
    private final DatagramSocket inbound;
    private final InetSocketAddress target;
    private final Set<InetAddress> allowedPeerAddresses;
    private final Set<String> auditedAccessEvents = ConcurrentHashMap.newKeySet();
    private final ExecutorService executor;
    private final AtomicBoolean open = new AtomicBoolean(true);
    private final ConcurrentHashMap<SocketAddress, DatagramSocket> peers = new ConcurrentHashMap<>();

    private PeerServiceUdpBridge(String virtualIp, SpecusCore.LocalPeerService service, DatagramSocket inbound) {
        this.virtualIp = virtualIp;
        this.service = service;
        this.inbound = inbound;
        this.target = new InetSocketAddress(service.targetHost, service.targetPort);
        this.allowedPeerAddresses = PeerServiceBridge.allowedPeerAddresses(service);
        this.executor = Executors.newCachedThreadPool(r -> {
            Thread thread = new Thread(r, "peer-service-udp-" + service.serviceId);
            thread.setDaemon(true);
            return thread;
        });
        executor.execute(this::acceptLoop);
    }

    static PeerServiceUdpBridge bind(String virtualIp, SpecusCore.LocalPeerService service) throws Exception {
        if (!PeerServiceRuntime.isLocalServiceTarget(service.targetHost)) {
            throw new IllegalArgumentException("targetHost is not assigned to this device");
        }
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
                && this.service.targetPort == service.targetPort
                && allowedPeerAddresses.equals(PeerServiceBridge.allowedPeerAddresses(service));
    }

    private void acceptLoop() {
        byte[] buffer = new byte[65507];
        while (open.get() && !inbound.isClosed()) {
            try {
                DatagramPacket packet = new DatagramPacket(buffer, buffer.length);
                inbound.receive(packet);
                if (!allowedPeerAddresses.contains(packet.getAddress())) {
                    auditAccessOnce("deny", packet.getSocketAddress(), "source-not-allowed");
                    continue;
                }
                if (!peers.containsKey(packet.getSocketAddress()) && peers.size() >= MAX_PEERS) {
                    continue;
                }
                DatagramSocket outbound = peers.computeIfAbsent(packet.getSocketAddress(), this::openPeer);
                outbound.send(new DatagramPacket(packet.getData(), packet.getOffset(), packet.getLength(), target));
            } catch (Exception e) {
                return;
            }
        }
    }

    private DatagramSocket openPeer(SocketAddress peer) {
        try {
            auditAccessOnce("allow", peer, "acl-authorized");
            DatagramSocket socket = new DatagramSocket();
            socket.connect(target);
            socket.setSoTimeout(PEER_IDLE_TIMEOUT_MILLIS);
            executor.execute(() -> replyLoop(socket, peer));
            return socket;
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private void auditAccessOnce(String action, Object source, String reason) {
        String sourceAddress = String.valueOf(source);
        String key = action + '|' + sourceAddress;
        if (auditedAccessEvents.size() < 128 && auditedAccessEvents.add(key)) {
            LOG.info("[peer-service-access-audit] action=" + action
                    + " serviceId=" + service.serviceId
                    + " source=" + sourceAddress
                    + " reason=" + reason);
        }
    }

    private void replyLoop(DatagramSocket socket, SocketAddress peer) {
        byte[] buffer = new byte[65507];
        try {
            while (open.get() && !socket.isClosed()) {
                DatagramPacket packet = new DatagramPacket(buffer, buffer.length);
                socket.receive(packet);
                inbound.send(new DatagramPacket(packet.getData(), packet.getOffset(), packet.getLength(), peer));
            }
        } catch (Exception ignored) {
            // idle or closed
        } finally {
            peers.remove(peer, socket);
            socket.close();
        }
    }

    @Override
    public void close() {
        if (!open.compareAndSet(true, false)) {
            return;
        }
        LOG.info("[peer-service-access-audit] action=revoke serviceId=" + service.serviceId
                + " activePeers=" + peers.size()
                + " reason=config-withdrawn-or-shutdown");
        inbound.close();
        peers.values().forEach(DatagramSocket::close);
        peers.clear();
        executor.shutdownNow();
    }
}
