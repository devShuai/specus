package com.theshuai.specusclient.peer;

import com.theshuai.common.peermesh.LocalPeerService;
import com.theshuai.common.peermesh.PeerServiceDiscovery;
import com.theshuai.common.peermesh.PeerServiceStats;
import lombok.extern.slf4j.Slf4j;

import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.util.HashSet;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;

@Slf4j
final class PeerServiceUdpBridge implements PeerServiceForwarder {
    private final String virtualIp;
    private final LocalPeerService service;
    private final DatagramSocket inbound;
    private final InetSocketAddress target;
    private final Set<InetAddress> allowedPeerAddresses;
    private final Set<String> auditedAccessEvents = ConcurrentHashMap.newKeySet();
    private final ExecutorService executor;
    private final AtomicBoolean open = new AtomicBoolean(true);
    private final ConcurrentHashMap<SocketAddress, UdpPeer> peers = new ConcurrentHashMap<>();
    private final AtomicLong bytesIn = new AtomicLong();
    private final AtomicLong bytesOut = new AtomicLong();
    private final AtomicLong totalConnections = new AtomicLong();

    private PeerServiceUdpBridge(String virtualIp, LocalPeerService service, InetAddress targetAddress,
                                 DatagramSocket inbound) {
        this.virtualIp = virtualIp;
        this.service = service;
        this.inbound = inbound;
        this.target = new InetSocketAddress(targetAddress, service.getTargetPort());
        this.allowedPeerAddresses = allowedPeerAddresses(service);
        this.executor = Executors.newCachedThreadPool(r -> {
            Thread thread = new Thread(r, "peer-service-udp-" + service.getServiceId());
            thread.setDaemon(true);
            return thread;
        });
        executor.execute(this::acceptLoop);
    }

    static PeerServiceUdpBridge bind(String virtualIp, LocalPeerService service) throws Exception {
        String target = PeerServiceDiscovery.resolveLocalInterfaceTarget(service.getTargetHost());
        if (target == null) {
            throw new IllegalArgumentException("targetHost is not assigned to this device");
        }
        PeerServiceDiscovery.requirePort(service.getTargetPort(), "targetPort");
        PeerServiceDiscovery.requirePort(service.getPublishedPort(), "publishedPort");
        DatagramSocket socket = new DatagramSocket(new InetSocketAddress(InetAddress.getByName(virtualIp),
                service.getPublishedPort()));
        socket.setReuseAddress(true);
        return new PeerServiceUdpBridge(virtualIp, service, InetAddress.getByName(target), socket);
    }

    public boolean matches(String virtualIp, LocalPeerService service) {
        return Objects.equals(this.virtualIp, virtualIp)
                && Objects.equals(this.service.getServiceId(), service.getServiceId())
                && this.service.getPublishedPort() == service.getPublishedPort()
                && Objects.equals(this.service.getTargetHost(), service.getTargetHost())
                && this.service.getTargetPort() == service.getTargetPort()
                && allowedPeerAddresses.equals(allowedPeerAddresses(service));
    }

    public PeerServiceStats stats() {
        PeerServiceStats stats = new PeerServiceStats();
        stats.setServiceId(service.getServiceId());
        stats.setBytesIn(bytesIn.get());
        stats.setBytesOut(bytesOut.get());
        stats.setActiveConnections(peers.size());
        stats.setTotalConnections(totalConnections.get());
        return stats;
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
                if (!peers.containsKey(packet.getSocketAddress())
                        && peers.size() >= PeerServiceDiscovery.MAX_UDP_PEERS_PER_SERVICE) {
                    continue;
                }
                bytesIn.addAndGet(packet.getLength());
                UdpPeer binding = peers.get(packet.getSocketAddress());
                if (binding == null) {
                    binding = openPeerSocket(packet.getSocketAddress(), packet.getAddress());
                    if (binding == null) {
                        continue;
                    }
                    UdpPeer raced = peers.putIfAbsent(packet.getSocketAddress(), binding);
                    if (raced != null) {
                        binding.close();
                        binding = raced;
                    } else {
                        UdpPeer accepted = binding;
                        SocketAddress peer = packet.getSocketAddress();
                        try {
                            executor.execute(() -> replyLoop(accepted, peer));
                        } catch (RuntimeException rejected) {
                            peers.remove(peer, accepted);
                            accepted.close();
                            continue;
                        }
                    }
                }
                binding.socket.send(new DatagramPacket(packet.getData(), packet.getOffset(), packet.getLength(), target));
            } catch (Exception e) {
                if (open.get()) {
                    log.debug("Peer-only UDP 桥接结束: {}", e.getMessage());
                }
                return;
            }
        }
    }

    private static Set<InetAddress> allowedPeerAddresses(LocalPeerService service) {
        Set<InetAddress> addresses = new HashSet<>();
        if (service == null || service.getAllowedPeerVirtualIps() == null) {
            return Set.of();
        }
        for (String raw : service.getAllowedPeerVirtualIps()) {
            try {
                if (raw != null && !raw.isBlank()) {
                    addresses.add(InetAddress.getByName(raw.trim()));
                }
            } catch (Exception ignored) {
                // Invalid server-authored entries are ignored; an empty result is fail-closed.
            }
        }
        return Set.copyOf(addresses);
    }

    private UdpPeer openPeerSocket(SocketAddress peer, InetAddress source) {
        PeerServiceResourceLimiter.Lease lease = PeerServiceResourceLimiter.tryAcquireUdp(source);
        if (lease == null) {
            return null;
        }
        DatagramSocket socket = null;
        try {
            auditAccessOnce("allow", peer, "acl-authorized");
            socket = new DatagramSocket();
            socket.setReuseAddress(true);
            socket.setSoTimeout(PeerServiceDiscovery.IDLE_TIMEOUT_MILLIS);
            socket.connect(target);
            totalConnections.incrementAndGet();
            return new UdpPeer(socket, lease);
        } catch (Exception e) {
            if (socket != null) {
                socket.close();
            }
            lease.close();
            log.debug("Peer-only UDP 来源映射创建失败 service={} source={}: {}",
                    service.getServiceId(), peer, e.getMessage());
            return null;
        }
    }

    private void auditAccessOnce(String action, SocketAddress source, String reason) {
        String sourceAddress = String.valueOf(source);
        String key = action + '|' + sourceAddress;
        if (auditedAccessEvents.size() < 128 && auditedAccessEvents.add(key)) {
            log.info("[peer-service-access-audit] action={} serviceId={} source={} reason={}",
                    action, service.getServiceId(), sourceAddress, reason);
        }
    }

    private void replyLoop(UdpPeer binding, SocketAddress peer) {
        byte[] buffer = new byte[65507];
        try {
            while (open.get() && !binding.socket.isClosed()) {
                DatagramPacket packet = new DatagramPacket(buffer, buffer.length);
                binding.socket.receive(packet);
                bytesOut.addAndGet(packet.getLength());
                inbound.send(new DatagramPacket(packet.getData(), packet.getOffset(), packet.getLength(), peer));
            }
        } catch (Exception ignored) {
            // idle or closed
        } finally {
            peers.remove(peer, binding);
            binding.close();
        }
    }

    @Override
    public void close() {
        if (!open.compareAndSet(true, false)) {
            return;
        }
        log.info("[peer-service-access-audit] action=revoke serviceId={} activePeers={} reason=config-withdrawn-or-shutdown",
                service.getServiceId(), peers.size());
        inbound.close();
        peers.values().forEach(UdpPeer::close);
        peers.clear();
        executor.shutdownNow();
    }

    private static final class UdpPeer implements AutoCloseable {
        private final DatagramSocket socket;
        private final PeerServiceResourceLimiter.Lease lease;
        private final AtomicBoolean closed = new AtomicBoolean();

        private UdpPeer(DatagramSocket socket, PeerServiceResourceLimiter.Lease lease) {
            this.socket = socket;
            this.lease = lease;
        }

        @Override
        public void close() {
            if (closed.compareAndSet(false, true)) {
                socket.close();
                lease.close();
            }
        }
    }
}
