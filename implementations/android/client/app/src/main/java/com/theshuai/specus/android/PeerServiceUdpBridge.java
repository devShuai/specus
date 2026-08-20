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
    private static final Logger LOG = Logger.getLogger(PeerServiceUdpBridge.class.getName());
    private final String virtualIp;
    private final SpecusCore.LocalPeerService service;
    private final DatagramSocket inbound;
    private final InetSocketAddress target;
    private final Set<InetAddress> allowedPeerAddresses;
    private final Set<String> auditedAccessEvents = ConcurrentHashMap.newKeySet();
    private final ExecutorService executor;
    private final AtomicBoolean open = new AtomicBoolean(true);
    private final ConcurrentHashMap<SocketAddress, UdpPeer> peers = new ConcurrentHashMap<>();

    private PeerServiceUdpBridge(String virtualIp, SpecusCore.LocalPeerService service, InetAddress targetAddress,
                                 DatagramSocket inbound) {
        this.virtualIp = virtualIp;
        this.service = service;
        this.inbound = inbound;
        this.target = new InetSocketAddress(targetAddress, service.targetPort);
        this.allowedPeerAddresses = PeerServiceBridge.allowedPeerAddresses(service);
        this.executor = Executors.newCachedThreadPool(r -> {
            Thread thread = new Thread(r, "peer-service-udp-" + service.serviceId);
            thread.setDaemon(true);
            return thread;
        });
        executor.execute(this::acceptLoop);
    }

    static PeerServiceUdpBridge bind(String virtualIp, SpecusCore.LocalPeerService service) throws Exception {
        InetAddress target = PeerServiceRuntime.resolveLocalServiceTarget(service.targetHost);
        if (target == null) {
            throw new IllegalArgumentException("targetHost is not assigned to this device");
        }
        DatagramSocket socket = new DatagramSocket(new InetSocketAddress(InetAddress.getByName(virtualIp),
                service.publishedPort));
        socket.setReuseAddress(true);
        return new PeerServiceUdpBridge(virtualIp, service, target, socket);
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
                if (!peers.containsKey(packet.getSocketAddress())
                        && peers.size() >= PeerServiceResourceLimiter.MAX_UDP_PER_SERVICE) {
                    continue;
                }
                UdpPeer binding = peers.get(packet.getSocketAddress());
                if (binding == null) {
                    binding = openPeer(packet.getSocketAddress(), packet.getAddress());
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
                return;
            }
        }
    }

    private UdpPeer openPeer(SocketAddress peer, InetAddress source) {
        PeerServiceResourceLimiter.Lease lease = PeerServiceResourceLimiter.tryAcquireUdp(source);
        if (lease == null) {
            return null;
        }
        DatagramSocket socket = null;
        try {
            auditAccessOnce("allow", peer, "acl-authorized");
            socket = new DatagramSocket();
            socket.connect(target);
            socket.setSoTimeout(PeerServiceResourceLimiter.IDLE_TIMEOUT_MILLIS);
            return new UdpPeer(socket, lease);
        } catch (Exception e) {
            if (socket != null) {
                socket.close();
            }
            lease.close();
            LOG.fine("Peer-only UDP source mapping failed service=" + service.serviceId
                    + " source=" + peer + ": " + e.getMessage());
            return null;
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

    private void replyLoop(UdpPeer binding, SocketAddress peer) {
        byte[] buffer = new byte[65507];
        try {
            while (open.get() && !binding.socket.isClosed()) {
                DatagramPacket packet = new DatagramPacket(buffer, buffer.length);
                binding.socket.receive(packet);
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
        LOG.info("[peer-service-access-audit] action=revoke serviceId=" + service.serviceId
                + " activePeers=" + peers.size()
                + " reason=config-withdrawn-or-shutdown");
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
