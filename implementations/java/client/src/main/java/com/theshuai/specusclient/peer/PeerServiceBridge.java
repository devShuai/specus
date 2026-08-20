package com.theshuai.specusclient.peer;

import com.theshuai.common.peermesh.LocalPeerService;
import com.theshuai.common.peermesh.PeerServiceDiscovery;
import com.theshuai.common.peermesh.PeerServiceStats;
import lombok.extern.slf4j.Slf4j;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketAddress;
import java.util.HashSet;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Semaphore;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;

interface PeerServiceForwarder extends AutoCloseable {
    boolean matches(String virtualIp, LocalPeerService service);

    PeerServiceStats stats();
}

/**
 * Accepts TCP on the Peer virtual IP published port and splices to the configured local target.
 */
@Slf4j
final class PeerServiceBridge implements PeerServiceForwarder {
    private static final int MAX_ACTIVE_CONNECTIONS = 64;
    private final String virtualIp;
    private final LocalPeerService service;
    private final ServerSocket serverSocket;
    private final Set<InetAddress> allowedPeerAddresses;
    private final ExecutorService executor;
    private final AtomicBoolean open = new AtomicBoolean(true);
    private final ConcurrentHashMap<Socket, Socket> splices = new ConcurrentHashMap<>();
    private final Semaphore slots = new Semaphore(MAX_ACTIVE_CONNECTIONS);
    private final AtomicLong bytesIn = new AtomicLong();
    private final AtomicLong bytesOut = new AtomicLong();
    private final AtomicLong totalConnections = new AtomicLong();

    private PeerServiceBridge(String virtualIp, LocalPeerService service, ServerSocket serverSocket) {
        this.virtualIp = virtualIp;
        this.service = service;
        this.serverSocket = serverSocket;
        this.allowedPeerAddresses = allowedPeerAddresses(service);
        this.executor = Executors.newCachedThreadPool(r -> {
            Thread thread = new Thread(r, "peer-service-bridge-" + service.getServiceId());
            thread.setDaemon(true);
            return thread;
        });
        executor.execute(this::acceptLoop);
    }

    static PeerServiceBridge bind(String virtualIp, LocalPeerService service) throws IOException {
        if (!PeerServiceDiscovery.isLocalInterfaceTarget(service.getTargetHost())) {
            throw new IOException("targetHost is not assigned to this device");
        }
        PeerServiceDiscovery.requirePort(service.getTargetPort(), "targetPort");
        PeerServiceDiscovery.requirePort(service.getPublishedPort(), "publishedPort");
        ServerSocket server = new ServerSocket();
        server.setReuseAddress(true);
        server.bind(new InetSocketAddress(InetAddress.getByName(virtualIp), service.getPublishedPort()));
        return new PeerServiceBridge(virtualIp, service, server);
    }

    public PeerServiceStats stats() {
        PeerServiceStats stats = new PeerServiceStats();
        stats.setServiceId(service.getServiceId());
        stats.setBytesIn(bytesIn.get());
        stats.setBytesOut(bytesOut.get());
        stats.setActiveConnections(splices.size());
        stats.setTotalConnections(totalConnections.get());
        return stats;
    }

    public boolean matches(String virtualIp, LocalPeerService service) {
        return Objects.equals(this.virtualIp, virtualIp)
                && Objects.equals(this.service.getServiceId(), service.getServiceId())
                && this.service.getPublishedPort() == service.getPublishedPort()
                && Objects.equals(this.service.getTargetHost(), service.getTargetHost())
                && this.service.getTargetPort() == service.getTargetPort()
                && allowedPeerAddresses.equals(allowedPeerAddresses(service));
    }

    private void acceptLoop() {
        while (open.get() && !serverSocket.isClosed()) {
            try {
                Socket inbound = serverSocket.accept();
                if (!isAllowed(inbound.getRemoteSocketAddress())) {
                    closeQuietly(inbound);
                    continue;
                }
                if (!slots.tryAcquire()) {
                    closeQuietly(inbound);
                    continue;
                }
                try {
                    executor.execute(() -> splice(inbound));
                } catch (RuntimeException rejected) {
                    slots.release();
                    closeQuietly(inbound);
                }
            } catch (IOException e) {
                if (open.get()) {
                    log.debug("Peer-only 桥接 accept 结束: {}", e.getMessage());
                }
                return;
            }
        }
    }

    private boolean isAllowed(SocketAddress remoteAddress) {
        return remoteAddress instanceof InetSocketAddress inet
                && inet.getAddress() != null
                && allowedPeerAddresses.contains(inet.getAddress());
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

    private void splice(Socket inbound) {
        Socket outbound = new Socket();
        splices.put(inbound, outbound);
        totalConnections.incrementAndGet();
        try {
            inbound.setTcpNoDelay(true);
            outbound.setTcpNoDelay(true);
            outbound.connect(new InetSocketAddress(service.getTargetHost(), service.getTargetPort()), 3_000);
            Thread reply = new Thread(() -> copy(outbound, inbound, bytesOut), "peer-service-up-" + service.getServiceId());
            reply.setDaemon(true);
            reply.start();
            copy(inbound, outbound, bytesIn);
            reply.join(1_000);
        } catch (Exception e) {
            log.debug("Peer-only 桥接转发失败 service={}: {}", service.getServiceId(), e.getMessage());
        } finally {
            closeQuietly(inbound);
            closeQuietly(outbound);
            splices.remove(inbound);
            slots.release();
        }
    }

    private static void copy(Socket from, Socket to, AtomicLong counter) {
        try {
            InputStream in = from.getInputStream();
            OutputStream out = to.getOutputStream();
            byte[] buffer = new byte[8192];
            int read;
            while ((read = in.read(buffer)) >= 0) {
                out.write(buffer, 0, read);
                counter.addAndGet(read);
            }
        } catch (IOException ignored) {
            closeQuietly(from);
            closeQuietly(to);
        }
    }

    private static void closeQuietly(Socket socket) {
        try {
            socket.close();
        } catch (IOException ignored) {
        }
    }

    @Override
    public void close() {
        open.set(false);
        try {
            serverSocket.close();
        } catch (IOException ignored) {
        }
        splices.forEach((inbound, outbound) -> {
            closeQuietly(inbound);
            closeQuietly(outbound);
        });
        splices.clear();
        executor.shutdownNow();
    }
}
