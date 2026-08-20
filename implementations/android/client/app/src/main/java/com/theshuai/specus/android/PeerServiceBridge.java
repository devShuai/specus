package com.theshuai.specus.android;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.Objects;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Semaphore;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.logging.Logger;

final class PeerServiceBridge implements AutoCloseable {
    private static final int MAX_ACTIVE_CONNECTIONS = 64;
    private static final Logger LOG = Logger.getLogger(PeerServiceBridge.class.getName());
    private final String virtualIp;
    private final SpecusCore.LocalPeerService service;
    private final ServerSocket serverSocket;
    private final Set<InetAddress> allowedPeerAddresses;
    private final Set<String> auditedAccessEvents = ConcurrentHashMap.newKeySet();
    private final ExecutorService executor;
    private final AtomicBoolean open = new AtomicBoolean(true);
    private final ConcurrentHashMap<Socket, Socket> splices = new ConcurrentHashMap<>();
    private final Semaphore slots = new Semaphore(MAX_ACTIVE_CONNECTIONS);

    private PeerServiceBridge(String virtualIp, SpecusCore.LocalPeerService service, ServerSocket serverSocket) {
        this.virtualIp = virtualIp;
        this.service = service;
        this.serverSocket = serverSocket;
        this.allowedPeerAddresses = allowedPeerAddresses(service);
        this.executor = Executors.newCachedThreadPool(r -> {
            Thread thread = new Thread(r, "peer-service-bridge-" + service.serviceId);
            thread.setDaemon(true);
            return thread;
        });
        executor.execute(this::acceptLoop);
    }

    static PeerServiceBridge bind(String virtualIp, SpecusCore.LocalPeerService service) throws IOException {
        if (!PeerServiceRuntime.isLocalServiceTarget(service.targetHost)) {
            throw new IOException("targetHost is not assigned to this device");
        }
        ServerSocket server = new ServerSocket();
        server.setReuseAddress(true);
        server.bind(new InetSocketAddress(InetAddress.getByName(virtualIp), service.publishedPort));
        return new PeerServiceBridge(virtualIp, service, server);
    }

    boolean matches(String virtualIp, SpecusCore.LocalPeerService service) {
        return Objects.equals(this.virtualIp, virtualIp)
                && Objects.equals(this.service.serviceId, service.serviceId)
                && this.service.publishedPort == service.publishedPort
                && Objects.equals(this.service.targetHost, service.targetHost)
                && this.service.targetPort == service.targetPort
                && allowedPeerAddresses.equals(allowedPeerAddresses(service));
    }

    private void acceptLoop() {
        while (open.get() && !serverSocket.isClosed()) {
            try {
                Socket inbound = serverSocket.accept();
                if (!allowedPeerAddresses.contains(inbound.getInetAddress())) {
                    auditAccessOnce("deny", inbound.getRemoteSocketAddress(), "source-not-allowed");
                    closeQuietly(inbound);
                    continue;
                }
                auditAccessOnce("allow", inbound.getRemoteSocketAddress(), "acl-authorized");
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
                return;
            }
        }
    }

    static Set<InetAddress> allowedPeerAddresses(SpecusCore.LocalPeerService service) {
        Set<InetAddress> addresses = new HashSet<>();
        if (service == null || service.allowedPeerVirtualIps == null) {
            return Set.of();
        }
        for (String raw : service.allowedPeerVirtualIps) {
            try {
                if (raw != null && !raw.isBlank()) {
                    addresses.add(InetAddress.getByName(raw.trim()));
                }
            } catch (Exception ignored) {
                // Invalid server-authored entries are ignored; empty is fail-closed.
            }
        }
        return Set.copyOf(addresses);
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

    private void splice(Socket inbound) {
        Socket outbound = new Socket();
        splices.put(inbound, outbound);
        try {
            inbound.setTcpNoDelay(true);
            outbound.setTcpNoDelay(true);
            outbound.connect(new InetSocketAddress(service.targetHost, service.targetPort), 3_000);
            Thread reply = new Thread(() -> copy(outbound, inbound), "peer-service-up-" + service.serviceId);
            reply.setDaemon(true);
            reply.start();
            copy(inbound, outbound);
            reply.join(1_000);
        } catch (Exception ignored) {
        } finally {
            closeQuietly(inbound);
            closeQuietly(outbound);
            splices.remove(inbound);
            slots.release();
        }
    }

    private static void copy(Socket from, Socket to) {
        try {
            InputStream in = from.getInputStream();
            OutputStream out = to.getOutputStream();
            byte[] buffer = new byte[8192];
            int read;
            while ((read = in.read(buffer)) >= 0) {
                out.write(buffer, 0, read);
                out.flush();
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
        if (!open.compareAndSet(true, false)) {
            return;
        }
        LOG.info("[peer-service-access-audit] action=revoke serviceId=" + service.serviceId
                + " activeConnections=" + splices.size()
                + " reason=config-withdrawn-or-shutdown");
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
