package com.theshuai.specus.android;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicBoolean;

final class PeerServiceBridge implements AutoCloseable {
    private final String virtualIp;
    private final SpecusCore.LocalPeerService service;
    private final ServerSocket serverSocket;
    private final ExecutorService executor;
    private final AtomicBoolean open = new AtomicBoolean(true);
    private final ConcurrentHashMap<Socket, Socket> splices = new ConcurrentHashMap<>();

    private PeerServiceBridge(String virtualIp, SpecusCore.LocalPeerService service, ServerSocket serverSocket) {
        this.virtualIp = virtualIp;
        this.service = service;
        this.serverSocket = serverSocket;
        this.executor = Executors.newCachedThreadPool(r -> {
            Thread thread = new Thread(r, "peer-service-bridge-" + service.serviceId);
            thread.setDaemon(true);
            return thread;
        });
        executor.execute(this::acceptLoop);
    }

    static PeerServiceBridge bind(String virtualIp, SpecusCore.LocalPeerService service) throws IOException {
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
                && this.service.targetPort == service.targetPort;
    }

    private void acceptLoop() {
        while (open.get() && !serverSocket.isClosed()) {
            try {
                Socket inbound = serverSocket.accept();
                executor.execute(() -> splice(inbound));
            } catch (IOException e) {
                return;
            }
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
