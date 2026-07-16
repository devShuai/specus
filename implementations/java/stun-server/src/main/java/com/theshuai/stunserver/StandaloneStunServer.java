package com.theshuai.stunserver;

import com.theshuai.common.stun.StunBindingService;
import com.theshuai.common.stun.StunEndpointTopology;
import com.theshuai.common.stun.StunMessage;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetSocketAddress;
import java.net.SocketException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicBoolean;

public final class StandaloneStunServer implements AutoCloseable {
    private static final System.Logger LOG =
            System.getLogger(StandaloneStunServer.class.getName());
    private static final int MAX_UDP_PACKET_BYTES = 65_507;

    private final StandaloneStunServerConfig config;
    private final StunBindingService bindingService;
    private final Map<StunEndpointTopology.EndpointId, DatagramSocket> sockets =
            new ConcurrentHashMap<>();
    private final List<Thread> workers = new ArrayList<>();
    private final AtomicBoolean started = new AtomicBoolean();
    private final AtomicBoolean running = new AtomicBoolean();
    private final CountDownLatch stopped = new CountDownLatch(1);

    public StandaloneStunServer(StandaloneStunServerConfig config) {
        this.config = config;
        this.bindingService = new StunBindingService(
                config.topology(),
                config.software(),
                config.legacySingleIpOtherAddress());
    }

    public synchronized void start() throws IOException {
        if (!started.compareAndSet(false, true)) {
            throw new IllegalStateException("STUN server has already been started");
        }
        try {
            bindAllEndpoints();
            running.set(true);
            for (StunEndpointTopology.Endpoint endpoint : config.topology().endpoints()) {
                Thread worker = new Thread(
                        () -> receiveLoop(endpoint.id()),
                        "standalone-stun-" + endpoint.id());
                worker.setDaemon(false);
                workers.add(worker);
                worker.start();
            }
            LOG.log(System.Logger.Level.INFO, "STUN server started: " + config.describe());
        } catch (IOException | RuntimeException e) {
            running.set(false);
            closeSockets();
            stopped.countDown();
            throw e;
        }
    }

    public void await() throws InterruptedException {
        if (!started.get()) {
            throw new IllegalStateException("STUN server has not been started");
        }
        stopped.await();
    }

    public boolean isRunning() {
        return running.get();
    }

    private void bindAllEndpoints() throws SocketException {
        for (StunEndpointTopology.Endpoint endpoint : config.topology().endpoints()) {
            DatagramSocket socket = new DatagramSocket(null);
            try {
                socket.bind(endpoint.bindAddress());
                sockets.put(endpoint.id(), socket);
            } catch (SocketException e) {
                socket.close();
                throw new SocketException(
                        "cannot bind " + endpoint.id() + " to " + endpoint.bindAddress()
                                + ": " + e.getMessage());
            }
        }
    }

    private void receiveLoop(StunEndpointTopology.EndpointId incomingEndpoint) {
        DatagramSocket receiveSocket = sockets.get(incomingEndpoint);
        byte[] buffer = new byte[MAX_UDP_PACKET_BYTES];
        while (running.get() && receiveSocket != null && !receiveSocket.isClosed()) {
            DatagramPacket packet = new DatagramPacket(buffer, buffer.length);
            try {
                receiveSocket.receive(packet);
                process(packet, incomingEndpoint);
            } catch (SocketException e) {
                if (running.get()) {
                    LOG.log(System.Logger.Level.WARNING,
                            "STUN receive failed on " + incomingEndpoint + ": " + e.getMessage());
                }
            } catch (Exception e) {
                if (running.get()) {
                    LOG.log(System.Logger.Level.DEBUG,
                            "STUN packet processing failed on " + incomingEndpoint, e);
                }
            }
        }
    }

    private void process(
            DatagramPacket packet,
            StunEndpointTopology.EndpointId incomingEndpoint) throws IOException {
        StunMessage request = StunMessage.parse(
                packet.getData(),
                packet.getOffset(),
                packet.getLength());
        if (request == null || request.type() != StunMessage.BINDING_REQUEST) {
            return;
        }

        InetSocketAddress remote = new InetSocketAddress(packet.getAddress(), packet.getPort());
        StunBindingService.BindingResult result =
                bindingService.process(request, remote, incomingEndpoint);
        DatagramSocket responseSocket = sockets.get(result.responseEndpoint());
        if (responseSocket == null || responseSocket.isClosed()) {
            throw new SocketException(
                    "response endpoint is unavailable: " + result.responseEndpoint());
        }
        byte[] response = result.response().toBytes();
        responseSocket.send(new DatagramPacket(response, response.length, remote));
    }

    @Override
    public synchronized void close() {
        running.set(false);
        closeSockets();
        for (Thread worker : workers) {
            worker.interrupt();
        }
        for (Thread worker : workers) {
            try {
                worker.join(1_000);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            }
        }
        workers.clear();
        stopped.countDown();
    }

    private void closeSockets() {
        for (DatagramSocket socket : sockets.values()) {
            socket.close();
        }
        sockets.clear();
    }
}
