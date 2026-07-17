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
    private final StunRequestLimiter requestLimiter;
    private final StunServerMetrics metrics = new StunServerMetrics();
    private final StunMetricsHttpServer metricsHttpServer;
    private final DistributedStunForwarder distributedForwarder;
    private final Map<StunEndpointTopology.EndpointId, DatagramSocket> sockets =
            new ConcurrentHashMap<>();
    private final List<Thread> workers = new ArrayList<>();
    private final AtomicBoolean started = new AtomicBoolean();
    private final AtomicBoolean running = new AtomicBoolean();
    private final CountDownLatch stopped = new CountDownLatch(1);
    private DatagramSocket distributedControlSocket;

    public StandaloneStunServer(StandaloneStunServerConfig config) {
        this.config = config;
        this.bindingService = new StunBindingService(
                config.topology(),
                config.software(),
                config.legacySingleIpOtherAddress(),
                config.protection().maxPaddingResponseBytes());
        this.requestLimiter = new StunRequestLimiter(config.protection());
        this.metricsHttpServer = new StunMetricsHttpServer(
                config.metrics(),
                () -> metrics.render(requestLimiter::trackedSources));
        this.distributedForwarder = config.distribution().enabled()
                ? new DistributedStunForwarder(config.distribution())
                : null;
    }

    public synchronized void start() throws IOException {
        if (!started.compareAndSet(false, true)) {
            throw new IllegalStateException("STUN server has already been started");
        }
        try {
            bindAllEndpoints();
            bindDistributedControl();
            metricsHttpServer.start();
            running.set(true);
            for (StunEndpointTopology.Endpoint endpoint : config.localEndpoints()) {
                Thread worker = new Thread(
                        () -> receiveLoop(endpoint.id()),
                        "standalone-stun-" + endpoint.id());
                worker.setDaemon(false);
                workers.add(worker);
                worker.start();
            }
            if (distributedControlSocket != null) {
                Thread controlWorker = new Thread(
                        this::distributedControlLoop,
                        "standalone-stun-distributed-control");
                controlWorker.setDaemon(false);
                workers.add(controlWorker);
                controlWorker.start();
            }
            LOG.log(System.Logger.Level.INFO, "STUN server started: " + config.describe());
        } catch (IOException | RuntimeException e) {
            running.set(false);
            metricsHttpServer.close();
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
        for (StunEndpointTopology.Endpoint endpoint : config.localEndpoints()) {
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

    private void bindDistributedControl() throws SocketException {
        if (!config.distribution().enabled()) {
            return;
        }
        DatagramSocket socket = new DatagramSocket(null);
        try {
            socket.bind(config.distribution().controlBindAddress());
            distributedControlSocket = socket;
        } catch (SocketException e) {
            socket.close();
            throw new SocketException(
                    "cannot bind distributed STUN control socket to "
                            + config.distribution().controlBindAddress()
                            + ": " + e.getMessage());
        }
    }

    private void receiveLoop(StunEndpointTopology.EndpointId incomingEndpoint) {
        DatagramSocket receiveSocket = sockets.get(incomingEndpoint);
        int configuredMax = config.protection().maxPacketBytes();
        int receiveBytes = configuredMax >= MAX_UDP_PACKET_BYTES
                ? MAX_UDP_PACKET_BYTES
                : configuredMax + 1;
        byte[] buffer = new byte[receiveBytes];
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

    private void distributedControlLoop() {
        DatagramSocket controlSocket = distributedControlSocket;
        int configuredMax = config.distribution().maxForwardPacketBytes();
        int receiveBytes = configuredMax >= MAX_UDP_PACKET_BYTES
                ? MAX_UDP_PACKET_BYTES
                : configuredMax + 1;
        byte[] buffer = new byte[receiveBytes];
        while (running.get() && controlSocket != null && !controlSocket.isClosed()) {
            DatagramPacket packet = new DatagramPacket(buffer, buffer.length);
            try {
                controlSocket.receive(packet);
                processDistributedControl(packet);
            } catch (SocketException e) {
                if (running.get()) {
                    LOG.log(System.Logger.Level.WARNING,
                            "distributed STUN control receive failed: " + e.getMessage());
                }
            } catch (Exception e) {
                if (running.get()) {
                    metrics.recordDistributed("processing_failed");
                    LOG.log(System.Logger.Level.DEBUG,
                            "distributed STUN control processing failed", e);
                }
            }
        }
    }

    private void processDistributedControl(DatagramPacket packet) throws IOException {
        if (packet.getLength() > config.distribution().maxForwardPacketBytes()) {
            metrics.recordDistributed("packet_too_large");
            return;
        }
        DistributedStunForwarder.DecodeResult result = distributedForwarder.decode(packet);
        if (!result.accepted()) {
            metrics.recordDistributed(result.rejectionReason());
            return;
        }
        DistributedStunForwarder.ForwardedResponse forwarded = result.response();
        DatagramSocket responseSocket = sockets.get(forwarded.responseEndpoint());
        if (responseSocket == null || responseSocket.isClosed()) {
            metrics.recordDistributed("endpoint_unavailable");
            return;
        }
        byte[] response = forwarded.response();
        try {
            responseSocket.send(new DatagramPacket(
                    response,
                    response.length,
                    forwarded.responseTarget()));
        } catch (IOException e) {
            metrics.recordDistributed("response_send_failed");
            throw e;
        }
        StunMessage message = StunMessage.parse(response, 0, response.length);
        int responseCode = message != null && message.type() == StunMessage.BINDING_SUCCESS
                ? 200
                : message == null ? -1 : message.errorCode();
        metrics.recordResponse(responseCode, response.length);
        metrics.recordDistributed("received");
    }

    private void process(
            DatagramPacket packet,
            StunEndpointTopology.EndpointId incomingEndpoint) throws IOException {
        metrics.recordPacket(packet.getLength());
        if (packet.getLength() > config.protection().maxPacketBytes()) {
            metrics.recordDrop("packet_too_large");
            return;
        }
        StunRequestLimiter.Decision decision = requestLimiter.allow(packet.getAddress());
        if (decision != StunRequestLimiter.Decision.ALLOWED) {
            metrics.recordDrop(switch (decision) {
                case GLOBAL_RATE_LIMIT -> "global_rate_limit";
                case SOURCE_RATE_LIMIT -> "source_rate_limit";
                case SOURCE_TABLE_FULL -> "source_table_full";
                case ALLOWED -> "unknown";
            });
            return;
        }
        StunMessage request = StunMessage.parse(
                packet.getData(),
                packet.getOffset(),
                packet.getLength());
        if (request == null) {
            metrics.recordDrop("malformed");
            return;
        }
        if (request.type() != StunMessage.BINDING_REQUEST) {
            metrics.recordDrop("unsupported_method");
            return;
        }
        metrics.recordAcceptedRequest();
        if (request.hasAttribute(StunMessage.ATTR_CHANGE_REQUEST)) {
            metrics.recordFeature("change_request");
        }
        if (request.hasAttribute(StunMessage.ATTR_RESPONSE_PORT)) {
            metrics.recordFeature("response_port");
        }
        if (request.hasAttribute(StunMessage.ATTR_PADDING)) {
            metrics.recordFeature("padding");
        }

        InetSocketAddress remote = new InetSocketAddress(packet.getAddress(), packet.getPort());
        StunBindingService.BindingResult result =
                bindingService.process(
                        request,
                        remote,
                        incomingEndpoint,
                        packet.getLength());
        DatagramSocket responseSocket = sockets.get(result.responseEndpoint());
        byte[] response = result.response().toBytes();
        if (response.length > MAX_UDP_PACKET_BYTES) {
            metrics.recordDrop("response_too_large");
            return;
        }
        if (config.distribution().enabled()
                && !config.distribution().isLocal(result.responseEndpoint())) {
            DatagramSocket controlSocket = distributedControlSocket;
            if (controlSocket == null || controlSocket.isClosed()) {
                metrics.recordDrop("distributed_control_unavailable");
                metrics.recordDistributed("control_unavailable");
                return;
            }
            try {
                byte[] forwardPacket = distributedForwarder.encode(
                        result.responseEndpoint(),
                        result.responseTarget(),
                        response);
                controlSocket.send(new DatagramPacket(
                        forwardPacket,
                        forwardPacket.length,
                        config.distribution().peerControlAddress()));
                metrics.recordDistributed("sent");
            } catch (IOException e) {
                metrics.recordDistributed("send_failed");
                throw e;
            } catch (RuntimeException e) {
                metrics.recordDistributed("encode_failed");
                throw e;
            }
            return;
        }
        if (responseSocket == null || responseSocket.isClosed()) {
            throw new SocketException(
                    "response endpoint is unavailable: " + result.responseEndpoint());
        }
        responseSocket.send(new DatagramPacket(response, response.length, result.responseTarget()));
        recordResponse(result.response(), response.length);
    }

    private void recordResponse(StunMessage response, int bytes) {
        int responseCode = response.type() == StunMessage.BINDING_SUCCESS
                ? 200
                : response.errorCode();
        metrics.recordResponse(responseCode, bytes);
    }

    @Override
    public synchronized void close() {
        running.set(false);
        metricsHttpServer.close();
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
        if (distributedControlSocket != null) {
            distributedControlSocket.close();
            distributedControlSocket = null;
        }
        for (DatagramSocket socket : sockets.values()) {
            socket.close();
        }
        sockets.clear();
    }
}
