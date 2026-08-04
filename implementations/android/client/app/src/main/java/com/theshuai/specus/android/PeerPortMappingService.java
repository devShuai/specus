package com.theshuai.specus.android;

import android.content.Context;
import android.net.ConnectivityManager;
import android.net.LinkAddress;
import android.net.LinkProperties;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.net.RouteInfo;
import android.net.wifi.WifiManager;

import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import java.io.ByteArrayOutputStream;
import java.io.Closeable;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.net.URI;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.concurrent.CompletionService;
import java.util.concurrent.ExecutorCompletionService;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.xml.parsers.DocumentBuilderFactory;

/**
 * Android-safe UPnP IGD, NAT-PMP and PCP UDP port mapping service.
 * Every discovery and control socket is protected before it can enter the VPN.
 */
final class PeerPortMappingService {
    private static final int DEFAULT_TIMEOUT_SECONDS = 4;

    enum Protocol {
        UPNP,
        NAT_PMP,
        PCP
    }

    static final class Mapping {
        final Protocol protocol;
        final String externalAddress;
        final int externalPort;
        final int internalPort;
        final int leaseSeconds;
        final long createdAtMillis;
        final Object state;

        Mapping(Protocol protocol,
                String externalAddress,
                int externalPort,
                int internalPort,
                int leaseSeconds,
                long createdAtMillis,
                Object state) {
            this.protocol = protocol;
            this.externalAddress = externalAddress == null ? "" : externalAddress;
            this.externalPort = externalPort;
            this.internalPort = internalPort;
            this.leaseSeconds = Math.max(60, leaseSeconds);
            this.createdAtMillis = createdAtMillis;
            this.state = state;
        }

        boolean shouldRenew(long nowMillis) {
            return nowMillis >= createdAtMillis + leaseSeconds * 1_000L - 60_000L;
        }
    }

    interface SocketProtector {
        void protect(DatagramSocket socket) throws IOException;

        void protect(Socket socket) throws IOException;
    }

    interface Mapper {
        Protocol protocol();

        Mapping add(int internalPort, int preferredExternalPort, int leaseSeconds, String description)
                throws IOException;

        default Mapping renew(Mapping mapping, int leaseSeconds, String description) throws IOException {
            return add(mapping.internalPort, mapping.externalPort, leaseSeconds, description);
        }

        void delete(Mapping mapping);
    }

    interface GatewayProvider {
        Set<InetAddress> gateways();

        MulticastLease acquireMulticastLease();
    }

    interface MulticastLease extends Closeable {
        @Override
        void close();
    }

    private final int timeoutSeconds;
    private final List<Mapper> mappers;

    static PeerPortMappingService android(Context context, SocketProtector protector) {
        SocketProtector safeProtector = protector == null ? new NoopProtector() : protector;
        AndroidGatewayProvider gateways = new AndroidGatewayProvider(context, safeProtector);
        return new PeerPortMappingService(DEFAULT_TIMEOUT_SECONDS, List.of(
                new UpnpMapper(safeProtector, gateways),
                new NatPmpMapper(safeProtector, gateways),
                new PcpMapper(safeProtector, gateways)));
    }

    PeerPortMappingService(int timeoutSeconds, List<Mapper> mappers) {
        this.timeoutSeconds = Math.max(1, timeoutSeconds);
        this.mappers = mappers == null ? List.of() : List.copyOf(mappers);
    }

    Mapping acquire(int internalPort, int preferredExternalPort, int leaseSeconds, String description) {
        if (internalPort <= 0 || internalPort > 65_535 || mappers.isEmpty()) {
            return null;
        }
        ExecutorService executor = Executors.newFixedThreadPool(mappers.size(), task -> {
            Thread thread = new Thread(task, "specus-nat-port-mapper");
            thread.setDaemon(true);
            return thread;
        });
        CompletionService<Mapping> completion = new ExecutorCompletionService<>(executor);
        AcquisitionState acquisition = new AcquisitionState();
        List<Future<Mapping>> futures = new ArrayList<>();
        try {
            for (Mapper mapper : mappers) {
                futures.add(completion.submit(() -> {
                    try {
                        Mapping result = mapper.add(
                                internalPort, preferredExternalPort, leaseSeconds, description);
                        if (result == null) {
                            return null;
                        }
                        if (acquisition.claim(result)) {
                            return result;
                        }
                        mapper.delete(result);
                    } catch (Exception ignored) {
                        // A mapping protocol is optional; the caller falls back to STUN/TURN.
                    }
                    return null;
                }));
            }
            long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(timeoutSeconds);
            for (int completed = 0; completed < mappers.size(); completed++) {
                long remaining = deadline - System.nanoTime();
                if (remaining <= 0L) {
                    break;
                }
                Future<Mapping> future = completion.poll(remaining, TimeUnit.NANOSECONDS);
                if (future == null) {
                    break;
                }
                try {
                    Mapping result = future.get();
                    if (result != null) {
                        return acquisition.closeAndGet();
                    }
                } catch (Exception ignored) {
                }
            }
            return acquisition.closeAndGet();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return acquisition.closeAndGet();
        } finally {
            acquisition.close();
            for (Future<Mapping> future : futures) {
                if (!future.isDone()) {
                    future.cancel(true);
                }
            }
            executor.shutdownNow();
        }
    }

    private static final class AcquisitionState {
        private boolean accepting = true;
        private Mapping winner;

        synchronized boolean claim(Mapping candidate) {
            if (!accepting || winner != null) {
                return false;
            }
            winner = candidate;
            return true;
        }

        synchronized Mapping closeAndGet() {
            accepting = false;
            return winner;
        }

        synchronized void close() {
            accepting = false;
        }
    }

    Mapping renew(Mapping mapping, int leaseSeconds, String description) {
        Mapper mapper = mapper(mapping == null ? null : mapping.protocol);
        if (mapper == null) {
            return null;
        }
        try {
            return mapper.renew(mapping, leaseSeconds, description);
        } catch (Exception ignored) {
            return null;
        }
    }

    void release(Mapping mapping) {
        Mapper mapper = mapper(mapping == null ? null : mapping.protocol);
        if (mapper != null) {
            mapper.delete(mapping);
        }
    }

    private Mapper mapper(Protocol protocol) {
        if (protocol != null) {
            for (Mapper mapper : mappers) {
                if (mapper.protocol() == protocol) {
                    return mapper;
                }
            }
        }
        return null;
    }

    static byte[] natPmpMapRequest(int internalPort, int externalPort, int leaseSeconds) {
        return NatPmpMapper.natPmpMapRequest(internalPort, externalPort, leaseSeconds);
    }

    static byte[] pcpMapRequest(byte[] clientAddress,
                                byte[] nonce,
                                int internalPort,
                                int externalPort,
                                int leaseSeconds) {
        return PcpMapper.pcpMapRequest(
                clientAddress, nonce, internalPort, externalPort, leaseSeconds);
    }

    static URI parseUpnpLocation(String response) {
        return UpnpMapper.parseLocation(response);
    }

    private static boolean usableExternalAddress(String value) {
        if (value == null || value.trim().isEmpty()) {
            return false;
        }
        try {
            InetAddress address = InetAddress.getByName(value.trim());
            return !address.isAnyLocalAddress()
                    && !address.isLoopbackAddress()
                    && !address.isMulticastAddress();
        } catch (Exception ignored) {
            return false;
        }
    }

    private static final class NoopProtector implements SocketProtector {
        @Override
        public void protect(DatagramSocket socket) {
        }

        @Override
        public void protect(Socket socket) {
        }
    }

    private static final class AndroidGatewayProvider implements GatewayProvider {
        private static final MulticastLease NOOP_LEASE = () -> { };
        private final Context context;
        private final SocketProtector protector;

        AndroidGatewayProvider(Context context, SocketProtector protector) {
            this.context = context == null ? null : context.getApplicationContext();
            this.protector = protector;
        }

        @Override
        public Set<InetAddress> gateways() {
            Set<InetAddress> result = new LinkedHashSet<>();
            for (LinkProperties properties : physicalLinkProperties()) {
                for (RouteInfo route : properties.getRoutes()) {
                    InetAddress gateway = route.getGateway();
                    if (route.isDefaultRoute() && gateway instanceof Inet4Address) {
                        result.add(gateway);
                    }
                }
                for (LinkAddress linkAddress : properties.getLinkAddresses()) {
                    InetAddress address = linkAddress.getAddress();
                    if (address instanceof Inet4Address) {
                        addConventionalGateways(result, address);
                    }
                }
            }
            addRoutingProbeGateways(result, "1.1.1.1");
            addRoutingProbeGateways(result, "223.5.5.5");
            return result;
        }

        @Override
        public MulticastLease acquireMulticastLease() {
            if (context == null) {
                return NOOP_LEASE;
            }
            try {
                WifiManager manager = (WifiManager) context.getApplicationContext()
                        .getSystemService(Context.WIFI_SERVICE);
                if (manager == null) {
                    return NOOP_LEASE;
                }
                WifiManager.MulticastLock lock = manager.createMulticastLock("specus-upnp-discovery");
                lock.setReferenceCounted(false);
                lock.acquire();
                return () -> {
                    if (lock.isHeld()) {
                        lock.release();
                    }
                };
            } catch (Exception ignored) {
                return NOOP_LEASE;
            }
        }

        private List<LinkProperties> physicalLinkProperties() {
            List<LinkProperties> result = new ArrayList<>();
            if (context == null) {
                return result;
            }
            try {
                ConnectivityManager manager = (ConnectivityManager) context
                        .getSystemService(Context.CONNECTIVITY_SERVICE);
                if (manager == null) {
                    return result;
                }
                Network active = manager.getActiveNetwork();
                addPhysicalLinkProperties(result, manager, active);
                for (Network network : manager.getAllNetworks()) {
                    if (active == null || !active.equals(network)) {
                        addPhysicalLinkProperties(result, manager, network);
                    }
                }
            } catch (Exception ignored) {
            }
            return result;
        }

        private static void addPhysicalLinkProperties(List<LinkProperties> result,
                                                      ConnectivityManager manager,
                                                      Network network) {
            if (network == null) {
                return;
            }
            NetworkCapabilities capabilities = manager.getNetworkCapabilities(network);
            if (capabilities == null || capabilities.hasTransport(NetworkCapabilities.TRANSPORT_VPN)
                    || !capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)) {
                return;
            }
            LinkProperties properties = manager.getLinkProperties(network);
            if (properties != null && !result.contains(properties)) {
                result.add(properties);
            }
        }

        private void addRoutingProbeGateways(Set<InetAddress> result, String host) {
            try (DatagramSocket socket = new DatagramSocket()) {
                protector.protect(socket);
                socket.connect(new InetSocketAddress(host, 53));
                InetAddress local = socket.getLocalAddress();
                if (local instanceof Inet4Address && !local.isAnyLocalAddress()) {
                    addConventionalGateways(result, local);
                }
            } catch (Exception ignored) {
            }
        }

        private static void addConventionalGateways(Set<InetAddress> result, InetAddress local) {
            byte[] bytes = local.getAddress();
            if (bytes.length != 4) {
                return;
            }
            addGateway(result, bytes, (byte) 1);
            addGateway(result, bytes, (byte) 254);
        }

        private static void addGateway(Set<InetAddress> result, byte[] source, byte lastOctet) {
            try {
                byte[] candidate = source.clone();
                candidate[3] = lastOctet;
                result.add(InetAddress.getByAddress(candidate));
            } catch (Exception ignored) {
            }
        }
    }

    private static final class NatPmpMapper implements Mapper {
        private static final int PORT = 5351;
        private static final int TIMEOUT_MS = 1_000;
        private final SocketProtector protector;
        private final GatewayProvider gateways;

        NatPmpMapper(SocketProtector protector, GatewayProvider gateways) {
            this.protector = protector;
            this.gateways = gateways;
        }

        @Override
        public Protocol protocol() {
            return Protocol.NAT_PMP;
        }

        @Override
        public Mapping add(int internalPort, int preferredExternalPort, int leaseSeconds, String description)
                throws IOException {
            IOException last = null;
            for (InetAddress gateway : gateways.gateways()) {
                try {
                    String externalAddress = externalAddress(gateway);
                    byte[] response = exchange(gateway,
                            natPmpMapRequest(internalPort, preferredExternalPort, leaseSeconds), 16);
                    ByteBuffer buffer = ByteBuffer.wrap(response).order(ByteOrder.BIG_ENDIAN);
                    int version = Byte.toUnsignedInt(buffer.get());
                    int opcode = Byte.toUnsignedInt(buffer.get());
                    int result = Short.toUnsignedInt(buffer.getShort());
                    if (version != 0 || opcode != 129 || result != 0) {
                        throw new IOException("NAT-PMP map rejected: " + result);
                    }
                    buffer.getInt();
                    int reflectedInternal = Short.toUnsignedInt(buffer.getShort());
                    int externalPort = Short.toUnsignedInt(buffer.getShort());
                    int grantedLease = buffer.getInt();
                    if (reflectedInternal != internalPort || externalPort <= 0 || grantedLease <= 0
                            || !usableExternalAddress(externalAddress)) {
                        throw new IOException("NAT-PMP response does not match request");
                    }
                    return new Mapping(protocol(), externalAddress, externalPort, internalPort,
                            Math.max(60, grantedLease), System.currentTimeMillis(), gateway);
                } catch (IOException e) {
                    last = e;
                }
            }
            throw last == null ? new IOException("NAT-PMP gateway unavailable") : last;
        }

        @Override
        public Mapping renew(Mapping mapping, int leaseSeconds, String description) throws IOException {
            if (!(mapping.state instanceof InetAddress)) {
                return add(mapping.internalPort, mapping.externalPort, leaseSeconds, description);
            }
            InetAddress gateway = (InetAddress) mapping.state;
            String externalAddress = externalAddress(gateway);
            byte[] response = exchange(gateway,
                    natPmpMapRequest(mapping.internalPort, mapping.externalPort, leaseSeconds), 16);
            ByteBuffer buffer = ByteBuffer.wrap(response).order(ByteOrder.BIG_ENDIAN);
            if (Byte.toUnsignedInt(buffer.get()) != 0 || Byte.toUnsignedInt(buffer.get()) != 129
                    || Short.toUnsignedInt(buffer.getShort()) != 0) {
                throw new IOException("NAT-PMP renewal rejected");
            }
            buffer.getInt();
            int internalPort = Short.toUnsignedInt(buffer.getShort());
            int externalPort = Short.toUnsignedInt(buffer.getShort());
            int grantedLease = buffer.getInt();
            if (internalPort != mapping.internalPort || externalPort <= 0 || grantedLease <= 0) {
                throw new IOException("NAT-PMP renewal response does not match request");
            }
            return new Mapping(protocol(), externalAddress, externalPort, internalPort,
                    Math.max(60, grantedLease), System.currentTimeMillis(), gateway);
        }

        @Override
        public void delete(Mapping mapping) {
            if (mapping == null || !(mapping.state instanceof InetAddress)) {
                return;
            }
            try {
                exchange((InetAddress) mapping.state,
                        natPmpMapRequest(mapping.internalPort, 0, 0), 16);
            } catch (Exception ignored) {
            }
        }

        private String externalAddress(InetAddress gateway) throws IOException {
            byte[] response = exchange(gateway, new byte[]{0, 0}, 12);
            ByteBuffer buffer = ByteBuffer.wrap(response).order(ByteOrder.BIG_ENDIAN);
            if (Byte.toUnsignedInt(buffer.get()) != 0
                    || Byte.toUnsignedInt(buffer.get()) != 128
                    || Short.toUnsignedInt(buffer.getShort()) != 0) {
                throw new IOException("NAT-PMP external address rejected");
            }
            buffer.getInt();
            byte[] address = new byte[4];
            buffer.get(address);
            String value = InetAddress.getByAddress(address).getHostAddress();
            if (!usableExternalAddress(value)) {
                throw new IOException("NAT-PMP external address is unusable");
            }
            return value;
        }

        private byte[] exchange(InetAddress gateway, byte[] request, int minimumSize) throws IOException {
            IOException last = null;
            for (int attempt = 0; attempt < 2; attempt++) {
                try (DatagramSocket socket = new DatagramSocket()) {
                    protector.protect(socket);
                    socket.setSoTimeout(TIMEOUT_MS);
                    socket.send(new DatagramPacket(request, request.length,
                            new InetSocketAddress(gateway, PORT)));
                    byte[] bytes = new byte[64];
                    DatagramPacket response = new DatagramPacket(bytes, bytes.length);
                    socket.receive(response);
                    if (!gateway.equals(response.getAddress()) || response.getPort() != PORT
                            || response.getLength() < minimumSize) {
                        throw new IOException("NAT-PMP response source or length mismatch");
                    }
                    return Arrays.copyOfRange(response.getData(), response.getOffset(),
                            response.getOffset() + response.getLength());
                } catch (SocketTimeoutException e) {
                    last = e;
                }
            }
            throw last == null ? new IOException("NAT-PMP request failed") : last;
        }

        static byte[] natPmpMapRequest(int internalPort, int externalPort, int leaseSeconds) {
            return ByteBuffer.allocate(12).order(ByteOrder.BIG_ENDIAN)
                    .put((byte) 0).put((byte) 1).putShort((short) 0)
                    .putShort((short) internalPort).putShort((short) externalPort)
                    .putInt(Math.max(0, leaseSeconds)).array();
        }
    }

    private static final class PcpMapper implements Mapper {
        private static final int PORT = 5351;
        private static final int TIMEOUT_MS = 1_000;
        private static final int MESSAGE_SIZE = 60;
        private final SocketProtector protector;
        private final GatewayProvider gateways;
        private final SecureRandom random = new SecureRandom();

        PcpMapper(SocketProtector protector, GatewayProvider gateways) {
            this.protector = protector;
            this.gateways = gateways;
        }

        @Override
        public Protocol protocol() {
            return Protocol.PCP;
        }

        @Override
        public Mapping add(int internalPort, int preferredExternalPort, int leaseSeconds, String description)
                throws IOException {
            IOException last = null;
            for (InetAddress gateway : gateways.gateways()) {
                byte[] nonce = new byte[12];
                random.nextBytes(nonce);
                try {
                    return map(gateway, nonce, internalPort, preferredExternalPort, leaseSeconds);
                } catch (IOException e) {
                    last = e;
                }
            }
            throw last == null ? new IOException("PCP gateway unavailable") : last;
        }

        @Override
        public Mapping renew(Mapping mapping, int leaseSeconds, String description) throws IOException {
            if (!(mapping.state instanceof PcpState)) {
                return add(mapping.internalPort, mapping.externalPort, leaseSeconds, description);
            }
            PcpState state = (PcpState) mapping.state;
            return map(state.gateway, state.nonce, mapping.internalPort, mapping.externalPort, leaseSeconds);
        }

        @Override
        public void delete(Mapping mapping) {
            if (mapping == null || !(mapping.state instanceof PcpState)) {
                return;
            }
            PcpState state = (PcpState) mapping.state;
            try {
                map(state.gateway, state.nonce, mapping.internalPort, mapping.externalPort, 0);
            } catch (Exception ignored) {
            }
        }

        private Mapping map(InetAddress gateway,
                            byte[] nonce,
                            int internalPort,
                            int preferredExternalPort,
                            int leaseSeconds) throws IOException {
            byte[] request = pcpMapRequest(localAddressBytes(gateway), nonce,
                    internalPort, preferredExternalPort, leaseSeconds);
            byte[] response = exchange(gateway, request);
            ByteBuffer buffer = ByteBuffer.wrap(response).order(ByteOrder.BIG_ENDIAN);
            int version = Byte.toUnsignedInt(buffer.get());
            int opcode = Byte.toUnsignedInt(buffer.get());
            buffer.get();
            int result = Byte.toUnsignedInt(buffer.get());
            if (version != 2 || opcode != 129 || result != 0) {
                throw new IOException("PCP MAP rejected: " + result);
            }
            int grantedLease = buffer.getInt();
            buffer.getInt();
            buffer.position(24);
            byte[] reflectedNonce = new byte[12];
            buffer.get(reflectedNonce);
            int protocol = Byte.toUnsignedInt(buffer.get());
            buffer.position(buffer.position() + 3);
            int reflectedInternal = Short.toUnsignedInt(buffer.getShort());
            int externalPort = Short.toUnsignedInt(buffer.getShort());
            byte[] externalAddress = new byte[16];
            buffer.get(externalAddress);
            String decodedExternalAddress = decodePcpAddress(externalAddress);
            if (!Arrays.equals(nonce, reflectedNonce) || protocol != 17
                    || reflectedInternal != internalPort
                    || (leaseSeconds > 0 && (externalPort <= 0 || grantedLease <= 0
                    || !usableExternalAddress(decodedExternalAddress)))) {
                throw new IOException("PCP response does not match request");
            }
            return new Mapping(protocol(), decodedExternalAddress, externalPort, internalPort,
                    Math.max(60, grantedLease), System.currentTimeMillis(),
                    new PcpState(gateway, nonce.clone()));
        }

        private byte[] localAddressBytes(InetAddress gateway) throws IOException {
            try (DatagramSocket socket = new DatagramSocket()) {
                protector.protect(socket);
                socket.connect(new InetSocketAddress(gateway, PORT));
                InetAddress local = socket.getLocalAddress();
                if (local instanceof Inet4Address && !local.isAnyLocalAddress()) {
                    byte[] mapped = new byte[16];
                    mapped[10] = (byte) 0xff;
                    mapped[11] = (byte) 0xff;
                    System.arraycopy(local.getAddress(), 0, mapped, 12, 4);
                    return mapped;
                }
                if (local instanceof Inet6Address && !local.isAnyLocalAddress()) {
                    return local.getAddress();
                }
                throw new IOException("PCP local address unavailable");
            }
        }

        private byte[] exchange(InetAddress gateway, byte[] request) throws IOException {
            IOException last = null;
            for (int attempt = 0; attempt < 2; attempt++) {
                try (DatagramSocket socket = new DatagramSocket()) {
                    protector.protect(socket);
                    socket.setSoTimeout(TIMEOUT_MS);
                    socket.send(new DatagramPacket(request, request.length,
                            new InetSocketAddress(gateway, PORT)));
                    byte[] bytes = new byte[1_100];
                    DatagramPacket response = new DatagramPacket(bytes, bytes.length);
                    socket.receive(response);
                    if (!gateway.equals(response.getAddress()) || response.getPort() != PORT
                            || response.getLength() < MESSAGE_SIZE) {
                        throw new IOException("PCP response source or length mismatch");
                    }
                    return Arrays.copyOfRange(response.getData(), response.getOffset(),
                            response.getOffset() + response.getLength());
                } catch (SocketTimeoutException e) {
                    last = e;
                }
            }
            throw last == null ? new IOException("PCP request failed") : last;
        }

        static byte[] pcpMapRequest(byte[] clientAddress,
                                    byte[] nonce,
                                    int internalPort,
                                    int externalPort,
                                    int leaseSeconds) {
            return ByteBuffer.allocate(MESSAGE_SIZE).order(ByteOrder.BIG_ENDIAN)
                    .put((byte) 2).put((byte) 1).putShort((short) 0)
                    .putInt(Math.max(0, leaseSeconds)).put(clientAddress)
                    .put(nonce).put((byte) 17).put(new byte[3])
                    .putShort((short) internalPort).putShort((short) externalPort)
                    .put(new byte[16]).array();
        }

        private static String decodePcpAddress(byte[] bytes) throws IOException {
            boolean mapped = bytes.length == 16;
            for (int index = 0; mapped && index < 10; index++) {
                mapped = bytes[index] == 0;
            }
            if (mapped && bytes[10] == (byte) 0xff && bytes[11] == (byte) 0xff) {
                return InetAddress.getByAddress(Arrays.copyOfRange(bytes, 12, 16)).getHostAddress();
            }
            return InetAddress.getByAddress(bytes).getHostAddress();
        }

        private static final class PcpState {
            final InetAddress gateway;
            final byte[] nonce;

            PcpState(InetAddress gateway, byte[] nonce) {
                this.gateway = gateway;
                this.nonce = nonce;
            }
        }
    }

    private static final class UpnpMapper implements Mapper {
        private static final InetSocketAddress SSDP_ENDPOINT =
                new InetSocketAddress("239.255.255.250", 1900);
        private static final int IO_TIMEOUT_MS = 1_200;
        private static final int MAX_HTTP_BYTES = 512 * 1_024;
        private static final String[] SERVICE_PREFERENCE = {
                "urn:schemas-upnp-org:service:WANIPConnection:2",
                "urn:schemas-upnp-org:service:WANIPConnection:1",
                "urn:schemas-upnp-org:service:WANPPPConnection:1"
        };
        private final SocketProtector protector;
        private final GatewayProvider gatewayProvider;
        private final SecureRandom random = new SecureRandom();
        private volatile Gateway gateway;

        UpnpMapper(SocketProtector protector, GatewayProvider gatewayProvider) {
            this.protector = protector;
            this.gatewayProvider = gatewayProvider;
        }

        @Override
        public Protocol protocol() {
            return Protocol.UPNP;
        }

        @Override
        public Mapping add(int internalPort, int preferredExternalPort, int leaseSeconds, String description)
                throws IOException {
            Gateway selected = gateway;
            if (selected == null) {
                selected = discover();
                gateway = selected;
            }
            IOException last = null;
            int externalPort = preferredExternalPort > 0 ? preferredExternalPort : internalPort;
            for (int attempt = 0; attempt < 4; attempt++) {
                try {
                    String localAddress = localAddressFor(selected.controlUrl);
                    addPortMappingCompatible(selected, externalPort, internalPort, localAddress,
                            leaseSeconds, description == null ? "specus peer mesh" : description);
                    String externalAddress = externalAddress(selected);
                    return new Mapping(protocol(), externalAddress, externalPort, internalPort,
                            Math.max(60, leaseSeconds), System.currentTimeMillis(), selected);
                } catch (IOException e) {
                    last = e;
                    externalPort = 49_152 + random.nextInt(16_000);
                }
            }
            gateway = null;
            throw last == null ? new IOException("UPnP mapping rejected") : last;
        }

        @Override
        public Mapping renew(Mapping mapping, int leaseSeconds, String description) throws IOException {
            if (mapping.state instanceof Gateway) {
                Gateway selected = (Gateway) mapping.state;
                String localAddress = localAddressFor(selected.controlUrl);
                addPortMappingCompatible(selected, mapping.externalPort, mapping.internalPort, localAddress,
                        leaseSeconds, description == null ? "specus peer mesh" : description);
                return new Mapping(protocol(), externalAddress(selected), mapping.externalPort,
                        mapping.internalPort, Math.max(60, leaseSeconds), System.currentTimeMillis(), selected);
            }
            return add(mapping.internalPort, mapping.externalPort, leaseSeconds, description);
        }

        @Override
        public void delete(Mapping mapping) {
            if (mapping == null || !(mapping.state instanceof Gateway)) {
                return;
            }
            Gateway selected = (Gateway) mapping.state;
            try {
                String body = "<u:DeletePortMapping xmlns:u=\"" + xml(selected.serviceType) + "\">"
                        + "<NewRemoteHost></NewRemoteHost>"
                        + "<NewExternalPort>" + mapping.externalPort + "</NewExternalPort>"
                        + "<NewProtocol>UDP</NewProtocol></u:DeletePortMapping>";
                soap(selected, "DeletePortMapping", body);
            } catch (Exception ignored) {
            }
        }

        private Gateway discover() throws IOException {
            Set<URI> locations = discoverLocations();
            IOException last = null;
            for (URI location : locations) {
                try {
                    HttpResponse response = request(location, "GET", null, null);
                    if (response.statusCode / 100 != 2) {
                        continue;
                    }
                    Gateway parsed = parseDescription(location, response.body);
                    if (parsed != null) {
                        return parsed;
                    }
                } catch (IOException e) {
                    last = e;
                }
            }
            throw last == null ? new IOException("UPnP SSDP discovery found no IGD") : last;
        }

        private Set<URI> discoverLocations() throws IOException {
            Set<URI> locations = new LinkedHashSet<>();
            String[] targets = {
                    "urn:schemas-upnp-org:device:InternetGatewayDevice:1",
                    "urn:schemas-upnp-org:device:InternetGatewayDevice:2",
                    "urn:schemas-upnp-org:service:WANIPConnection:1",
                    "urn:schemas-upnp-org:service:WANIPConnection:2"
            };
            long deadline = System.currentTimeMillis() + IO_TIMEOUT_MS;
            try (MulticastLease ignored = gatewayProvider.acquireMulticastLease();
                 DatagramSocket socket = new DatagramSocket()) {
                protector.protect(socket);
                socket.setSoTimeout(250);
                for (String target : targets) {
                    byte[] bytes = ("M-SEARCH * HTTP/1.1\r\n"
                            + "HOST: 239.255.255.250:1900\r\n"
                            + "MAN: \"ssdp:discover\"\r\n"
                            + "MX: 1\r\n"
                            + "ST: " + target + "\r\n\r\n")
                            .getBytes(StandardCharsets.US_ASCII);
                    socket.send(new DatagramPacket(bytes, bytes.length, SSDP_ENDPOINT));
                }
                while (System.currentTimeMillis() < deadline && !Thread.currentThread().isInterrupted()) {
                    byte[] responseBytes = new byte[8_192];
                    DatagramPacket response = new DatagramPacket(responseBytes, responseBytes.length);
                    try {
                        socket.receive(response);
                    } catch (SocketTimeoutException e) {
                        continue;
                    }
                    URI location = parseLocation(new String(response.getData(), response.getOffset(),
                            response.getLength(), StandardCharsets.ISO_8859_1));
                    if (location != null && isHttp(location)) {
                        locations.add(location);
                    }
                }
            }
            return locations;
        }

        static URI parseLocation(String response) {
            if (response == null) {
                return null;
            }
            for (String line : response.split("\\r?\\n")) {
                int colon = line.indexOf(':');
                if (colon > 0 && "location".equalsIgnoreCase(line.substring(0, colon).trim())) {
                    try {
                        return URI.create(line.substring(colon + 1).trim());
                    } catch (Exception ignored) {
                        return null;
                    }
                }
            }
            return null;
        }

        private Gateway parseDescription(URI location, byte[] xmlBytes) throws IOException {
            Document document = parseXml(xmlBytes);
            URI base = location;
            String urlBase = firstText(document, "URLBase");
            if (urlBase != null) {
                try {
                    URI advertisedBase = URI.create(urlBase.trim());
                    if (isHttp(advertisedBase)) {
                        base = advertisedBase;
                    }
                } catch (Exception ignored) {
                }
            }
            for (String preferred : SERVICE_PREFERENCE) {
                NodeList services = document.getElementsByTagNameNS("*", "service");
                if (services.getLength() == 0) {
                    services = document.getElementsByTagName("service");
                }
                for (int index = 0; index < services.getLength(); index++) {
                    Node service = services.item(index);
                    String serviceType = childText(service, "serviceType");
                    String controlUrl = childText(service, "controlURL");
                    if (preferred.equals(serviceType) && controlUrl != null && !controlUrl.trim().isEmpty()) {
                        return new Gateway(base.resolve(controlUrl.trim()), serviceType);
                    }
                }
            }
            return null;
        }

        private String externalAddress(Gateway selected) throws IOException {
            String body = "<u:GetExternalIPAddress xmlns:u=\"" + xml(selected.serviceType)
                    + "\"></u:GetExternalIPAddress>";
            HttpResponse response = soap(selected, "GetExternalIPAddress", body);
            Document document = parseXml(response.body);
            String value = firstText(document, "NewExternalIPAddress");
            if (!usableExternalAddress(value)) {
                throw new IOException("UPnP external address missing");
            }
            return value.trim();
        }

        private void addPortMapping(Gateway selected,
                                    int externalPort,
                                    int internalPort,
                                    String internalClient,
                                    int leaseSeconds,
                                    String description) throws IOException {
            String body = "<u:AddPortMapping xmlns:u=\"" + xml(selected.serviceType) + "\">"
                    + "<NewRemoteHost></NewRemoteHost>"
                    + "<NewExternalPort>" + externalPort + "</NewExternalPort>"
                    + "<NewProtocol>UDP</NewProtocol>"
                    + "<NewInternalPort>" + internalPort + "</NewInternalPort>"
                    + "<NewInternalClient>" + xml(internalClient) + "</NewInternalClient>"
                    + "<NewEnabled>1</NewEnabled>"
                    + "<NewPortMappingDescription>" + xml(description) + "</NewPortMappingDescription>"
                    + "<NewLeaseDuration>" + Math.max(0, leaseSeconds) + "</NewLeaseDuration>"
                    + "</u:AddPortMapping>";
            soap(selected, "AddPortMapping", body);
        }

        private void addPortMappingCompatible(Gateway selected,
                                              int externalPort,
                                              int internalPort,
                                              String internalClient,
                                              int leaseSeconds,
                                              String description) throws IOException {
            try {
                addPortMapping(selected, externalPort, internalPort, internalClient, leaseSeconds, description);
            } catch (IOException first) {
                if (leaseSeconds <= 0) {
                    throw first;
                }
                // A large number of IGD v1 routers only accept permanent (zero-duration) leases.
                addPortMapping(selected, externalPort, internalPort, internalClient, 0, description);
            }
        }

        private HttpResponse soap(Gateway selected, String action, String actionBody) throws IOException {
            String envelope = "<?xml version=\"1.0\"?>"
                    + "<s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" "
                    + "s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\">"
                    + "<s:Body>" + actionBody + "</s:Body></s:Envelope>";
            HttpResponse response = request(selected.controlUrl, "POST",
                    "\"" + selected.serviceType + "#" + action + "\"",
                    envelope.getBytes(StandardCharsets.UTF_8));
            if (response.statusCode / 100 != 2) {
                throw new IOException("UPnP " + action + " failed with HTTP " + response.statusCode);
            }
            return response;
        }

        private String localAddressFor(URI uri) throws IOException {
            int port = effectivePort(uri);
            try (Socket socket = new Socket()) {
                protector.protect(socket);
                socket.connect(new InetSocketAddress(uri.getHost(), port), IO_TIMEOUT_MS);
                return socket.getLocalAddress().getHostAddress();
            }
        }

        private HttpResponse request(URI uri, String method, String soapAction, byte[] body) throws IOException {
            if (!isHttp(uri) || uri.getHost() == null) {
                throw new IOException("unsupported UPnP control URL");
            }
            int port = effectivePort(uri);
            Socket base = new Socket();
            protector.protect(base);
            base.connect(new InetSocketAddress(uri.getHost(), port), IO_TIMEOUT_MS);
            base.setSoTimeout(IO_TIMEOUT_MS);
            Socket socket = base;
            if ("https".equalsIgnoreCase(uri.getScheme())) {
                socket = ((SSLSocketFactory) SSLSocketFactory.getDefault())
                        .createSocket(base, uri.getHost(), port, true);
                ((SSLSocket) socket).startHandshake();
            }
            try (Socket closeable = socket) {
                String path = uri.getRawPath();
                if (path == null || path.isEmpty()) {
                    path = "/";
                }
                if (uri.getRawQuery() != null) {
                    path += "?" + uri.getRawQuery();
                }
                byte[] payload = body == null ? new byte[0] : body;
                String hostHeader = uri.getHost().contains(":") ? "[" + uri.getHost() + "]" : uri.getHost();
                StringBuilder headers = new StringBuilder()
                        .append(method).append(' ').append(path).append(" HTTP/1.1\r\n")
                        .append("Host: ").append(hostHeader).append(':').append(port).append("\r\n")
                        .append("Connection: close\r\n");
                if (soapAction != null) {
                    headers.append("Content-Type: text/xml; charset=\"utf-8\"\r\n")
                            .append("SOAPAction: ").append(soapAction).append("\r\n");
                }
                headers.append("Content-Length: ").append(payload.length).append("\r\n\r\n");
                OutputStream output = closeable.getOutputStream();
                output.write(headers.toString().getBytes(StandardCharsets.ISO_8859_1));
                output.write(payload);
                output.flush();
                return readHttpResponse(closeable.getInputStream());
            }
        }

        private static HttpResponse readHttpResponse(InputStream input) throws IOException {
            ByteArrayOutputStream output = new ByteArrayOutputStream();
            byte[] buffer = new byte[8_192];
            int read;
            while ((read = input.read(buffer)) >= 0) {
                if (read == 0) {
                    continue;
                }
                if (output.size() + read > MAX_HTTP_BYTES) {
                    throw new IOException("UPnP HTTP response too large");
                }
                output.write(buffer, 0, read);
            }
            byte[] raw = output.toByteArray();
            int headerEnd = indexOf(raw, new byte[]{'\r', '\n', '\r', '\n'});
            if (headerEnd < 0) {
                throw new IOException("UPnP HTTP response has no headers");
            }
            String headers = new String(raw, 0, headerEnd, StandardCharsets.ISO_8859_1);
            String[] lines = headers.split("\\r\\n");
            String[] status = lines.length == 0 ? new String[0] : lines[0].split(" ", 3);
            if (status.length < 2) {
                throw new IOException("UPnP HTTP status malformed");
            }
            int statusCode;
            try {
                statusCode = Integer.parseInt(status[1]);
            } catch (NumberFormatException e) {
                throw new IOException("UPnP HTTP status malformed", e);
            }
            byte[] body = Arrays.copyOfRange(raw, headerEnd + 4, raw.length);
            if (headers.toLowerCase(Locale.ROOT).contains("transfer-encoding: chunked")) {
                body = decodeChunked(body);
            }
            return new HttpResponse(statusCode, body);
        }

        private static byte[] decodeChunked(byte[] encoded) throws IOException {
            ByteArrayOutputStream decoded = new ByteArrayOutputStream();
            int offset = 0;
            while (offset < encoded.length) {
                int lineEnd = indexOf(encoded, offset, new byte[]{'\r', '\n'});
                if (lineEnd < 0) {
                    throw new IOException("UPnP chunk header malformed");
                }
                String sizeText = new String(encoded, offset, lineEnd - offset,
                        StandardCharsets.US_ASCII).split(";", 2)[0].trim();
                int size;
                try {
                    size = Integer.parseInt(sizeText, 16);
                } catch (NumberFormatException e) {
                    throw new IOException("UPnP chunk size malformed", e);
                }
                offset = lineEnd + 2;
                if (size == 0) {
                    return decoded.toByteArray();
                }
                if (size < 0 || offset > encoded.length - size) {
                    throw new IOException("UPnP chunk truncated");
                }
                decoded.write(encoded, offset, size);
                offset += size;
                if (offset > encoded.length - 2 || encoded[offset] != '\r' || encoded[offset + 1] != '\n') {
                    throw new IOException("UPnP chunk terminator malformed");
                }
                offset += 2;
            }
            throw new IOException("UPnP chunk stream incomplete");
        }

        private static Document parseXml(byte[] bytes) throws IOException {
            try {
                String raw = new String(bytes, StandardCharsets.UTF_8);
                if (raw.toUpperCase(Locale.ROOT).contains("<!DOCTYPE")) {
                    throw new IOException("UPnP XML DOCTYPE is not allowed");
                }
                DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
                factory.setNamespaceAware(true);
                setXmlFeature(factory, "http://apache.org/xml/features/disallow-doctype-decl", true);
                setXmlFeature(factory, "http://xml.org/sax/features/external-general-entities", false);
                setXmlFeature(factory, "http://xml.org/sax/features/external-parameter-entities", false);
                factory.setExpandEntityReferences(false);
                return factory.newDocumentBuilder().parse(new java.io.ByteArrayInputStream(bytes));
            } catch (Exception e) {
                throw new IOException("UPnP XML parse failed", e);
            }
        }

        private static void setXmlFeature(DocumentBuilderFactory factory, String feature, boolean value) {
            try {
                factory.setFeature(feature, value);
            } catch (Exception ignored) {
                // Older Android XML providers do not expose every hardening feature.
            }
        }

        private static String firstText(Document document, String name) {
            NodeList nodes = document.getElementsByTagNameNS("*", name);
            if (nodes.getLength() == 0) {
                nodes = document.getElementsByTagName(name);
            }
            return nodes.getLength() == 0 ? null : nodes.item(0).getTextContent();
        }

        private static String childText(Node parent, String name) {
            NodeList children = parent.getChildNodes();
            for (int index = 0; index < children.getLength(); index++) {
                Node child = children.item(index);
                String local = child.getLocalName();
                if (name.equals(local) || name.equals(child.getNodeName())) {
                    return child.getTextContent();
                }
            }
            return null;
        }

        private static String xml(String value) {
            return value == null ? "" : value.replace("&", "&amp;")
                    .replace("<", "&lt;").replace(">", "&gt;")
                    .replace("\"", "&quot;").replace("'", "&apos;");
        }

        private static int effectivePort(URI uri) {
            return uri.getPort() > 0 ? uri.getPort()
                    : "https".equalsIgnoreCase(uri.getScheme()) ? 443 : 80;
        }

        private static boolean isHttp(URI uri) {
            return uri != null && ("http".equalsIgnoreCase(uri.getScheme())
                    || "https".equalsIgnoreCase(uri.getScheme()));
        }

        private static int indexOf(byte[] haystack, byte[] needle) {
            return indexOf(haystack, 0, needle);
        }

        private static int indexOf(byte[] haystack, int start, byte[] needle) {
            outer:
            for (int index = Math.max(0, start); index <= haystack.length - needle.length; index++) {
                for (int part = 0; part < needle.length; part++) {
                    if (haystack[index + part] != needle[part]) {
                        continue outer;
                    }
                }
                return index;
            }
            return -1;
        }

        private static final class Gateway {
            final URI controlUrl;
            final String serviceType;

            Gateway(URI controlUrl, String serviceType) {
                this.controlUrl = controlUrl;
                this.serviceType = serviceType;
            }
        }

        private static final class HttpResponse {
            final int statusCode;
            final byte[] body;

            HttpResponse(int statusCode, byte[] body) {
                this.statusCode = statusCode;
                this.body = body;
            }
        }
    }
}
