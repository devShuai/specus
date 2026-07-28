package com.theshuai.specusserver.peer;

import com.theshuai.common.peermesh.PeerDataFrameHeader;
import com.theshuai.common.peermesh.PeerUdpProbe;
import com.theshuai.common.stun.StunBindingService;
import com.theshuai.common.stun.StunEndpointTopology;
import com.theshuai.common.stun.StunMessage;
import com.theshuai.common.stun.TurnChannelData;
import com.theshuai.common.util.JsonUtil;
import com.theshuai.specusserver.config.PeerMeshProperties;
import com.theshuai.specusserver.management.service.PeerMeshService;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.Gauge;
import io.micrometer.core.instrument.MeterRegistry;
import jakarta.annotation.PreDestroy;
import lombok.extern.slf4j.Slf4j;
import org.jspecify.annotations.NonNull;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.ThreadLocalRandom;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

@Component
@Slf4j
public class StunTurnServer implements ApplicationRunner {
    private static final String SOFTWARE = "specus-standard-stun-turn";
    private static final long PERMISSION_TTL_SECONDS = 300;
    private static final long CHANNEL_TTL_SECONDS = 600;
    private static final int MAX_PROBE_BYTES = 2_048;

    private final PeerMeshProperties properties;
    private final PeerMeshService peerMeshService;
    private final TurnCredentialService turnCredentialService;
    private final Counter relayQueueDropped;
    private final Counter relaySendFailed;
    private final Counter generalRelayQuotaRejected;
    private final Counter generalRelayForbiddenDestination;
    private final Counter generalRelayBytes;
    private final Counter generalRelayQuotaClosed;
    private final AtomicInteger relayQueueHighWater = new AtomicInteger();
    private final Map<String, Allocation> allocations = new ConcurrentHashMap<>();
    private final Map<String, String> allocationByEndpoint = new ConcurrentHashMap<>();
    private final Map<String, String> allocationByRelayEndpoint = new ConcurrentHashMap<>();
    private final Map<StunEndpointTopology.EndpointId, DatagramSocket> stunSockets = new ConcurrentHashMap<>();
    private DatagramSocket primarySocket;
    private StunEndpointTopology stunTopology;
    private StunBindingService stunBindingService;
    private InetAddress turnBindAddress;
    private InetAddress turnAdvertisedAddress;
    private ThreadPoolExecutor relayExecutor;
    private volatile boolean running;

    public StunTurnServer(PeerMeshProperties properties,
                          PeerMeshService peerMeshService,
                          TurnCredentialService turnCredentialService,
                          MeterRegistry meterRegistry) {
        this.properties = properties;
        this.peerMeshService = peerMeshService;
        this.turnCredentialService = turnCredentialService;
        this.relayQueueDropped = Counter.builder("specus.peer_mesh.turn.relay.queue.dropped")
                .description("TURN relay tasks rejected by the bounded worker queue")
                .register(meterRegistry);
        this.relaySendFailed = Counter.builder("specus.peer_mesh.turn.relay.send.failures")
                .description("TURN relay datagrams that failed during send")
                .register(meterRegistry);
        this.generalRelayQuotaRejected = Counter.builder("specus.peer_mesh.turn.general_relay.quota.rejected")
                .description("General TURN relay allocations rejected by quota")
                .register(meterRegistry);
        this.generalRelayForbiddenDestination = Counter.builder("specus.peer_mesh.turn.general_relay.destination.forbidden")
                .description("General TURN relay permissions rejected by the destination policy")
                .register(meterRegistry);
        this.generalRelayBytes = Counter.builder("specus.peer_mesh.turn.general_relay.bytes")
                .description("Bytes relayed on behalf of general TURN allocations")
                .register(meterRegistry);
        this.generalRelayQuotaClosed = Counter.builder("specus.peer_mesh.turn.general_relay.quota.closed")
                .description("General TURN allocations closed after exhausting the byte quota")
                .register(meterRegistry);
        Gauge.builder("specus.peer_mesh.turn.relay.queue.depth", this, StunTurnServer::relayQueueDepth)
                .description("Current TURN relay worker queue depth")
                .register(meterRegistry);
        Gauge.builder("specus.peer_mesh.turn.relay.queue.high.water", relayQueueHighWater, AtomicInteger::get)
                .description("Maximum observed TURN relay worker queue depth")
                .register(meterRegistry);
    }

    @Override
    public void run(@NonNull ApplicationArguments args) {
        if (!properties.isEnabled()) {
            return;
        }
        try {
            configureStunSockets();
            relayExecutor = createRelayExecutor();
            running = true;
            startStunThreads();
            log.info("[peer-mesh] standard STUN/TURN UDP server listening on {}, rfc5780={}",
                    stunTopology.endpoints().stream()
                            .map(endpoint -> endpoint.advertisedAddress().toString())
                            .toList(),
                    stunTopology.supportsRfc5780());
        } catch (Exception e) {
            closeStunSockets();
            log.warn("[peer-mesh] standard STUN/TURN UDP server failed to start on {}: {}",
                    properties.getStunTurnPort(), e.getMessage());
        }
    }

    private void configureStunSockets() throws Exception {
        int primaryPort = properties.getStunTurnPort();
        int alternatePort = natProbeAlternatePort();
        InetAddress primaryBind = resolveBindAddress(properties.getStunPrimaryBindAddress());
        InetAddress primaryPublic = resolvePrimaryAdvertisedAddress(primaryBind);
        boolean alternateRequested = hasText(properties.getStunAlternateBindAddress())
                || hasText(properties.getStunAlternatePublicAddress());
        boolean fullConfiguration = hasText(properties.getStunPrimaryBindAddress())
                && hasText(properties.getStunAlternateBindAddress())
                && hasText(properties.getStunAlternatePublicAddress())
                && hasText(properties.getPublicAddress())
                && alternatePort > 0
                && alternatePort != primaryPort;

        if (properties.isStunBehaviorStrict() && !fullConfiguration) {
            throw new IllegalStateException(
                    "strict RFC 5780 mode requires primary/alternate bind addresses, two public addresses and two ports");
        }
        if (alternateRequested && !fullConfiguration) {
            log.warn("[peer-mesh] incomplete RFC 5780 endpoint configuration; falling back to single-IP compatibility mode");
        }

        if (fullConfiguration) {
            InetAddress alternateBind = InetAddress.getByName(properties.getStunAlternateBindAddress().trim());
            InetAddress alternatePublic = InetAddress.getByName(properties.getStunAlternatePublicAddress().trim());
            stunTopology = StunEndpointTopology.rfc5780(
                    endpoint(StunEndpointTopology.PRIMARY, primaryBind, primaryPublic, primaryPort),
                    endpoint(StunEndpointTopology.PRIMARY_ALTERNATE_PORT,
                            primaryBind, primaryPublic, alternatePort),
                    endpoint(StunEndpointTopology.ALTERNATE_PRIMARY_PORT,
                            alternateBind, alternatePublic, primaryPort),
                    endpoint(StunEndpointTopology.ALTERNATE,
                            alternateBind, alternatePublic, alternatePort));
        } else {
            StunEndpointTopology.Endpoint alternateEndpoint =
                    alternatePort > 0 && alternatePort != primaryPort
                            ? endpoint(StunEndpointTopology.PRIMARY_ALTERNATE_PORT,
                            primaryBind, primaryPublic, alternatePort)
                            : null;
            stunTopology = StunEndpointTopology.basic(
                    endpoint(StunEndpointTopology.PRIMARY, primaryBind, primaryPublic, primaryPort),
                    alternateEndpoint);
        }

        try {
            for (StunEndpointTopology.Endpoint endpoint : stunTopology.endpoints()) {
                DatagramSocket socket = new DatagramSocket(null);
                configureUdpSocket(socket);
                socket.bind(endpoint.bindAddress());
                stunSockets.put(endpoint.id(), socket);
            }
        } catch (Exception e) {
            closeStunSockets();
            throw e;
        }

        primarySocket = stunSockets.get(StunEndpointTopology.PRIMARY);
        turnBindAddress = stunTopology.endpoint(StunEndpointTopology.PRIMARY).bindAddress().getAddress();
        turnAdvertisedAddress = stunTopology.endpoint(StunEndpointTopology.PRIMARY)
                .advertisedAddress()
                .getAddress();
        stunBindingService = new StunBindingService(
                stunTopology,
                SOFTWARE,
                !stunTopology.supportsRfc5780());
    }

    private StunEndpointTopology.Endpoint endpoint(StunEndpointTopology.EndpointId id,
                                                   InetAddress bindAddress,
                                                   InetAddress advertisedAddress,
                                                   int port) {
        return new StunEndpointTopology.Endpoint(
                id,
                new InetSocketAddress(bindAddress, port),
                new InetSocketAddress(advertisedAddress, port));
    }

    private void startStunThreads() {
        for (StunEndpointTopology.Endpoint endpoint : stunTopology.endpoints()) {
            Thread thread = new Thread(
                    () -> receiveLoop(endpoint.id()),
                    "peer-mesh-stun-" + endpoint.id());
            thread.setDaemon(true);
            thread.start();
        }
    }

    private void receiveLoop(StunEndpointTopology.EndpointId endpointId) {
        DatagramSocket receiveSocket = stunSockets.get(endpointId);
        byte[] buffer = new byte[65_507];
        while (running && receiveSocket != null && !receiveSocket.isClosed()) {
            DatagramPacket packet = new DatagramPacket(buffer, buffer.length);
            try {
                receiveSocket.receive(packet);
                handle(packet, endpointId);
            } catch (Exception e) {
                if (running) {
                    log.debug("[peer-mesh] STUN/TURN receive failed: {}", e.toString());
                }
            }
        }
    }

    private void handle(DatagramPacket packet,
                        StunEndpointTopology.EndpointId incomingEndpoint) throws Exception {
        DatagramSocket receiveSocket = stunSockets.get(incomingEndpoint);
        InetSocketAddress remote = new InetSocketAddress(packet.getAddress(), packet.getPort());
        if (StunEndpointTopology.PRIMARY.equals(incomingEndpoint)
                && TurnChannelData.looksLike(packet.getData(), packet.getOffset(), packet.getLength())) {
            handleChannelData(packet, remote);
            return;
        }
        StunMessage message = StunMessage.parse(packet.getData(), packet.getOffset(), packet.getLength());
        if (message == null) {
            return;
        }
        if (message.type() == StunMessage.BINDING_REQUEST) {
            StunBindingService.BindingResult result =
                    stunBindingService.process(
                            message,
                            remote,
                            incomingEndpoint,
                            packet.getLength());
            sendStun(
                    stunSockets.get(result.responseEndpoint()),
                    result.responseTarget(),
                    result.response());
            log.trace("[peer-mesh] STUN binding incoming={} outgoing={} remote={}",
                    incomingEndpoint, result.responseEndpoint(), remote);
            return;
        }
        if (!StunEndpointTopology.PRIMARY.equals(incomingEndpoint)) {
            sendError(receiveSocket, remote, message, errorType(message.type()), 400, "unsupported-endpoint");
            return;
        }
        switch (message.type()) {
            case StunMessage.ALLOCATE_REQUEST -> allocate(message, packet, remote);
            case StunMessage.REFRESH_REQUEST -> refresh(message, packet, remote);
            case StunMessage.CREATE_PERMISSION_REQUEST -> createPermission(message, packet, remote);
            case StunMessage.CHANNEL_BIND_REQUEST -> channelBind(message, packet, remote);
            case StunMessage.SEND_INDICATION -> sendIndication(message, remote);
            default -> sendError(receiveSocket, remote, message, errorType(message.type()), 400, "unsupported-method");
        }
    }

    private void allocate(StunMessage request, DatagramPacket packet, InetSocketAddress remote) throws Exception {
        TurnAuth auth = authenticate(request, packet, remote, StunMessage.ALLOCATE_ERROR);
        if (!auth.allowed()) {
            return;
        }
        if (!request.requestedUdpTransport()) {
            sendError(primarySocket, remote, request, StunMessage.ALLOCATE_ERROR, 442, "unsupported-transport");
            return;
        }
        String endpointKey = endpointKey(remote);
        Allocation allocation = allocationByEndpoint.containsKey(endpointKey)
                ? allocations.get(allocationByEndpoint.get(endpointKey))
                : null;
        if (allocation == null || allocation.isExpired(Instant.now())
                || !allocation.matchesClient(auth.clientId())
                || allocation.generalRelay != auth.generalRelay()) {
            if (auth.generalRelay()) {
                String rejection = generalRelayQuotaRejection(remote, allocation);
                if (rejection != null) {
                    generalRelayQuotaRejected.increment();
                    // 审计：通用中继由公开 ICE 配置驱动，配额拒绝必须可追溯
                    log.warn("[peer-mesh][audit] general TURN allocation rejected: client={}, reason={}",
                            remote, rejection);
                    sendError(primarySocket, remote, request,
                            StunMessage.ALLOCATE_ERROR, 486, rejection);
                    return;
                }
            }
            closeAllocation(allocation);
            allocation = createAllocation(remote, auth.clientId(), auth.generalRelay());
            if (auth.generalRelay()) {
                log.info("[peer-mesh][audit] general TURN allocation created: client={}, relay={}, active={}",
                        remote, allocation.relayAddress, countGeneralRelayAllocations(null));
            }
        } else {
            allocation.expiresAt = Instant.now().plusSeconds(properties.getAllocationTtlSeconds());
        }
        StunMessage response = StunMessage.of(
                StunMessage.ALLOCATE_SUCCESS,
                request.transactionId(),
                StunMessage.xorRelayedAddress(allocation.relayAddress, request.transactionId()),
                StunMessage.xorMappedAddress(remote, request.transactionId()),
                StunMessage.lifetime(properties.getAllocationTtlSeconds()),
                StunMessage.software(SOFTWARE)
        );
        sendStun(primarySocket, remote, response, auth.messageIntegrityKey());
    }

    /**
     * 通用中继 allocation 的准入配额。返回非 null 表示拒绝原因。
     *
     * <p>{@code current} 是同一来源端点上待替换的旧 allocation，计数时需要排除它，
     * 否则同一客户端的正常重建会被自己占用的名额挡住。
     */
    private String generalRelayQuotaRejection(InetSocketAddress remote, Allocation current) {
        int maxTotal = properties.getGeneralRelayMaxAllocations();
        if (maxTotal <= 0) {
            return "general-relay-disabled";
        }
        if (countGeneralRelayAllocations(current) >= maxTotal) {
            return "general-relay-allocation-quota";
        }
        int maxPerAddress = properties.getGeneralRelayMaxAllocationsPerAddress();
        if (maxPerAddress > 0 && remote != null && remote.getAddress() != null) {
            long sameAddress = allocations.values().stream()
                    .filter(item -> item.generalRelay && item != current && !item.closed)
                    .filter(item -> item.clientRemote != null
                            && item.clientRemote.getAddress() != null
                            && item.clientRemote.getAddress().equals(remote.getAddress()))
                    .count();
            if (sameAddress >= maxPerAddress) {
                return "general-relay-address-quota";
            }
        }
        return null;
    }

    private long countGeneralRelayAllocations(Allocation exclude) {
        return allocations.values().stream()
                .filter(item -> item.generalRelay && item != exclude && !item.closed)
                .count();
    }

    /**
     * 通用中继的转发总量配额。Peer Mesh 专用 allocation 不受此约束。
     *
     * <p><b>不做包级限速。</b>TURN 承载的是浏览器 WebRTC 的 SCTP-over-DTLS（可靠传输），
     * 按包丢弃来限速会直接打乱 SCTP 的拥塞控制与重传，导致吞吐崩溃甚至连接超时——这正是
     * 之前"网页互传中继发文件失败"的根因。防滥用改为准入层（并发 allocation 数、
     * 同源上限）+ 总量层：单 allocation 生命周期累计字节超过 {@code max-bytes} 时直接关闭
     * allocation，让 SCTP 干净断开，而不是把它拖进持续丢包的泥潭。
     */
    private boolean allowGeneralRelayTraffic(Allocation allocation, int bytes) {
        if (allocation == null || !allocation.generalRelay) {
            return true;
        }
        long maxBytes = properties.getGeneralRelayMaxBytes();
        long total = allocation.relayedBytes.addAndGet(bytes);
        if (maxBytes > 0 && total > maxBytes) {
            if (allocation.quotaLogged.compareAndSet(false, true)) {
                generalRelayQuotaClosed.increment();
                log.warn("[peer-mesh][audit] general TURN byte quota exhausted, closing allocation: client={}, bytes={}",
                        allocation.clientRemote, total);
                closeAllocation(allocation);
            }
            return false;
        }
        generalRelayBytes.increment(bytes);
        return true;
    }

    private Allocation createAllocation(InetSocketAddress remote, long clientId, boolean generalRelay) throws Exception {
        DatagramSocket relaySocket = bindRelaySocket();
        Allocation allocation = new Allocation(
                UUID.randomUUID().toString(),
                remote,
                relaySocket,
                advertisedSocketAddress(relaySocket),
                Instant.now().plusSeconds(properties.getAllocationTtlSeconds()),
                clientId,
                generalRelay
        );
        allocations.put(allocation.id, allocation);
        allocationByEndpoint.put(endpointKey(remote), allocation.id);
        allocationByRelayEndpoint.put(endpointKey(allocation.relayAddress), allocation.id);

        Thread thread = Thread.ofVirtual()
                .name("peer-turn-relay-" + relaySocket.getLocalPort())
                .start(() -> relayReceiveLoop(allocation));
        allocation.relayThread = thread;
        log.info("[peer-mesh] TURN allocation created: client={}, relay={}", remote, allocation.relayAddress);
        return allocation;
    }

    private DatagramSocket bindRelaySocket() throws Exception {
        int min = Math.clamp(properties.getRelayMinPort(), 1, 65_535);
        int max = Math.clamp(properties.getRelayMaxPort(), 1, 65_535);
        if (min > max) {
            int tmp = min;
            min = max;
            max = tmp;
        }
        int capacity = max - min + 1;
        int attempts = Math.clamp(capacity, 16, 128);
        int start = min + ThreadLocalRandom.current().nextInt(capacity);
        Exception last = null;
        for (int i = 0; i < attempts; i++) {
            int port = min + ((start - min + i) % capacity);
            try {
                DatagramSocket socket = new DatagramSocket(null);
                configureUdpSocket(socket);
                socket.bind(new InetSocketAddress(turnBindAddress, port));
                return socket;
            } catch (Exception e) {
                last = e;
            }
        }
        if (last != null) {
            throw last;
        }
        DatagramSocket socket = new DatagramSocket(null);
        configureUdpSocket(socket);
        socket.bind(new InetSocketAddress(turnBindAddress, 0));
        return socket;
    }

    private void refresh(StunMessage request, DatagramPacket packet, InetSocketAddress remote) throws Exception {
        TurnAuth auth = authenticate(request, packet, remote, StunMessage.REFRESH_ERROR);
        if (!auth.allowed()) {
            return;
        }
        Allocation allocation = allocationForRemote(remote);
        if (allocation == null || !allocation.matchesClient(auth.clientId())) {
            sendError(primarySocket, remote, request, StunMessage.REFRESH_ERROR, 437, "allocation-mismatch");
            return;
        }
        long lifetime = request.lifetimeSeconds(properties.getAllocationTtlSeconds());
        if (lifetime <= 0) {
            closeAllocation(allocation);
        } else {
            allocation.expiresAt = Instant.now().plusSeconds(Math.min(lifetime, properties.getAllocationTtlSeconds()));
        }
        StunMessage response = StunMessage.of(
                StunMessage.REFRESH_SUCCESS,
                request.transactionId(),
                StunMessage.lifetime(lifetime <= 0 ? 0 : properties.getAllocationTtlSeconds()),
                StunMessage.software(SOFTWARE)
        );
        sendStun(primarySocket, remote, response, auth.messageIntegrityKey());
    }

    private void createPermission(StunMessage request, DatagramPacket packet, InetSocketAddress remote) throws Exception {
        TurnAuth auth = authenticate(request, packet, remote, StunMessage.CREATE_PERMISSION_ERROR);
        if (!auth.allowed()) {
            return;
        }
        Allocation allocation = allocationForRemote(remote);
        if (allocation == null || !allocation.matchesClient(auth.clientId())) {
            sendError(primarySocket, remote, request, StunMessage.CREATE_PERMISSION_ERROR, 437, "allocation-mismatch");
            return;
        }
        Instant expiresAt = Instant.now().plusSeconds(PERMISSION_TTL_SECONDS);
        for (StunMessage.Attribute attribute : request.all(StunMessage.ATTR_XOR_PEER_ADDRESS)) {
            InetSocketAddress address = new StunMessage(
                    request.type(), request.transactionId(), java.util.List.of(attribute))
                    .xorPeerAddress()
                    .orElse(null);
            if (address == null) {
                continue;
            }
            if (auth.generalRelay() && !isRelayableDestination(address)) {
                generalRelayForbiddenDestination.increment();
                log.warn("[peer-mesh][audit] general TURN permission refused: client={}, peer={}",
                        remote, address);
                // 通用 TURN 模式下目的地址由客户端指定，必须拒绝内网/回环/组播等目标，
                // 否则中继会变成打向服务端内网的跳板。
                sendError(primarySocket, remote, request,
                        StunMessage.CREATE_PERMISSION_ERROR, 403, "forbidden-peer-address");
                return;
            }
            allocation.permissions.put(permissionKey(address), expiresAt);
        }
        StunMessage response = StunMessage.of(
                StunMessage.CREATE_PERMISSION_SUCCESS,
                request.transactionId(),
                StunMessage.software(SOFTWARE)
        );
        sendStun(primarySocket, remote, response, auth.messageIntegrityKey());
    }

    /**
     * 中继目的地址白名单策略：只允许公网单播地址。
     *
     * <p>只对通用 TURN 模式（公开互传）生效：其目的地址完全由浏览器指定，若不加限制，
     * 任何拿到公开 ICE 配置的人都能把中继当作打向服务端内网的跳板。Peer Mesh 专用模式的
     * 目的地址必然是本服务端的另一个 relay 端点，且本地/私网部署会用到回环与站点本地地址，
     * 因此不施加该策略。
     */
    boolean isRelayableDestination(InetSocketAddress address) {
        if (address == null || address.getAddress() == null || address.getPort() <= 0) {
            return false;
        }
        InetAddress host = address.getAddress();
        if (host.isAnyLocalAddress()
                || host.isLoopbackAddress()
                || host.isLinkLocalAddress()
                || host.isSiteLocalAddress()
                || host.isMulticastAddress()) {
            return false;
        }
        // 注意：不拒绝 100.64.0.0/10。它是 RFC 6598 运营商级 CGNAT，大量家宽/移动网用户的
        // 公网映射地址（WebRTC srflx candidate）落在此段；整段拒绝会让这些对端的
        // CreatePermission 直接 403，中继根本建不起来。Peer Mesh 虚拟网段虽也在 100.64/10 内，
        // 但通用中继的对端是浏览器的真实公网地址，不可能是只在 overlay 内部使用的 mesh 虚拟 IP。
        byte[] raw = host.getAddress();
        // IPv6 ULA fc00::/7 仍然禁止（不可全局路由）
        if (raw.length == 16 && (raw[0] & 0xFE) == 0xFC) {
            return false;
        }
        return true;
    }

    private void channelBind(StunMessage request, DatagramPacket packet, InetSocketAddress remote) throws Exception {
        TurnAuth auth = authenticate(request, packet, remote, StunMessage.CHANNEL_BIND_ERROR);
        if (!auth.allowed()) {
            return;
        }
        Allocation allocation = allocationForRemote(remote);
        int channelNumber = request.channelNumber().orElse(-1);
        InetSocketAddress peer = request.xorPeerAddress().orElse(null);
        if (allocation == null || !allocation.matchesClient(auth.clientId())) {
            sendError(primarySocket, remote, request, StunMessage.CHANNEL_BIND_ERROR, 437, "allocation-mismatch");
            return;
        }
        if (channelNumber < TurnChannelData.MIN_CHANNEL || peer == null) {
            sendError(primarySocket, remote, request, StunMessage.CHANNEL_BIND_ERROR, 400, "bad-channel-bind");
            return;
        }
        if (auth.generalRelay() && !isRelayableDestination(peer)) {
            generalRelayForbiddenDestination.increment();
            log.warn("[peer-mesh][audit] general TURN channel bind refused: client={}, peer={}",
                    remote, peer);
            // ChannelBind 同样会隐式创建 permission，必须执行与 CreatePermission 一致的目的地址策略
            sendError(primarySocket, remote, request, StunMessage.CHANNEL_BIND_ERROR, 403, "forbidden-peer-address");
            return;
        }
        Instant now = Instant.now();
        ChannelBinding occupied = allocation.channelsByNumber.get(channelNumber);
        if (occupied != null && occupied.activeAt(now) && !sameEndpoint(occupied.peer(), peer)) {
            sendError(primarySocket, remote, request, StunMessage.CHANNEL_BIND_ERROR, 400, "channel-in-use");
            return;
        }

        String peerKey = endpointKey(peer);
        ChannelBinding previous = allocation.channelsByPeer.put(
                peerKey,
                new ChannelBinding(channelNumber, peer, now.plusSeconds(CHANNEL_TTL_SECONDS)));
        if (previous != null && previous.channelNumber() != channelNumber) {
            allocation.channelsByNumber.remove(previous.channelNumber(), previous);
        }
        allocation.channelsByNumber.put(channelNumber, allocation.channelsByPeer.get(peerKey));
        allocation.permissions.put(permissionKey(peer), now.plusSeconds(PERMISSION_TTL_SECONDS));
        sendStun(
                primarySocket,
                remote,
                StunMessage.of(
                        StunMessage.CHANNEL_BIND_SUCCESS,
                        request.transactionId(),
                        StunMessage.software(SOFTWARE)),
                auth.messageIntegrityKey());
    }

    private void handleChannelData(DatagramPacket packet, InetSocketAddress remote) {
        Allocation allocation = allocationForRemote(remote);
        TurnChannelData.Frame frame = TurnChannelData.parse(packet.getData(), packet.getOffset(), packet.getLength());
        if (allocation == null || frame == null) {
            return;
        }
        ChannelBinding binding = allocation.channelsByNumber.get(frame.channelNumber());
        if (binding == null || !binding.activeAt(Instant.now()) || hasNotPermission(allocation, binding.peer())) {
            return;
        }
        Allocation target = allocationForRelayEndpoint(binding.peer());
        byte[] payload = frame.payload();
		if (!authorizeRelayPayload(payload, allocation, target, true)) {
            return;
        }
        if (!allowGeneralRelayTraffic(allocation, payload.length)) {
            return;
        }
        submitRelayTask(() -> {
            try {
                allocation.relaySocket.send(new DatagramPacket(payload, payload.length, binding.peer()));
            } catch (Exception e) {
                relaySendFailed.increment();
                log.debug("[peer-mesh] TURN ChannelData relay failed: {}", e.toString());
            }
        });
    }

    private TurnAuth authenticate(StunMessage request,
                                  DatagramPacket packet,
                                  InetSocketAddress remote,
                                  int responseType) throws Exception {
        if (!turnCredentialService.authRequired()) {
            return TurnAuth.none();
        }
        String username = request.username().orElse("");
        String realm = request.realm().orElse("");
        String nonce = request.nonce().orElse("");
        if (!turnCredentialService.realm().equals(realm)
                || username.isBlank()
                || nonce.isBlank()) {
            sendTurnAuthError(remote, request, responseType, 401, "unauthorized");
            return TurnAuth.denied();
        }
        if (!turnCredentialService.nonce().equals(nonce)) {
            sendTurnAuthError(remote, request, responseType, 438, "stale-nonce");
            return TurnAuth.denied();
        }
        String credential = turnCredentialService.credentialForUsername(username);
        if (!turnCredentialService.usernameCredentialValid(username, credential)) {
            sendTurnAuthError(remote, request, responseType, 401, "unauthorized");
            return TurnAuth.denied();
        }
        byte[] key = turnCredentialService.longTermKey(username, credential);
        if (!StunMessage.verifyMessageIntegrity(
                packet.getData(), packet.getOffset(), packet.getLength(), key)) {
            sendTurnAuthError(remote, request, responseType, 401, "bad-message-integrity");
            return TurnAuth.denied();
        }
        return TurnAuth.allowed(
                key,
                turnCredentialService.peerMeshClientId(username),
                turnCredentialService.isGeneralRelaySubject(username));
    }

    private void sendTurnAuthError(InetSocketAddress remote,
                                   StunMessage request,
                                   int responseType,
                                   int code,
                                   String reason) throws Exception {
        sendError(
                primarySocket,
                remote,
                request,
                responseType,
                code,
                reason,
                StunMessage.realm(turnCredentialService.realm()),
                StunMessage.nonce(turnCredentialService.nonce()));
    }

    private void sendIndication(StunMessage indication, InetSocketAddress remote) throws Exception {
        Allocation allocation = allocationForRemote(remote);
        if (allocation == null) {
            return;
        }
        InetSocketAddress peer = indication.xorPeerAddress().orElse(null);
        byte[] payload = indication.data().orElse(null);
        if (peer == null || payload == null || hasNotPermission(allocation, peer)) {
            return;
        }
        Allocation target = allocationForRelayEndpoint(peer);
		if (!authorizeRelayPayload(payload, allocation, target, true)) {
            return;
        }
        if (!allowGeneralRelayTraffic(allocation, payload.length)) {
            return;
        }
        submitRelayTask(() -> {
            try {
                allocation.relaySocket.send(new DatagramPacket(payload, payload.length, peer));
            } catch (Exception e) {
                relaySendFailed.increment();
                log.debug("[peer-mesh] TURN send indication relay failed: {}", e.toString());
            }
        });
    }

	private boolean authorizeRelayPayload(byte[] payload,
                                        Allocation source,
                                        Allocation target,
                                        boolean account) {
        // 通用 TURN 模式（公开互传的浏览器 WebRTC）：转发的是 DTLS/SRTP/SCTP 与 STUN 连通性
        // 检查，既不是 SPM2 帧也不是本项目的 probe JSON，无法走 Peer Mesh 专用校验。
        // 这类 allocation 按标准 TURN 语义放行——身份在 Allocate 阶段、目的地址在
        // CreatePermission/ChannelBind 阶段都已校验，调用方也已确认 permission。
        // 出站时本端是 source，入站时本端是 target，任一侧标记为通用中继即放行。
        if ((source != null && source.generalRelay) || (target != null && target.generalRelay)) {
            return true;
        }
        if (source == null || target == null) {
            return false;
        }
        // TURN 认证关闭时 allocation 上没有 clientId（凭证里本就没有身份），此时按 0 传下去，
        // 由 PeerMeshService 退化为"仅校验 session 存在且未关闭"。若这里坚持要求 clientId>0，
        // 关闭认证会让全部中继载荷（连探针也包括）被拒，中继完全不可用。
        boolean identified = turnCredentialService.authRequired();
        if (identified && (source.clientId <= 0 || target.clientId <= 0)) {
            return false;
        }
        long sourceClientId = identified ? source.clientId : 0L;
        long targetClientId = identified ? target.clientId : 0L;
        PeerDataFrameHeader header = PeerDataFrameHeader.parse(payload);
        if (header != null) {
			return account
					? peerMeshService.authorizeRelayFrameForRelay(
                            header, sourceClientId, targetClientId, payload.length)
					: peerMeshService.validateRelayFrameForRelay(
                            header, sourceClientId, targetClientId);
        }
        if (payload == null
                || payload.length < 16
                || payload.length > MAX_PROBE_BYTES
                || payload[0] != '{'
                || payload[payload.length - 1] != '}') {
            return false;
        }
        PeerUdpProbe probe = JsonUtil.bytesToObjectQuietly(payload, 0, payload.length, PeerUdpProbe.class);
        return probe != null
                && PeerUdpProbe.MAGIC.equals(probe.getMagic())
                && probe.getFromClientId() != null
                && probe.getToClientId() != null
                && (!identified
                        || (probe.getFromClientId() == sourceClientId
                                && probe.getToClientId() == targetClientId))
                && peerMeshService.authorizeRelayProbeForRelay(probe);
    }

    private void relayReceiveLoop(Allocation allocation) {
        byte[] buffer = new byte[65_507];
        while (running && !allocation.closed && allocation.relaySocket != null && !allocation.relaySocket.isClosed()) {
            DatagramPacket packet = new DatagramPacket(buffer, buffer.length);
            try {
                allocation.relaySocket.receive(packet);
                InetSocketAddress peer = new InetSocketAddress(packet.getAddress(), packet.getPort());
                if (hasNotPermission(allocation, peer)) {
                    continue;
                }
                byte[] payload = java.util.Arrays.copyOfRange(packet.getData(), packet.getOffset(), packet.getOffset() + packet.getLength());
                Allocation source = allocationForRelayEndpoint(peer);
				if (!authorizeRelayPayload(payload, source, allocation, false)) {
					continue;
				}
                if (!allowGeneralRelayTraffic(allocation, payload.length)) {
                    continue;
                }
                dispatchPeerData(allocation, peer, payload);
            } catch (Exception e) {
                if (running && !allocation.closed) {
                    log.debug("[peer-mesh] TURN relay receive failed: {}", e.toString());
                }
            }
        }
    }

    private void dispatchPeerData(Allocation allocation, InetSocketAddress peer, byte[] payload) {
        Runnable task = () -> {
            try {
                ChannelBinding binding = allocation.channelsByPeer.get(endpointKey(peer));
                if (binding != null && binding.activeAt(Instant.now())) {
                    byte[] channelData = TurnChannelData.encode(binding.channelNumber(), payload);
                    primarySocket.send(new DatagramPacket(channelData, channelData.length, allocation.clientRemote));
                    return;
                }
                byte[] transactionId = StunMessage.newTransactionId();
                StunMessage data = StunMessage.of(
                        StunMessage.DATA_INDICATION,
                        transactionId,
                        StunMessage.xorPeerAddress(peer, transactionId),
                        StunMessage.data(payload)
                );
                sendStun(primarySocket, allocation.clientRemote, data);
            } catch (Exception e) {
                relaySendFailed.increment();
                log.debug("[peer-mesh] TURN data indication failed: {}", e.toString());
            }
        };
        submitRelayTask(task);
    }

    private void submitRelayTask(Runnable task) {
        ThreadPoolExecutor executor = relayExecutor;
        if (executor == null) {
            task.run();
            return;
        }
        try {
            executor.execute(task);
            relayQueueHighWater.accumulateAndGet(executor.getQueue().size(), Math::max);
        } catch (RuntimeException e) {
            relayQueueDropped.increment();
            log.debug("[peer-mesh] TURN data indication dropped: {}", e.toString());
        }
    }

    private Allocation allocationForRemote(InetSocketAddress remote) {
        String id = allocationByEndpoint.get(endpointKey(remote));
        Allocation allocation = id == null ? null : allocations.get(id);
        if (allocation == null || allocation.isExpired(Instant.now())) {
            if (allocation != null) {
                closeAllocation(allocation);
            }
            return null;
        }
        allocation.clientRemote = remote;
        return allocation;
    }

    private boolean hasNotPermission(Allocation allocation, InetSocketAddress peer) {
        Instant expiresAt = allocation.permissions.get(permissionKey(peer));
        return expiresAt == null || !expiresAt.isAfter(Instant.now());
    }

    private void sendStun(DatagramSocket socket, InetSocketAddress remote, StunMessage message) throws Exception {
        sendStun(socket, remote, message, null);
    }

    private void sendStun(DatagramSocket socket,
                          InetSocketAddress remote,
                          StunMessage message,
                          byte[] messageIntegrityKey) throws Exception {
        if (socket == null || socket.isClosed() || remote == null) {
            return;
        }
        byte[] bytes = message.toBytes(messageIntegrityKey);
        socket.send(new DatagramPacket(bytes, bytes.length, remote));
    }

    private void sendError(DatagramSocket socket,
                           InetSocketAddress remote,
                           StunMessage request,
                           int responseType,
                           int code,
                           String reason,
                           StunMessage.Attribute... extraAttributes) throws Exception {
        List<StunMessage.Attribute> attributes = new ArrayList<>();
        attributes.add(StunMessage.errorCode(code, reason));
        attributes.add(StunMessage.software(SOFTWARE));
        if (extraAttributes != null) {
            attributes.addAll(List.of(extraAttributes));
        }
        StunMessage response = new StunMessage(responseType, request.transactionId(), attributes);
        sendStun(socket, remote, response);
    }

    private int errorType(int requestType) {
        return switch (requestType) {
            case StunMessage.ALLOCATE_REQUEST -> StunMessage.ALLOCATE_ERROR;
            case StunMessage.REFRESH_REQUEST -> StunMessage.REFRESH_ERROR;
            case StunMessage.CREATE_PERMISSION_REQUEST -> StunMessage.CREATE_PERMISSION_ERROR;
            case StunMessage.CHANNEL_BIND_REQUEST -> StunMessage.CHANNEL_BIND_ERROR;
            default -> StunMessage.BINDING_ERROR;
        };
    }

    @Scheduled(fixedDelay = 30_000)
    public void cleanupExpiredAllocations() {
        Instant now = Instant.now();
        for (Allocation allocation : allocations.values()) {
            allocation.permissions.entrySet().removeIf(entry -> entry.getValue().isBefore(now));
            allocation.channelsByNumber.entrySet().removeIf(entry -> !entry.getValue().activeAt(now));
            allocation.channelsByPeer.entrySet().removeIf(entry -> !entry.getValue().activeAt(now));
            if (allocation.isExpired(now)) {
                closeAllocation(allocation);
            }
        }
    }

    @PreDestroy
    public void stop() {
        running = false;
        closeStunSockets();
        for (Allocation allocation : allocations.values()) {
            closeAllocation(allocation);
        }
        if (relayExecutor != null) {
            relayExecutor.shutdownNow();
        }
    }

    private void closeStunSockets() {
        for (DatagramSocket socket : stunSockets.values()) {
            if (socket != null) {
                socket.close();
            }
        }
        stunSockets.clear();
        primarySocket = null;
    }

    private void closeAllocation(Allocation allocation) {
        if (allocation == null || allocation.closed) {
            return;
        }
        allocation.closed = true;
        allocations.remove(allocation.id);
        allocationByEndpoint.remove(endpointKey(allocation.clientRemote), allocation.id);
        allocationByRelayEndpoint.remove(endpointKey(allocation.relayAddress), allocation.id);
        if (allocation.relaySocket != null) {
            allocation.relaySocket.close();
        }
        if (allocation.relayThread != null) {
            allocation.relayThread.interrupt();
        }
    }

    private String endpointKey(InetSocketAddress remote) {
        if (remote == null || remote.getAddress() == null) {
            return "";
        }
        return remote.getAddress().getHostAddress() + ":" + remote.getPort();
    }

    private Allocation allocationForRelayEndpoint(InetSocketAddress remote) {
        if (remote == null) {
            return null;
        }
        String id = allocationByRelayEndpoint.get(endpointKey(remote));
        Allocation exact = id == null ? null : allocations.get(id);
        Instant now = Instant.now();
        if (exact != null && !exact.isExpired(now)) {
            return exact;
        }
        for (Allocation candidate : allocations.values()) {
            if (!candidate.isExpired(now)
                    && candidate.relayAddress.getPort() == remote.getPort()) {
                return candidate;
            }
        }
        return null;
    }

    private String permissionKey(InetSocketAddress remote) {
        if (remote == null || remote.getAddress() == null) {
            return "";
        }
        return remote.getAddress().getHostAddress();
    }

    private boolean sameEndpoint(InetSocketAddress left, InetSocketAddress right) {
        return Objects.equals(endpointKey(left), endpointKey(right));
    }

    private int natProbeAlternatePort() {
        int configured = properties.getNatProbeAlternatePort();
        if (configured > 0) {
            return configured;
        }
        int next = properties.getStunTurnPort() + 1;
        return next > 0 && next <= 65_535 ? next : 0;
    }

    private InetSocketAddress advertisedSocketAddress(DatagramSocket socket) {
        return new InetSocketAddress(advertisedAddress(socket), socket == null ? 0 : socket.getLocalPort());
    }

    private InetAddress advertisedAddress(DatagramSocket socket) {
        if (turnAdvertisedAddress != null) {
            return turnAdvertisedAddress;
        }
        try {
            if (properties.getPublicAddress() != null && !properties.getPublicAddress().isBlank()) {
                return InetAddress.getByName(properties.getPublicAddress().trim());
            }
            if (socket != null && socket.getLocalAddress() != null && !socket.getLocalAddress().isAnyLocalAddress()) {
                return socket.getLocalAddress();
            }
            return InetAddress.getLocalHost();
        } catch (Exception e) {
            throw new IllegalStateException("cannot resolve advertised TURN address", e);
        }
    }

    private InetAddress resolveBindAddress(String configured) throws Exception {
        if (hasText(configured)) {
            return InetAddress.getByName(configured.trim());
        }
        return InetAddress.getByName("0.0.0.0");
    }

    private InetAddress resolvePrimaryAdvertisedAddress(InetAddress bindAddress) throws Exception {
        if (hasText(properties.getPublicAddress())) {
            return InetAddress.getByName(properties.getPublicAddress().trim());
        }
        if (bindAddress != null && !bindAddress.isAnyLocalAddress()) {
            return bindAddress;
        }
        return InetAddress.getLocalHost();
    }

    private boolean hasText(String value) {
        return value != null && !value.isBlank();
    }

    ThreadPoolExecutor createRelayExecutor() {
        int configuredThreads = properties.getRelayWorkerThreads();
        int workers = configuredThreads > 0
                ? configuredThreads
                : Math.clamp(Runtime.getRuntime().availableProcessors(), 2, 8);
        int queueCapacity = Math.max(1, properties.getRelayWorkerQueueCapacity());
        ThreadFactory threadFactory = new ThreadFactory() {
            private int index;

            @Override
            public Thread newThread(@NonNull Runnable runnable) {
                Thread thread = new Thread(runnable, "peer-mesh-relay-" + (++index));
                thread.setDaemon(true);
                return thread;
            }
        };
        return new ThreadPoolExecutor(
                workers,
                workers,
                0L,
                TimeUnit.MILLISECONDS,
                new ArrayBlockingQueue<>(queueCapacity),
                threadFactory,
                (task, executor) -> {
                    relayQueueDropped.increment();
                    relayQueueHighWater.accumulateAndGet(executor.getQueue().size(), Math::max);
                });
    }

    private void configureUdpSocket(DatagramSocket socket) {
        int receiveBufferBytes = properties.getUdpReceiveBufferBytes();
        if (receiveBufferBytes > 0) {
            try {
                socket.setReceiveBufferSize(Math.max(65_507, receiveBufferBytes));
            } catch (Exception e) {
                log.warn("[peer-mesh] unable to configure UDP receive buffer: {}", e.getMessage());
            }
        }
        int sendBufferBytes = properties.getUdpSendBufferBytes();
        if (sendBufferBytes > 0) {
            try {
                socket.setSendBufferSize(Math.max(65_507, sendBufferBytes));
            } catch (Exception e) {
                log.warn("[peer-mesh] unable to configure UDP send buffer: {}", e.getMessage());
            }
        }
        int trafficClass = properties.getUdpTrafficClass();
        if (trafficClass >= 0 && trafficClass <= 255) {
            try {
                socket.setTrafficClass(trafficClass);
            } catch (Exception e) {
                log.debug("[peer-mesh] UDP traffic class is not supported: {}", e.getMessage());
            }
        }
    }

    private double relayQueueDepth() {
        ThreadPoolExecutor executor = relayExecutor;
        return executor == null ? 0 : executor.getQueue().size();
    }

    private static final class Allocation {
        private final String id;
        private volatile InetSocketAddress clientRemote;
        private final DatagramSocket relaySocket;
        private final InetSocketAddress relayAddress;
        private final Map<String, Instant> permissions = new ConcurrentHashMap<>();
        private final Map<Integer, ChannelBinding> channelsByNumber = new ConcurrentHashMap<>();
        private final Map<String, ChannelBinding> channelsByPeer = new ConcurrentHashMap<>();
        private volatile Instant expiresAt;
        private final long clientId;
        /** true 表示按标准 TURN 语义转发任意载荷（公开互传的浏览器 WebRTC） */
        private final boolean generalRelay;
        /** 通用中继配额计数：生命周期累计转发字节与令牌桶 */
        private final java.util.concurrent.atomic.AtomicLong relayedBytes =
                new java.util.concurrent.atomic.AtomicLong();
        private final java.util.concurrent.atomic.AtomicBoolean quotaLogged =
                new java.util.concurrent.atomic.AtomicBoolean();
        private volatile Thread relayThread;
        private volatile boolean closed;

        private Allocation(String id,
                           InetSocketAddress clientRemote,
                           DatagramSocket relaySocket,
                           InetSocketAddress relayAddress,
                           Instant expiresAt,
                           long clientId,
                           boolean generalRelay) {
            this.id = Objects.requireNonNull(id, "id");
            this.clientRemote = clientRemote;
            this.relaySocket = relaySocket;
            this.relayAddress = relayAddress;
            this.expiresAt = expiresAt;
            this.clientId = clientId;
            this.generalRelay = generalRelay;
        }

        private boolean isExpired(Instant now) {
            return closed || expiresAt == null || !expiresAt.isAfter(now);
        }

        private boolean matchesClient(long authenticatedClientId) {
            return clientId == authenticatedClientId;
        }
    }

    private record ChannelBinding(int channelNumber, InetSocketAddress peer, Instant expiresAt) {
        private boolean activeAt(Instant now) {
            return expiresAt != null && expiresAt.isAfter(now);
        }
    }

    private record TurnAuth(boolean allowed, byte[] messageIntegrityKey, long clientId, boolean generalRelay) {
        private static TurnAuth none() {
            return new TurnAuth(true, null, 0, false);
        }

        private static TurnAuth denied() {
            return new TurnAuth(false, null, 0, false);
        }

        private static TurnAuth allowed(byte[] messageIntegrityKey, long clientId, boolean generalRelay) {
            return new TurnAuth(true, messageIntegrityKey, clientId, generalRelay);
        }
    }
}
