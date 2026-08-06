package com.theshuai.specusserver.websocket;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.theshuai.specusserver.config.PublicTransferProperties;
import io.lettuce.core.KeyValue;
import io.lettuce.core.RedisClient;
import io.lettuce.core.RedisURI;
import io.lettuce.core.ScriptOutputType;
import io.lettuce.core.api.StatefulRedisConnection;
import io.lettuce.core.api.sync.RedisCommands;
import io.lettuce.core.codec.ByteArrayCodec;
import io.lettuce.core.codec.RedisCodec;
import io.lettuce.core.codec.StringCodec;
import io.lettuce.core.pubsub.RedisPubSubAdapter;
import io.lettuce.core.pubsub.StatefulRedisPubSubConnection;
import jakarta.annotation.PostConstruct;
import jakarta.annotation.PreDestroy;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.text.Normalizer;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;

/**
 * Redis-backed presence, Pub/Sub, room revision and fixed-window limits for public transfer.
 *
 * <p>Roster visibility and directed routing are net-merged: a participant sees everyone in the
 * same room ({@code roomId + roomKey}) plus everyone on the same network (same
 * {@code publicAddress}, regardless of {@code roomId}), so presence/members stay keyed by
 * groupID while {@code nets:<netID>} indexes the groupIDs present on a net and
 * {@code revision:<netID>} versions the net dimension of the merged roster. Roster revisions
 * are the sum of the group and net counters so they stay monotonic for every recipient.
 *
 * <p>Deployment constraint: old and new nodes sharing one keyspace would corrupt rosters and
 * routing (the new {@code nets:<netID>} index and net-scoped revisions are maintained only by
 * new nodes). Upgrade every cluster node together, or bump {@code RedisKeyPrefix} for the new
 * fleet.
 */
@Component
public class PublicTransferCoordinationService implements AutoCloseable {
    private static final Logger log = LoggerFactory.getLogger(PublicTransferCoordinationService.class);
    private static final long REVISION_TTL_MILLIS = Duration.ofDays(7).toMillis();
    // KEYS: 1=presence:<group>:<member> 2=name:<digest> 3=members:<group>
    //       4=revision:<group> 5=revision:<net> 6=nets:<net>
    // ARGV: 1=peerValue 2=nameValue 3=memberId 4=leaseMs 5=limit 6=presencePrefix(group)
    //       7=revisionTtlMs 8=groupId 9=presenceBasePrefix
    private static final String REGISTER_SCRIPT = """
            local members = redis.call('SMEMBERS', KEYS[3])
            local count = 0
            for _, member in ipairs(members) do
              if redis.call('EXISTS', ARGV[6] .. member) == 1 then
                count = count + 1
              else
                redis.call('SREM', KEYS[3], member)
              end
            end
            if redis.call('EXISTS', KEYS[1]) == 1 then return {-1, 0} end
            local netGroups = redis.call('SMEMBERS', KEYS[6])
            for _, group in ipairs(netGroups) do
              if redis.call('EXISTS', ARGV[9] .. group .. ':' .. ARGV[3]) == 1 then return {-1, 0} end
            end
            if redis.call('EXISTS', KEYS[2]) == 1 then return {-2, 0} end
            if count >= tonumber(ARGV[5]) then return {-3, 0} end
            redis.call('SET', KEYS[1], ARGV[1], 'PX', ARGV[4])
            redis.call('SET', KEYS[2], ARGV[2], 'PX', ARGV[4])
            redis.call('SADD', KEYS[3], ARGV[3])
            redis.call('PEXPIRE', KEYS[3], tonumber(ARGV[4]) * 3)
            redis.call('SADD', KEYS[6], ARGV[8])
            redis.call('PEXPIRE', KEYS[6], tonumber(ARGV[4]) * 3)
            local groupRevision = redis.call('INCR', KEYS[4])
            redis.call('PEXPIRE', KEYS[4], ARGV[7])
            local netRevision = redis.call('INCR', KEYS[5])
            redis.call('PEXPIRE', KEYS[5], ARGV[7])
            return {1, groupRevision + netRevision}
            """;
    // KEYS: 1=presence:<group>:<member> 2=name:<digest> 3=members:<group> 4=nets:<net>
    private static final String REFRESH_SCRIPT = """
            if redis.call('GET', KEYS[1]) ~= ARGV[1] then return 0 end
            if redis.call('GET', KEYS[2]) ~= ARGV[2] then return 0 end
            redis.call('PEXPIRE', KEYS[1], ARGV[3])
            redis.call('PEXPIRE', KEYS[2], ARGV[3])
            redis.call('PEXPIRE', KEYS[3], tonumber(ARGV[3]) * 3)
            redis.call('PEXPIRE', KEYS[4], tonumber(ARGV[3]) * 3)
            return 1
            """;
    // KEYS: 1=presence:<group>:<member> 2=name:<digest> 3=members:<group>
    //       4=revision:<group> 5=revision:<net> 6=nets:<net>
    // ARGV: 1=peerValue 2=nameValue 3=memberId 4=revisionTtlMs 5=groupId
    private static final String UNREGISTER_SCRIPT = """
            if redis.call('GET', KEYS[1]) ~= ARGV[1] then return 0 end
            redis.call('DEL', KEYS[1])
            if redis.call('GET', KEYS[2]) == ARGV[2] then redis.call('DEL', KEYS[2]) end
            redis.call('SREM', KEYS[3], ARGV[3])
            if redis.call('SCARD', KEYS[3]) == 0 then redis.call('SREM', KEYS[6], ARGV[5]) end
            local groupRevision = redis.call('INCR', KEYS[4])
            redis.call('PEXPIRE', KEYS[4], ARGV[4])
            local netRevision = redis.call('INCR', KEYS[5])
            redis.call('PEXPIRE', KEYS[5], ARGV[4])
            return groupRevision + netRevision
            """;
    // KEYS: 1=members:<group> 2=revision:<group> 3=revision:<net> 4=nets:<net>
    // ARGV: 1=presencePrefix(group) 2=revisionTtlMs 3=groupId
    private static final String CLEANUP_SCRIPT = """
            local removed = 0
            local members = redis.call('SMEMBERS', KEYS[1])
            for _, member in ipairs(members) do
              if redis.call('EXISTS', ARGV[1] .. member) == 0 then
                redis.call('SREM', KEYS[1], member)
                removed = removed + 1
              end
            end
            if redis.call('SCARD', KEYS[1]) == 0 then redis.call('SREM', KEYS[4], ARGV[3]) end
            local groupRevision = tonumber(redis.call('GET', KEYS[2]) or '0')
            local netRevision = tonumber(redis.call('GET', KEYS[3]) or '0')
            if removed > 0 then
              groupRevision = redis.call('INCR', KEYS[2])
              redis.call('PEXPIRE', KEYS[2], ARGV[2])
              netRevision = redis.call('INCR', KEYS[3])
              redis.call('PEXPIRE', KEYS[3], ARGV[2])
            end
            return {removed, groupRevision + netRevision}
            """;
    private static final String RATE_SCRIPT = """
            local count = redis.call('INCR', KEYS[1])
            if count == 1 then redis.call('PEXPIRE', KEYS[1], ARGV[2]) end
            if count > tonumber(ARGV[1]) then return 0 end
            return 1
            """;

    private final PublicTransferProperties properties;
    private final ObjectMapper objectMapper = new ObjectMapper();
    private final List<Consumer<PublicTransferClusterFrame.Event>> listeners = new CopyOnWriteArrayList<>();
    private final ThreadPoolExecutor eventExecutor = new ThreadPoolExecutor(
            1, 1, 0L, TimeUnit.MILLISECONDS,
            new ArrayBlockingQueue<>(4096),
            Thread.ofPlatform().name("public-transfer-cluster-events").factory(),
            (task, executor) -> log.warn("public transfer cluster event queue is full"));

    private RedisClient redisClient;
    private StatefulRedisConnection<String, String> stateConnection;
    private StatefulRedisConnection<String, byte[]> eventPublishConnection;
    private StatefulRedisPubSubConnection<String, byte[]> eventSubscribeConnection;
    private RedisCommands<String, String> state;

    public PublicTransferCoordinationService(PublicTransferProperties properties) {
        this.properties = properties;
    }

    @PostConstruct
    void start() {
        if (!enabled()) {
            return;
        }
        if (!StringUtils.hasText(properties.getRedisUri())) {
            throw new IllegalStateException(
                    "specus.public-transfer.redis-uri is required when cluster-enabled=true");
        }
        long leaseMillis = leaseMillis();
        if (properties.getPresenceRefreshIntervalMs() <= 0
                || properties.getPresenceRefreshIntervalMs() * 2 >= leaseMillis) {
            throw new IllegalStateException(
                    "public transfer presence refresh interval must be positive and less than half the lease TTL");
        }
        try {
            RedisURI redisUri = RedisURI.create(properties.getRedisUri().trim());
            redisUri.setTimeout(Duration.ofMillis(commandTimeoutMillis()));
            redisClient = RedisClient.create(redisUri);
            stateConnection = redisClient.connect();
            eventPublishConnection = redisClient.connect(
                    RedisCodec.of(StringCodec.UTF8, ByteArrayCodec.INSTANCE));
            eventSubscribeConnection = redisClient.connectPubSub(
                    RedisCodec.of(StringCodec.UTF8, ByteArrayCodec.INSTANCE));
            eventSubscribeConnection.addListener(new RedisPubSubAdapter<>() {
                @Override
                public void message(String channel, byte[] message) {
                    if (!eventChannel().equals(channel) || message == null) {
                        return;
                    }
                    try {
                        PublicTransferClusterFrame.Event event = PublicTransferClusterFrame.decode(message);
                        eventExecutor.execute(() -> listeners.forEach(listener -> notifyListener(listener, event)));
                    } catch (IllegalArgumentException exception) {
                        log.warn("discarding invalid public transfer cluster event: {}", exception.getMessage());
                    }
                }
            });
            state = stateConnection.sync();
            state.ping();
            eventSubscribeConnection.sync().subscribe(eventChannel());
            log.info("public transfer Redis coordination enabled: prefix={}", keyPrefix());
        } catch (RuntimeException exception) {
            close();
            throw new IllegalStateException("could not initialize public transfer Redis coordination", exception);
        }
    }

    public boolean enabled() {
        return properties.isClusterEnabled();
    }

    public void addListener(Consumer<PublicTransferClusterFrame.Event> listener) {
        listeners.add(listener);
    }

    public Registration register(Participant participant, int configuredLimit) {
        requireEnabled();
        String groupId = participant.groupId();
        String netId = participant.netId();
        String memberId = digest(participant.peerId());
        String nameValue = participant.leaseId() + "\n" + participant.peerId();
        String peerValue = encodeParticipant(participant);
        List<?> result = command(() -> state.eval(
                REGISTER_SCRIPT,
                ScriptOutputType.MULTI,
                new String[]{presenceKey(groupId, memberId), nameKey(participant.displayName()),
                        membersKey(groupId), revisionKey(groupId), revisionKey(netId),
                        netsKey(netId)},
                peerValue,
                nameValue,
                memberId,
                Long.toString(leaseMillis()),
                Integer.toString(Math.max(1, configuredLimit)),
                presencePrefix(groupId),
                Long.toString(REVISION_TTL_MILLIS),
                groupId,
                presenceBasePrefix()));
        long code = number(result, 0);
        long revision = number(result, 1);
        return switch ((int) code) {
            case 1 -> new Registration(null, revision);
            case -1 -> new Registration("peer id is already connected", 0);
            case -2 -> new Registration("client name is already in use", 0);
            case -3 -> new Registration("room is full", 0);
            default -> throw new IllegalStateException("unexpected public transfer registration result");
        };
    }

    public boolean refresh(Participant participant) {
        requireEnabled();
        String groupId = participant.groupId();
        String memberId = digest(participant.peerId());
        Long refreshed = command(() -> state.eval(
                REFRESH_SCRIPT,
                ScriptOutputType.INTEGER,
                new String[]{presenceKey(groupId, memberId), nameKey(participant.displayName()),
                        membersKey(groupId), netsKey(participant.netId())},
                encodeParticipant(participant),
                participant.leaseId() + "\n" + participant.peerId(),
                Long.toString(leaseMillis())));
        return refreshed != null && refreshed == 1L;
    }

    public long unregister(Participant participant) {
        requireEnabled();
        String groupId = participant.groupId();
        String memberId = digest(participant.peerId());
        Long revision = command(() -> state.eval(
                UNREGISTER_SCRIPT,
                ScriptOutputType.INTEGER,
                new String[]{presenceKey(groupId, memberId), nameKey(participant.displayName()),
                        membersKey(groupId), revisionKey(groupId), revisionKey(participant.netId()),
                        netsKey(participant.netId())},
                encodeParticipant(participant),
                participant.leaseId() + "\n" + participant.peerId(),
                memberId,
                Long.toString(REVISION_TTL_MILLIS),
                groupId));
        return revision == null ? 0 : revision;
    }

    /**
     * Reads the merged roster for {@code recipient}: everyone in the recipient's room plus
     * everyone on the recipient's network (same {@code publicAddress}, regardless of
     * {@code roomId}), deduplicated by peerId. The returned revision is the sum of the group
     * and net revision counters, so it increases monotonically whenever either dimension of
     * the roster changes.
     */
    public Roster roster(Participant recipient) {
        requireEnabled();
        String groupId = recipient.groupId();
        String netId = recipient.netId();
        // Hygiene pass: prune stale members of the own group and of every group on the net
        // (also drops emptied groups from the nets index and bumps both revision counters so
        // presence expiries surface to merged-roster recipients). Reads below self-heal anyway,
        // this pass is what makes expiries visible to push recipients in a timely manner.
        List<String> groups = netGroups(netId, groupId);
        boolean removedAny = false;
        long cleanupRevision = 0;
        for (String group : groups) {
            Cleanup cleanup = cleanup(group, netId);
            removedAny |= cleanup.removed() > 0;
            cleanupRevision = cleanup.revision();
        }
        if (removedAny) {
            publishRoster(groupId, cleanupRevision);
            publishRoster(netId, cleanupRevision);
        }
        for (int attempt = 0; attempt < 2; attempt++) {
            long beforeGroup = revision(groupId);
            long beforeNet = revision(netId);
            List<Participant> participants = readMergedParticipants(recipient,
                    netGroups(netId, groupId));
            long afterGroup = revision(groupId);
            long afterNet = revision(netId);
            if (attempt == 1 || (beforeGroup == afterGroup && beforeNet == afterNet)) {
                participants.sort(Comparator.comparing(Participant::connectedAt));
                return new Roster(afterGroup + afterNet, List.copyOf(participants));
            }
        }
        throw new IllegalStateException("could not read stable public transfer roster");
    }

    /**
     * Locates a visible peer by peerId within the recipient's merged visibility domain
     * (same room or same network). Used to route directed messages cross-room on one network;
     * returns {@code null} when the target is not visible to the recipient.
     */
    public Participant findPeer(Participant recipient, String peerId) {
        requireEnabled();
        if (!StringUtils.hasText(peerId)) {
            return null;
        }
        for (String group : netGroups(recipient.netId(), recipient.groupId())) {
            List<String> members = new ArrayList<>(command(() -> state.smembers(membersKey(group))));
            if (members.isEmpty()) {
                continue;
            }
            String[] keys = members.stream()
                    .map(member -> presenceKey(group, member))
                    .toArray(String[]::new);
            for (KeyValue<String, String> value : command(() -> state.mget(keys))) {
                if (!value.hasValue()) {
                    continue;
                }
                Participant participant = decodeParticipant(value.getValue());
                // 内存复核:同房间需 roomId+roomKey 一致;同网只看 publicAddress(与 roomId 无关)。
                if (participant != null && participant.peerId().equals(peerId)
                        && ((participant.roomId().equals(recipient.roomId())
                                && participant.roomKey().equals(recipient.roomKey()))
                                || sameNetAddress(participant.publicAddress(),
                                        recipient.publicAddress()))) {
                    return participant;
                }
            }
        }
        return null;
    }

    private List<String> netGroups(String netId, String groupId) {
        List<String> groups = new ArrayList<>(command(() -> state.smembers(netsKey(netId))));
        // 自身 group 排首位:定向路由查找与 roster 读取都以同房间目标为主,可提前命中。
        groups.remove(groupId);
        groups.add(0, groupId);
        return groups;
    }

    private List<Participant> readMergedParticipants(Participant recipient, List<String> groups) {
        Map<String, Participant> participantsByPeerId = new LinkedHashMap<>();
        for (String group : groups) {
            List<String> members = new ArrayList<>(command(() -> state.smembers(membersKey(group))));
            if (members.isEmpty()) {
                continue;
            }
            String[] keys = members.stream()
                    .map(member -> presenceKey(group, member))
                    .toArray(String[]::new);
            List<KeyValue<String, String>> values = command(() -> state.mget(keys));
            for (KeyValue<String, String> value : values) {
                if (!value.hasValue()) {
                    continue;
                }
                Participant participant = decodeParticipant(value.getValue());
                // 内存复核:合并可见域 = 同房间(roomId+roomKey)或同网(publicAddress 可辨识且
                // 相等,与 roomId 无关);"unknown"/空地址不构成同网。
                if (participant != null
                        && ((participant.roomId().equals(recipient.roomId())
                                && participant.roomKey().equals(recipient.roomKey()))
                                || sameNetAddress(participant.publicAddress(),
                                        recipient.publicAddress()))) {
                    participantsByPeerId.putIfAbsent(participant.peerId(), participant);
                }
            }
        }
        return new ArrayList<>(participantsByPeerId.values());
    }

    public long sweep(String groupId, String netId) {
        requireEnabled();
        Cleanup cleanup = cleanup(groupId, netId);
        if (cleanup.removed() > 0) {
            publishRoster(groupId, cleanup.revision());
            publishRoster(netId, cleanup.revision());
        }
        return cleanup.revision();
    }

    public boolean isClientNameAvailable(String displayName, String excludePeerId) {
        requireEnabled();
        String owner = command(() -> state.get(nameKey(displayName)));
        if (!StringUtils.hasText(owner)) {
            return true;
        }
        int separator = owner.indexOf('\n');
        String peerId = separator < 0 ? "" : owner.substring(separator + 1);
        return StringUtils.hasText(excludePeerId) && peerId.equals(excludePeerId.trim());
    }

    public boolean allowRate(String bucket, String identity, int configuredLimit, long configuredWindowSeconds) {
        requireEnabled();
        Long allowed = command(() -> state.eval(
                RATE_SCRIPT,
                ScriptOutputType.INTEGER,
                new String[]{rateKey(bucket, identity)},
                Integer.toString(Math.max(1, configuredLimit)),
                Long.toString(Math.max(1L, configuredWindowSeconds) * 1000L)));
        return allowed != null && allowed == 1L;
    }

    public void publishRoster(String groupId, long revision) {
        publish(new PublicTransferClusterFrame.Event(
                PublicTransferClusterFrame.KIND_ROSTER,
                false,
                revision,
                groupId,
                "",
                "",
                new byte[0]));
    }

    public void publishText(String groupId, String targetPeerId, String sourceLeaseId,
                            boolean excludeSource, byte[] payload) {
        publish(new PublicTransferClusterFrame.Event(
                PublicTransferClusterFrame.KIND_TEXT,
                excludeSource,
                0,
                groupId,
                targetPeerId,
                sourceLeaseId,
                payload));
    }

    public void publishBinary(String groupId, String targetPeerId, byte[] payload) {
        publish(new PublicTransferClusterFrame.Event(
                PublicTransferClusterFrame.KIND_BINARY,
                false,
                0,
                groupId,
                targetPeerId,
                "",
                payload));
    }

    public void publishManagement(String tenantId, byte[] payload) {
        publish(new PublicTransferClusterFrame.Event(
                PublicTransferClusterFrame.KIND_MANAGEMENT,
                false,
                0,
                managementGroupId(tenantId),
                "",
                "",
                payload));
    }

    public static String groupId(String roomId, String roomKey) {
        return digest((roomId == null ? "" : roomId) + "\u0000" + (roomKey == null ? "" : roomKey));
    }

    public static String managementGroupId(String tenantId) {
        return digest(tenantId == null ? "" : tenantId.trim());
    }

    /**
     * 同网标识:仅由公网地址 digest 得出(sha256 UTF-8 小写 hex),不含 roomId 分量——
     * 同网设备无论房间名如何都互相自动发现。
     */
    public static String netId(String publicAddress) {
        return digest(publicAddress == null ? "" : publicAddress);
    }

    /**
     * 同网判定:公网地址相等且可辨识。空串与 {@link WebSocketRequestAddress#UNKNOWN} 兜底值
     * 不构成同网,避免地址解析失败的客户端被异常聚为一组。
     */
    public static boolean sameNetAddress(String left, String right) {
        return left != null && !left.isBlank() && !WebSocketRequestAddress.UNKNOWN.equals(left)
                && left.equals(right);
    }

    private void publish(PublicTransferClusterFrame.Event event) {
        requireEnabled();
        byte[] encoded = PublicTransferClusterFrame.encode(event);
        command(() -> eventPublishConnection.sync().publish(eventChannel(), encoded));
    }

    private Cleanup cleanup(String groupId, String netId) {
        List<?> result = command(() -> state.eval(
                CLEANUP_SCRIPT,
                ScriptOutputType.MULTI,
                new String[]{membersKey(groupId), revisionKey(groupId), revisionKey(netId),
                        netsKey(netId)},
                presencePrefix(groupId),
                Long.toString(REVISION_TTL_MILLIS),
                groupId));
        return new Cleanup(number(result, 0), number(result, 1));
    }

    private long revision(String id) {
        String value = command(() -> state.get(revisionKey(id)));
        if (!StringUtils.hasText(value)) {
            return 0;
        }
        try {
            return Long.parseLong(value);
        } catch (NumberFormatException exception) {
            throw new IllegalStateException("invalid public transfer room revision", exception);
        }
    }

    private String encodeParticipant(Participant participant) {
        try {
            return participant.leaseId() + "\n" + objectMapper.writeValueAsString(participant);
        } catch (Exception exception) {
            throw new IllegalStateException("could not encode public transfer participant", exception);
        }
    }

    private Participant decodeParticipant(String encoded) {
        try {
            int separator = encoded.indexOf('\n');
            if (separator <= 0) {
                return null;
            }
            Participant participant = objectMapper.readValue(encoded.substring(separator + 1), Participant.class);
            return encoded.substring(0, separator).equals(participant.leaseId()) ? participant : null;
        } catch (Exception exception) {
            log.warn("discarding invalid public transfer presence record: {}", exception.getMessage());
            return null;
        }
    }

    private String presencePrefix(String groupId) {
        return presenceBasePrefix() + groupId + ":";
    }

    private String presenceBasePrefix() {
        return keyPrefix() + ":presence:";
    }

    private String presenceKey(String groupId, String memberId) {
        return presencePrefix(groupId) + memberId;
    }

    private String membersKey(String groupId) {
        return keyPrefix() + ":members:" + groupId;
    }

    private String netsKey(String netId) {
        return keyPrefix() + ":nets:" + netId;
    }

    private String revisionKey(String id) {
        return keyPrefix() + ":revision:" + id;
    }

    private String nameKey(String displayName) {
        String normalized = Normalizer.normalize(displayName.trim(), Normalizer.Form.NFC)
                .toLowerCase(Locale.ROOT);
        return keyPrefix() + ":name:" + digest(normalized);
    }

    private String rateKey(String bucket, String identity) {
        return keyPrefix() + ":rate:" + digest(bucket + "\u0000" + identity);
    }

    private String eventChannel() {
        return keyPrefix() + ":events";
    }

    private String keyPrefix() {
        String configured = properties.getRedisKeyPrefix();
        return StringUtils.hasText(configured)
                ? configured.trim().replaceAll(":+$", "")
                : "specus:v2:public-transfer";
    }

    private long leaseMillis() {
        return Math.max(5L, properties.getPresenceLeaseSeconds()) * 1000L;
    }

    private long commandTimeoutMillis() {
        return Math.max(100L, properties.getRedisCommandTimeoutMs());
    }

    private void requireEnabled() {
        if (!enabled() || state == null) {
            throw new IllegalStateException("public transfer Redis coordination is not enabled");
        }
    }

    private <T> T command(Command<T> command) {
        try {
            return command.execute();
        } catch (RuntimeException exception) {
            throw new IllegalStateException("public transfer Redis coordination unavailable", exception);
        }
    }

    private void notifyListener(Consumer<PublicTransferClusterFrame.Event> listener,
                                PublicTransferClusterFrame.Event event) {
        try {
            listener.accept(event);
        } catch (RuntimeException exception) {
            log.warn("public transfer cluster event listener failed: {}", exception.toString());
        }
    }

    private static long number(List<?> values, int index) {
        if (values == null || index >= values.size() || !(values.get(index) instanceof Number number)) {
            throw new IllegalStateException("invalid Redis script result");
        }
        return number.longValue();
    }

    private static String digest(String value) {
        try {
            byte[] bytes = MessageDigest.getInstance("SHA-256")
                    .digest(value.getBytes(StandardCharsets.UTF_8));
            return java.util.HexFormat.of().formatHex(bytes);
        } catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException("SHA-256 unavailable", exception);
        }
    }

    @PreDestroy
    @Override
    public void close() {
        eventExecutor.shutdownNow();
        closeQuietly(eventSubscribeConnection);
        closeQuietly(eventPublishConnection);
        closeQuietly(stateConnection);
        if (redisClient != null) {
            redisClient.shutdown();
        }
        state = null;
    }

    private static void closeQuietly(AutoCloseable closeable) {
        if (closeable == null) {
            return;
        }
        try {
            closeable.close();
        } catch (Exception ignored) {
            // best effort during shutdown
        }
    }

    @FunctionalInterface
    private interface Command<T> {
        T execute();
    }

    public record Participant(
            String leaseId,
            String peerId,
            String displayName,
            String roomId,
            String publicAddress,
            String roomKey,
            String roomRole,
            boolean sharedRoom,
            String connectedAt) {
        public String groupId() {
            return PublicTransferCoordinationService.groupId(roomId, roomKey);
        }

        public String netId() {
            return PublicTransferCoordinationService.netId(publicAddress);
        }
    }

    public record Registration(String error, long revision) {
        public boolean accepted() {
            return error == null;
        }
    }

    public record Roster(long revision, List<Participant> participants) {
    }

    private record Cleanup(long removed, long revision) {
    }
}
