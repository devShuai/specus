package com.theshuai.tunnelserver.websocket;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.theshuai.tunnelserver.config.PublicTransferProperties;
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
import java.util.List;
import java.util.Locale;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;

/** Redis-backed presence, Pub/Sub, room revision and fixed-window limits for public transfer. */
@Component
public class PublicTransferCoordinationService implements AutoCloseable {
    private static final Logger log = LoggerFactory.getLogger(PublicTransferCoordinationService.class);
    private static final long REVISION_TTL_MILLIS = Duration.ofDays(7).toMillis();
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
            if redis.call('EXISTS', KEYS[2]) == 1 then return {-2, 0} end
            if count >= tonumber(ARGV[5]) then return {-3, 0} end
            redis.call('SET', KEYS[1], ARGV[1], 'PX', ARGV[4])
            redis.call('SET', KEYS[2], ARGV[2], 'PX', ARGV[4])
            redis.call('SADD', KEYS[3], ARGV[3])
            redis.call('PEXPIRE', KEYS[3], tonumber(ARGV[4]) * 3)
            local revision = redis.call('INCR', KEYS[4])
            redis.call('PEXPIRE', KEYS[4], ARGV[7])
            return {1, revision}
            """;
    private static final String REFRESH_SCRIPT = """
            if redis.call('GET', KEYS[1]) ~= ARGV[1] then return 0 end
            if redis.call('GET', KEYS[2]) ~= ARGV[2] then return 0 end
            redis.call('PEXPIRE', KEYS[1], ARGV[3])
            redis.call('PEXPIRE', KEYS[2], ARGV[3])
            redis.call('PEXPIRE', KEYS[3], tonumber(ARGV[3]) * 3)
            return 1
            """;
    private static final String UNREGISTER_SCRIPT = """
            if redis.call('GET', KEYS[1]) ~= ARGV[1] then return 0 end
            redis.call('DEL', KEYS[1])
            if redis.call('GET', KEYS[2]) == ARGV[2] then redis.call('DEL', KEYS[2]) end
            redis.call('SREM', KEYS[3], ARGV[3])
            local revision = redis.call('INCR', KEYS[4])
            redis.call('PEXPIRE', KEYS[4], ARGV[4])
            return revision
            """;
    private static final String CLEANUP_SCRIPT = """
            local removed = 0
            local members = redis.call('SMEMBERS', KEYS[1])
            for _, member in ipairs(members) do
              if redis.call('EXISTS', ARGV[1] .. member) == 0 then
                redis.call('SREM', KEYS[1], member)
                removed = removed + 1
              end
            end
            local revision = tonumber(redis.call('GET', KEYS[2]) or '0')
            if removed > 0 then
              revision = redis.call('INCR', KEYS[2])
              redis.call('PEXPIRE', KEYS[2], ARGV[2])
            end
            return {removed, revision}
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
                    "tunnel.public-transfer.redis-uri is required when cluster-enabled=true");
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
        String memberId = digest(participant.peerId());
        String nameValue = participant.leaseId() + "\n" + participant.peerId();
        String peerValue = encodeParticipant(participant);
        List<?> result = command(() -> state.eval(
                REGISTER_SCRIPT,
                ScriptOutputType.MULTI,
                new String[]{presenceKey(groupId, memberId), nameKey(participant.displayName()),
                        membersKey(groupId), revisionKey(groupId)},
                peerValue,
                nameValue,
                memberId,
                Long.toString(leaseMillis()),
                Integer.toString(Math.max(1, configuredLimit)),
                presencePrefix(groupId),
                Long.toString(REVISION_TTL_MILLIS)));
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
                        membersKey(groupId)},
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
                        membersKey(groupId), revisionKey(groupId)},
                encodeParticipant(participant),
                participant.leaseId() + "\n" + participant.peerId(),
                memberId,
                Long.toString(REVISION_TTL_MILLIS)));
        return revision == null ? 0 : revision;
    }

    public Roster roster(String groupId) {
        requireEnabled();
        Cleanup cleanup = cleanup(groupId);
        if (cleanup.removed() > 0) {
            publishRoster(groupId, cleanup.revision());
        }
        for (int attempt = 0; attempt < 2; attempt++) {
            long before = revision(groupId);
            List<String> members = new ArrayList<>(command(() -> state.smembers(membersKey(groupId))));
            List<Participant> participants = new ArrayList<>(members.size());
            if (!members.isEmpty()) {
                String[] keys = members.stream()
                        .map(member -> presenceKey(groupId, member))
                        .toArray(String[]::new);
                List<KeyValue<String, String>> values = command(() -> state.mget(keys));
                for (KeyValue<String, String> value : values) {
                    if (value.hasValue()) {
                        Participant participant = decodeParticipant(value.getValue());
                        if (participant != null && participant.groupId().equals(groupId)) {
                            participants.add(participant);
                        }
                    }
                }
            }
            long after = revision(groupId);
            if (attempt == 1 || before == after) {
                participants.sort(Comparator.comparing(Participant::connectedAt));
                return new Roster(after, List.copyOf(participants));
            }
        }
        throw new IllegalStateException("could not read stable public transfer roster");
    }

    public long sweep(String groupId) {
        requireEnabled();
        Cleanup cleanup = cleanup(groupId);
        if (cleanup.removed() > 0) {
            publishRoster(groupId, cleanup.revision());
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

    private void publish(PublicTransferClusterFrame.Event event) {
        requireEnabled();
        byte[] encoded = PublicTransferClusterFrame.encode(event);
        command(() -> eventPublishConnection.sync().publish(eventChannel(), encoded));
    }

    private Cleanup cleanup(String groupId) {
        List<?> result = command(() -> state.eval(
                CLEANUP_SCRIPT,
                ScriptOutputType.MULTI,
                new String[]{membersKey(groupId), revisionKey(groupId)},
                presencePrefix(groupId),
                Long.toString(REVISION_TTL_MILLIS)));
        return new Cleanup(number(result, 0), number(result, 1));
    }

    private long revision(String groupId) {
        String value = command(() -> state.get(revisionKey(groupId)));
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
        return keyPrefix() + ":presence:" + groupId + ":";
    }

    private String presenceKey(String groupId, String memberId) {
        return presencePrefix(groupId) + memberId;
    }

    private String membersKey(String groupId) {
        return keyPrefix() + ":members:" + groupId;
    }

    private String revisionKey(String groupId) {
        return keyPrefix() + ":revision:" + groupId;
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
                : "shuai-tunnel:v2:public-transfer";
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
