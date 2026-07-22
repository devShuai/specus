package com.theshuai.stunserver;

import com.theshuai.common.stun.StunEndpointTopology;
import com.theshuai.common.stun.StunMessage;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.net.DatagramPacket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Clock;
import java.util.Arrays;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicLong;

final class DistributedStunForwarder {
    private static final byte[] MAGIC =
            new byte[]{'S', 'T', 'F', 'W', 'D', '2', '\r', '\n'};
    private static final int VERSION = 2;
    private static final int HMAC_BYTES = 32;
    private static final int MIN_PACKET_BYTES =
            MAGIC.length + 1 + 1 + 1 + Integer.BYTES
                    + Long.BYTES + Long.BYTES + Long.BYTES + 1
                    + Short.BYTES + 4 + Short.BYTES
                    + StunMessage.HEADER_BYTES + HMAC_BYTES;
    private static final int MAX_TRACKED_EPOCHS = 64;

    private final StandaloneStunDistributionConfig config;
    private final Clock clock;
    private final long senderEpoch;
    private final AtomicLong nextSequence = new AtomicLong(1);
    private final EpochReplayWindow replayWindow;
    private final TokenBucket rateLimiter;
    private final Map<Integer, ThreadLocal<Mac>> macs;

    DistributedStunForwarder(StandaloneStunDistributionConfig config) {
        this(config, Clock.systemUTC(), new SecureRandom());
    }

    DistributedStunForwarder(
            StandaloneStunDistributionConfig config,
            Clock clock,
            SecureRandom random) {
        this.config = Objects.requireNonNull(config, "config");
        if (!config.enabled()) {
            throw new IllegalArgumentException("distributed forwarding is disabled");
        }
        this.clock = Objects.requireNonNull(clock, "clock");
        SecureRandom epochRandom = Objects.requireNonNull(random, "random");
        long epoch;
        do {
            epoch = epochRandom.nextLong() & Long.MAX_VALUE;
        } while (epoch == 0);
        this.senderEpoch = epoch;
        this.replayWindow = new EpochReplayWindow(
                config.replayWindowSize(),
                config.maxClockSkewSeconds() * 2_000L);
        this.rateLimiter = new TokenBucket(config.forwardBurst(), clock.millis());
        Map<Integer, ThreadLocal<Mac>> configuredMacs = new LinkedHashMap<>();
        configuredMacs.put(config.currentKey().keyId(), mac(config.currentKey()));
        if (config.previousKey() != null) {
            configuredMacs.put(config.previousKey().keyId(), mac(config.previousKey()));
        }
        this.macs = Map.copyOf(configuredMacs);
    }

    byte[] encode(
            StunEndpointTopology.EndpointId responseEndpoint,
            InetSocketAddress responseTarget,
            byte[] response) {
        Objects.requireNonNull(responseEndpoint, "responseEndpoint");
        validateTarget(responseTarget);
        validateResponse(response);
        if (config.isLocal(responseEndpoint)) {
            throw new IllegalArgumentException("response endpoint is local");
        }

        byte[] targetAddress = responseTarget.getAddress().getAddress();
        int family = switch (targetAddress.length) {
            case 4 -> 1;
            case 16 -> 2;
            default -> throw new IllegalArgumentException("unsupported target address family");
        };
        int unsignedBytes = MAGIC.length + 1 + 1 + 1 + Integer.BYTES
                + Long.BYTES + Long.BYTES + Long.BYTES
                + 1 + Short.BYTES + targetAddress.length + Short.BYTES + response.length;
        int packetBytes = unsignedBytes + HMAC_BYTES;
        if (packetBytes > config.maxForwardPacketBytes()) {
            throw new IllegalArgumentException(
                    "distributed forward packet exceeds configured maximum");
        }

        long sequence = nextSequence.getAndIncrement();
        if (sequence <= 0) {
            throw new IllegalStateException("distributed STUN sequence exhausted; restart to create a fresh epoch");
        }
        ByteBuffer buffer = ByteBuffer.allocate(packetBytes);
        buffer.put(MAGIC);
        buffer.put((byte) VERSION);
        buffer.put((byte) 0);
        buffer.put((byte) endpointCode(responseEndpoint));
        buffer.putInt(config.currentKey().keyId());
        buffer.putLong(senderEpoch);
        buffer.putLong(sequence);
        buffer.putLong(clock.millis());
        buffer.put((byte) family);
        buffer.putShort((short) responseTarget.getPort());
        buffer.put(targetAddress);
        buffer.putShort((short) response.length);
        buffer.put(response);
        byte[] unsigned = Arrays.copyOf(buffer.array(), unsignedBytes);
        buffer.put(hmac(config.currentKey().keyId(), unsigned));
        return buffer.array();
    }

    DecodeResult decode(DatagramPacket packet) {
        if (packet == null || packet.getAddress() == null) {
            return DecodeResult.rejected("malformed");
        }
        InetSocketAddress source = new InetSocketAddress(packet.getAddress(), packet.getPort());
        if (!source.equals(config.peerControlAddress())) {
            return DecodeResult.rejected("bad_source");
        }
        long now = clock.millis();
        if (!rateLimiter.tryConsume(
                now,
                config.forwardRatePerSecond(),
                config.forwardBurst())) {
            return DecodeResult.rejected("rate_limited");
        }
        if (packet.getLength() < MIN_PACKET_BYTES
                || packet.getLength() > config.maxForwardPacketBytes()) {
            return DecodeResult.rejected("bad_length");
        }

        int offset = packet.getOffset();
        int length = packet.getLength();
        byte[] bytes = packet.getData();
        int signedLength = length - HMAC_BYTES;
        byte[] signed = Arrays.copyOfRange(bytes, offset, offset + signedLength);
        byte[] actualHmac = Arrays.copyOfRange(
                bytes,
                offset + signedLength,
                offset + length);
        int keyId;
        try {
            ByteBuffer header = ByteBuffer.wrap(signed);
            byte[] magic = new byte[MAGIC.length];
            header.get(magic);
            if (!Arrays.equals(MAGIC, magic)
                    || Byte.toUnsignedInt(header.get()) != VERSION
                    || Byte.toUnsignedInt(header.get()) != 0) {
                return DecodeResult.rejected("bad_magic");
            }
            header.get();
            keyId = header.getInt();
        } catch (RuntimeException exception) {
            return DecodeResult.rejected("malformed");
        }
        if (!macs.containsKey(keyId)) {
            return DecodeResult.rejected("unknown_key");
        }
        byte[] expectedHmac = hmac(keyId, signed);
        if (!MessageDigest.isEqual(expectedHmac, actualHmac)) {
            return DecodeResult.rejected("bad_hmac");
        }

        try {
            ByteBuffer buffer = ByteBuffer.wrap(signed);
            byte[] magic = new byte[MAGIC.length];
            buffer.get(magic);
            if (!Arrays.equals(MAGIC, magic)
                    || Byte.toUnsignedInt(buffer.get()) != VERSION
                    || Byte.toUnsignedInt(buffer.get()) != 0) {
                return DecodeResult.rejected("bad_magic");
            }
            StunEndpointTopology.EndpointId endpoint =
                    endpointId(Byte.toUnsignedInt(buffer.get()));
            if (endpoint == null || !config.isLocal(endpoint)) {
                return DecodeResult.rejected("bad_endpoint");
            }
            if (buffer.getInt() != keyId) {
                return DecodeResult.rejected("malformed");
            }
            long epoch = buffer.getLong();
            long sequence = buffer.getLong();
            long timestamp = buffer.getLong();
            long skewMillis = config.maxClockSkewSeconds() * 1_000L;
            if (epoch <= 0 || sequence <= 0
                    || timestamp < now - skewMillis || timestamp > now + skewMillis) {
                return DecodeResult.rejected("stale");
            }
            int family = Byte.toUnsignedInt(buffer.get());
            int addressBytes = switch (family) {
                case 1 -> 4;
                case 2 -> 16;
                default -> 0;
            };
            if (addressBytes == 0 || buffer.remaining() < Short.BYTES + addressBytes + Short.BYTES) {
                return DecodeResult.rejected("malformed");
            }
            int targetPort = Short.toUnsignedInt(buffer.getShort());
            byte[] targetAddressBytes = new byte[addressBytes];
            buffer.get(targetAddressBytes);
            int responseBytes = Short.toUnsignedInt(buffer.getShort());
            if (targetPort == 0
                    || responseBytes < StunMessage.HEADER_BYTES
                    || buffer.remaining() != responseBytes) {
                return DecodeResult.rejected("malformed");
            }
            InetSocketAddress target = new InetSocketAddress(
                    InetAddress.getByAddress(targetAddressBytes),
                    targetPort);
            validateTarget(target);
            byte[] response = new byte[responseBytes];
            buffer.get(response);
            validateResponse(response);
            if (!replayWindow.accept(epoch, sequence, now)) {
                return DecodeResult.rejected("replay");
            }
            return DecodeResult.accepted(
                    new ForwardedResponse(endpoint, target, response));
        } catch (Exception e) {
            return DecodeResult.rejected("malformed");
        }
    }

    private static void validateTarget(InetSocketAddress target) {
        if (target == null || target.getAddress() == null || target.isUnresolved()) {
            throw new IllegalArgumentException("response target must be resolved");
        }
        if (target.getPort() <= 0
                || target.getAddress().isAnyLocalAddress()
                || target.getAddress().isMulticastAddress()) {
            throw new IllegalArgumentException("response target is invalid");
        }
    }

    private static void validateResponse(byte[] response) {
        if (response == null || response.length < StunMessage.HEADER_BYTES) {
            throw new IllegalArgumentException("forwarded STUN response is missing");
        }
        int declaredBytes = Short.toUnsignedInt(
                ByteBuffer.wrap(response, Short.BYTES, Short.BYTES).getShort());
        if (declaredBytes + StunMessage.HEADER_BYTES != response.length) {
            throw new IllegalArgumentException("forwarded STUN response has trailing bytes");
        }
        StunMessage message = StunMessage.parse(response, 0, response.length);
        if (message == null
                || (message.type() != StunMessage.BINDING_SUCCESS
                && message.type() != StunMessage.BINDING_ERROR)) {
            throw new IllegalArgumentException("forwarded payload is not a Binding response");
        }
    }

    private static int endpointCode(StunEndpointTopology.EndpointId endpointId) {
        int address = endpointId.addressSlot() == StunEndpointTopology.AddressSlot.ALTERNATE
                ? 2
                : 0;
        int port = endpointId.portSlot() == StunEndpointTopology.PortSlot.ALTERNATE
                ? 1
                : 0;
        return address | port;
    }

    private static StunEndpointTopology.EndpointId endpointId(int code) {
        return switch (code) {
            case 0 -> StunEndpointTopology.PRIMARY;
            case 1 -> StunEndpointTopology.PRIMARY_ALTERNATE_PORT;
            case 2 -> StunEndpointTopology.ALTERNATE_PRIMARY_PORT;
            case 3 -> StunEndpointTopology.ALTERNATE;
            default -> null;
        };
    }

    private byte[] hmac(int keyId, byte[] payload) {
        ThreadLocal<Mac> local = macs.get(keyId);
        if (local == null) {
            throw new IllegalArgumentException("unknown distributed STUN key");
        }
        Mac mac = local.get();
        mac.reset();
        return mac.doFinal(payload);
    }

    private static ThreadLocal<Mac> mac(StandaloneStunDistributionConfig.ForwardKey key) {
        byte[] secret = key.secret();
        return ThreadLocal.withInitial(() -> newMac(secret));
    }

    private static Mac newMac(byte[] secret) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(secret, "HmacSHA256"));
            return mac;
        } catch (Exception e) {
            throw new IllegalStateException("cannot initialize distributed STUN HMAC", e);
        }
    }

    record ForwardedResponse(
            StunEndpointTopology.EndpointId responseEndpoint,
            InetSocketAddress responseTarget,
            byte[] response) {
        ForwardedResponse {
            Objects.requireNonNull(responseEndpoint, "responseEndpoint");
            Objects.requireNonNull(responseTarget, "responseTarget");
            response = Arrays.copyOf(response, response.length);
        }

        @Override
        public byte[] response() {
            return Arrays.copyOf(response, response.length);
        }
    }

    record DecodeResult(ForwardedResponse response, String rejectionReason) {
        static DecodeResult accepted(ForwardedResponse response) {
            return new DecodeResult(Objects.requireNonNull(response), "");
        }

        static DecodeResult rejected(String reason) {
            return new DecodeResult(null, reason == null ? "unknown" : reason);
        }

        boolean accepted() {
            return response != null;
        }
    }

    private static final class EpochReplayWindow {
        private final int windowSize;
        private final long retentionMillis;
        private final LinkedHashMap<Long, EpochState> epochs = new LinkedHashMap<>(16, 0.75F, true);

        private EpochReplayWindow(int windowSize, long retentionMillis) {
            this.windowSize = windowSize;
            this.retentionMillis = retentionMillis;
        }

        private synchronized boolean accept(long epoch, long sequence, long now) {
            Iterator<Map.Entry<Long, EpochState>> iterator = epochs.entrySet().iterator();
            while (iterator.hasNext()) {
                if (iterator.next().getValue().expiresAt < now) {
                    iterator.remove();
                }
            }
            EpochState state = epochs.get(epoch);
            if (state == null) {
                while (epochs.size() >= MAX_TRACKED_EPOCHS) {
                    Iterator<Long> keys = epochs.keySet().iterator();
                    keys.next();
                    keys.remove();
                }
                state = new EpochState(new SequenceWindow(windowSize), now + retentionMillis);
                epochs.put(epoch, state);
            }
            if (!state.window.accept(sequence)) {
                return false;
            }
            state.expiresAt = now + retentionMillis;
            return true;
        }
    }

    private static final class EpochState {
        private final SequenceWindow window;
        private long expiresAt;

        private EpochState(SequenceWindow window, long expiresAt) {
            this.window = window;
            this.expiresAt = expiresAt;
        }
    }

    private static final class SequenceWindow {
        private final long[] slots;
        private long highest;

        private SequenceWindow(int size) {
            this.slots = new long[size];
        }

        private boolean accept(long sequence) {
            if (sequence <= highest && highest - sequence >= slots.length) {
                return false;
            }
            int slot = (int) (sequence % slots.length);
            if (slots[slot] == sequence) {
                return false;
            }
            slots[slot] = sequence;
            if (sequence > highest) {
                highest = sequence;
            }
            return true;
        }
    }

    private static final class TokenBucket {
        private double tokens;
        private long updatedMillis;

        private TokenBucket(int burst, long now) {
            tokens = burst;
            updatedMillis = now;
        }

        private synchronized boolean tryConsume(long now, int ratePerSecond, int burst) {
            long elapsed = Math.max(0, now - updatedMillis);
            if (elapsed > 0) {
                tokens = Math.min(burst, tokens + elapsed * (double) ratePerSecond / 1_000D);
                updatedMillis = now;
            }
            if (tokens < 1D) {
                return false;
            }
            tokens -= 1D;
            return true;
        }
    }
}
