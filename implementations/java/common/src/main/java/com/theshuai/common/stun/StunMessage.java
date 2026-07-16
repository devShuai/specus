package com.theshuai.common.stun;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;
import java.util.Optional;

public final class StunMessage {
    public static final int MAGIC_COOKIE = 0x2112A442;
    public static final int HEADER_BYTES = 20;
    public static final int TRANSACTION_ID_BYTES = 12;

    public static final int BINDING_REQUEST = 0x0001;
    public static final int BINDING_SUCCESS = 0x0101;
    public static final int BINDING_ERROR = 0x0111;
    public static final int ALLOCATE_REQUEST = 0x0003;
    public static final int ALLOCATE_SUCCESS = 0x0103;
    public static final int ALLOCATE_ERROR = 0x0113;
    public static final int REFRESH_REQUEST = 0x0004;
    public static final int REFRESH_SUCCESS = 0x0104;
    public static final int REFRESH_ERROR = 0x0114;
    public static final int CREATE_PERMISSION_REQUEST = 0x0008;
    public static final int CREATE_PERMISSION_SUCCESS = 0x0108;
    public static final int CREATE_PERMISSION_ERROR = 0x0118;
    public static final int SEND_INDICATION = 0x0016;
    public static final int DATA_INDICATION = 0x0017;

    public static final int ATTR_MAPPED_ADDRESS = 0x0001;
    public static final int ATTR_CHANGE_REQUEST = 0x0003;
    public static final int ATTR_USERNAME = 0x0006;
    public static final int ATTR_MESSAGE_INTEGRITY = 0x0008;
    public static final int ATTR_ERROR_CODE = 0x0009;
    public static final int ATTR_UNKNOWN_ATTRIBUTES = 0x000A;
    public static final int ATTR_LIFETIME = 0x000D;
    public static final int ATTR_XOR_PEER_ADDRESS = 0x0012;
    public static final int ATTR_DATA = 0x0013;
    public static final int ATTR_REALM = 0x0014;
    public static final int ATTR_NONCE = 0x0015;
    public static final int ATTR_XOR_RELAYED_ADDRESS = 0x0016;
    public static final int ATTR_REQUESTED_TRANSPORT = 0x0019;
    public static final int ATTR_XOR_MAPPED_ADDRESS = 0x0020;
    public static final int ATTR_SOFTWARE = 0x8022;
    public static final int ATTR_RESPONSE_ORIGIN = 0x802B;
    public static final int ATTR_OTHER_ADDRESS = 0x802C;
    public static final int ATTR_FINGERPRINT = 0x8028;

    public static final int TRANSPORT_UDP = 17;
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    private final int type;
    private final byte[] transactionId;
    private final List<Attribute> attributes;

    public StunMessage(int type, byte[] transactionId, List<Attribute> attributes) {
        this.type = type & 0xFFFF;
        this.transactionId = normalizeTransactionId(transactionId);
        this.attributes = attributes == null ? List.of() : List.copyOf(attributes);
    }

    public static StunMessage of(int type, byte[] transactionId, Attribute... attributes) {
        return new StunMessage(type, transactionId, attributes == null ? List.of() : List.of(attributes));
    }

    public static byte[] newTransactionId() {
        byte[] bytes = new byte[TRANSACTION_ID_BYTES];
        SECURE_RANDOM.nextBytes(bytes);
        return bytes;
    }

    public static boolean looksLike(byte[] packet, int offset, int length) {
        if (packet == null || offset < 0 || length < HEADER_BYTES || offset + HEADER_BYTES > packet.length) {
            return false;
        }
        if ((packet[offset] & 0xC0) != 0) {
            return false;
        }
        int declaredLength = Short.toUnsignedInt(ByteBuffer.wrap(packet, offset + 2, Short.BYTES).getShort());
        int cookie = ByteBuffer.wrap(packet, offset + 4, Integer.BYTES).getInt();
        return cookie == MAGIC_COOKIE && declaredLength + HEADER_BYTES <= length;
    }

    public static StunMessage parse(byte[] packet, int offset, int length) {
        if (!looksLike(packet, offset, length)) {
            return null;
        }
        ByteBuffer buffer = ByteBuffer.wrap(packet, offset, length);
        int type = Short.toUnsignedInt(buffer.getShort());
        int messageLength = Short.toUnsignedInt(buffer.getShort());
        int cookie = buffer.getInt();
        if (cookie != MAGIC_COOKIE || messageLength + HEADER_BYTES > length) {
            return null;
        }
        byte[] transactionId = new byte[TRANSACTION_ID_BYTES];
        buffer.get(transactionId);

        int end = offset + HEADER_BYTES + messageLength;
        List<Attribute> attributes = new ArrayList<>();
        while (buffer.position() < end) {
            if (end - buffer.position() < 4) {
                return null;
            }
            int attrType = Short.toUnsignedInt(buffer.getShort());
            int attrLength = Short.toUnsignedInt(buffer.getShort());
            if (attrLength > end - buffer.position()) {
                return null;
            }
            byte[] value = new byte[attrLength];
            buffer.get(value);
            int padding = padding(attrLength);
            if (padding > 0) {
                if (padding > end - buffer.position()) {
                    return null;
                }
                buffer.position(buffer.position() + padding);
            }
            attributes.add(new Attribute(attrType, value));
        }
        return new StunMessage(type, transactionId, attributes);
    }

    public byte[] toBytes() {
        return toBytes(null);
    }

    public byte[] toBytes(byte[] messageIntegrityKey) {
        int attributeBytes = 0;
        for (Attribute attribute : attributes) {
            attributeBytes += 4 + attribute.value().length + padding(attribute.value().length);
        }
        if (messageIntegrityKey != null && messageIntegrityKey.length > 0) {
            byte[] beforeIntegrity = serialize(attributeBytes + 24, attributes);
            byte[] digest = hmacSha1(messageIntegrityKey, beforeIntegrity);
            ByteBuffer packet = ByteBuffer.allocate(beforeIntegrity.length + 24);
            packet.put(beforeIntegrity);
            packet.putShort((short) ATTR_MESSAGE_INTEGRITY);
            packet.putShort((short) digest.length);
            packet.put(digest);
            return packet.array();
        }
        return serialize(attributeBytes, attributes);
    }

    private byte[] serialize(int declaredAttributeBytes, List<Attribute> serializedAttributes) {
        int actualAttributeBytes = 0;
        for (Attribute attribute : serializedAttributes) {
            actualAttributeBytes += 4 + attribute.value().length + padding(attribute.value().length);
        }
        ByteBuffer buffer = ByteBuffer.allocate(HEADER_BYTES + actualAttributeBytes);
        buffer.putShort((short) type);
        buffer.putShort((short) declaredAttributeBytes);
        buffer.putInt(MAGIC_COOKIE);
        buffer.put(transactionId);
        for (Attribute attribute : serializedAttributes) {
            buffer.putShort((short) attribute.type());
            buffer.putShort((short) attribute.value().length);
            buffer.put(attribute.value());
            for (int i = 0; i < padding(attribute.value().length); i++) {
                buffer.put((byte) 0);
            }
        }
        return buffer.array();
    }

    public static boolean verifyMessageIntegrity(byte[] packet, int offset, int length, byte[] messageIntegrityKey) {
        if (messageIntegrityKey == null || messageIntegrityKey.length == 0 || !looksLike(packet, offset, length)) {
            return false;
        }
        int declaredLength = Short.toUnsignedInt(ByteBuffer.wrap(packet, offset + 2, Short.BYTES).getShort());
        int end = offset + HEADER_BYTES + declaredLength;
        int position = offset + HEADER_BYTES;
        while (position < end) {
            if (end - position < 4) {
                return false;
            }
            int attrType = Short.toUnsignedInt(ByteBuffer.wrap(packet, position, Short.BYTES).getShort());
            int attrLength = Short.toUnsignedInt(ByteBuffer.wrap(packet, position + 2, Short.BYTES).getShort());
            int valueOffset = position + 4;
            int next = valueOffset + attrLength + padding(attrLength);
            if (attrLength > end - valueOffset || next > end) {
                return false;
            }
            if (attrType == ATTR_MESSAGE_INTEGRITY) {
                if (attrLength != 20) {
                    return false;
                }
                int signedLength = position - offset + 24 - HEADER_BYTES;
                byte[] signed = Arrays.copyOfRange(packet, offset, position);
                ByteBuffer.wrap(signed, 2, Short.BYTES).putShort((short) signedLength);
                byte[] expected = hmacSha1(messageIntegrityKey, signed);
                byte[] actual = Arrays.copyOfRange(packet, valueOffset, valueOffset + attrLength);
                return Arrays.equals(expected, actual);
            }
            position = next;
        }
        return false;
    }

    public int type() {
        return type;
    }

    public byte[] transactionId() {
        return Arrays.copyOf(transactionId, transactionId.length);
    }

    public String transactionIdHex() {
        return HexFormat.of().formatHex(transactionId);
    }

    public List<Attribute> attributes() {
        return attributes;
    }

    public Optional<Attribute> first(int type) {
        return attributes.stream().filter(attribute -> attribute.type() == type).findFirst();
    }

    public boolean hasAttribute(int type) {
        return attributes.stream().anyMatch(attribute -> attribute.type() == type);
    }

    public List<Attribute> all(int type) {
        return attributes.stream().filter(attribute -> attribute.type() == type).toList();
    }

    public Optional<InetSocketAddress> mappedAddress() {
        return first(ATTR_MAPPED_ADDRESS).flatMap(this::decodeAddress);
    }

    public Optional<InetSocketAddress> xorMappedAddress() {
        return first(ATTR_XOR_MAPPED_ADDRESS).flatMap(this::decodeXorAddress);
    }

    public Optional<InetSocketAddress> xorRelayedAddress() {
        return first(ATTR_XOR_RELAYED_ADDRESS).flatMap(this::decodeXorAddress);
    }

    public Optional<InetSocketAddress> xorPeerAddress() {
        return first(ATTR_XOR_PEER_ADDRESS).flatMap(this::decodeXorAddress);
    }

    public Optional<InetSocketAddress> responseOrigin() {
        return first(ATTR_RESPONSE_ORIGIN).flatMap(this::decodeAddress);
    }

    public Optional<InetSocketAddress> otherAddress() {
        return first(ATTR_OTHER_ADDRESS).flatMap(this::decodeAddress);
    }

    public Optional<InetSocketAddress> legacyXorResponseOrigin() {
        return first(ATTR_RESPONSE_ORIGIN).flatMap(this::decodeXorAddress);
    }

    public Optional<InetSocketAddress> legacyXorOtherAddress() {
        return first(ATTR_OTHER_ADDRESS).flatMap(this::decodeXorAddress);
    }

    public Optional<ChangeRequest> changeRequest() {
        return first(ATTR_CHANGE_REQUEST)
                .filter(attribute -> attribute.value().length == Integer.BYTES)
                .map(attribute -> {
                    int flags = ByteBuffer.wrap(attribute.value()).getInt();
                    return new ChangeRequest((flags & 0x04) != 0, (flags & 0x02) != 0);
                });
    }

    public int errorCode() {
        return first(ATTR_ERROR_CODE)
                .filter(attribute -> attribute.value().length >= 4)
                .map(attribute -> {
                    byte[] value = attribute.value();
                    return (value[2] & 0x07) * 100 + (value[3] & 0xFF);
                })
                .orElse(-1);
    }

    public List<Integer> unknownAttributes() {
        return first(ATTR_UNKNOWN_ATTRIBUTES)
                .map(attribute -> {
                    byte[] value = attribute.value();
                    List<Integer> result = new ArrayList<>(value.length / Short.BYTES);
                    ByteBuffer buffer = ByteBuffer.wrap(value);
                    while (buffer.remaining() >= Short.BYTES) {
                        result.add(Short.toUnsignedInt(buffer.getShort()));
                    }
                    return List.copyOf(result);
                })
                .orElseGet(List::of);
    }

    public Optional<byte[]> data() {
        return first(ATTR_DATA).map(attribute -> Arrays.copyOf(attribute.value(), attribute.value().length));
    }

    public Optional<String> username() {
        return textAttribute(ATTR_USERNAME);
    }

    public Optional<String> realm() {
        return textAttribute(ATTR_REALM);
    }

    public Optional<String> nonce() {
        return textAttribute(ATTR_NONCE);
    }

    public long lifetimeSeconds(long fallback) {
        return first(ATTR_LIFETIME)
                .filter(attribute -> attribute.value().length == Integer.BYTES)
                .map(attribute -> Integer.toUnsignedLong(ByteBuffer.wrap(attribute.value()).getInt()))
                .orElse(fallback);
    }

    public boolean requestedUdpTransport() {
        return first(ATTR_REQUESTED_TRANSPORT)
                .filter(attribute -> attribute.value().length >= 1)
                .map(attribute -> (attribute.value()[0] & 0xFF) == TRANSPORT_UDP)
                .orElse(false);
    }

    private Optional<InetSocketAddress> decodeXorAddress(Attribute attribute) {
        byte[] value = attribute.value();
        if (value.length != 8 && value.length != 20) {
            return Optional.empty();
        }
        int family = value[1] & 0xFF;
        int port = (((value[2] & 0xFF) << 8) | (value[3] & 0xFF)) ^ (MAGIC_COOKIE >>> 16);
        try {
            byte[] address;
            if (family == 0x01 && value.length >= 8) {
                int mask = MAGIC_COOKIE;
                address = new byte[4];
                for (int i = 0; i < 4; i++) {
                    address[i] = (byte) (value[4 + i] ^ ((mask >>> (24 - i * 8)) & 0xFF));
                }
            } else if (family == 0x02 && value.length >= 20) {
                byte[] mask = new byte[16];
                ByteBuffer.wrap(mask).putInt(MAGIC_COOKIE).put(transactionId);
                address = new byte[16];
                for (int i = 0; i < 16; i++) {
                    address[i] = (byte) (value[4 + i] ^ mask[i]);
                }
            } else {
                return Optional.empty();
            }
            return Optional.of(new InetSocketAddress(InetAddress.getByAddress(address), port));
        } catch (Exception e) {
            return Optional.empty();
        }
    }

    private Optional<InetSocketAddress> decodeAddress(Attribute attribute) {
        byte[] value = attribute.value();
        if (value.length != 8 && value.length != 20) {
            return Optional.empty();
        }
        int family = value[1] & 0xFF;
        int port = Short.toUnsignedInt(ByteBuffer.wrap(value, 2, Short.BYTES).getShort());
        try {
            byte[] address;
            if (family == 0x01 && value.length == 8) {
                address = Arrays.copyOfRange(value, 4, 8);
            } else if (family == 0x02 && value.length == 20) {
                address = Arrays.copyOfRange(value, 4, 20);
            } else {
                return Optional.empty();
            }
            return Optional.of(new InetSocketAddress(InetAddress.getByAddress(address), port));
        } catch (Exception e) {
            return Optional.empty();
        }
    }

    public static Attribute mappedAddress(InetSocketAddress address) {
        return new Attribute(ATTR_MAPPED_ADDRESS, encodeAddress(address));
    }

    public static Attribute xorMappedAddress(InetSocketAddress address, byte[] transactionId) {
        return new Attribute(ATTR_XOR_MAPPED_ADDRESS, encodeXorAddress(address, transactionId));
    }

    public static Attribute xorRelayedAddress(InetSocketAddress address, byte[] transactionId) {
        return new Attribute(ATTR_XOR_RELAYED_ADDRESS, encodeXorAddress(address, transactionId));
    }

    public static Attribute xorPeerAddress(InetSocketAddress address, byte[] transactionId) {
        return new Attribute(ATTR_XOR_PEER_ADDRESS, encodeXorAddress(address, transactionId));
    }

    public static Attribute responseOrigin(InetSocketAddress address) {
        return new Attribute(ATTR_RESPONSE_ORIGIN, encodeAddress(address));
    }

    public static Attribute otherAddress(InetSocketAddress address) {
        return new Attribute(ATTR_OTHER_ADDRESS, encodeAddress(address));
    }

    public static Attribute changeRequest(boolean changeIp, boolean changePort) {
        int flags = (changeIp ? 0x04 : 0) | (changePort ? 0x02 : 0);
        return new Attribute(ATTR_CHANGE_REQUEST, ByteBuffer.allocate(Integer.BYTES).putInt(flags).array());
    }

    public static Attribute unknownAttributes(int... types) {
        int[] normalized = types == null ? new int[0] : types;
        ByteBuffer buffer = ByteBuffer.allocate(normalized.length * Short.BYTES);
        for (int type : normalized) {
            buffer.putShort((short) (type & 0xFFFF));
        }
        return new Attribute(ATTR_UNKNOWN_ATTRIBUTES, buffer.array());
    }

    public static Attribute data(byte[] payload) {
        return new Attribute(ATTR_DATA, payload == null ? new byte[0] : Arrays.copyOf(payload, payload.length));
    }

    public static Attribute lifetime(long seconds) {
        ByteBuffer buffer = ByteBuffer.allocate(Integer.BYTES);
        buffer.putInt((int) Math.max(0, Math.min(Integer.toUnsignedLong(-1), seconds)));
        return new Attribute(ATTR_LIFETIME, buffer.array());
    }

    public static Attribute requestedUdpTransportAttribute() {
        return new Attribute(ATTR_REQUESTED_TRANSPORT, new byte[]{(byte) TRANSPORT_UDP, 0, 0, 0});
    }

    public static Attribute software(String value) {
        return new Attribute(ATTR_SOFTWARE, text(value));
    }

    public static Attribute username(String value) {
        return new Attribute(ATTR_USERNAME, text(value));
    }

    public static Attribute realm(String value) {
        return new Attribute(ATTR_REALM, text(value));
    }

    public static Attribute nonce(String value) {
        return new Attribute(ATTR_NONCE, text(value));
    }

    public static Attribute errorCode(int code, String reason) {
        int klass = Math.max(3, Math.min(6, code / 100));
        int number = Math.max(0, Math.min(99, code % 100));
        byte[] reasonBytes = text(reason == null ? "" : reason);
        ByteBuffer buffer = ByteBuffer.allocate(4 + reasonBytes.length);
        buffer.put((byte) 0);
        buffer.put((byte) 0);
        buffer.put((byte) klass);
        buffer.put((byte) number);
        buffer.put(reasonBytes);
        return new Attribute(ATTR_ERROR_CODE, buffer.array());
    }

    public static byte[] encodeAddress(InetSocketAddress address) {
        if (address == null || address.getAddress() == null) {
            throw new IllegalArgumentException("address is required");
        }
        byte[] raw = address.getAddress().getAddress();
        byte family = switch (raw.length) {
            case 4 -> 0x01;
            case 16 -> 0x02;
            default -> throw new IllegalArgumentException("unsupported address family");
        };
        ByteBuffer buffer = ByteBuffer.allocate(raw.length == 4 ? 8 : 20);
        buffer.put((byte) 0);
        buffer.put(family);
        buffer.putShort((short) address.getPort());
        buffer.put(raw);
        return buffer.array();
    }

    public static byte[] encodeXorAddress(InetSocketAddress address, byte[] transactionId) {
        if (address == null || address.getAddress() == null) {
            throw new IllegalArgumentException("address is required");
        }
        byte[] raw = address.getAddress().getAddress();
        byte family = switch (raw.length) {
            case 4 -> 0x01;
            case 16 -> 0x02;
            default -> throw new IllegalArgumentException("unsupported address family");
        };
        byte[] normalizedTransaction = normalizeTransactionId(transactionId);
        ByteBuffer buffer = ByteBuffer.allocate(raw.length == 4 ? 8 : 20);
        buffer.put((byte) 0);
        buffer.put(family);
        buffer.putShort((short) (address.getPort() ^ (MAGIC_COOKIE >>> 16)));
        if (raw.length == 4) {
            int mask = MAGIC_COOKIE;
            for (int i = 0; i < 4; i++) {
                buffer.put((byte) (raw[i] ^ ((mask >>> (24 - i * 8)) & 0xFF)));
            }
        } else {
            byte[] mask = new byte[16];
            ByteBuffer.wrap(mask).putInt(MAGIC_COOKIE).put(normalizedTransaction);
            for (int i = 0; i < 16; i++) {
                buffer.put((byte) (raw[i] ^ mask[i]));
            }
        }
        return buffer.array();
    }

    public static String hex(byte[] transactionId) {
        return HexFormat.of().formatHex(normalizeTransactionId(transactionId));
    }

    private static byte[] normalizeTransactionId(byte[] transactionId) {
        if (transactionId == null || transactionId.length != TRANSACTION_ID_BYTES) {
            byte[] generated = new byte[TRANSACTION_ID_BYTES];
            SECURE_RANDOM.nextBytes(generated);
            return generated;
        }
        return Arrays.copyOf(transactionId, transactionId.length);
    }

    private static int padding(int length) {
        return (4 - (length % 4)) % 4;
    }

    private static byte[] text(String value) {
        return (value == null ? "" : value).getBytes(StandardCharsets.UTF_8);
    }

    private Optional<String> textAttribute(int type) {
        return first(type).map(attribute -> new String(attribute.value(), StandardCharsets.UTF_8));
    }

    private static byte[] hmacSha1(byte[] key, byte[] payload) {
        try {
            Mac mac = Mac.getInstance("HmacSHA1");
            mac.init(new SecretKeySpec(key, "HmacSHA1"));
            return mac.doFinal(payload);
        } catch (Exception e) {
            throw new IllegalStateException("cannot compute STUN message integrity", e);
        }
    }

    public record Attribute(int type, byte[] value) {
        public Attribute {
            value = value == null ? new byte[0] : Arrays.copyOf(value, value.length);
        }
    }

    public record ChangeRequest(boolean changeIp, boolean changePort) {
        public static final ChangeRequest NONE = new ChangeRequest(false, false);
    }
}
