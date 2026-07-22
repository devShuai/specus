package com.theshuai.common.serialize.impl;

import com.theshuai.common.protocol.MessageType;
import com.theshuai.common.protocol.request.HeartBeatRequestPacket;
import com.theshuai.common.protocol.request.LoginRequestPacket;
import com.theshuai.common.protocol.request.LogoutRequestPacket;
import com.theshuai.common.protocol.request.MessageRequestPacket;
import com.theshuai.common.protocol.response.HeartBeatResponsePacket;
import com.theshuai.common.protocol.response.LoginResponsePacket;
import com.theshuai.common.protocol.response.LogoutResponsePacket;
import com.theshuai.common.protocol.response.MessageResponsePacket;
import com.theshuai.common.serialize.Serializer;
import com.theshuai.common.serialize.SerializerAlgorithm;

import java.io.ByteArrayOutputStream;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

public class CompactBinarySerializer implements Serializer {
    private static final ValueCodec STRING = new StringCodec();
    private static final ValueCodec BOOLEAN = new BooleanCodec();
    private static final ValueCodec LONG = new LongCodec();
    private static final ValueCodec NUMERIC_STRING = new NumericStringCodec();
    private static final ValueCodec MD5_STRING = new FixedHexStringCodec(16);
    private static final ValueCodec UUID_STRING = new UuidStringCodec();
    private static final ValueCodec HTTP_METHOD = new HttpMethodCodec();
    private static final ValueCodec MESSAGE_TYPE = new MessageTypeCodec();
    private static final ValueCodec STRING_MAP = new StringMapCodec();

    private static final Map<Class<?>, ObjectSchema<?>> SCHEMAS = createSchemas();

    @Override
    public byte getSerializerAlgorithm() {
        return SerializerAlgorithm.BIN;
    }

    @Override
    public byte[] serialize(Object object) {
        if (object == null) {
            throw new IllegalArgumentException("object cannot be null");
        }

        return getSchema(object.getClass()).serialize(object);
    }

    @Override
    public <T> T deserialize(Class<T> clazz, byte[] bytes) {
        if (clazz == null) {
            throw new IllegalArgumentException("clazz cannot be null");
        }
        if (bytes == null) {
            throw new IllegalArgumentException("bytes cannot be null");
        }

        return getSchema(clazz).deserialize(bytes);
    }

    private static Map<Class<?>, ObjectSchema<?>> createSchemas() {
        Map<Class<?>, ObjectSchema<?>> schemas = new ConcurrentHashMap<>();
        register(schemas, schema(LoginRequestPacket.class,
                field("clientName", STRING),
                field("clientSessionId", LONG),
                field("accessToken", STRING),
                field("connectionRole", STRING)));
        register(schemas, schema(LoginResponsePacket.class,
                field("clientName", STRING),
                field("success", BOOLEAN),
                field("reason", STRING)));
        register(schemas, schema(MessageRequestPacket.class,
                field("clientName", STRING),
                field("toClientName", STRING),
                field("messageType", MESSAGE_TYPE),
                field("message", STRING)));
        register(schemas, schema(MessageResponsePacket.class,
                field("clientName", STRING),
                field("toClientName", STRING),
                field("messageType", MESSAGE_TYPE),
                field("message", STRING)));
        register(schemas, schema(LogoutRequestPacket.class));
        register(schemas, schema(LogoutResponsePacket.class,
                field("success", BOOLEAN),
                field("reason", STRING)));
        register(schemas, schema(HeartBeatRequestPacket.class));
        register(schemas, schema(HeartBeatResponsePacket.class));
        return schemas;
    }

    private static void register(Map<Class<?>, ObjectSchema<?>> schemas, ObjectSchema<?> schema) {
        schemas.put(schema.type, schema);
    }

    private static <T> ObjectSchema<T> schema(Class<T> type, FieldSpec... fieldSpecs) {
        return new ObjectSchema<>(type, fieldSpecs);
    }

    private static FieldSpec field(String name, ValueCodec codec) {
        return new FieldSpec(name, codec);
    }

    @SuppressWarnings("unchecked")
    private static <T> ObjectSchema<T> getSchema(Class<T> type) {
        ObjectSchema<?> schema = SCHEMAS.get(type);
        if (schema == null) {
            throw new IllegalArgumentException("unsupported compact binary type: " + type.getName());
        }
        return (ObjectSchema<T>) schema;
    }

    private static class ObjectSchema<T> {
        private final Class<T> type;
        private final Constructor<T> constructor;
        private final List<FieldBinding> fields;

        private ObjectSchema(Class<T> type, FieldSpec... fieldSpecs) {
            this.type = type;
            try {
                constructor = type.getDeclaredConstructor();
                constructor.setAccessible(true);
                fields = Arrays.stream(fieldSpecs)
                        .map(fieldSpec -> new FieldBinding(type, fieldSpec))
                        .toList();
            } catch (ReflectiveOperationException e) {
                throw new IllegalArgumentException("cannot create compact binary schema for " + type.getName(), e);
            }
        }

        private byte[] serialize(Object object) {
            CompactOutput output = new CompactOutput();
            for (FieldBinding field : fields) {
                field.write(output, object);
            }
            return output.toByteArray();
        }

        private T deserialize(byte[] bytes) {
            try {
                T object = constructor.newInstance();
                CompactInput input = new CompactInput(bytes);
                for (FieldBinding field : fields) {
                    field.read(input, object);
                }
                if (input.hasRemaining()) {
                    throw new IllegalArgumentException("compact binary payload has trailing bytes");
                }
                return object;
            } catch (ReflectiveOperationException e) {
                throw new IllegalArgumentException("cannot deserialize " + type.getName(), e);
            }
        }
    }

    private record FieldSpec(String name, ValueCodec codec) {
    }

    private static class FieldBinding {
        private final Field field;
        private final ValueCodec codec;

        private FieldBinding(Class<?> type, FieldSpec fieldSpec) {
            try {
                field = type.getDeclaredField(fieldSpec.name);
                field.setAccessible(true);
                codec = fieldSpec.codec;
            } catch (ReflectiveOperationException e) {
                throw new IllegalArgumentException("cannot bind field " + type.getName() + "." + fieldSpec.name, e);
            }
        }

        private void write(CompactOutput output, Object object) {
            try {
                codec.write(output, field.get(object));
            } catch (IllegalAccessException e) {
                throw new IllegalArgumentException("cannot read field " + field.getName(), e);
            }
        }

        private void read(CompactInput input, Object object) {
            try {
                field.set(object, codec.read(input));
            } catch (IllegalAccessException e) {
                throw new IllegalArgumentException("cannot write field " + field.getName(), e);
            }
        }
    }

    private interface ValueCodec {
        void write(CompactOutput output, Object value);

        Object read(CompactInput input);
    }

    private static class StringCodec implements ValueCodec {
        @Override
        public void write(CompactOutput output, Object value) {
            output.writeString((String) value);
        }

        @Override
        public Object read(CompactInput input) {
            return input.readString();
        }
    }

    private static class BooleanCodec implements ValueCodec {
        @Override
        public void write(CompactOutput output, Object value) {
            output.writeByte(Boolean.TRUE.equals(value) ? 1 : 0);
        }

        @Override
        public Object read(CompactInput input) {
            int value = input.readUnsignedByte();
            if (value > 1) {
                throw new IllegalArgumentException("invalid boolean value: " + value);
            }
            return value == 1;
        }
    }

    private static class IntegerCodec implements ValueCodec {
        @Override
        public void write(CompactOutput output, Object value) {
            output.writeVarInt((Integer) value);
        }

        @Override
        public Object read(CompactInput input) {
            return input.readVarInt();
        }
    }

    private static class LongCodec implements ValueCodec {
        @Override
        public void write(CompactOutput output, Object value) {
            Long longValue = (Long) value;
            if (longValue == null) {
                output.writeByte(0);
                return;
            }
            output.writeByte(1);
            output.writeVarLong(zigZagEncode(longValue));
        }

        @Override
        public Object read(CompactInput input) {
            return switch (input.readUnsignedByte()) {
                case 0 -> null;
                case 1 -> zigZagDecode(input.readVarLong());
                default -> throw new IllegalArgumentException("invalid long type");
            };
        }
    }

    private static class ByteArrayCodec implements ValueCodec {
        @Override
        public void write(CompactOutput output, Object value) {
            output.writeByteArray((byte[]) value);
        }

        @Override
        public Object read(CompactInput input) {
            return input.readByteArray();
        }
    }

    private static class NumericStringCodec implements ValueCodec {
        @Override
        public void write(CompactOutput output, Object value) {
            if (value == null) {
                output.writeByte(0);
                return;
            }
            try {
                long longValue = Long.parseLong((String) value);
                output.writeByte(1);
                output.writeVarLong(zigZagEncode(longValue));
            } catch (NumberFormatException e) {
                output.writeByte(2);
                output.writeString((String) value);
            }
        }

        @Override
        public Object read(CompactInput input) {
            return switch (input.readUnsignedByte()) {
                case 0 -> null;
                case 1 -> String.valueOf(zigZagDecode(input.readVarLong()));
                case 2 -> input.readString();
                default -> throw new IllegalArgumentException("invalid numeric string type");
            };
        }
    }

    private static class FixedHexStringCodec implements ValueCodec {
        private final int byteLength;

        private FixedHexStringCodec(int byteLength) {
            this.byteLength = byteLength;
        }

        @Override
        public void write(CompactOutput output, Object value) {
            String stringValue = (String) value;
            if (stringValue == null) {
                output.writeByte(0);
            } else if (isFixedHex(stringValue, false)) {
                output.writeByte(1);
                output.writeBytes(decodeHex(stringValue));
            } else if (isFixedHex(stringValue, true)) {
                output.writeByte(2);
                output.writeBytes(decodeHex(stringValue));
            } else {
                output.writeByte(3);
                output.writeString(stringValue);
            }
        }

        @Override
        public Object read(CompactInput input) {
            return switch (input.readUnsignedByte()) {
                case 0 -> null;
                case 1 -> encodeHex(input.readBytes(byteLength), false);
                case 2 -> encodeHex(input.readBytes(byteLength), true);
                case 3 -> input.readString();
                default -> throw new IllegalArgumentException("invalid hexadecimal string type");
            };
        }

        private boolean isFixedHex(String value, boolean uppercase) {
            if (value.length() != byteLength * 2) {
                return false;
            }
            for (int i = 0; i < value.length(); i++) {
                char character = value.charAt(i);
                if (Character.digit(character, 16) == -1
                        || Character.isLetter(character) && Character.isUpperCase(character) != uppercase) {
                    return false;
                }
            }
            return true;
        }
    }

    private static class UuidStringCodec implements ValueCodec {
        @Override
        public void write(CompactOutput output, Object value) {
            String stringValue = (String) value;
            if (stringValue == null) {
                output.writeByte(0);
                return;
            }
            try {
                UUID uuid = UUID.fromString(stringValue);
                if (uuid.toString().equals(stringValue)) {
                    output.writeByte(1);
                    output.writeLong(uuid.getMostSignificantBits());
                    output.writeLong(uuid.getLeastSignificantBits());
                    return;
                }
            } catch (IllegalArgumentException ignored) {
                // Fall back to the original string representation.
            }
            output.writeByte(2);
            output.writeString(stringValue);
        }

        @Override
        public Object read(CompactInput input) {
            return switch (input.readUnsignedByte()) {
                case 0 -> null;
                case 1 -> new UUID(input.readLong(), input.readLong()).toString();
                case 2 -> input.readString();
                default -> throw new IllegalArgumentException("invalid UUID string type");
            };
        }
    }

    private static class HttpMethodCodec implements ValueCodec {
        private static final List<String> METHODS = List.of("GET", "POST", "PUT", "DELETE");

        @Override
        public void write(CompactOutput output, Object value) {
            String method = (String) value;
            if (method == null) {
                output.writeByte(0);
                return;
            }
            int index = METHODS.indexOf(method);
            if (index >= 0) {
                output.writeByte(index + 1);
            } else {
                output.writeByte(METHODS.size() + 1);
                output.writeString(method);
            }
        }

        @Override
        public Object read(CompactInput input) {
            int type = input.readUnsignedByte();
            if (type == 0) {
                return null;
            }
            if (type <= METHODS.size()) {
                return METHODS.get(type - 1);
            }
            if (type == METHODS.size() + 1) {
                return input.readString();
            }
            throw new IllegalArgumentException("invalid HTTP method type");
        }
    }

    private static class MessageTypeCodec implements ValueCodec {
        @Override
        public void write(CompactOutput output, Object value) {
            output.writeVarInt(value == null ? 0 : ((MessageType) value).getWireId());
        }

        @Override
        public Object read(CompactInput input) {
            int wireId = input.readVarInt();
            if (wireId == 0) {
                return null;
            }
            MessageType value = MessageType.fromWireId(wireId);
            if (value == null) {
                throw new IllegalArgumentException("invalid message type wire id: " + wireId);
            }
            return value;
        }
    }

    private static class StringMapCodec implements ValueCodec {
        @Override
        public void write(CompactOutput output, Object value) {
            if (value == null) {
                output.writeVarInt(0);
                return;
            }
            @SuppressWarnings("unchecked")
            Map<String, String> map = (Map<String, String>) value;
            output.writeVarInt(map.size() + 1);
            map.forEach((key, mapValue) -> {
                output.writeString(key);
                output.writeString(mapValue);
            });
        }

        @Override
        public Object read(CompactInput input) {
            int sizeMarker = input.readVarInt();
            if (sizeMarker == 0) {
                return null;
            }
            Map<String, String> map = new LinkedHashMap<>();
            for (int i = 0; i < sizeMarker - 1; i++) {
                map.put(input.readString(), input.readString());
            }
            return map;
        }
    }

    private static class StringListCodec implements ValueCodec {
        @Override
        public void write(CompactOutput output, Object value) {
            if (value == null) {
                output.writeVarInt(0);
                return;
            }
            @SuppressWarnings("unchecked")
            List<String> list = (List<String>) value;
            output.writeVarInt(list.size() + 1);
            list.forEach(output::writeString);
        }

        @Override
        public Object read(CompactInput input) {
            int sizeMarker = input.readVarInt();
            if (sizeMarker == 0) {
                return null;
            }
            java.util.ArrayList<String> list = new java.util.ArrayList<>(sizeMarker - 1);
            for (int i = 0; i < sizeMarker - 1; i++) {
                list.add(input.readString());
            }
            return list;
        }
    }

    private static class CompactOutput {
        private final ByteArrayOutputStream output = new ByteArrayOutputStream();

        private void writeByte(int value) {
            output.write(value);
        }

        private void writeBytes(byte[] bytes) {
            output.writeBytes(bytes);
        }

        private void writeString(String value) {
            if (value == null) {
                writeVarInt(0);
                return;
            }
            byte[] bytes = value.getBytes(StandardCharsets.UTF_8);
            writeVarInt(bytes.length + 1);
            writeBytes(bytes);
        }

        private void writeByteArray(byte[] value) {
            if (value == null) {
                writeVarInt(0);
                return;
            }
            writeVarInt(value.length + 1);
            writeBytes(value);
        }

        private void writeVarInt(int value) {
            if (value < 0) {
                throw new IllegalArgumentException("variable-length integer cannot be negative");
            }
            while ((value & ~0x7F) != 0) {
                writeByte(value & 0x7F | 0x80);
                value >>>= 7;
            }
            writeByte(value);
        }

        private void writeVarLong(long value) {
            while ((value & ~0x7FL) != 0) {
                writeByte((int) value & 0x7F | 0x80);
                value >>>= 7;
            }
            writeByte((int) value);
        }

        private void writeLong(long value) {
            for (int shift = 56; shift >= 0; shift -= 8) {
                writeByte((int) (value >>> shift));
            }
        }

        private byte[] toByteArray() {
            return output.toByteArray();
        }
    }

    private static class CompactInput {
        private final byte[] bytes;
        private int index;

        private CompactInput(byte[] bytes) {
            this.bytes = bytes;
        }

        private int readUnsignedByte() {
            if (!hasRemaining()) {
                throw new IllegalArgumentException("unexpected end of compact binary payload");
            }
            return bytes[index++] & 0xFF;
        }

        private byte[] readBytes(int length) {
            if (length < 0 || bytes.length - index < length) {
                throw new IllegalArgumentException("unexpected end of compact binary payload");
            }
            byte[] result = Arrays.copyOfRange(bytes, index, index + length);
            index += length;
            return result;
        }

        private String readString() {
            int lengthMarker = readVarInt();
            if (lengthMarker == 0) {
                return null;
            }
            return new String(readBytes(lengthMarker - 1), StandardCharsets.UTF_8);
        }

        private byte[] readByteArray() {
            int lengthMarker = readVarInt();
            return lengthMarker == 0 ? null : readBytes(lengthMarker - 1);
        }

        private int readVarInt() {
            int value = 0;
            for (int shift = 0; shift < 32; shift += 7) {
                int currentByte = readUnsignedByte();
                value |= (currentByte & 0x7F) << shift;
                if ((currentByte & 0x80) == 0) {
                    return value;
                }
            }
            throw new IllegalArgumentException("variable-length integer is too long");
        }

        private long readVarLong() {
            long value = 0;
            for (int shift = 0; shift < 64; shift += 7) {
                int currentByte = readUnsignedByte();
                value |= (long) (currentByte & 0x7F) << shift;
                if ((currentByte & 0x80) == 0) {
                    return value;
                }
            }
            throw new IllegalArgumentException("variable-length long is too long");
        }

        private long readLong() {
            long value = 0;
            for (int i = 0; i < Long.BYTES; i++) {
                value = value << 8 | readUnsignedByte();
            }
            return value;
        }

        private boolean hasRemaining() {
            return index < bytes.length;
        }
    }

    private static long zigZagEncode(long value) {
        return value << 1 ^ value >> 63;
    }

    private static long zigZagDecode(long value) {
        return value >>> 1 ^ -(value & 1);
    }

    private static byte[] decodeHex(String value) {
        byte[] bytes = new byte[value.length() / 2];
        for (int i = 0; i < bytes.length; i++) {
            int high = Character.digit(value.charAt(i * 2), 16);
            int low = Character.digit(value.charAt(i * 2 + 1), 16);
            bytes[i] = (byte) (high << 4 | low);
        }
        return bytes;
    }

    private static String encodeHex(byte[] bytes, boolean uppercase) {
        char[] alphabet = uppercase ? "0123456789ABCDEF".toCharArray() : "0123456789abcdef".toCharArray();
        char[] result = new char[bytes.length * 2];
        for (int i = 0; i < bytes.length; i++) {
            result[i * 2] = alphabet[(bytes[i] >>> 4) & 0x0F];
            result[i * 2 + 1] = alphabet[bytes[i] & 0x0F];
        }
        return new String(result);
    }
}
